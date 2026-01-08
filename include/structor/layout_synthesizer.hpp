#pragma once

#include "synth_types.hpp"
#include "config.hpp"
#include "utils.hpp"

namespace structor {

/// Synthesizes structure layouts from collected access patterns
class LayoutSynthesizer {
public:
    explicit LayoutSynthesizer(const SynthOptions& opts = Config::instance().options())
        : options_(opts) {}

    /// Synthesize a structure from access patterns
    [[nodiscard]] SynthStruct synthesize(const AccessPattern& pattern);

    /// Get any detected conflicts
    [[nodiscard]] const qvector<AccessConflict>& conflicts() const noexcept {
        return conflicts_;
    }

    /// Check if there were conflicts during synthesis
    [[nodiscard]] bool has_conflicts() const noexcept {
        return !conflicts_.empty();
    }

private:
    /// Group accesses by offset range
    struct OffsetGroup {
        sval_t          offset;
        std::uint32_t   size;
        qvector<FieldAccess> accesses;
        bool            is_union;

        OffsetGroup() : offset(0), size(0), is_union(false) {}
    };

    void group_accesses(const AccessPattern& pattern, qvector<OffsetGroup>& groups);
    void resolve_conflicts(qvector<OffsetGroup>& groups);
    void generate_fields(const qvector<OffsetGroup>& groups, SynthStruct& result);
    void insert_padding(SynthStruct& result);
    void infer_field_types(SynthStruct& result, const AccessPattern& pattern);
    void generate_field_names(SynthStruct& result);
    void compute_struct_size(SynthStruct& result);

    [[nodiscard]] tinfo_t select_best_type(const qvector<FieldAccess>& accesses);
    [[nodiscard]] SemanticType select_best_semantic(const qvector<FieldAccess>& accesses);

    const SynthOptions& options_;
    qvector<AccessConflict> conflicts_;
};

// ============================================================================
// Implementation
// ============================================================================

inline SynthStruct LayoutSynthesizer::synthesize(const AccessPattern& pattern) {
    conflicts_.clear();

    SynthStruct result;
    result.source_func = pattern.func_ea;
    result.source_var = pattern.var_name;
    result.alignment = options_.alignment;
    result.name = generate_struct_name(pattern.func_ea);
    result.add_provenance(pattern.func_ea);

    if (pattern.accesses.empty()) {
        return result;
    }

    // Group accesses by offset
    qvector<OffsetGroup> groups;
    group_accesses(pattern, groups);

    // Resolve any conflicts
    resolve_conflicts(groups);

    // Generate fields from groups
    generate_fields(groups, result);

    // Insert padding where needed
    insert_padding(result);

    // Infer and set field types
    infer_field_types(result, pattern);

    // Generate meaningful field names
    generate_field_names(result);

    // Compute final structure size
    compute_struct_size(result);

    return result;
}

inline void LayoutSynthesizer::group_accesses(const AccessPattern& pattern, qvector<OffsetGroup>& groups) {
    // Sort accesses by offset
    qvector<FieldAccess> sorted = pattern.accesses;
    std::sort(sorted.begin(), sorted.end());

    // Group overlapping accesses
    for (const auto& access : sorted) {
        bool merged = false;

        for (auto& group : groups) {
            // Check for overlap
            sval_t group_end = group.offset + static_cast<sval_t>(group.size);
            sval_t access_end = access.offset + static_cast<sval_t>(access.size);

            if (access.offset < group_end && access_end > group.offset) {
                // Overlapping - merge into group
                group.accesses.push_back(access);
                group.offset = std::min(group.offset, access.offset);
                group.size = std::max(group_end, access_end) - group.offset;

                // Mark as potential union if different sizes at same offset
                if (access.offset == group.accesses[0].offset &&
                    access.size != group.accesses[0].size) {
                    group.is_union = true;
                }

                merged = true;
                break;
            }
        }

        if (!merged) {
            OffsetGroup new_group;
            new_group.offset = access.offset;
            new_group.size = access.size;
            new_group.accesses.push_back(access);
            groups.push_back(std::move(new_group));
        }
    }

    // Sort groups by offset
    std::sort(groups.begin(), groups.end(), [](const OffsetGroup& a, const OffsetGroup& b) {
        return a.offset < b.offset;
    });
}

inline void LayoutSynthesizer::resolve_conflicts(qvector<OffsetGroup>& groups) {
    for (auto& group : groups) {
        if (group.accesses.size() <= 1) continue;

        // Check for conflicting access sizes at the same offset
        std::unordered_map<sval_t, qvector<FieldAccess*>> by_offset;
        for (auto& access : group.accesses) {
            by_offset[access.offset].push_back(&access);
        }

        for (auto& [off, acc_list] : by_offset) {
            if (acc_list.size() <= 1) continue;

            // Check for size conflicts
            std::uint32_t first_size = acc_list[0]->size;
            bool has_conflict = false;

            for (size_t i = 1; i < acc_list.size(); ++i) {
                if (acc_list[i]->size != first_size) {
                    has_conflict = true;
                    break;
                }
            }

            if (has_conflict) {
                AccessConflict conflict;
                conflict.offset = off;
                conflict.description.sprnt("Conflicting access sizes at offset 0x%X", static_cast<unsigned>(off));

                for (auto* acc : acc_list) {
                    conflict.conflicting_accesses.push_back(*acc);
                }

                conflicts_.push_back(std::move(conflict));
                group.is_union = true;
            }
        }
    }
}

inline void LayoutSynthesizer::generate_fields(const qvector<OffsetGroup>& groups, SynthStruct& result) {
    for (const auto& group : groups) {
        SynthField field;
        field.offset = group.offset;
        field.size = group.size;
        field.is_union_candidate = group.is_union;
        field.source_accesses = group.accesses;

        // Select best type and semantic from all accesses
        field.type = select_best_type(group.accesses);
        field.semantic = select_best_semantic(group.accesses);

        result.fields.push_back(std::move(field));
    }

    // Sort fields by offset
    std::sort(result.fields.begin(), result.fields.end(),
        [](const SynthField& a, const SynthField& b) {
            return a.offset < b.offset;
        });
}

inline void LayoutSynthesizer::insert_padding(SynthStruct& result) {
    if (result.fields.empty()) return;

    qvector<SynthField> with_padding;
    sval_t current_offset = 0;

    for (auto& field : result.fields) {
        // Insert padding if there's a gap
        if (field.offset > current_offset) {
            std::uint32_t gap = field.offset - current_offset;
            with_padding.push_back(SynthField::create_padding(current_offset, gap));
        }

        with_padding.push_back(std::move(field));
        current_offset = with_padding.back().offset + with_padding.back().size;
    }

    result.fields = std::move(with_padding);
}

inline void LayoutSynthesizer::infer_field_types(SynthStruct& result, const AccessPattern& pattern) {
    std::uint32_t ptr_size = get_ptr_size();

    for (auto& field : result.fields) {
        if (field.is_padding) continue;
        if (!field.type.empty()) continue;

        // Infer type from semantic and size
        switch (field.semantic) {
            case SemanticType::VTablePointer: {
                // Create pointer to vtable type if vtable was synthesized
                if (result.has_vtable() && result.vtable->tid != BADADDR) {
                    tinfo_t vtbl_type;
                    if (vtbl_type.get_type_by_tid(result.vtable->tid)) {
                        field.type.create_ptr(vtbl_type);
                    }
                }
                if (field.type.empty()) {
                    tinfo_t void_type;
                    void_type.create_simple_type(BTF_VOID);
                    tinfo_t void_ptr;
                    void_ptr.create_ptr(void_type);
                    field.type.create_ptr(void_ptr);  // void**
                }
                break;
            }

            case SemanticType::FunctionPointer: {
                func_type_data_t ftd;
                ftd.rettype.create_simple_type(BTF_VOID);
                ftd.set_cc(CM_CC_UNKNOWN);
                tinfo_t func_type;
                func_type.create_func(ftd);
                field.type.create_ptr(func_type);
                break;
            }

            case SemanticType::Pointer: {
                tinfo_t void_type;
                void_type.create_simple_type(BTF_VOID);
                field.type.create_ptr(void_type);
                break;
            }

            case SemanticType::Float:
                field.type.create_simple_type(BTF_FLOAT);
                break;

            case SemanticType::Double:
                field.type.create_simple_type(BTF_DOUBLE);
                break;

            case SemanticType::UnsignedInteger:
                field.type = utils::create_basic_type(field.size, SemanticType::UnsignedInteger);
                break;

            case SemanticType::Integer:
            case SemanticType::Unknown:
            default:
                // Default to integer type based on size
                if (field.size == ptr_size) {
                    // Could be pointer - check accesses
                    bool any_deref = false;
                    for (const auto& acc : field.source_accesses) {
                        if (acc.semantic_type == SemanticType::Pointer ||
                            acc.semantic_type == SemanticType::FunctionPointer) {
                            any_deref = true;
                            break;
                        }
                    }

                    if (any_deref) {
                        tinfo_t void_type;
                        void_type.create_simple_type(BTF_VOID);
                        field.type.create_ptr(void_type);
                    } else {
                        field.type = utils::create_basic_type(field.size, SemanticType::Integer);
                    }
                } else {
                    field.type = utils::create_basic_type(field.size, SemanticType::Integer);
                }
                break;
        }
    }
}

inline void LayoutSynthesizer::generate_field_names(SynthStruct& result) {
    for (auto& field : result.fields) {
        if (field.is_padding) continue;
        if (!field.name.empty()) continue;

        field.name = generate_field_name(field.offset, field.semantic);

        // Generate comment if enabled
        if (options_.generate_comments) {
            qstring comment;
            comment.sprnt("size: %u, accesses: %zu", field.size, field.source_accesses.size());

            if (!field.source_accesses.empty()) {
                const auto& first_access = field.source_accesses[0];
                comment.cat_sprnt(", %s", access_type_str(first_access.access_type));
            }

            if (field.is_union_candidate) {
                comment.append(" [union candidate]");
            }

            field.comment = std::move(comment);
        }
    }
}

inline void LayoutSynthesizer::compute_struct_size(SynthStruct& result) {
    if (result.fields.empty()) {
        result.size = 0;
        return;
    }

    const auto& last_field = result.fields.back();
    sval_t end = last_field.offset + last_field.size;

    // Align to structure alignment
    result.size = align_offset(end, result.alignment);
}

// Type resolution utilities (type_priority_score, strip_ptr, resolve_type_conflict)
// are defined in synth_types.hpp and available via include

inline tinfo_t LayoutSynthesizer::select_best_type(const qvector<FieldAccess>& accesses) {
    // Use type-aware conflict resolution (adopted from Suture)
    tinfo_t best;

    for (const auto& access : accesses) {
        if (access.inferred_type.empty()) continue;

        if (best.empty()) {
            best = access.inferred_type;
            continue;
        }

        // Use Suture-style conflict resolution
        best = resolve_type_conflict(best, access.inferred_type);
    }

    return best;
}

// semantic_priority() is defined in synth_types.hpp

/// Calculate complexity score for an access pattern (adopted from Suture)
/// More complex patterns (vtable calls, nested derefs) get higher scores
[[nodiscard]] inline int access_complexity_score(const FieldAccess& access) {
    int score = 0;

    // Base score from semantic type
    score += semantic_priority(access.semantic_type);

    // Bonus for vtable accesses (more complex pattern)
    if (access.is_vtable_access) {
        score += 20;
    }

    // Bonus for call accesses (indicates function pointer)
    if (access.access_type == AccessType::Call) {
        score += 15;
    }

    // Bonus for having concrete type info
    if (!access.inferred_type.empty()) {
        score += 10;
        if (access.inferred_type.is_funcptr()) {
            score += 5;
        }
    }

    return score;
}

inline SemanticType LayoutSynthesizer::select_best_semantic(const qvector<FieldAccess>& accesses) {
    // Use complexity-weighted selection (adopted from Suture's pattern prioritization)
    SemanticType best = SemanticType::Unknown;
    int best_score = 0;

    for (const auto& access : accesses) {
        int score = access_complexity_score(access);
        if (score > best_score) {
            best_score = score;
            best = access.semantic_type;
        }
    }

    return best;
}

} // namespace structor
