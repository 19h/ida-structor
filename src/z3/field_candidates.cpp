#include "structor/z3/field_candidates.hpp"
#include "structor/z3/array_constraints.hpp"
#include "structor/naming.hpp"
#include "structor/optimized_algorithms.hpp"
#include "structor/optimized_containers.hpp"
#include <algorithm>
#include <unordered_map>
#include <unordered_set>

#ifndef STRUCTOR_TESTING
#include <pro.h>
#include <kernwin.hpp>
#endif

namespace structor::z3 {

namespace {
    // Helper for conditional logging
    inline void z3_log(const char* fmt, ...) {
#ifndef STRUCTOR_TESTING
        va_list va;
        va_start(va, fmt);
        vmsg(fmt, va);
        va_end(va);
#endif
    }

    struct MixedStrideField {
        uint32_t inner_offset = 0;
        uint32_t size = 0;
        tinfo_t type;
        qvector<int> access_indices;
    };

    struct MixedStrideKey {
        uint32_t inner_offset = 0;
        uint32_t size = 0;

        bool operator==(const MixedStrideKey& other) const noexcept {
            return inner_offset == other.inner_offset && size == other.size;
        }
    };

    struct MixedStrideKeyHash {
        size_t operator()(const MixedStrideKey& key) const noexcept {
            return (static_cast<size_t>(key.inner_offset) << 16) ^ key.size;
        }
    };

    bool is_dominated_by_struct_array(const FieldCandidate& array_candidate,
                                      const FieldCandidate& other) {
        if (array_candidate.kind != FieldCandidate::Kind::ArrayField ||
            array_candidate.type_category != TypeCategory::Struct) {
            return false;
        }

        if (other.kind != FieldCandidate::Kind::DirectAccess &&
            other.kind != FieldCandidate::Kind::ArrayField) {
            return false;
        }

        const bool compact_byte_array =
            other.kind == FieldCandidate::Kind::ArrayField &&
            other.type_category == TypeCategory::UInt8 &&
            other.array_stride.value_or(0) == 1 &&
            other.size <= 16;
        if (compact_byte_array) {
            return false;
        }

        if (array_candidate.offset > other.offset ||
            array_candidate.end_offset() < other.end_offset()) {
            return false;
        }

        if (other.kind == FieldCandidate::Kind::DirectAccess) {
            return other.offset == array_candidate.offset ||
                   (other.offset >= array_candidate.offset &&
                    other.offset < array_candidate.end_offset() &&
                    array_candidate.source_access_indices.size() > other.source_access_indices.size());
        }

        if (other.kind == FieldCandidate::Kind::ArrayField &&
            other.type_category == TypeCategory::Struct) {
            return array_candidate.offset < other.offset &&
                   array_candidate.end_offset() >= other.end_offset();
        }

        return array_candidate.offset < other.offset ||
               array_candidate.source_access_indices.size() > other.source_access_indices.size();
    }

    bool build_struct_type_from_groups(
        const qvector<MixedStrideField>& fields,
        uint32_t stride,
        tinfo_t& out_type)
    {
        if (fields.size() < 2) {
            return false;
        }

        udt_type_data_t udt;
        udt.is_union = false;
        udt.total_size = stride;

        auto append_gap_member = [&](uint32_t offset, uint32_t size) {
            if (size == 0) {
                return;
            }

            udm_t gap;
            gap.offset = static_cast<uint64>(offset) * 8;
            gap.name = generate_field_name(offset, SemanticType::Unknown, size);

            if (size == 4) {
                gap.type.create_simple_type(BT_INT32 | BTMT_UNSIGNED);
            } else if (size == 2) {
                gap.type.create_simple_type(BT_INT16 | BTMT_UNSIGNED);
            } else if (size == 1) {
                gap.type.create_simple_type(BT_INT8 | BTMT_UNSIGNED);
            } else {
                tinfo_t byte_type;
                byte_type.create_simple_type(BT_INT8 | BTMT_UNSIGNED);
                gap.type.create_array(byte_type, size);
            }

            const asize_t member_size = gap.type.get_size();
            gap.size = member_size == BADSIZE ? size * 8 : member_size * 8;
            udt.push_back(gap);
        };

        uint32_t cursor = 0;

        auto is_function_pointer_type = [](const tinfo_t& type) {
            if (type.empty()) {
                return false;
            }
            if (type.is_func()) {
                return true;
            }
            if (type.is_funcptr()) {
                return true;
            }
            if (!type.is_ptr()) {
                return false;
            }
            tinfo_t pointed = type.get_pointed_object();
            return !pointed.empty() && pointed.is_func();
        };

        int func_field_count = 0;
        for (const auto& field : fields) {
            if (is_function_pointer_type(field.type)) {
                ++func_field_count;
            }
        }

        auto is_array_mergeable = [](const MixedStrideField& a, const MixedStrideField& b) {
            if (a.inner_offset + a.size != b.inner_offset) {
                return false;
            }
            if (a.size != b.size) {
                return false;
            }
            if (a.type.empty() != b.type.empty()) {
                return false;
            }
            if (!a.type.empty()) {
                return a.type.equals_to(b.type);
            }
            return true;
        };

        auto is_byte_field = [](const MixedStrideField& field) {
            if (field.size != 1) {
                return false;
            }
            return field.type.empty() || field.type.get_size() == 1;
        };

        for (size_t i = 0; i < fields.size(); ++i) {
            MixedStrideField merged = fields[i];
            uint32_t merged_count = 1;

            size_t j = i + 1;
            while (j < fields.size() && is_array_mergeable(merged, fields[j])) {
                merged.size += fields[j].size;
                ++merged_count;
                ++j;
            }
            i = j - 1;

            if (merged.inner_offset > cursor) {
                append_gap_member(cursor, merged.inner_offset - cursor);
            }

            udm_t udm;
            udm.offset = static_cast<uint64>(merged.inner_offset) * 8;
            if (merged_count > 1) {
                udm.name = make_array_field_name(merged.inner_offset,
                                                 merged.type,
                                                 SemanticType::Unknown,
                                                 fields[i].size);
            } else if (is_function_pointer_type(merged.type)) {
                if (func_field_count == 1) {
                    udm.name = "callback";
                } else {
                    udm.name.sprnt("callback_%X", merged.inner_offset);
                }
            } else {
                udm.name = generate_field_name(merged.inner_offset,
                                               SemanticType::Unknown,
                                               merged.size);
            }

            if (merged_count > 1) {
                tinfo_t elem_type;
                if (!merged.type.empty()) {
                    elem_type = merged.type;
                } else {
                    elem_type.create_simple_type(BT_INT8 | BTMT_USIGNED);
                }

                udm.type.create_array(elem_type, merged_count);
                udm.size = merged.size * 8;
            } else if (!merged.type.empty()) {
                udm.type = merged.type;
                udm.size = merged.type.get_size() * 8;
            } else {
                tinfo_t byte_type;
                byte_type.create_simple_type(BT_INT8 | BTMT_USIGNED);
                if (merged.size > 1) {
                    udm.type.create_array(byte_type, merged.size);
                } else {
                    udm.type = byte_type;
                }
                udm.size = merged.size * 8;
            }
            udt.push_back(udm);

            cursor = std::max(cursor, merged.inner_offset + merged.size);
        }

        if (cursor < stride) {
            append_gap_member(cursor, stride - cursor);
        }

        if (!out_type.create_udt(udt)) {
            return false;
        }

        out_type.set_udt_pack(1);
        out_type.set_udt_alignment(1);
        return true;
    }

    void augment_struct_array_candidate(ArrayCandidate& array, const UnifiedAccessPattern& pattern) {
        if (!array.needs_element_struct || array.stride == 0 || array.element_count < 3) {
            return;
        }

        struct BestAugmentation {
            sval_t base = 0;
            qvector<MixedStrideField> fields;
            int score = -1;
        } best;

        for (uint32_t shift = 0; shift < array.stride; ++shift) {
            const sval_t base = array.base_offset - static_cast<sval_t>(shift);
            std::unordered_map<MixedStrideKey, MixedStrideField, MixedStrideKeyHash> groups;

            for (size_t i = 0; i < pattern.all_accesses.size(); ++i) {
                const auto& access = pattern.all_accesses[i];
                if (access.offset < base) {
                    continue;
                }
                const sval_t rel = access.offset - base;
                if (rel < 0) {
                    continue;
                }
                uint32_t idx = static_cast<uint32_t>(rel / array.stride);
                if (idx >= array.element_count) {
                    continue;
                }
                uint32_t inner = static_cast<uint32_t>(rel % array.stride);
                if (inner + access.size > array.stride) {
                    continue;
                }

                MixedStrideKey key{inner, access.size};
                auto& field = groups[key];
                field.inner_offset = inner;
                field.size = access.size;
                if (field.type.empty() && !access.inferred_type.empty()) {
                    field.type = access.inferred_type;
                }
                field.access_indices.push_back(static_cast<int>(i));
            }

            qvector<MixedStrideField> repeated;
            int score = 0;
            for (auto& [key, field] : groups) {
                std::unordered_set<uint32_t> indices;
                for (int idx : field.access_indices) {
                    const auto& access = pattern.all_accesses[idx];
                    indices.insert(static_cast<uint32_t>((access.offset - base) / array.stride));
                }
                if (indices.size() >= std::min<uint32_t>(3, array.element_count)) {
                    repeated.push_back(field);
                    ++score;
                }
            }

            if (score < 2) {
                continue;
            }

            std::sort(repeated.begin(), repeated.end(), [](const MixedStrideField& a, const MixedStrideField& b) {
                if (a.inner_offset != b.inner_offset) return a.inner_offset < b.inner_offset;
                return a.size > b.size;
            });

            if (score > best.score || (score == best.score && base < best.base)) {
                best.base = base;
                best.fields = std::move(repeated);
                best.score = score;
            }
        }

        if (best.score < 2) {
            return;
        }

        tinfo_t struct_type;
        if (!build_struct_type_from_groups(best.fields, array.stride, struct_type)) {
            return;
        }

        array.base_offset = best.base;
        array.element_type = struct_type;
        array.member_offsets.clear();
        for (const auto& field : best.fields) {
            for (uint32_t i = 0; i < array.element_count; ++i) {
                array.member_offsets.push_back(best.base + field.inner_offset + i * array.stride);
            }
        }
        std::sort(array.member_offsets.begin(), array.member_offsets.end());
        array.member_offsets.erase(std::unique(array.member_offsets.begin(), array.member_offsets.end()),
                                   array.member_offsets.end());
    }

    std::optional<FieldCandidate> build_struct_array_candidate(
        Z3Context& ctx,
        const UnifiedAccessPattern& pattern,
        sval_t base,
        uint32_t stride,
        uint32_t count)
    {
        if (count < 3 || stride == 0) {
            return std::nullopt;
        }

        std::unordered_map<MixedStrideKey, MixedStrideField, MixedStrideKeyHash> by_inner;
        qvector<int> used_indices;

        for (size_t i = 0; i < pattern.all_accesses.size(); ++i) {
            const auto& access = pattern.all_accesses[i];
            if (access.offset < base) {
                continue;
            }
            sval_t rel = access.offset - base;
            if (rel < 0) {
                continue;
            }
            uint32_t idx = static_cast<uint32_t>(rel / stride);
            if (idx >= count) {
                continue;
            }
            uint32_t inner = static_cast<uint32_t>(rel % stride);
            if (inner + access.size > stride) {
                continue;
            }

            MixedStrideKey key{inner, access.size};
            auto& field = by_inner[key];
            field.inner_offset = inner;
            field.size = access.size;
            if (field.type.empty() && !access.inferred_type.empty()) {
                field.type = access.inferred_type;
            }
            field.access_indices.push_back(static_cast<int>(i));
        }

        qvector<MixedStrideField> repeated;
        for (auto& [key, field] : by_inner) {
            std::unordered_set<uint32_t> indices;
            for (int access_idx : field.access_indices) {
                const auto& access = pattern.all_accesses[access_idx];
                indices.insert(static_cast<uint32_t>((access.offset - base) / stride));
            }
            if (indices.size() >= 3) {
                repeated.push_back(field);
            }
        }

        if (repeated.size() < 2) {
            return std::nullopt;
        }

        std::sort(repeated.begin(), repeated.end(), [](const MixedStrideField& a, const MixedStrideField& b) {
            if (a.access_indices.size() != b.access_indices.size()) {
                return a.access_indices.size() > b.access_indices.size();
            }
            if (a.inner_offset != b.inner_offset) {
                return a.inner_offset < b.inner_offset;
            }
            return a.size > b.size;
        });

        uint32_t effective_count = count;
        for (const auto& field : repeated) {
            std::unordered_set<uint32_t> indices;
            for (int access_idx : field.access_indices) {
                const auto& access = pattern.all_accesses[access_idx];
                indices.insert(static_cast<uint32_t>((access.offset - base) / stride));
            }
            uint32_t contiguous = 0;
            while (indices.count(contiguous) > 0) {
                ++contiguous;
            }
            effective_count = std::min(effective_count, contiguous);
        }

        if (effective_count < 3) {
            return std::nullopt;
        }

        for (const auto& field : repeated) {
            for (int access_idx : field.access_indices) {
                const auto& access = pattern.all_accesses[access_idx];
                uint32_t idx = static_cast<uint32_t>((access.offset - base) / stride);
                if (idx < effective_count) {
                    used_indices.push_back(access_idx);
                }
            }
        }

        std::sort(repeated.begin(), repeated.end(), [](const MixedStrideField& a, const MixedStrideField& b) {
            return a.inner_offset < b.inner_offset;
        });

        repeated.erase(std::remove_if(repeated.begin(), repeated.end(), [&](const MixedStrideField& field) {
            std::unordered_set<uint32_t> indices;
            for (int access_idx : field.access_indices) {
                const auto& access = pattern.all_accesses[access_idx];
                uint32_t idx = static_cast<uint32_t>((access.offset - base) / stride);
                if (idx < effective_count) {
                    indices.insert(idx);
                }
            }
            return indices.size() < effective_count;
        }), repeated.end());

        if (repeated.size() < 2) {
            return std::nullopt;
        }

        // Reject spurious "struct arrays" that only explain roughly one
        // access per element. Real arrays-of-structs should expose multiple
        // inner members across repeated elements.
        if (used_indices.size() < effective_count * 2) {
            return std::nullopt;
        }

        tinfo_t elem_type;
        if (!build_struct_type_from_groups(repeated, stride, elem_type)) {
            return std::nullopt;
        }

        FieldCandidate candidate;
        candidate.offset = base;
        candidate.size = stride * effective_count;
        candidate.kind = FieldCandidate::Kind::ArrayField;
        candidate.type_category = TypeCategory::Struct;
        candidate.extended_type = ctx.type_encoder().extract_extended_info(elem_type);
        candidate.array_element_count = effective_count;
        candidate.array_stride = stride;
        candidate.confidence = TypeConfidence::Medium;
        candidate.source_access_indices = std::move(used_indices);
        return candidate;
    }
}

// ============================================================================
// FieldCandidateGenerator Implementation
// ============================================================================

FieldCandidateGenerator::FieldCandidateGenerator(
    Z3Context& ctx,
    const CandidateGenerationConfig& config)
    : ctx_(ctx)
    , config_(config) {}

qvector<FieldCandidate> FieldCandidateGenerator::generate(
    const UnifiedAccessPattern& pattern)
{
    qvector<FieldCandidate> candidates;
    next_id_ = 0;

    z3_log("[Structor/Z3] Generating field candidates from %zu accesses\n", pattern.all_accesses.size());

    if (pattern.all_accesses.empty()) {
        return candidates;
    }

    // Pre-allocate: estimate ~1.5x accesses for direct + covering + arrays + padding
    candidates.reserve(pattern.all_accesses.size() * 3 / 2 + 16);

    // Step 1: Generate direct access candidates
    generate_direct_candidates(pattern, candidates);
    size_t direct_count = candidates.size();
    z3_log("[Structor/Z3]   Direct access candidates: %zu\n", direct_count);

    // Step 2: Generate covering candidates (larger fields that cover multiple accesses)
    if (config_.generate_covering_candidates) {
        generate_covering_candidates(pattern, candidates);
        z3_log("[Structor/Z3]   Covering candidates: %zu\n", candidates.size() - direct_count);
    }

    size_t before_array = candidates.size();
    // Step 3: Generate array candidates
    if (config_.generate_array_candidates) {
        generate_array_candidates(pattern, candidates);
        z3_log("[Structor/Z3]   Array candidates: %zu\n", candidates.size() - before_array);
    }

    size_t before_padding = candidates.size();
    // Step 4: Generate padding candidates
    if (config_.generate_padding_candidates) {
        generate_padding_candidates(candidates, pattern.global_max_offset, candidates);
        z3_log("[Structor/Z3]   Padding candidates: %zu\n", candidates.size() - before_padding);
    }

    // Step 5: Prune candidates dominated by richer struct-array candidates.
    qvector<FieldCandidate> pruned;
    pruned.reserve(candidates.size());
    for (size_t i = 0; i < candidates.size(); ++i) {
        bool dominated = false;

        if (candidates[i].kind == FieldCandidate::Kind::DirectAccess) {
            for (size_t j = 0; j < candidates.size(); ++j) {
                if (i == j) {
                    continue;
                }
                const auto& other = candidates[j];
                if (other.kind == FieldCandidate::Kind::ArrayField &&
                    other.type_category == TypeCategory::Struct &&
                    other.offset == candidates[i].offset &&
                    other.end_offset() >= candidates[i].end_offset()) {
                    dominated = true;
                    break;
                }
            }
        }

        for (size_t j = 0; j < candidates.size(); ++j) {
            if (i == j) {
                continue;
            }
            if (is_dominated_by_struct_array(candidates[j], candidates[i])) {
                dominated = true;
                break;
            }
        }
        if (!dominated) {
            pruned.push_back(std::move(candidates[i]));
        }
    }
    candidates = std::move(pruned);

    // Finalize: assign IDs and sort
    finalize_candidates(candidates);

    z3_log("[Structor/Z3]   Total candidates generated: %zu\n", candidates.size());
    
    // Log candidate summary by offset
    if (!candidates.empty()) {
        z3_log("[Structor/Z3]   Candidate summary:\n");
        for (const auto& cand : candidates) {
            const char* kind_str = "unknown";
            switch (cand.kind) {
                case FieldCandidate::Kind::DirectAccess: kind_str = "direct"; break;
                case FieldCandidate::Kind::CoveringField: kind_str = "covering"; break;
                case FieldCandidate::Kind::ArrayElement: kind_str = "array_elem"; break;
                case FieldCandidate::Kind::ArrayField: kind_str = "array"; break;
                case FieldCandidate::Kind::PaddingField: kind_str = "padding"; break;
                case FieldCandidate::Kind::UnionAlternative: kind_str = "union_alt"; break;
            }
            z3_log("[Structor/Z3]     [%d] offset=0x%llX size=%u type=%s kind=%s\n",
                   cand.id, static_cast<unsigned long long>(cand.offset), cand.size,
                   type_category_name(cand.type_category), kind_str);
        }
    }

    return candidates;
}

void FieldCandidateGenerator::generate_direct_candidates(
    const UnifiedAccessPattern& pattern,
    qvector<FieldCandidate>& candidates)
{
    for (size_t i = 0; i < pattern.all_accesses.size(); ++i) {
        const auto& access = pattern.all_accesses[i];

        if (!access.inferred_type.empty() &&
            (access.inferred_type.is_array() || access.inferred_type.is_struct()) &&
            access.size > 8) {
            int covered_subaccesses = 0;
            const sval_t access_end = access.offset + static_cast<sval_t>(access.size);
            for (size_t j = 0; j < pattern.all_accesses.size(); ++j) {
                if (i == j) {
                    continue;
                }
                const auto& other = pattern.all_accesses[j];
                const sval_t other_end = other.offset + static_cast<sval_t>(other.size);
                if (other.offset >= access.offset && other_end <= access_end &&
                    (other.size < access.size || other.offset != access.offset)) {
                    ++covered_subaccesses;
                }
            }
            if (covered_subaccesses >= 2) {
                continue;
            }
        }

        TypeCategory new_cat = infer_category(access);
        bool merged = false;

        for (auto& existing : candidates) {
            if (existing.offset != access.offset || existing.size != access.size) {
                continue;
            }

            if (existing.type_category == new_cat ||
                new_cat == TypeCategory::Unknown ||
                existing.type_category == TypeCategory::Unknown ||
                types_compatible(existing.type_category, new_cat)) {
                existing.source_access_indices.push_back(static_cast<int>(i));
                if (static_cast<int>(new_cat) > static_cast<int>(existing.type_category)) {
                    existing.type_category = new_cat;
                }
                if (!access.inferred_type.empty()) {
                    existing.extended_type = ctx_.type_encoder().extract_extended_info(access.inferred_type);
                }
                merged = true;
                break;
            }
        }

        if (!merged) {
            FieldCandidate candidate = create_from_access(access, static_cast<int>(i));
            if (std::any_of(candidates.begin(), candidates.end(), [&](const FieldCandidate& existing) {
                    return existing.offset == candidate.offset &&
                           existing.size == candidate.size;
                })) {
                candidate.kind = FieldCandidate::Kind::UnionAlternative;
            }
            candidates.push_back(std::move(candidate));
        }
    }
}

void FieldCandidateGenerator::generate_covering_candidates(
    const UnifiedAccessPattern& pattern,
    qvector<FieldCandidate>& candidates)
{
    if (candidates.empty()) return;

    // Sort candidates by offset for analysis
    qvector<FieldCandidate> sorted_candidates = candidates;
    std::sort(sorted_candidates.begin(), sorted_candidates.end(),
        [](const FieldCandidate& a, const FieldCandidate& b) {
            return a.offset < b.offset;
        });

    // Find groups of adjacent small fields that could be covered by a larger field
    qvector<FieldCandidate> covering;

    size_t i = 0;
    while (i < sorted_candidates.size()) {
        // Look for sequence of small fields
        size_t j = i + 1;
        sval_t group_start = sorted_candidates[i].offset;
        sval_t group_end = sorted_candidates[i].end_offset();

        // Extend group while fields are adjacent or slightly gapped
        while (j < sorted_candidates.size()) {
            const auto& next = sorted_candidates[j];
            sval_t gap = next.offset - group_end;

            // Allow small gaps (padding)
            if (gap < 0 || gap > 4) break;

            group_end = next.end_offset();
            ++j;
        }

        // If we found multiple fields, create covering candidate
        if (j > i + 1) {
            uint32_t covering_size = static_cast<uint32_t>(group_end - group_start);

            if (covering_size <= config_.max_covering_size) {
                FieldCandidate cover;
                cover.offset = group_start;
                cover.size = covering_size;
                cover.kind = FieldCandidate::Kind::CoveringField;
                cover.type_category = TypeCategory::RawBytes;
                cover.confidence = TypeConfidence::Low;

                // Track which candidates this covers
                for (size_t k = i; k < j; ++k) {
                    for (int idx : sorted_candidates[k].source_access_indices) {
                        cover.source_access_indices.push_back(idx);
                    }
                }

                covering.push_back(std::move(cover));
            }
        }

        i = j;
    }

    // Add covering candidates
    for (auto& c : covering) {
        candidates.push_back(std::move(c));
    }
}

void FieldCandidateGenerator::generate_array_candidates(
    const UnifiedAccessPattern& pattern,
    qvector<FieldCandidate>& candidates)
{
    constexpr double kMinArrayCoverageRatio = 0.75;

    ArrayDetectionConfig array_config;
    array_config.min_elements = static_cast<int>(config_.min_array_elements);

    ArrayConstraintBuilder array_builder(ctx_, array_config);
    auto arrays = array_builder.detect_arrays(pattern.all_accesses);
    if (arrays.empty()) {
        return;
    }

    std::unordered_map<uint64_t, int> direct_index;
    for (size_t i = 0; i < candidates.size(); ++i) {
        if (candidates[i].kind != FieldCandidate::Kind::DirectAccess) {
            continue;
        }
        uint64_t key = (static_cast<uint64_t>(candidates[i].offset) << 32) |
                       static_cast<uint64_t>(candidates[i].size);
        direct_index[key] = static_cast<int>(i);
    }

    for (const auto& detected_array : arrays) {
        ArrayCandidate array = detected_array;
        augment_struct_array_candidate(array, pattern);

        if (array.element_count == 0) {
            continue;
        }

        std::unordered_set<sval_t> member_offsets;
        for (sval_t off : array.member_offsets) {
            member_offsets.insert(off);
        }

        const double ratio = static_cast<double>(member_offsets.size()) /
                             static_cast<double>(array.element_count);
        if (ratio < kMinArrayCoverageRatio) {
            continue;
        }

        size_t elem_size = array.element_type.get_size();
        if (elem_size == BADSIZE || elem_size == 0) {
            elem_size = array.stride;
        }

        uint32_t access_size = static_cast<uint32_t>(elem_size);
        if (array.needs_element_struct && array.inner_access_size > 0) {
            access_size = array.inner_access_size;
        }

        if (array.element_count == 3 && access_size == 4 && !array.needs_element_struct) {
            continue;
        }

        bool conflicting_access = false;
        if (!array.needs_element_struct) {
            for (const auto& access : pattern.all_accesses) {
                if (!array.contains_offset(access.offset)) {
                    continue;
                }

                if (member_offsets.count(access.offset) > 0 && access.size == access_size) {
                    continue;
                }

                conflicting_access = true;
                break;
            }
        }

        if (conflicting_access) {
            continue;
        }

        FieldCandidate array_candidate;
        array_candidate.offset = array.base_offset;
        array_candidate.size = array.total_size();
        array_candidate.kind = FieldCandidate::Kind::ArrayField;
        array_candidate.type_category = ctx_.type_encoder().categorize(array.element_type);
        array_candidate.extended_type = ctx_.type_encoder().extract_extended_info(array.element_type);
        array_candidate.array_element_count = array.element_count;
        array_candidate.array_stride = array.stride;
        array_candidate.confidence = array.confidence;

        for (size_t i = 0; i < pattern.all_accesses.size(); ++i) {
            const auto& access = pattern.all_accesses[i];
            if (member_offsets.count(access.offset) == 0) {
                continue;
            }
            if (access.size == access_size) {
                array_candidate.source_access_indices.push_back(static_cast<int>(i));
            }
        }

        for (sval_t off : array.member_offsets) {
            uint64_t key = (static_cast<uint64_t>(off) << 32) |
                           static_cast<uint64_t>(access_size);
            auto it = direct_index.find(key);
            if (it != direct_index.end()) {
                candidates[it->second].kind = FieldCandidate::Kind::ArrayElement;
            }
        }

        candidates.push_back(std::move(array_candidate));
    }

    // Direct contiguous byte-run detection for compact tails such as
    // checksum arrays. This prevents larger shifted struct-array candidates
    // from being the only way to cover a short byte sequence.
    qvector<sval_t> byte_offsets;
    for (const auto& access : pattern.all_accesses) {
        if (access.size == 1) {
            byte_offsets.push_back(access.offset);
        }
    }

    std::sort(byte_offsets.begin(), byte_offsets.end());
    byte_offsets.erase(std::unique(byte_offsets.begin(), byte_offsets.end()), byte_offsets.end());

    size_t run_start = 0;
    while (run_start < byte_offsets.size()) {
        size_t run_end = run_start + 1;
        while (run_end < byte_offsets.size() && byte_offsets[run_end] == byte_offsets[run_end - 1] + 1) {
            ++run_end;
        }

        const size_t run_len = run_end - run_start;
        const int byte_tail_min = config_.min_array_elements > 2 ? 2 : config_.min_array_elements;
        if (run_len >= static_cast<size_t>(byte_tail_min)) {
            FieldCandidate byte_array;
            byte_array.offset = byte_offsets[run_start];
            byte_array.size = static_cast<uint32_t>(run_len);
            byte_array.kind = FieldCandidate::Kind::ArrayField;
            byte_array.type_category = TypeCategory::UInt8;
            byte_array.array_element_count = static_cast<uint32_t>(run_len);
            byte_array.array_stride = 1;
            byte_array.confidence = TypeConfidence::Medium;

            for (size_t i = 0; i < pattern.all_accesses.size(); ++i) {
                const auto& access = pattern.all_accesses[i];
                if (access.size == 1 &&
                    access.offset >= byte_array.offset &&
                    access.offset < byte_array.offset + static_cast<sval_t>(byte_array.size)) {
                    byte_array.source_access_indices.push_back(static_cast<int>(i));
                }
            }

            bool duplicate = std::any_of(candidates.begin(), candidates.end(), [&](const FieldCandidate& existing) {
                return existing.kind == FieldCandidate::Kind::ArrayField &&
                       existing.offset == byte_array.offset &&
                       existing.size == byte_array.size;
            });
            if (!duplicate) {
                candidates.push_back(std::move(byte_array));
            }
        }

        run_start = run_end;
    }

    // Explicit repeated-anchor detection for arrays-of-structs. Start from a
    // repeated same-size anchor field (e.g. element.kind at offsets 8,20,32)
    // and then try to build a mixed-layout element struct around that stride.
    std::unordered_map<uint32_t, qvector<sval_t>> offsets_by_size;
    for (const auto& access : pattern.all_accesses) {
        if (access.size >= 2 && access.size <= 8) {
            offsets_by_size[access.size].push_back(access.offset);
        }
    }

    auto array_candidate_exists = [&](const FieldCandidate& candidate) {
        return std::any_of(candidates.begin(), candidates.end(), [&](const FieldCandidate& existing) {
            return existing.kind == FieldCandidate::Kind::ArrayField &&
                   existing.offset == candidate.offset &&
                   existing.size == candidate.size;
        });
    };

    for (auto& [size, offsets_for_size] : offsets_by_size) {
        std::sort(offsets_for_size.begin(), offsets_for_size.end());
        offsets_for_size.erase(std::unique(offsets_for_size.begin(), offsets_for_size.end()), offsets_for_size.end());

        if (offsets_for_size.size() < static_cast<size_t>(config_.min_array_elements)) {
            continue;
        }

        for (size_t i = 0; i + 2 < offsets_for_size.size(); ++i) {
            for (size_t j = i + 1; j < offsets_for_size.size() && j <= i + 8; ++j) {
                const uint32_t stride = static_cast<uint32_t>(offsets_for_size[j] - offsets_for_size[i]);
                if (stride < size || stride > 64) {
                    continue;
                }

                uint32_t count = 1;
                sval_t expected = offsets_for_size[i];
                while (std::binary_search(offsets_for_size.begin(), offsets_for_size.end(), expected)) {
                    ++count;
                    expected += stride;
                }
                --count;

                if (count >= static_cast<uint32_t>(config_.min_array_elements)) {
                    auto candidate = build_struct_array_candidate(
                        ctx_, pattern, offsets_for_size[i], stride, count);
                    if (candidate.has_value() && !array_candidate_exists(*candidate)) {
                        candidates.push_back(std::move(*candidate));
                    }
                }
            }
        }
    }

    // Mixed-size repeated-stride detection for arrays of structs.
    if (pattern.all_accesses.size() >= 6) {
        std::unordered_set<uint32_t> stride_candidates;
        qvector<sval_t> offsets;
        offsets.reserve(pattern.all_accesses.size());
        for (const auto& access : pattern.all_accesses) {
            offsets.push_back(access.offset);
        }
        std::sort(offsets.begin(), offsets.end());
        const size_t max_lookahead = std::min<std::size_t>(offsets.size(), 16);
        for (size_t i = 0; i < offsets.size(); ++i) {
            for (size_t j = i + 1; j < offsets.size() && j <= i + max_lookahead; ++j) {
                sval_t diff = offsets[j] - offsets[i];
                if (diff >= 8 && diff <= 64) {
                    stride_candidates.insert(static_cast<uint32_t>(diff));
                }
            }
        }

        for (uint32_t stride : stride_candidates) {
            for (const auto& access : pattern.all_accesses) {
                std::unordered_set<uint32_t> indices;
                for (const auto& other : pattern.all_accesses) {
                    if (other.offset < access.offset) {
                        continue;
                    }
                    sval_t rel = other.offset - access.offset;
                    if (rel >= 0 && rel % stride == 0) {
                        indices.insert(static_cast<uint32_t>(rel / stride));
                    }
                }

                uint32_t count = 0;
                while (indices.count(count) > 0) {
                    ++count;
                }

                auto candidate = build_struct_array_candidate(ctx_, pattern, access.offset, stride, count);
                if (!candidate.has_value()) {
                    continue;
                }

                if (!array_candidate_exists(*candidate)) {
                    candidates.push_back(std::move(*candidate));
                }
            }
        }
    }
}

void FieldCandidateGenerator::generate_padding_candidates(
    const qvector<FieldCandidate>& existing_candidates,
    sval_t struct_end,
    qvector<FieldCandidate>& candidates)
{
    if (existing_candidates.empty()) return;

    // Get non-overlapping coverage ranges
    qvector<std::pair<sval_t, sval_t>> ranges;  // (start, end)

    for (const auto& c : existing_candidates) {
        if (c.kind == FieldCandidate::Kind::ArrayElement) {
            continue;  // Skip array elements (covered by ArrayField)
        }
        ranges.push_back({c.offset, c.end_offset()});
    }

    if (ranges.empty()) return;

    // Sort by start offset
    std::sort(ranges.begin(), ranges.end());

    // Merge overlapping ranges
    qvector<std::pair<sval_t, sval_t>> merged;
    merged.push_back(ranges[0]);

    for (size_t i = 1; i < ranges.size(); ++i) {
        if (ranges[i].first <= merged.back().second) {
            merged.back().second = std::max(merged.back().second, ranges[i].second);
        } else {
            merged.push_back(ranges[i]);
        }
    }

    // Find gaps
    sval_t current_pos = 0;

    for (const auto& [start, end] : merged) {
        if (start > current_pos) {
            // Gap found - create padding
            FieldCandidate padding;
            padding.offset = current_pos;
            padding.size = static_cast<uint32_t>(start - current_pos);
            padding.kind = FieldCandidate::Kind::PaddingField;
            padding.type_category = TypeCategory::RawBytes;
            padding.confidence = TypeConfidence::Low;

            candidates.push_back(std::move(padding));
        }
        current_pos = std::max(current_pos, end);
    }

    // Final padding to struct end
    if (struct_end > current_pos) {
        FieldCandidate padding;
        padding.offset = current_pos;
        padding.size = static_cast<uint32_t>(struct_end - current_pos);
        padding.kind = FieldCandidate::Kind::PaddingField;
        padding.type_category = TypeCategory::RawBytes;
        padding.confidence = TypeConfidence::Low;

        candidates.push_back(std::move(padding));
    }
}

void FieldCandidateGenerator::finalize_candidates(qvector<FieldCandidate>& candidates) {
    // Sort by offset, then by size (smaller first)
    std::sort(candidates.begin(), candidates.end(),
        [](const FieldCandidate& a, const FieldCandidate& b) {
            if (a.offset != b.offset) return a.offset < b.offset;
            return a.size < b.size;
        });

    // Assign IDs
    for (size_t i = 0; i < candidates.size(); ++i) {
        candidates[i].id = static_cast<int>(i);
    }
}

TypeCategory FieldCandidateGenerator::infer_category(const FieldAccess& access) const {
    // Prefer explicit function pointer types from inference
    if (!access.inferred_type.empty()) {
        TypeCategory inferred = ctx_.type_encoder().categorize(access.inferred_type);
        if (inferred == TypeCategory::FuncPtr) {
            return inferred;
        }
    }

    // First check semantic type
    switch (access.semantic_type) {
        case SemanticType::Pointer:
            return TypeCategory::Pointer;
        case SemanticType::FunctionPointer:
        case SemanticType::VTablePointer:
            return TypeCategory::FuncPtr;
        case SemanticType::Float:
            return TypeCategory::Float32;
        case SemanticType::Double:
            return TypeCategory::Float64;
        default:
            break;
    }

    // Then check inferred type
    if (!access.inferred_type.empty()) {
        return ctx_.type_encoder().categorize(access.inferred_type);
    }

    // Fall back to size-based inference
    switch (access.size) {
        case 1:
            return TypeCategory::UInt8;
        case 2:
            return TypeCategory::UInt16;
        case 4:
            return TypeCategory::UInt32;
        case 8:
            // Could be uint64 or pointer
            if (get_ptr_size() == 8) {
                return TypeCategory::Pointer;  // Conservative assumption
            }
            return TypeCategory::UInt64;
        default:
            return TypeCategory::RawBytes;
    }
}

FieldCandidate FieldCandidateGenerator::create_from_access(
    const FieldAccess& access,
    int access_index)
{
    FieldCandidate candidate;
    candidate.offset = access.offset;
    candidate.size = access.size;
    candidate.kind = FieldCandidate::Kind::DirectAccess;
    candidate.type_category = infer_category(access);
    candidate.source_access_indices.push_back(access_index);

    // Extract extended type info if available
    if (!access.inferred_type.empty()) {
        candidate.extended_type = ctx_.type_encoder().extract_extended_info(access.inferred_type);
    } else {
        candidate.extended_type.category = candidate.type_category;
        candidate.extended_type.size = access.size;
    }

    // Set confidence based on access type
    if (access.semantic_type != SemanticType::Unknown) {
        candidate.confidence = TypeConfidence::Medium;
    } else {
        candidate.confidence = TypeConfidence::Low;
    }

    return candidate;
}

qvector<qvector<int>> FieldCandidateGenerator::find_array_patterns(
    const qvector<FieldCandidate>& candidates) const
{
    qvector<qvector<int>> result;

    // Group candidates by size and type
    std::unordered_map<uint64_t, qvector<int>> size_type_groups;

    for (size_t i = 0; i < candidates.size(); ++i) {
        const auto& c = candidates[i];

        // Skip non-direct-access candidates
        if (c.kind != FieldCandidate::Kind::DirectAccess) continue;

        // Key: (size, type_category)
        uint64_t key = (static_cast<uint64_t>(c.size) << 32) |
                       static_cast<uint64_t>(c.type_category);
        size_type_groups[key].push_back(static_cast<int>(i));
    }

    // For each group, check if offsets form arithmetic progression
    for (const auto& [key, indices] : size_type_groups) {
        if (indices.size() < config_.min_array_elements) continue;

        // Extract offsets
        qvector<std::pair<sval_t, int>> offset_idx;
        for (int idx : indices) {
            offset_idx.push_back({candidates[idx].offset, idx});
        }

        // Sort by offset
        std::sort(offset_idx.begin(), offset_idx.end());

        // Find longest arithmetic progression subsequence
        uint32_t size = static_cast<uint32_t>(key >> 32);
        qvector<int> current_group;

        for (size_t i = 0; i < offset_idx.size(); ++i) {
            if (current_group.empty()) {
                current_group.push_back(offset_idx[i].second);
                continue;
            }

            // Check if this extends current progression
            sval_t expected_offset = candidates[current_group.back()].offset + size;
            if (offset_idx[i].first == expected_offset) {
                current_group.push_back(offset_idx[i].second);
            } else {
                // Break in progression
                if (current_group.size() >= config_.min_array_elements) {
                    result.push_back(current_group);
                }
                current_group.clear();
                current_group.push_back(offset_idx[i].second);
            }
        }

        // Don't forget the last group
        if (current_group.size() >= config_.min_array_elements) {
            result.push_back(current_group);
        }
    }

    return result;
}

bool FieldCandidateGenerator::is_arithmetic_progression(
    const qvector<sval_t>& offsets,
    uint32_t expected_stride) const
{
    if (offsets.size() < 2) return true;

    for (size_t i = 1; i < offsets.size(); ++i) {
        sval_t actual_stride = offsets[i] - offsets[i - 1];
        if (actual_stride != static_cast<sval_t>(expected_stride)) {
            return false;
        }
    }

    return true;
}

// ============================================================================
// OverlapAnalysis Implementation
// ============================================================================

OverlapAnalysis FieldCandidateGenerator::analyze_overlaps(
    const qvector<FieldCandidate>& candidates) const
{
    OverlapAnalysis result;

    // OPTIMIZATION: Use sweep line for large sets, O(n²) for small sets
    const size_t n = candidates.size();
    
    if (n >= 64) {
        // Use sweep line algorithm - O(n log n + k)
        std::vector<algorithms::Interval> intervals;
        intervals.reserve(n);
        
        for (size_t i = 0; i < n; ++i) {
            intervals.emplace_back(
                candidates[i].offset,
                candidates[i].offset + static_cast<int64_t>(candidates[i].size),
                static_cast<int32_t>(candidates[i].id)
            );
        }
        
        auto overlapping = algorithms::find_overlapping_pairs(intervals);
        
        for (const auto& [id1, id2] : overlapping) {
            result.overlapping_pairs.push_back({id1, id2});
        }
    } else {
        // Use O(n²) for small sets - lower constant factors
        for (size_t i = 0; i < n; ++i) {
            for (size_t j = i + 1; j < n; ++j) {
                if (candidates[i].overlaps(candidates[j])) {
                    result.overlapping_pairs.push_back({
                        candidates[i].id,
                        candidates[j].id
                    });
                }
            }
        }
    }

    if (result.overlapping_pairs.empty()) {
        return result;
    }

    // OPTIMIZATION: Use optimized FlatUnionFind
    FlatUnionFind uf;
    
    // Unite overlapping candidates
    for (const auto& [id1, id2] : result.overlapping_pairs) {
        uf.unite_by_id(id1, id2);
    }

    // Collect groups - use root as key to group overlapping candidates
    std::unordered_map<size_t, qvector<int>> groups;
    for (const auto& [id1, id2] : result.overlapping_pairs) {
        size_t root = uf.find_by_id(id1);
        // Both id1 and id2 have same root since they were united
        
        // Track both IDs under the root
        auto& group = groups[root];
        if (std::find(group.begin(), group.end(), id1) == group.end()) {
            group.push_back(id1);
        }
        if (std::find(group.begin(), group.end(), id2) == group.end()) {
            group.push_back(id2);
        }
    }

    for (auto& [root, members] : groups) {
        if (members.size() > 1) {
            std::sort(members.begin(), members.end());
            result.overlap_groups.push_back(std::move(members));
        }
    }

    return result;
}

} // namespace structor::z3
