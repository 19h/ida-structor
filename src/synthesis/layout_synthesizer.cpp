/// @file layout_synthesizer.cpp
/// @brief Structure layout synthesis implementation

#include <structor/layout_synthesizer.hpp>
#include <structor/field_fragment_type.hpp>
#include <structor/naming.hpp>

#include <limits>
#include <string>

namespace structor {

namespace {

bool synth_debug_enabled() { return Config::instance().options().debug_mode; }

bool is_generated_padding_name(const qstring &name) {
    return name.find("__pad_") == 0;
}

bool ends_with_text(const qstring &value, const char *suffix) {
    const size_t value_len = value.length();
    const size_t suffix_len = strlen(suffix);
    if (suffix_len > value_len) {
        return false;
    }

    return strcmp(value.c_str() + value_len - suffix_len, suffix) == 0;
}

bool starts_with_text(const qstring &value, const char *prefix) {
    const size_t value_len = value.length();
    const size_t prefix_len = strlen(prefix);
    if (prefix_len > value_len) {
        return false;
    }

    return strncmp(value.c_str(), prefix, prefix_len) == 0;
}

qstring qstring_slice(const char *text, size_t len) {
    std::string tmp(text, len);
    qstring out;
    out = tmp.c_str();
    return out;
}

qstring erase_suffix(const qstring &value, size_t suffix_len) {
    std::string tmp = value.c_str();
    tmp.erase(tmp.size() - suffix_len, suffix_len);
    qstring out;
    out = tmp.c_str();
    return out;
}

qstring normalize_symbolic_stem(const qstring &value) {
    std::string snake;
    const char *text = value.c_str();
    const size_t len = value.length();

    for (size_t i = 0; i < len; ++i) {
        const unsigned char ch = static_cast<unsigned char>(text[i]);
        if (!(std::isalnum(ch) || ch == '_')) {
            if (!snake.empty() && snake.back() != '_') {
                snake.push_back('_');
            }
            continue;
        }

        if (std::isupper(ch) && !snake.empty() && snake.back() != '_') {
            const unsigned char prev = static_cast<unsigned char>(text[i - 1]);
            const unsigned char next =
                    i + 1 < len ? static_cast<unsigned char>(text[i + 1]) : 0;
            const bool prev_lower = std::islower(prev) || std::isdigit(prev);
            const bool next_lower = next != 0 && std::islower(next);
            if (prev_lower || next_lower) {
                snake.push_back('_');
            }
        }

        snake.push_back(static_cast<char>(std::tolower(ch)));
    }

    qstring normalized = sanitize_identifier(qstring(snake.c_str()), "");
    if (starts_with_text(normalized, "s_") && normalized.length() > 2) {
        normalized = qstring(normalized.c_str() + 2);
    }
    return normalized;
}

qstring suggest_subobject_stem(ea_t func_ea) {
    qstring func_name = utils::get_func_name(func_ea);
    if (func_name.empty() || is_placeholder_identifier(func_name)) {
        return qstring();
    }

    const char *raw = func_name.c_str();
    const char *scope = strstr(raw, "::");
    qstring stem_source;
    bool member_owner = false;
    if (scope != nullptr && scope != raw) {
        stem_source = qstring_slice(raw, static_cast<size_t>(scope - raw));
        member_owner = true;
    } else {
        stem_source = func_name;
    }

    qstring stem = normalize_symbolic_stem(stem_source);
    if (stem.empty()) {
        return qstring();
    }

    bool recognized_factory = member_owner;
    constexpr const char *kFactorySuffixes[] = {
            "_copy_params", "_copyparams", "_constructor", "_construct",
            "_ctor",        "_init",       "_copy",
    };
    for (const char *suffix : kFactorySuffixes) {
        if (!ends_with_text(stem, suffix)) {
            continue;
        }
        stem = erase_suffix(stem, strlen(suffix));
        recognized_factory = true;
        break;
    }

    if (!recognized_factory) {
        constexpr const char *kFactoryPrefixes[] = {
                "make_",
                "create_",
                "build_",
        };
        for (const char *prefix : kFactoryPrefixes) {
            if (!starts_with_text(stem, prefix)) {
                continue;
            }
            stem = qstring(stem.c_str() + strlen(prefix));
            recognized_factory = true;
            break;
        }
    }

    if (ends_with_text(stem, "_recovered")) {
        stem = erase_suffix(stem, strlen("_recovered"));
    }

    if (!recognized_factory || stem.empty() || is_placeholder_identifier(stem)) {
        return qstring();
    }

    return stem;
}

qstring suggest_subobject_type_name(ea_t func_ea) {
    const qstring stem = suggest_subobject_stem(func_ea);
    if (stem.empty()) {
        return qstring();
    }

    qstring name;
    name.sprnt("auto_%s", stem.c_str());
    return name;
}

qstring suggest_subobject_field_name(ea_t func_ea) {
    const qstring stem = suggest_subobject_stem(func_ea);
    if (stem.empty()) {
        return qstring();
    }

    return singularize_identifier(stem);
}

bool should_rebase_generated_name(const SynthField &field, sval_t old_offset) {
    if (field.name.empty()) {
        return true;
    }

    if (field.naming.is_generated() ||
            is_generated_name(field.name, &field.naming)) {
        return true;
    }

    return field.is_padding && is_generated_padding_name(field.name);
}

void rebase_field_name(SynthField &field, sval_t old_offset) {
    if (!should_rebase_generated_name(field, old_offset)) {
        return;
    }

    if (field.is_padding && is_generated_padding_name(field.name)) {
        field.name.sprnt("__pad_%s", make_offset_suffix(field.offset).c_str());
        return;
    }

    if (field.naming.kind == GeneratedNameKind::SubStructField ||
            field.semantic == SemanticType::NestedStruct) {
        set_generated_name(
                field.name, field.naming, make_substruct_field_name(field.offset),
                GeneratedNameKind::SubStructField, field.naming.confidence);
        return;
    }

    if (field.is_array || field.naming.kind == GeneratedNameKind::ArrayField) {
        tinfo_t elem_type = field.type;
        array_type_data_t atd;
        if (elem_type.is_array() && elem_type.get_array_details(&atd)) {
            elem_type = atd.elem_type;
        }
        const size_t elem_size = elem_type.get_size();
        set_generated_name(
                field.name, field.naming,
                make_array_field_name(
                        field.offset, elem_type, field.semantic,
                        static_cast<std::uint32_t>(elem_size == BADSIZE ? 0 : elem_size)),
                GeneratedNameKind::ArrayField, field.naming.confidence);
        return;
    }

    set_generated_name(
            field.name, field.naming,
            generate_field_name(field.offset, field.semantic, field.size),
            field.naming.kind == GeneratedNameKind::Unknown ? GeneratedNameKind::Field
                                                                                                            : field.naming.kind,
            field.naming.confidence);
}

uint32_t fallback_natural_alignment(uint32_t size, uint32_t abi_default) {
    if (size == 0 || abi_default == 0) {
        return 1;
    }

    // Unknown-width byte regions do not establish scalar alignment. Only
    // canonical scalar widths carry a defensible fallback requirement.
    switch (size) {
        case 1:
        case 2:
        case 4:
        case 8:
        case 16:
            return std::min(size, abi_default);
        default:
            return 1;
    }
}

SynthesisResult resource_limit_result(ResourceLimitKind kind,
                                      uint64_t configured_limit,
                                      uint64_t observed_value,
                                      const char* phase,
                                      const char* message) {
    SynthesisResult result;
    result.error = SynthError::ResourceLimitExceeded;
    result.error_message = message;
    result.fallback_reason = message;
    result.resource_limit = ResourceLimitViolation{
        kind, configured_limit, observed_value, qstring(phase)};
    return result;
}

std::optional<ResourceLimitKind> classify_solver_resource_failure(
    const char* message,
    const LayoutSynthConfig& config) {
    if (!message) {
        return std::nullopt;
    }
    std::string normalized(message);
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    if (config.z3_memory_mb != 0 &&
        normalized.find("memory") != std::string::npos) {
        return ResourceLimitKind::SolverMemory;
    }
    if (config.z3_timeout_ms != 0 &&
        (normalized.find("timeout") != std::string::npos ||
         normalized.find("deadline") != std::string::npos ||
         normalized.find("canceled") != std::string::npos)) {
        return ResourceLimitKind::SolverTimeout;
    }
    return std::nullopt;
}

std::optional<uint64_t> checked_pattern_span(
    const UnifiedAccessPattern& pattern) {
    if (pattern.all_accesses.empty()) {
        return uint64_t{0};
    }

    sval_t origin = 0;
    sval_t maximum_end = 0;
    for (const auto& access : pattern.all_accesses) {
        origin = std::min(origin, access.offset);
        const auto access_end = checked_interval_end(access.offset, access.size);
        if (!access_end) {
            return std::nullopt;
        }
        maximum_end = std::max(maximum_end, *access_end);
    }

    return checked_interval_span(origin, maximum_end);
}

std::optional<std::uint64_t> mandatory_union_alternative_excess(
    const UnifiedAccessPattern& pattern,
    std::uint32_t maximum_alternatives) {
    std::vector<const FieldAccess*> ordered;
    ordered.reserve(pattern.all_accesses.size());
    for (const auto& access : pattern.all_accesses) {
        ordered.push_back(&access);
    }
    std::stable_sort(ordered.begin(), ordered.end(), [](const auto* lhs, const auto* rhs) {
        if (lhs->offset != rhs->offset) return lhs->offset < rhs->offset;
        if (lhs->size != rhs->size) return lhs->size < rhs->size;
        return canonical_field_access_less(*lhs, *rhs);
    });

    std::size_t begin = 0;
    while (begin < ordered.size()) {
        std::size_t end = begin + 1;
        while (end < ordered.size() &&
               ordered[end]->offset == ordered[begin]->offset &&
               ordered[end]->size == ordered[begin]->size) {
            ++end;
        }

        qvector<FieldAccess> distinct;
        const std::size_t configured_cap = maximum_alternatives;
        const std::size_t reserve_cap =
            configured_cap == std::numeric_limits<std::size_t>::max()
                ? configured_cap
                : configured_cap + 1;
        distinct.reserve(std::min<std::size_t>(
            end - begin,
            reserve_cap));
        for (std::size_t i = begin; i < end; ++i) {
            auto compatible = std::find_if(
                distinct.begin(), distinct.end(), [&](const FieldAccess& existing) {
                    return field_access_evidence_compatible(existing, *ordered[i]);
                });
            if (compatible == distinct.end()) {
                distinct.push_back(*ordered[i]);
                if (distinct.size() > maximum_alternatives) {
                    return distinct.size();
                }
            } else {
                merge_field_access_evidence(*compatible, *ordered[i]);
            }
        }
        begin = end;
    }
    return std::nullopt;
}

uint32_t field_type_alignment(const tinfo_t& type,
                              uint32_t storage_size,
                              uint32_t abi_default) {
    if (!type.empty()) {
        const size_t type_size = type.get_size();
        if (type_size != BADSIZE && type_size == storage_size) {
            const uint32_t alignment = type.get_alignment();
            if (alignment != 0) {
                return alignment;
            }
        }
    }
    return fallback_natural_alignment(storage_size, abi_default);
}

const SynthStruct* substructure_at(const qvector<SubStructInfo>* sub_structs,
                                   sval_t offset) {
    if (!sub_structs) {
        return nullptr;
    }
    for (const auto& sub : *sub_structs) {
        if (sub.parent_offset == offset) {
            return &sub.structure;
        }
    }
    return nullptr;
}

void synchronize_substruct_field_names(
        SynthStruct& structure,
        qvector<SubStructInfo>& sub_structs) {
    for (auto& sub : sub_structs) {
        synchronize_substruct_field_names(sub.structure, sub.children);

        SynthField* named_match = nullptr;
        SynthField* sole_nested_match = nullptr;
        std::size_t nested_matches = 0;
        for (auto& field : structure.fields) {
            if (field.offset != sub.parent_offset) {
                continue;
            }
            if (field.name == sub.field_name || field.name.empty()) {
                named_match = &field;
                break;
            }
            if (field.semantic == SemanticType::NestedStruct &&
                !field.is_union_candidate) {
                sole_nested_match = &field;
                ++nested_matches;
            }
        }

        SynthField* match = named_match;
        if (match == nullptr && nested_matches == 1) {
            match = sole_nested_match;
        }
        if (match != nullptr && !match->name.empty()) {
            sub.field_name = match->name;
            sub.field_naming = match->naming;
        }
    }
}

std::size_t materialize_internal_padding(
        SynthStruct& structure,
        qvector<SubStructInfo>& sub_structs) {
    std::size_t maximum_field_count = 0;
    for (auto& sub : sub_structs) {
        maximum_field_count = std::max(
            maximum_field_count,
            materialize_internal_padding(sub.structure, sub.children));
    }

    std::sort(structure.fields.begin(), structure.fields.end(),
              [](const SynthField& lhs, const SynthField& rhs) {
                  if (lhs.offset != rhs.offset) return lhs.offset < rhs.offset;
                  if (lhs.is_bitfield != rhs.is_bitfield) return lhs.is_bitfield;
                  if (lhs.size != rhs.size) return lhs.size > rhs.size;
                  return lhs.bit_offset < rhs.bit_offset;
              });

    qvector<SynthField> with_padding;
    with_padding.reserve(structure.fields.size());
    sval_t covered_end = 0;
    for (auto& field : structure.fields) {
        if (field.offset > covered_end) {
            const auto gap = static_cast<std::uint64_t>(field.offset) -
                             static_cast<std::uint64_t>(covered_end);
            if (gap <= std::numeric_limits<std::uint32_t>::max()) {
                with_padding.push_back(SynthField::create_padding(
                    covered_end, static_cast<std::uint32_t>(gap)));
            }
        }
        const auto field_end = checked_interval_end(field.offset, field.size);
        if (field_end.has_value()) {
            covered_end = std::max(covered_end, *field_end);
        }
        with_padding.push_back(std::move(field));
    }
    structure.fields = std::move(with_padding);
    return std::max(maximum_field_count, structure.fields.size());
}

void finalize_structure_abi(SynthStruct& structure,
                            qvector<SubStructInfo>* sub_structs,
                            uint32_t abi_default) {
    abi_default = std::max<uint32_t>(1, abi_default);

    if (sub_structs) {
        for (auto& sub : *sub_structs) {
            finalize_structure_abi(
                sub.structure, &sub.children, abi_default);
        }
    }

    qvector<PackingAlignmentRequirement> requirements;
    for (const auto& field : structure.fields) {
        if (field.is_padding || field.size == 0) {
            continue;
        }

        if (field.is_union_candidate && !field.union_members.empty()) {
            for (const auto& member : field.union_members) {
                if (member.size == 0) {
                    continue;
                }
                requirements.push_back({
                    field.offset + member.offset,
                    field_type_alignment(member.type, member.size, abi_default)});
            }
            continue;
        }

        uint32_t natural_alignment = 1;
        if (field.semantic == SemanticType::NestedStruct) {
            if (const SynthStruct* child = substructure_at(sub_structs, field.offset)) {
                natural_alignment = std::max<uint32_t>(1, child->alignment);
            } else {
                natural_alignment = field_type_alignment(
                    field.type, field.size, abi_default);
            }
        } else if (field.is_bitfield) {
            natural_alignment = fallback_natural_alignment(field.size, abi_default);
        } else {
            natural_alignment = field_type_alignment(
                field.type, field.size, abi_default);
        }

        requirements.push_back({field.offset, natural_alignment});
    }

    uint32_t upper_bound = structure.packing.value_or(abi_default);
    upper_bound = std::max<uint32_t>(1, std::min(upper_bound, abi_default));

    qvector<uint32_t> options;
    for (uint32_t value = 1; value <= upper_bound;) {
        options.push_back(value);
        if (value > upper_bound / 2) {
            break;
        }
        value *= 2;
    }
    const uint32_t selected_packing = canonical_packing_cap(
        std::span<const PackingAlignmentRequirement>(
            requirements.begin(), requirements.size()),
        std::span<const uint32_t>(options.begin(), options.size()),
        upper_bound).value_or(1);

    const uint32_t effective_alignment = effective_alignment_for_packing(
        std::span<const PackingAlignmentRequirement>(
            requirements.begin(), requirements.size()),
        selected_packing);

    structure.alignment = effective_alignment;
    if (selected_packing < abi_default) {
        structure.packing = selected_packing;
    } else {
        structure.packing.reset();
    }
}

void rebase_negative_offsets(SynthStruct &structure,
                                                         qvector<SubStructInfo> *sub_structs) {
    sval_t min_offset = 0;
    bool found = false;
    for (const auto &field : structure.fields) {
        min_offset = found ? std::min(min_offset, field.offset) : field.offset;
        found = true;
    }

    if (!found || min_offset >= 0) {
        return;
    }

    const sval_t delta = -min_offset;
    for (auto &field : structure.fields) {
        const sval_t old_offset = field.offset;
        field.offset += delta;
        for (auto &access : field.source_accesses) {
            access.offset += delta;
        }

        rebase_field_name(field, old_offset);
    }

    if (sub_structs) {
        for (auto &sub : *sub_structs) {
            const sval_t old_parent_offset = sub.parent_offset;
            sub.parent_offset += delta;
            if (is_generated_name(sub.field_name, &sub.field_naming) ||
                    old_parent_offset < 0) {
                if (sub.field_naming.kind == GeneratedNameKind::SubStructField ||
                        sub.field_naming.kind == GeneratedNameKind::Unknown) {
                    sub.field_name = make_substruct_field_name(sub.parent_offset);
                    sub.field_naming.kind = GeneratedNameKind::SubStructField;
                    sub.field_naming.origin = NameOrigin::GeneratedFallback;
                } else {
                    sub.field_name =
                            rebase_textual_generated_name(sub.field_name, sub.parent_offset);
                }
            }
            rebase_negative_offsets(sub.structure, nullptr);
        }
    }

    if (!extract_shifted_view_delta(structure.name).has_value()) {
        structure.name = make_shifted_view_type_name(structure.name, delta);
    }
}

tinfo_t make_scalar_type_for_access(const FieldAccess &access) {
    tinfo_t type;

    switch (access.semantic_type) {
    case SemanticType::Double:
        if (access.size == 8) {
            type.create_simple_type(BTF_DOUBLE);
            return type;
        }
        break;
    case SemanticType::Float:
        if (access.size == 4) {
            type.create_simple_type(BTF_FLOAT);
            return type;
        }
        break;
    case SemanticType::Pointer:
    case SemanticType::FunctionPointer:
    case SemanticType::VTablePointer:
        if (access.size == get_ptr_size()) {
            tinfo_t void_type;
            void_type.create_simple_type(BTF_VOID);
            type.create_ptr(void_type);
            return type;
        }
        break;
    default:
        break;
    }

    switch (access.size) {
    case 1:
        type.create_simple_type(BT_INT8 | BTMT_USIGNED);
        break;
    case 2:
        type.create_simple_type(BT_INT16 | BTMT_USIGNED);
        break;
    case 4:
        type.create_simple_type(BT_INT32 | BTMT_USIGNED);
        break;
    case 8:
        type.create_simple_type(BT_INT64 | BTMT_USIGNED);
        break;
    default:
        break;
    }

    return type;
}

void prune_intermediate_positive_delta_patterns(
        ea_t source_func, UnifiedAccessPattern &unified_pattern) {
    auto source_it = unified_pattern.function_deltas.find(source_func);
    if (source_it == unified_pattern.function_deltas.end()) {
        return;
    }

    const sval_t source_delta = source_it->second;
    if (source_delta <= 0) {
        return;
    }

    bool has_negative_helper = false;
    for (const auto &fn_pattern : unified_pattern.per_function_patterns) {
        if (fn_pattern.func_ea == source_func) {
            continue;
        }

        sval_t delta = 0;
        if (auto it = unified_pattern.function_deltas.find(fn_pattern.func_ea);
                it != unified_pattern.function_deltas.end()) {
            delta = it->second;
        }

        if (delta < 0) {
            has_negative_helper = true;
            break;
        }
    }

    if (!has_negative_helper) {
        return;
    }

    qvector<AccessPattern> kept_patterns;
    kept_patterns.reserve(unified_pattern.per_function_patterns.size());
    std::unordered_set<ea_t> kept_funcs;
    bool changed = false;

    for (auto &fn_pattern : unified_pattern.per_function_patterns) {
        sval_t delta = 0;
        if (auto it = unified_pattern.function_deltas.find(fn_pattern.func_ea);
                it != unified_pattern.function_deltas.end()) {
            delta = it->second;
        }

        const bool drop_pattern =
                fn_pattern.func_ea != source_func && delta >= 0 && delta < source_delta;
        if (drop_pattern) {
            changed = true;
            continue;
        }

        kept_funcs.insert(fn_pattern.func_ea);
        kept_patterns.push_back(std::move(fn_pattern));
    }

    if (!changed) {
        return;
    }

    UnifiedAccessPattern pruned = UnifiedAccessPattern::merge(
            std::move(kept_patterns), unified_pattern.function_deltas);
    // Pruning evidence must not erase a failed or imprecise local scan.
    pruned.flow_diagnostics = unified_pattern.flow_diagnostics;

    // merge() cannot rediscover a boundary whose frame-scratch observation was
    // already rejected from per_function_patterns.  Preserve it only while its
    // provenance function remains part of the pruned equivalence class.
    if (!pruned.inferred_object_end.has_value() &&
            unified_pattern.inferred_object_end.has_value() &&
            kept_funcs.contains(unified_pattern.inferred_object_end_source)) {
        pruned.inferred_object_end = unified_pattern.inferred_object_end;
        pruned.inferred_object_end_source =
                unified_pattern.inferred_object_end_source;
        pruned.global_max_offset = std::max(
                pruned.global_max_offset, *pruned.inferred_object_end);
    }

    for (const auto &edge : unified_pattern.flow_edges) {
        if (kept_funcs.contains(edge.caller_ea) &&
                kept_funcs.contains(edge.callee_ea)) {
            pruned.flow_edges.push_back(edge);
        }
    }

    unified_pattern = std::move(pruned);
}

void recompute_unified_bounds(UnifiedAccessPattern &unified_pattern) {
  if (unified_pattern.all_accesses.empty()) {
        unified_pattern.global_min_offset = 0;
        unified_pattern.global_max_offset =
                unified_pattern.inferred_object_end.value_or(0);
        return;
    }

    bool first = true;
    for (const auto &access : unified_pattern.all_accesses) {
        const sval_t access_end = checked_interval_end(access.offset, access.size)
            .value_or(std::numeric_limits<sval_t>::max());
        if (first) {
            unified_pattern.global_min_offset = access.offset;
            unified_pattern.global_max_offset = access_end;
            first = false;
            continue;
        }

        unified_pattern.global_min_offset =
                std::min(unified_pattern.global_min_offset, access.offset);
        unified_pattern.global_max_offset =
                std::max(unified_pattern.global_max_offset, access_end);
  }

    if (unified_pattern.inferred_object_end.has_value()) {
        unified_pattern.global_max_offset = std::max(
                unified_pattern.global_max_offset,
                *unified_pattern.inferred_object_end);
    }
}

void recompute_pattern_bounds(AccessPattern &pattern) {
  if (pattern.accesses.empty()) {
    pattern.min_offset = 0;
    pattern.max_offset = 0;
    return;
  }

  std::sort(pattern.accesses.begin(), pattern.accesses.end());
  pattern.min_offset = pattern.accesses.front().offset;
  pattern.max_offset = checked_interval_end(
      pattern.accesses.front().offset, pattern.accesses.front().size)
      .value_or(std::numeric_limits<sval_t>::max());

  for (const auto &access : pattern.accesses) {
    pattern.min_offset = std::min(pattern.min_offset, access.offset);
    pattern.max_offset = std::max(
        pattern.max_offset,
        checked_interval_end(access.offset, access.size)
            .value_or(std::numeric_limits<sval_t>::max()));
  }
}

void reanchor_source_window_accesses(ea_t source_func,
                                     UnifiedAccessPattern &unified_pattern) {
    auto source_it = unified_pattern.function_deltas.find(source_func);
    if (source_it == unified_pattern.function_deltas.end()) {
        return;
    }

    const sval_t source_delta = source_it->second;
    if (source_delta <= 0) {
        return;
    }

    bool has_negative_helper = false;
    for (const auto &fn_pattern : unified_pattern.per_function_patterns) {
        if (fn_pattern.func_ea == source_func) {
            continue;
        }

        sval_t delta = 0;
        if (auto it = unified_pattern.function_deltas.find(fn_pattern.func_ea);
                it != unified_pattern.function_deltas.end()) {
            delta = it->second;
        }

        if (delta < 0) {
            has_negative_helper = true;
            break;
        }
    }

    if (!has_negative_helper) {
        return;
    }

    const auto reanchored_offset = [source_delta](sval_t value) {
        if (value < std::numeric_limits<sval_t>::min() + source_delta) {
            // Preserve an invalid sentinel that the synthesis preflight will
            // report as a structure-domain ResourceLimit.
            return std::numeric_limits<sval_t>::max();
        }
        return value - source_delta;
    };

    bool changed = false;
  for (auto &access : unified_pattern.all_accesses) {
    if (access.source_func_ea != source_func) {
      continue;
        }

    access.offset = reanchored_offset(access.offset);
    changed = true;
  }

    for (auto &fn_pattern : unified_pattern.per_function_patterns) {
    if (fn_pattern.func_ea != source_func) {
      continue;
    }

    for (auto &access : fn_pattern.accesses) {
      access.offset = reanchored_offset(access.offset);
    }
    recompute_pattern_bounds(fn_pattern);
  }

    bool boundary_changed = false;
    if (unified_pattern.inferred_object_end.has_value() &&
            unified_pattern.inferred_object_end_source == source_func) {
        *unified_pattern.inferred_object_end =
            reanchored_offset(*unified_pattern.inferred_object_end);
        boundary_changed = true;
    }

  if (!changed && !boundary_changed) {
    return;
    }

    std::sort(unified_pattern.all_accesses.begin(),
                        unified_pattern.all_accesses.end(),
                        [](const FieldAccess &a, const FieldAccess &b) {
                            if (a.offset != b.offset)
                                return a.offset < b.offset;
                            if (a.size != b.size)
                                return a.size < b.size;
                            if (a.source_func_ea != b.source_func_ea)
                                return a.source_func_ea < b.source_func_ea;
                            return a.insn_ea < b.insn_ea;
                        });

    recompute_unified_bounds(unified_pattern);
}

void append_inferred_tail_padding(
        const UnifiedAccessPattern &pattern, SynthStruct &structure) {
    if (!pattern.inferred_object_end.has_value() || structure.fields.empty()) {
        return;
    }

    const sval_t inferred_end = *pattern.inferred_object_end;

    sval_t field_end = std::numeric_limits<sval_t>::min();
    for (const auto &field : structure.fields) {
        if (field.offset > std::numeric_limits<sval_t>::max() -
                                   static_cast<sval_t>(field.size)) {
            return;
        }
        field_end = std::max(
                field_end, field.offset + static_cast<sval_t>(field.size));
    }

    if (inferred_end <= field_end) {
        return;
    }

    // Compute the positive mathematical difference without first evaluating a
    // potentially overflowing signed subtraction (for example INT64_MAX minus
    // a negative field end).
    const auto gap = static_cast<std::uint64_t>(inferred_end) -
                     static_cast<std::uint64_t>(field_end);
    if (gap > std::numeric_limits<std::uint32_t>::max()) {
        return;
    }

    structure.fields.push_back(SynthField::create_padding(
            field_end, static_cast<std::uint32_t>(gap)));
}

bool field_already_covers_exact_access(const SynthStruct &structure,
                                                                             const FieldAccess &access) {
    for (const auto &field : structure.fields) {
        if (field.offset == access.offset && field.size == access.size) {
            return true;
        }

        if (field.is_union_candidate) {
            for (const auto &member : field.union_members) {
                if (field.offset + member.offset == access.offset &&
                        member.size == access.size) {
                    return true;
                }
            }
        }
    }

    return false;
}

void apply_inner_scalar_overlay_recovery(SynthStruct &structure,
                                                                                 const qvector<FieldAccess> &accesses) {
    for (const auto &access : accesses) {
        if (access.size == 0 ||
                field_already_covers_exact_access(structure, access)) {
            continue;
        }

        const sval_t access_end = access.offset + static_cast<sval_t>(access.size);
        for (auto &field : structure.fields) {
            if (field.is_padding || field.is_bitfield || field.is_array ||
                    field.semantic == SemanticType::NestedStruct) {
                continue;
            }

            const sval_t field_end = field.offset + static_cast<sval_t>(field.size);
            if (access.offset <= field.offset || access_end > field_end) {
                continue;
            }

            const sval_t rel_offset = access.offset - field.offset;
            bool duplicate = false;
            for (const auto &member : field.union_members) {
                if (member.offset == rel_offset && member.size == access.size) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) {
                break;
            }

            if (!field.is_union_candidate) {
                SynthField::UnionMember base;
                base.name = field.name;
                base.offset = 0;
                base.size = field.size;
                base.type = field.type;
                base.comment = field.comment;
                field.union_members.push_back(std::move(base));
                field.is_union_candidate = true;
            }

            SynthField::UnionMember overlay;
            if (!field.name.empty()) {
                overlay.name = make_overlay_member_name(field.name, field.size,
                                                                                                rel_offset, access.size);
            } else {
                overlay.name = generate_field_name(access.offset, access.semantic_type,
                                                                                     access.size);
            }
            overlay.naming.kind = GeneratedNameKind::UnionAlternative;
            overlay.naming.origin = field.naming.origin;
            overlay.naming.confidence = field.naming.confidence;
            overlay.offset = rel_offset;
            overlay.size = access.size;
            overlay.type = !access.inferred_type.empty()
                                                 ? access.inferred_type
                                                 : make_scalar_type_for_access(access);
            field.union_members.push_back(std::move(overlay));
            break;
        }
    }
}

void adopt_field_names_from_original_type(SynthStruct &structure,
                                                                                    const tinfo_t &original_type) {
    tinfo_t udt_type = original_type;
    if (udt_type.is_ptr()) {
        udt_type = udt_type.get_pointed_object();
    }

    (void)refine_struct_names_from_udt(structure, udt_type,
                                                                         NameOrigin::OriginalType);
}

void adopt_field_names_from_access_contexts(
        SynthStruct &structure, const qvector<FieldAccess> &accesses) {
    (void)refine_struct_names_from_accesses(structure, accesses,
                                                                                    NameOrigin::AccessContext);
}

bool type_has_named_udt_details(const tinfo_t &type) {
    if (type.empty()) {
        return false;
    }

    tinfo_t udt_type = type;
    if (udt_type.is_ptr()) {
        udt_type = udt_type.get_pointed_object();
    }

    if (!(udt_type.is_struct() || udt_type.is_union())) {
        return false;
    }

    udt_type_data_t udt;
    if (!udt_type.get_udt_details(&udt) || udt.empty()) {
        return false;
    }

    return true;
}

} // namespace

LayoutSynthesizer::LayoutSynthesizer(const LayoutSynthConfig &config)
        : config_(config) {
    if (!is_valid_abi_alignment(
            static_cast<std::int64_t>(config_.default_alignment))) {
        throw std::invalid_argument(
            "ABI alignment must be a non-zero power of two representable by SynthOptions::alignment");
    }
}

LayoutSynthesizer::LayoutSynthesizer(const SynthOptions &opts) : config_() {
    const SynthOptionsValidationError validation = validate_synth_options(opts);
    // Zero resource bounds are carried into synthesis so callers receive a
    // typed ResourceLimit result.  Other malformed public options cannot be
    // represented safely and are rejected at construction.
    if (validation != SynthOptionsValidationError::None &&
        validation != SynthOptionsValidationError::InvalidHardLimit) {
        throw std::invalid_argument(synth_options_validation_error_str(validation));
    }

    // Map SynthOptions to LayoutSynthConfig
    config_.z3_timeout_ms = opts.z3.timeout_ms;
    config_.z3_memory_mb = opts.z3.memory_limit_mb;
    config_.use_z3 = opts.z3.mode != Z3SynthesisMode::Disabled;
    config_.fallback_to_heuristics = opts.z3.mode != Z3SynthesisMode::Required;
    config_.enable_maxsmt = opts.z3.enable_maxsmt;
    config_.enable_unsat_core = opts.z3.enable_unsat_core;
    config_.relax_on_unsat = opts.z3.relax_on_unsat;
    config_.max_relaxation_iterations = opts.z3.max_relax_iterations;
    config_.max_accesses = opts.z3.max_accesses;
    config_.max_candidates = opts.z3.max_candidates;
    config_.max_fields = opts.z3.max_fields;
    config_.max_array_elements = opts.z3.max_array_elements;
    config_.max_struct_size = opts.z3.max_structure_size;
    config_.max_constraint_pairs = opts.z3.max_constraint_pairs;
    config_.min_confidence_percent = opts.z3.min_confidence;
    config_.detect_arrays = opts.z3.detect_arrays;
    config_.default_alignment = static_cast<uint32_t>(opts.alignment);
    config_.generate_comments = opts.generate_comments;
    config_.cross_function = opts.z3.cross_function;
    config_.cross_function_depth = opts.max_propagation_depth;
    config_.emit_substructs = opts.emit_substructs;
    config_.min_array_elements = opts.z3.min_array_elements;
    config_.detect_symbolic_arrays = opts.z3.detect_symbolic_arrays;
    config_.max_array_stride = opts.z3.max_array_stride;
    config_.create_unions = opts.z3.allow_unions;
    config_.max_union_alternatives = opts.z3.max_union_alternatives;
    config_.relax_alignment_on_unsat = opts.z3.relax_on_unsat;
    config_.relax_types_on_unsat = opts.z3.relax_on_unsat;
    config_.weight_minimize_padding = opts.z3.weight_minimize_padding;
    config_.weight_prefer_non_union = opts.z3.weight_prefer_non_union;
}

SynthesisResult LayoutSynthesizer::synthesize(const AccessPattern &pattern,
                                                                                            const SynthOptions &opts) {
    auto start_time = std::chrono::steady_clock::now();
    conflicts_.clear();

    SynthesisResult result;
    result.structure.source_func = pattern.func_ea;
    result.structure.source_var = pattern.var_name;
    result.structure.alignment = config_.default_alignment;
    set_generated_name(
            result.structure.name, result.structure.naming,
            make_auto_root_type_name(pattern.func_ea, pattern.var_name),
            GeneratedNameKind::RootStruct, NameConfidence::Medium);
    result.structure.add_provenance(pattern.func_ea);

    if (pattern.flow_analysis.started || pattern.flow_analysis.invalid_limits) {
        result.flow_diagnostics.push_back({pattern.func_ea, pattern.var_idx, pattern.flow_analysis});
    }
    if (pattern.accesses.empty()) {
        result.error = SynthError::NoAccessesFound;
        result.error_message = "No access evidence was supplied for synthesis";
        return result;
    }

    // Perform cross-function analysis if enabled
    UnifiedAccessPattern unified_pattern;

    if (config_.cross_function) {
        CrossFunctionConfig cf_config;
        cf_config.max_depth = config_.cross_function_depth;
        cf_config.max_functions = config_.max_functions;
        cf_config.track_pointer_deltas = config_.track_pointer_deltas;
        cf_config.follow_forward = opts.propagate_to_callees;
        cf_config.follow_backward = opts.propagate_to_callers;

        CrossFunctionAnalyzer analyzer(cf_config);
        unified_pattern = analyzer.analyze(pattern.func_ea, pattern.var_idx, opts);
        result.functions_analyzed =
                static_cast<int>(analyzer.equivalence_class().variables.size());
        prune_intermediate_positive_delta_patterns(pattern.func_ea,
                                                                                             unified_pattern);
        reanchor_source_window_accesses(pattern.func_ea, unified_pattern);
    } else {
        // Single-function mode
        AccessPattern mutable_pattern = pattern;
        unified_pattern =
                UnifiedAccessPattern::from_single(std::move(mutable_pattern));
        result.functions_analyzed = 1;
    }

    // Synthesize from unified pattern
    SynthesisResult synth_result =
            synthesize(unified_pattern, opts, pattern.func_ea);

    // Preserve seed diagnostics even when cross-function pruning omitted it.
    if (!result.flow_diagnostics.empty() &&
        std::none_of(synth_result.flow_diagnostics.begin(), synth_result.flow_diagnostics.end(),
            [&](const FlowAnalysisDiagnostic& diagnostic) {
                return diagnostic.func_ea == pattern.func_ea && diagnostic.var_idx == pattern.var_idx;
            })) {
        synth_result.flow_diagnostics.push_back(result.flow_diagnostics.front());
    }

    // Copy metadata
    synth_result.structure.source_func = pattern.func_ea;
    synth_result.structure.source_var = pattern.var_name;
    set_generated_name(
            synth_result.structure.name, synth_result.structure.naming,
            make_auto_root_type_name(pattern.func_ea, pattern.var_name),
            GeneratedNameKind::RootStruct, NameConfidence::Medium);
    synth_result.functions_analyzed = result.functions_analyzed;

    sval_t source_delta = 0;
    if (auto it = unified_pattern.function_deltas.find(pattern.func_ea);
            it != unified_pattern.function_deltas.end()) {
        source_delta = it->second;
    }

    if (source_delta > 0 &&
            !extract_shifted_view_delta(synth_result.structure.name).has_value()) {
        synth_result.structure.name =
                make_shifted_view_type_name(synth_result.structure.name, source_delta);
    }

    auto end_time = std::chrono::steady_clock::now();
    synth_result.synthesis_time =
            std::chrono::duration_cast<std::chrono::milliseconds>(end_time -
                                                                                                                        start_time);

    conflicts_ = synth_result.conflicts;
    return synth_result;
}

SynthesisResult LayoutSynthesizer::synthesize(const AccessPattern &pattern) {
    return synthesize(pattern, Config::instance().options());
}

SynthesisResult
LayoutSynthesizer::synthesize(const UnifiedAccessPattern &unified_pattern,
                                                            const SynthOptions &requested_opts, ea_t source_func_hint) {
    auto diagnostics = unified_pattern.flow_diagnostics;
    // Callers can also supply patterns directly without the merge helpers.
    if (diagnostics.empty()) {
        for (const auto& pattern : unified_pattern.per_function_patterns) {
            if (pattern.flow_analysis.started || pattern.flow_analysis.invalid_limits) {
                diagnostics.push_back({pattern.func_ea, pattern.var_idx, pattern.flow_analysis});
            }
        }
    }
    const bool exhausted = std::any_of(diagnostics.begin(), diagnostics.end(),
        [](const FlowAnalysisDiagnostic& diagnostic) { return diagnostic.analysis.budget_exhausted(); });
    // A budget can leave individually valid offsets observed before widening.
    // They do not establish a finite array extent for the unexplored paths.
    // Restrict aggregate inference for this call and restore reusable config.
    struct RestoreArrayOptions {
        LayoutSynthConfig& config;
        bool arrays;
        bool symbolic;
        ~RestoreArrayOptions() {
            config.detect_arrays = arrays;
            config.detect_symbolic_arrays = symbolic;
        }
    } restore_arrays{config_, config_.detect_arrays, config_.detect_symbolic_arrays};
    SynthOptions opts = requested_opts;
    if (exhausted) {
        config_.detect_arrays = false;
        config_.detect_symbolic_arrays = false;
        opts.z3.detect_arrays = false;
        opts.z3.detect_symbolic_arrays = false;
    }
    SynthesisResult output = [&]() -> SynthesisResult {
    auto start_time = std::chrono::steady_clock::now();

    SynthesisResult result;

    if (unified_pattern.all_accesses.empty()) {
        result.error = SynthError::NoAccessesFound;
        result.error_message = "No unified access evidence was supplied for synthesis";
        return result;
    }

    if (config_.use_z3 && config_.enable_maxsmt &&
        config_.z3_memory_mb != 0) {
        return resource_limit_result(
            ResourceLimitKind::SolverMemory,
            config_.z3_memory_mb,
            0,
            "solver_configuration",
            "configured per-instance memory limit is unavailable for the MaxSMT optimizer");
    }

    if (config_.max_accesses == 0) {
        return resource_limit_result(
            ResourceLimitKind::Accesses, 0,
            unified_pattern.all_accesses.size(),
            "synthesis_preflight",
            "configured access-evidence limit is zero");
    }
    if (config_.max_candidates == 0) {
        return resource_limit_result(
            ResourceLimitKind::Candidates, 0, 0,
            "synthesis_preflight",
            "configured field-candidate limit is zero");
    }
    if (config_.max_fields == 0) {
        return resource_limit_result(
            ResourceLimitKind::Fields, 0, 0,
            "synthesis_preflight",
            "configured materialized-field limit is zero");
    }
    if (config_.max_array_elements == 0) {
        return resource_limit_result(
            ResourceLimitKind::ArrayElements, 0, 0,
            "synthesis_preflight",
            "configured array-inference element limit is zero");
    }
    if (config_.max_struct_size == 0) {
        return resource_limit_result(
            ResourceLimitKind::StructureSize, 0, 0,
            "synthesis_preflight",
            "configured structure-size limit is zero");
    }
    if (config_.max_constraint_pairs == 0) {
        return resource_limit_result(
            ResourceLimitKind::ConstraintPairs, 0, 0,
            "synthesis_preflight",
            "configured constraint-relation limit is zero");
    }
    if (config_.max_union_alternatives == 0) {
        return resource_limit_result(
            ResourceLimitKind::UnionAlternatives, 0, 0,
            "synthesis_preflight",
            "configured per-union alternative limit is zero");
    }
    if (unified_pattern.all_accesses.size() > config_.max_accesses) {
        return resource_limit_result(
            ResourceLimitKind::Accesses,
            config_.max_accesses,
            unified_pattern.all_accesses.size(),
            "synthesis_preflight",
            "access evidence exceeds the configured synthesis limit");
    }

    const auto evidence_span = checked_pattern_span(unified_pattern);
    if (!evidence_span || *evidence_span > config_.max_struct_size) {
        return resource_limit_result(
            ResourceLimitKind::StructureSize,
            config_.max_struct_size,
            evidence_span.value_or(std::numeric_limits<uint64_t>::max()),
            "synthesis_preflight",
            "recovered object span exceeds the configured structure-size limit");
    }

    if (config_.create_unions) {
        if (const auto excess = mandatory_union_alternative_excess(
                unified_pattern, config_.max_union_alternatives)) {
            return resource_limit_result(
                ResourceLimitKind::UnionAlternatives,
                config_.max_union_alternatives,
                *excess,
                "synthesis_preflight",
                "mandatory storage interpretations exceed the per-union alternative limit");
        }
    }

    std::optional<SynthesisResult> failed_z3_attempt;

    // Try Z3 synthesis first if enabled.
    if (config_.use_z3) {
        result = synthesize_z3(unified_pattern);
        result.used_z3 = true;
        if (result.error == SynthError::ResourceLimitExceeded) {
            return result;
        }
        if (result.error != SynthError::Success || result.structure.fields.empty()) {
            if (!config_.fallback_to_heuristics) {
                if (result.error == SynthError::Success) {
                    result.error = SynthError::TypeCreationFailed;
                    result.error_message =
                        "Required Z3 synthesis produced no materializable fields";
                }
                return result;
            }
            failed_z3_attempt = std::move(result);
            result = SynthesisResult{};
        }
    }

    if (result.error != SynthError::Success) {
        return result;
    }

    // Fallback to heuristic synthesis
    if (result.structure.fields.empty() && config_.fallback_to_heuristics) {
        result = synthesize_heuristic(unified_pattern);
        if (failed_z3_attempt.has_value()) {
            result.used_z3 = true;
            result.fell_back_to_heuristic = true;
            result.fallback_reason = failed_z3_attempt->error_message.empty()
                ? failed_z3_attempt->fallback_reason
                : failed_z3_attempt->error_message;
            if (result.fallback_reason.empty()) {
                result.fallback_reason = "Z3 synthesis failed";
            }
            result.had_relaxation = failed_z3_attempt->had_relaxation;
            result.dropped_constraints =
                std::move(failed_z3_attempt->dropped_constraints);
            result.unsat_core = std::move(failed_z3_attempt->unsat_core);
            result.z3_solve_time = failed_z3_attempt->z3_solve_time;
            result.z3_stats = failed_z3_attempt->z3_stats;
        }
    }

    if (!result.structure.fields.empty()) {
        result.structure.source_func = source_func_hint;
        if (result.structure.name.empty()) {
            set_generated_name(
                    result.structure.name, result.structure.naming,
                    make_auto_root_type_name(source_func_hint, qstring()),
                    GeneratedNameKind::RootStruct, NameConfidence::Medium);
        }
        if (config_.emit_substructs) {
            detect_subobjects(unified_pattern, opts, result);
        }
        apply_bitfield_recovery(unified_pattern, result.structure);
        result.unified_pattern = unified_pattern;
        result.functions_analyzed =
                static_cast<int>(unified_pattern.contributing_functions.size());

        append_inferred_tail_padding(unified_pattern, result.structure);
        rebase_negative_offsets(result.structure, &result.sub_structs);
        const std::size_t materialized_field_count =
            materialize_internal_padding(
                result.structure, result.sub_structs);
        if (materialized_field_count > config_.max_fields) {
            return resource_limit_result(
                ResourceLimitKind::Fields,
                config_.max_fields,
                materialized_field_count,
                "layout_materialization",
                "explicit internal padding exceeds the configured materialized-field limit");
        }
        synchronize_substruct_field_names(
            result.structure, result.sub_structs);
        finalize_structure_abi(
            result.structure, &result.sub_structs, config_.default_alignment);
        result.inferred_packing =
            result.structure.packing.value_or(config_.default_alignment);
        compute_struct_size(result.structure);

        if (!result.structure.fields.empty() && result.structure.size == 0) {
            return resource_limit_result(
                ResourceLimitKind::StructureSize,
                config_.max_struct_size,
                std::numeric_limits<uint64_t>::max(),
                "layout_materialization",
                "materialized structure bounds overflow the supported size domain");
        }
        if (result.structure.size > config_.max_struct_size) {
            return resource_limit_result(
                ResourceLimitKind::StructureSize,
                config_.max_struct_size,
                result.structure.size,
                "layout_materialization",
                "materialized structure exceeds the configured size limit");
        }
        if (result.structure.fields.size() > config_.max_fields) {
            return resource_limit_result(
                ResourceLimitKind::Fields,
                config_.max_fields,
                result.structure.fields.size(),
                "layout_materialization",
                "materialized field count exceeds the configured field limit");
        }
    }

    auto end_time = std::chrono::steady_clock::now();
    result.synthesis_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time);

    return result;
    }();
    output.arrays_suppressed_by_flow_budget = exhausted;
    output.flow_diagnostics = std::move(diagnostics);
    return output;
}

SynthesisResult
LayoutSynthesizer::synthesize(const UnifiedAccessPattern &unified_pattern) {
    return synthesize(unified_pattern, Config::instance().options(), BADADDR);
}

SynthesisResult
LayoutSynthesizer::synthesize_z3(const UnifiedAccessPattern &pattern) {
    SynthesisResult result;
    result.used_z3 = true;

    detail::synth_log("[Structor] Starting Z3-based structure synthesis...\n");

    try {
        // Create Z3 context
        z3::Z3Config z3_config = make_z3_config();
        z3_ctx_ = std::make_unique<z3::Z3Context>(z3_config);

        // Generate field candidates
        z3::CandidateGenerationConfig cand_config = make_candidate_config();
        z3::FieldCandidateGenerator generator(*z3_ctx_, cand_config);
        auto candidates = generator.generate(pattern);

        detail::synth_log(
                "[Structor] Generated %zu field candidates from %zu accesses\n",
                candidates.size(), pattern.all_accesses.size());

        if (candidates.empty()) {
            detail::synth_log(
                    "[Structor] No field candidates were generated\n");
            result.error = SynthError::TypeCreationFailed;
            result.error_message = "Z3 generated no field candidates";
            result.fallback_reason = "No field candidates generated";
            return result;
        }

        // Build and solve constraints
        z3::LayoutConstraintConfig layout_config = make_layout_config();
        z3::LayoutConstraintBuilder builder(*z3_ctx_, layout_config);
        builder.build_constraints(pattern, candidates);

        auto z3_result = builder.solve();
        result.z3_solve_time = z3_result.solve_time;
        result.z3_stats = builder.statistics();

        if (z3_result.is_sat()) {
            // Extract struct from model
            result.structure = builder.extract_struct(*z3_result.model);
            result.inferred_packing = builder.inferred_packing();

            // Count detected features
            result.arrays_detected =
                    static_cast<int>(builder.detected_arrays().size());
            result.unions_created =
                    static_cast<int>(builder.union_resolutions().size());

            // Handle relaxed constraints
            if (z3_result.has_dropped_constraints()) {
                result.had_relaxation = true;
                result.dropped_constraints =
                    z3::copy_constraint_diagnostics(z3_result.dropped_constraints);
                detail::synth_log(
                        "[Structor] Z3 synthesis completed with %zu relaxed constraints\n",
                        z3_result.dropped_constraints.size());
            } else {
                detail::synth_log("[Structor] Z3 synthesis completed successfully\n");
            }

            detail::synth_log("[Structor] Result: %zu fields, %u bytes",
                                                result.structure.fields.size(), result.structure.size);
            if (result.arrays_detected > 0) {
                detail::synth_log(", %d arrays", result.arrays_detected);
            }
            if (result.unions_created > 0) {
                detail::synth_log(", %d unions", result.unions_created);
            }
            detail::synth_log("\n");

            // Preserve the solver-compatible packing cap separately from the
            // effective structure alignment. Post-processing computes the
            // latter from the final materialized fields.
            if (result.inferred_packing &&
                *result.inferred_packing < config_.default_alignment) {
                result.structure.packing = *result.inferred_packing;
            } else {
                result.structure.packing.reset();
            }

            if (result.structure.fields.empty()) {
                result.error = SynthError::TypeCreationFailed;
                result.error_message =
                    "Z3 returned SAT but selected no materializable fields";
            }

            return result;
        } else if (z3_result.is_unsat()) {
            detail::synth_log(
                    "[Structor] Z3 returned UNSAT - constraints unsatisfiable\n");
            // Try relaxation if configured
            if (config_.relax_alignment_on_unsat || config_.relax_types_on_unsat) {
                return try_relaxed_solve(builder, z3_result, result);
            }

            result.unsat_core = z3::copy_constraint_diagnostics(z3_result.unsat_core);
            result.fallback_reason = "Z3 UNSAT: ";
            if (!z3_result.unsat_core.empty()) {
                result.fallback_reason.append(
                    z3_result.unsat_core[0].description.c_str());
            }
            result.error = SynthError::Z3Unsat;
            result.error_message = result.fallback_reason;
            return result;
        } else {
            // Unknown or error
            if (const auto resource_kind = classify_solver_resource_failure(
                    z3_result.error_message.c_str(), config_)) {
                const bool timeout =
                    *resource_kind == ResourceLimitKind::SolverTimeout;
                SynthesisResult limited = resource_limit_result(
                    *resource_kind,
                    timeout ? config_.z3_timeout_ms : config_.z3_memory_mb,
                    timeout
                        ? static_cast<std::uint64_t>(std::max<std::int64_t>(
                              0, z3_result.solve_time.count()))
                        : 0,
                    "solver",
                    z3_result.error_message.c_str());
                limited.used_z3 = true;
                limited.z3_solve_time = z3_result.solve_time;
                limited.z3_stats = builder.statistics();
                return limited;
            }

            detail::synth_log("[Structor] Z3 returned unknown - falling back "
                              "to heuristics\n");
            result.fallback_reason = "Z3 ";
            result.fallback_reason.append(z3_result.status_string());
            if (!z3_result.error_message.empty()) {
                result.fallback_reason.append(": ");
                result.fallback_reason.append(z3_result.error_message.c_str());
            }
            result.error = SynthError::InternalError;
            result.error_message = result.fallback_reason;
            return result;
        }
    } catch (const ResourceLimitException& e) {
        SynthesisResult limited = resource_limit_result(
            e.violation.kind,
            e.violation.configured_limit,
            e.violation.observed_value,
            e.violation.phase.c_str(),
            e.what());
        limited.used_z3 = true;
        return limited;
    } catch (const std::exception &e) {
        if (const auto resource_kind = classify_solver_resource_failure(
                e.what(), config_)) {
            const bool timeout =
                *resource_kind == ResourceLimitKind::SolverTimeout;
            SynthesisResult limited = resource_limit_result(
                *resource_kind,
                timeout ? config_.z3_timeout_ms : config_.z3_memory_mb,
                0,
                "solver",
                e.what());
            limited.used_z3 = true;
            return limited;
        }
        detail::synth_log("[Structor] Z3 exception: %s\n", e.what());
        result.fallback_reason = "Z3 exception: ";
        result.fallback_reason.append(e.what());
        result.error = SynthError::InternalError;
        result.error_message = result.fallback_reason;
        return result;
    } catch (...) {
        detail::synth_log("[Structor] Unknown Z3 exception\n");
        result.fallback_reason = "Unknown Z3 exception";
        result.error = SynthError::InternalError;
        result.error_message = result.fallback_reason;
        return result;
    }
}

SynthesisResult
LayoutSynthesizer::try_relaxed_solve(z3::LayoutConstraintBuilder &builder,
                                                                         const z3::Z3Result &initial_result,
                                                                         SynthesisResult &result) {
    // The solve() method already calls solve_with_relaxation() internally
    // when UNSAT is encountered. If we got here, relaxation was attempted
    // but failed to produce SAT.
    //
    // At this point we have options:
    // 1. Accept partial results with raw bytes for irreconcilable regions
    // 2. Return to heuristic fallback
    //
    // Check if we have any dropped constraints - if so, some relaxation worked
    // but ultimately failed. Log this for debugging.

    if (!initial_result.dropped_constraints.empty()) {
        qstring dropped_info;
        dropped_info.sprnt("Relaxed %zu constraints but still UNSAT",
                                             initial_result.dropped_constraints.size());
        result.fallback_reason = dropped_info;
        result.dropped_constraints =
            z3::copy_constraint_diagnostics(initial_result.dropped_constraints);
    }

    // Record the UNSAT core for diagnostics
    result.unsat_core = z3::copy_constraint_diagnostics(initial_result.unsat_core);

    // If use_raw_bytes_fallback is enabled, we could try creating raw byte fields
    // for the problematic regions identified in the UNSAT core
    if (config_.use_raw_bytes_fallback && !initial_result.unsat_core.empty()) {
        // Identify the minimum region that must be covered by examining core
        // For now, signal that fallback to heuristics should use raw bytes
        result.fallback_reason = "Z3 UNSAT - using raw bytes for ambiguous regions";
    }

    if (result.fallback_reason.empty()) {
        result.fallback_reason = "Z3 constraints unsatisfiable";
    }

    result.error = SynthError::Z3Unsat;
    result.error_message = result.fallback_reason;
    return result;
}

SynthesisResult
LayoutSynthesizer::synthesize_heuristic(const UnifiedAccessPattern &pattern) {
    detail::synth_log("[Structor] Using heuristic structure synthesis\n");

    SynthesisResult result;
    result.used_z3 = false;

    // Set basic struct properties
    result.structure.alignment = config_.default_alignment;

    if (!pattern.contributing_functions.empty()) {
        result.structure.source_func = pattern.contributing_functions[0];
        for (ea_t func : pattern.contributing_functions) {
            result.structure.add_provenance(func);
        }
    }

    if (pattern.all_accesses.empty()) {
        return result;
    }

    // Group accesses by offset
    qvector<OffsetGroup> groups;
    group_accesses_heuristic(pattern, groups);

    // Resolve any conflicts
    resolve_conflicts_heuristic(groups);

    // Generate fields from groups
    generate_fields_heuristic(groups, result.structure);

    // Insert padding where needed
    insert_padding_heuristic(result.structure);

    // Infer and set field types
    infer_field_types_heuristic(result.structure, pattern);

    // Generate meaningful field names
    generate_field_names(result.structure);

    // Compute final structure size
    compute_struct_size(result.structure);

    // Copy conflicts
    result.conflicts = conflicts_;

    detail::synth_log(
            "[Structor] Heuristic synthesis completed: %zu fields, %u bytes\n",
            result.structure.fields.size(), result.structure.size);
    if (!conflicts_.empty()) {
        detail::synth_log("[Structor] Warning: %zu conflicts detected\n",
                                            conflicts_.size());
    }

    return result;
}

void LayoutSynthesizer::group_accesses_heuristic(
        const UnifiedAccessPattern &pattern, qvector<OffsetGroup> &groups) {
    // Sort accesses by offset
    qvector<FieldAccess> sorted = pattern.all_accesses;
    std::sort(sorted.begin(), sorted.end());

    // Group overlapping accesses
    for (const auto &access : sorted) {
        bool merged = false;

        for (auto &group : groups) {
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
    std::sort(groups.begin(), groups.end(),
                        [](const OffsetGroup &a, const OffsetGroup &b) {
                            return a.offset < b.offset;
                        });
}

void LayoutSynthesizer::resolve_conflicts_heuristic(
        qvector<OffsetGroup> &groups) {
    for (auto &group : groups) {
        if (group.accesses.size() <= 1)
            continue;

        // Check for conflicting access sizes at the same offset
        std::unordered_map<sval_t, qvector<FieldAccess *>> by_offset;
        for (auto &access : group.accesses) {
            by_offset[access.offset].push_back(&access);
        }

        for (auto &[off, acc_list] : by_offset) {
            if (acc_list.size() <= 1)
                continue;

            bool has_conflict = false;
            for (size_t i = 0; i < acc_list.size() && !has_conflict; ++i) {
                for (size_t j = i + 1; j < acc_list.size(); ++j) {
                    if (acc_list[i]->size != acc_list[j]->size ||
                        !field_access_evidence_compatible(*acc_list[i], *acc_list[j])) {
                        has_conflict = true;
                        break;
                    }
                }
            }

            if (has_conflict) {
                AccessConflict conflict;
                conflict.offset = off;
                conflict.description.sprnt(
                    "Conflicting storage views at offset 0x%X",
                    static_cast<unsigned>(off));

                for (auto *acc : acc_list) {
                    conflict.conflicting_accesses.push_back(*acc);
                }

                conflicts_.push_back(std::move(conflict));
                group.is_union = true;
            }
        }
    }
}

void LayoutSynthesizer::generate_fields_heuristic(
        const qvector<OffsetGroup> &groups, SynthStruct &result) {
    for (const auto &group : groups) {
        SynthField field;
        field.offset = group.offset;
        field.size = group.size;
        field.is_union_candidate = group.is_union;
        field.source_accesses = group.accesses;

        // Select best type and semantic from all accesses
        field.type = select_best_type(group.accesses);
        field.semantic = select_best_semantic(group.accesses);

        if (group.is_union) {
            qvector<FieldAccess> alternatives = group.accesses;
            std::sort(alternatives.begin(), alternatives.end(),
                      canonical_field_access_less);

            qvector<FieldAccess> distinct;
            for (const auto& access : alternatives) {
                auto compatible = std::find_if(
                    distinct.begin(), distinct.end(), [&](const FieldAccess& existing) {
                        return existing.offset == access.offset &&
                               existing.size == access.size &&
                               field_access_evidence_compatible(existing, access);
                    });
                if (compatible == distinct.end()) {
                    distinct.push_back(access);
                } else {
                    merge_field_access_evidence(*compatible, access);
                }
            }

            std::unordered_map<std::string, size_t> member_name_counts;
            for (const auto& access : distinct) {
                qvector<FieldAccess> singleton;
                singleton.push_back(access);

                SynthField::UnionMember member;
                member.offset = access.offset - group.offset;
                member.size = access.size;
                member.type = select_best_type(singleton);
                member.name = generate_field_name(
                    access.offset, access.semantic_type, access.size);

                const std::string base_name = member.name.c_str();
                const size_t duplicate_index = member_name_counts[base_name]++;
                if (duplicate_index != 0) {
                    member.name.sprnt("%s_alt%zu", base_name.c_str(), duplicate_index);
                }
                member.naming.kind = GeneratedNameKind::UnionAlternative;
                member.naming.origin = NameOrigin::GeneratedFallback;
                member.naming.confidence = NameConfidence::Medium;
                field.union_members.push_back(std::move(member));
            }
        }

        result.fields.push_back(std::move(field));
    }

    // Sort fields by offset
    std::sort(result.fields.begin(), result.fields.end(),
                        [](const SynthField &a, const SynthField &b) {
                            return a.offset < b.offset;
                        });
}

void LayoutSynthesizer::insert_padding_heuristic(SynthStruct &result) {
    if (result.fields.empty())
        return;

    qvector<SynthField> with_padding;
    sval_t current_offset = 0;

    for (auto &field : result.fields) {
        // Insert padding if there's a gap
        if (field.offset > current_offset) {
            std::uint32_t gap = field.offset - current_offset;
            with_padding.push_back(SynthField::create_padding(current_offset, gap));
        }

        with_padding.push_back(std::move(field));
        current_offset = std::max(
            current_offset,
            with_padding.back().offset +
                static_cast<sval_t>(with_padding.back().size));
    }

    result.fields = std::move(with_padding);
}

void LayoutSynthesizer::infer_field_types_heuristic(
        SynthStruct &result, const UnifiedAccessPattern &pattern) {
    std::uint32_t ptr_size = get_ptr_size();

    for (auto &field : result.fields) {
        if (field.is_padding)
            continue;
        if (!field.type.empty())
            continue;

        // Infer type from semantic and size
        switch (field.semantic) {
        case SemanticType::VTablePointer: {
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
                field.type.create_ptr(void_ptr);
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
            field.type =
                    utils::create_basic_type(field.size, SemanticType::UnsignedInteger);
            break;

        case SemanticType::Integer:
        case SemanticType::Unknown:
        default:
            if (field.size == ptr_size) {
                bool any_deref = false;
                for (const auto &acc : field.source_accesses) {
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
                    field.type =
                            utils::create_basic_type(field.size, SemanticType::Integer);
                }
            } else {
                field.type =
                        utils::create_basic_type(field.size, SemanticType::Integer);
            }
            break;
        }
    }
}

void LayoutSynthesizer::generate_field_names(SynthStruct &result) {
    for (auto &field : result.fields) {
        if (field.is_padding)
            continue;
        if (!field.name.empty())
            continue;

        if (!field.is_array && !field.is_union_candidate && !field.type.empty() &&
                (field.type.is_struct() || field.type.is_union() ||
                 field.semantic == SemanticType::NestedStruct)) {
            set_generated_name(
                    field.name, field.naming, make_substruct_field_name(field.offset),
                    GeneratedNameKind::SubStructField, NameConfidence::Medium);
        } else if (field.is_array) {
            tinfo_t elem_type = field.type;
            array_type_data_t atd;
            if (elem_type.is_array() && elem_type.get_array_details(&atd)) {
                elem_type = atd.elem_type;
            }
            const size_t elem_size = elem_type.get_size();
            set_generated_name(
                    field.name, field.naming,
                    make_array_field_name(
                            field.offset, elem_type, field.semantic,
                            static_cast<std::uint32_t>(elem_size == BADSIZE ? 0 : elem_size)),
                    GeneratedNameKind::ArrayField, NameConfidence::Medium);
        } else {
            set_generated_name(
                    field.name, field.naming,
                    generate_field_name(field.offset, field.semantic, field.size),
                    field.is_array ? GeneratedNameKind::ArrayField
                                                 : GeneratedNameKind::Field,
                    NameConfidence::Medium);
        }
    }

    apply_role_based_field_names(result);
    disambiguate_repeated_field_names(result);

    if (!config_.generate_comments) {
        return;
    }

    for (auto &field : result.fields) {
        if (field.is_padding) {
            continue;
        }

        qstring comment;
        comment.sprnt("size: %u, accesses: %zu", field.size,
                                    field.source_accesses.size());

        if (!field.source_accesses.empty()) {
            const auto &first_access = field.source_accesses[0];
            comment.cat_sprnt(", %s", access_type_str(first_access.access_type));
        }

        if (field.is_union_candidate) {
            comment.append(" [union candidate]");
        }

        field.comment = std::move(comment);
    }
}

void LayoutSynthesizer::compute_struct_size(SynthStruct &result) {
    if (result.fields.empty()) {
        result.size = 0;
        return;
    }

    sval_t end = 0;
    for (const auto& field : result.fields) {
        if (field.offset < 0 ||
            field.offset > std::numeric_limits<sval_t>::max() -
                               static_cast<sval_t>(field.size)) {
            result.size = 0;
            return;
        }
        end = std::max(
            end, field.offset + static_cast<sval_t>(field.size));
    }

    // Align to structure alignment
    const sval_t aligned_end = align_offset(end, result.alignment);
    if (aligned_end < end ||
        static_cast<uint64_t>(aligned_end) >
            std::numeric_limits<uint32_t>::max()) {
        result.size = 0;
        return;
    }
    result.size = static_cast<uint32_t>(aligned_end);
}

void LayoutSynthesizer::apply_bitfield_recovery(
        const UnifiedAccessPattern &pattern, SynthStruct &result) {
    if (pattern.all_accesses.empty() || result.fields.empty())
        return;

    std::unordered_map<uint64_t, qvector<BitfieldInfo>> by_field;
    for (const auto &access : pattern.all_accesses) {
        if (access.bitfields.empty())
            continue;
        uint64_t key = (static_cast<uint64_t>(access.offset) << 32) |
                                     static_cast<uint64_t>(access.size);
        auto &list = by_field[key];
        for (const auto &bf : access.bitfields) {
            bool found = false;
            for (const auto &existing : list) {
                if (existing == bf) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                list.push_back(bf);
            }
        }
    }

    if (by_field.empty())
        return;

    auto make_base_type = [](uint32_t size) {
        tinfo_t type;
        switch (size) {
        case 1:
            type.create_simple_type(BT_INT8 | BTMT_USIGNED);
            break;
        case 2:
            type.create_simple_type(BT_INT16 | BTMT_USIGNED);
            break;
        case 4:
            type.create_simple_type(BT_INT32 | BTMT_USIGNED);
            break;
        case 8:
            type.create_simple_type(BT_INT64 | BTMT_USIGNED);
            break;
        default:
            type.create_simple_type(BT_INT8 | BTMT_USIGNED);
            break;
        }
        return type;
    };

    qvector<SynthField> updated;
    updated.reserve(result.fields.size());

    for (const auto &field : result.fields) {
        uint64_t key = (static_cast<uint64_t>(field.offset) << 32) |
                                     static_cast<uint64_t>(field.size);
        auto it = by_field.find(key);
        if (it == by_field.end() || field.is_padding || field.is_array ||
                field.is_union_candidate) {
            updated.push_back(field);
            continue;
        }

        // Hex-Rays handles packed misaligned scalar fields much more reliably as
        // plain storage than as synthetic C bitfields. Converting those fields
        // into bitfields tends to skew later member accesses back into casts.
        if (field.size > 1 && field.offset >= 0 &&
                (field.offset % static_cast<sval_t>(field.size)) != 0) {
            updated.push_back(field);
            continue;
        }

        const auto &bfs = it->second;
        bool valid = true;
        for (const auto &bf : bfs) {
            if (static_cast<unsigned>(bf.bit_offset + bf.bit_size) > field.size * 8) {
                valid = false;
                break;
            }
        }

        if (!valid || bfs.empty()) {
            updated.push_back(field);
            continue;
        }

        for (const auto &bf : bfs) {
            SynthField bf_field = SynthField::create_bitfield(
                    field.offset, field.size, bf.bit_offset, bf.bit_size);
            const size_t observed_type_size =
                field.type.empty() ? BADSIZE : field.type.get_size();
            const bool signedness_matches =
                field.semantic != SemanticType::UnsignedInteger ||
                field.type.is_unsigned();
            bf_field.type = observed_type_size == field.size && signedness_matches
                ? field.type
                : make_base_type(field.size);
            updated.push_back(std::move(bf_field));
        }
    }

    std::sort(updated.begin(), updated.end(),
                        [](const SynthField &a, const SynthField &b) {
                            if (a.offset != b.offset)
                                return a.offset < b.offset;
                            if (a.is_bitfield != b.is_bitfield)
                                return a.is_bitfield;
                            return a.bit_offset < b.bit_offset;
                        });

    result.fields = std::move(updated);
    compute_struct_size(result);
}

void LayoutSynthesizer::detect_subobjects(const UnifiedAccessPattern &pattern,
                                                                                    const SynthOptions &opts,
                                                                                    SynthesisResult &result) {
    if (!config_.emit_substructs || !config_.cross_function)
        return;
    if (pattern.per_function_patterns.empty())
        return;

    struct SubGroup {
        sval_t offset = 0;
        qvector<AccessPattern> patterns;
        std::unordered_set<ea_t> funcs;
    };

    std::unordered_map<sval_t, SubGroup> groups;
    if (!pattern.flow_edges.empty()) {
        for (const auto &edge : pattern.flow_edges) {
            if (edge.delta == 0 || edge.callee_param_idx < 0) {
                continue;
            }

            sval_t caller_delta = 0;
            if (auto caller_it = pattern.function_deltas.find(edge.caller_ea);
                    caller_it != pattern.function_deltas.end()) {
                caller_delta = caller_it->second;
            }
            if (caller_delta != 0) {
                continue;
            }

            for (const auto &fn_pattern : pattern.per_function_patterns) {
                if (fn_pattern.func_ea == result.structure.source_func &&
                        edge.callee_ea == result.structure.source_func) {
                    continue;
                }
                if (fn_pattern.func_ea != edge.callee_ea ||
                        fn_pattern.var_idx != edge.callee_param_idx) {
                    continue;
                }

                const sval_t group_delta = caller_delta + edge.delta;
                if (group_delta <= 0) {
                    continue;
                }

                auto &group = groups[group_delta];
                group.offset = group_delta;
                group.patterns.push_back(fn_pattern);
                group.funcs.insert(fn_pattern.func_ea);
            }
        }
    }

    // Flow-edge recovery can be partial (for example when a decompiler folds
    // one wrapper but preserves a deeper call).  Always augment, rather than
    // only when no edge-derived group survived.
    for (const auto &fn_pattern : pattern.per_function_patterns) {
        if (fn_pattern.func_ea == result.structure.source_func) {
            continue;
        }

        auto it = pattern.function_deltas.find(fn_pattern.func_ea);
        sval_t delta = it != pattern.function_deltas.end() ? it->second : 0;
        if (delta <= 0)
            continue;

        auto &group = groups[delta];
        group.offset = delta;
        if (group.funcs.insert(fn_pattern.func_ea).second) {
            group.patterns.push_back(fn_pattern);
        }
    }

    // IDA can inline a direct child wrapper into the caller ctree while the
    // machine-code call xref remains.  Recover such an intermediate child by
    // matching at least two of its direct accesses against the unified parent
    // evidence, anchored by one or more identical, nontrivial write constants.
    // This is a bounded fallback for missing ctree flow edges, not general
    // similarity matching.
    const AccessPattern *source_seed_pattern = nullptr;
    for (const auto &fn_pattern : pattern.per_function_patterns) {
        if (fn_pattern.func_ea == result.structure.source_func) {
            source_seed_pattern = &fn_pattern;
            break;
        }
    }

    std::optional<AccessPattern> caller_anchor_pattern;
    if (source_seed_pattern && source_seed_pattern->var_idx >= 0) {
        cfuncptr_t source_cfunc = utils::get_cfunc(result.structure.source_func);
        if (source_cfunc) {
            AccessCollector source_collector(opts);
            caller_anchor_pattern.emplace(source_collector.collect(
                    source_cfunc, source_seed_pattern->var_idx));
        }
    }

    qvector<ea_t> direct_callees =
            utils::get_callees(result.structure.source_func);
    std::sort(direct_callees.begin(), direct_callees.end());
    const std::size_t callee_limit = static_cast<std::size_t>(
            std::max(0, config_.max_functions));
    if (direct_callees.size() > callee_limit) {
        direct_callees.resize(callee_limit);
    }

    for (ea_t callee_ea : direct_callees) {
        func_t *callee_func = get_func(callee_ea);
        segment_t *callee_segment = getseg(callee_ea);
        if (!callee_func || callee_ea == result.structure.source_func ||
                (callee_func->flags & (FUNC_LIB | FUNC_THUNK)) != 0 ||
                (callee_segment && callee_segment->type == SEG_XTRN)) {
            continue;
        }

        bool already_grouped = false;
        for (const auto &[_, group] : groups) {
            if (group.funcs.count(callee_ea) != 0) {
                already_grouped = true;
                break;
            }
        }
        if (already_grouped) {
            continue;
        }

        cfuncptr_t callee_cfunc = utils::get_cfunc(callee_ea);
        if (!callee_cfunc) {
            continue;
        }

        lvars_t *callee_lvars = callee_cfunc->get_lvars();
        if (!callee_lvars) {
            continue;
        }

        int callee_var_idx = -1;
        for (size_t i = 0; i < callee_lvars->size(); ++i) {
            if (callee_lvars->at(i).is_arg_var()) {
                callee_var_idx = static_cast<int>(i);
                break;
            }
        }
        if (callee_var_idx < 0) {
            continue;
        }

        AccessCollector collector(opts);
        AccessPattern candidate = collector.collect(callee_cfunc, callee_var_idx);
        if (candidate.accesses.size() < 2) {
            continue;
        }

        std::unordered_set<sval_t> candidate_data_offsets;
        for (const auto &access : candidate.accesses) {
            if (access.access_type == AccessType::Read ||
                    access.access_type == AccessType::Write ||
                    access.access_type == AccessType::ReadWrite) {
                candidate_data_offsets.insert(access.offset);
            }
        }
        if (candidate_data_offsets.size() < 2) {
            continue;
        }

        if (!caller_anchor_pattern.has_value()) {
            continue;
        }

        std::unordered_map<sval_t, int> constant_scores;
        for (const auto &child_access : candidate.accesses) {
            if (child_access.access_type != AccessType::Write ||
                    child_access.offset != candidate.min_offset ||
                    child_access.observed_constants.empty()) {
                continue;
            }

            // Anchor only in the direct caller's unmixed observations.  The
            // unified list may have combined a write with a comparison/read at
            // the same range, making a comparison literal indistinguishable
            // from a value that was actually stored.
            for (const auto &parent_access : caller_anchor_pattern->accesses) {
                if (parent_access.size != child_access.size ||
                        parent_access.access_type != AccessType::Write ||
                        parent_access.observed_constants.empty()) {
                    continue;
                }

                bool shares_constant = false;
                for (std::uint64_t child_value : child_access.observed_constants) {
                    // Small initializer values are too common to provide a
                    // discriminating folded-constructor header anchor.
                    if (child_value > std::numeric_limits<std::uint16_t>::max() &&
                            std::find(parent_access.observed_constants.begin(),
                                      parent_access.observed_constants.end(),
                                      child_value) != parent_access.observed_constants.end()) {
                        shares_constant = true;
                        break;
                    }
                }
                if (!shares_constant) {
                    continue;
                }

                const sval_t delta = parent_access.offset - child_access.offset;
                if (delta > 0) {
                    ++constant_scores[delta];
                }
            }
        }

        sval_t best_delta = 0;
        int best_constant_score = 0;
        int best_coverage = 0;
        bool best_tied = false;
        for (const auto &[delta, constant_score] : constant_scores) {
            if ((candidate.min_offset > 0 &&
                    delta > std::numeric_limits<sval_t>::max() -
                                    candidate.min_offset) ||
                    (candidate.max_offset > 0 &&
                     delta > std::numeric_limits<sval_t>::max() -
                                     candidate.max_offset)) {
                continue;
            }
            const sval_t shifted_min = candidate.min_offset + delta;
            const sval_t shifted_max = candidate.max_offset + delta;
            if (shifted_min < pattern.global_min_offset ||
                    shifted_max > pattern.global_max_offset) {
                continue;
            }

            std::unordered_set<sval_t> covered_offsets;
            for (const auto &child_access : candidate.accesses) {
                if (child_access.access_type != AccessType::Read &&
                        child_access.access_type != AccessType::Write &&
                        child_access.access_type != AccessType::ReadWrite) {
                    continue;
                }
                if (child_access.offset > 0 &&
                        delta > std::numeric_limits<sval_t>::max() -
                                        child_access.offset) {
                    continue;
                }
                const sval_t shifted_offset = child_access.offset + delta;
                const bool covered = std::any_of(
                    pattern.all_accesses.begin(),
                    pattern.all_accesses.end(),
                    [&](const FieldAccess &parent_access) {
                        return parent_access.offset == shifted_offset &&
                               parent_access.size == child_access.size;
                    });
                if (covered) {
                    covered_offsets.insert(child_access.offset);
                }
            }
            const int coverage = static_cast<int>(covered_offsets.size());

            // One exact header location is sufficient because the machine-call
            // edge and the contained multi-location callee span provide the
            // independent evidence.  More coverage wins when available.
            if (coverage < 1) {
                continue;
            }
            if (constant_score > best_constant_score ||
                (constant_score == best_constant_score && coverage > best_coverage)) {
                best_delta = delta;
                best_constant_score = constant_score;
                best_coverage = coverage;
                best_tied = false;
            } else if (constant_score == best_constant_score &&
                       coverage == best_coverage && delta != best_delta) {
                best_tied = true;
            }
        }

        if (best_delta <= 0 || best_constant_score <= 0 || best_tied) {
            continue;
        }

        auto &group = groups[best_delta];
        group.offset = best_delta;
        if (group.funcs.insert(callee_ea).second) {
            group.patterns.push_back(std::move(candidate));
        }
        result.structure.add_provenance(callee_ea);

        if (synth_debug_enabled()) {
            detail::synth_log(
                "[Structor] detect_subobjects: recovered folded callee=%s "
                "delta=0x%llX constants=%d coverage=%d\n",
                utils::get_func_name(callee_ea).c_str(),
                static_cast<unsigned long long>(best_delta),
                best_constant_score,
                best_coverage);
        }
    }

    if (groups.empty())
        return;

    if (synth_debug_enabled()) {
        detail::synth_log("[Structor] detect_subobjects: %zu candidate group(s)\n",
                                            groups.size());
    }

    qvector<sval_t> ordered_deltas;
    ordered_deltas.reserve(groups.size());
    for (const auto &[delta, _] : groups) {
        ordered_deltas.push_back(delta);
    }
    std::sort(ordered_deltas.begin(), ordered_deltas.end());

    LayoutSynthConfig recursive_sub_config = config_;
    recursive_sub_config.cross_function = true;
    recursive_sub_config.emit_substructs = true;
    recursive_sub_config.cross_function_depth =
            std::max(1, recursive_sub_config.cross_function_depth - 1);

    LayoutSynthConfig flat_sub_config = config_;
    flat_sub_config.cross_function = false;
    flat_sub_config.emit_substructs = false;

    LayoutSynthesizer recursive_sub_synth(recursive_sub_config);
    LayoutSynthesizer flat_sub_synth(flat_sub_config);

    auto choose_recursive_seed =
            [&](const SubGroup &group) -> std::optional<AccessPattern> {
        const AccessPattern *best = nullptr;
        int best_score = -1;
        for (const auto &candidate : group.patterns) {
            if (candidate.var_idx < 0 || candidate.accesses.empty()) {
                continue;
            }

            int score = static_cast<int>(candidate.accesses.size());
            const sval_t span = candidate.max_offset - candidate.min_offset;
            if (span > 0) {
                score += static_cast<int>(span) * 10;
            }
            if (type_has_named_udt_details(candidate.original_type)) {
                score += 1000;
            }

            bool has_outgoing_child = false;
            for (const auto &edge : pattern.flow_edges) {
                if (edge.caller_ea == candidate.func_ea && edge.callee_param_idx >= 0) {
                    has_outgoing_child = true;
                    break;
                }
            }
            if (has_outgoing_child) {
                score += 5000;
            }

            if (score > best_score) {
                best = &candidate;
                best_score = score;
            }
        }

        if (best == nullptr) {
            return std::nullopt;
        }

        return *best;
    };

    auto access_covered_by_other_fields = [&](const FieldAccess &access,
                                                                                        size_t skip_index) {
        const sval_t access_end = access.offset + static_cast<sval_t>(access.size);
        for (size_t i = 0; i < result.structure.fields.size(); ++i) {
            if (i == skip_index) {
                continue;
            }

            const auto &other = result.structure.fields[i];
            const sval_t other_end = other.offset + static_cast<sval_t>(other.size);
            if (access.offset >= other.offset && access_end <= other_end) {
                return true;
            }
        }
        return false;
    };

    auto region_covered_by_other_fields =
            [&](sval_t start, sval_t end, size_t skip_index,
                    const qvector<FieldAccess> *extra_accesses = nullptr) {
                if (start >= end) {
                    return true;
                }

                auto access_covered_in_region = [&](const FieldAccess &access) {
                    const sval_t access_end =
                            access.offset + static_cast<sval_t>(access.size);
                    if (access.offset >= end || access_end <= start) {
                        return true;
                    }

                    for (size_t i = 0; i < result.structure.fields.size(); ++i) {
                        if (i == skip_index) {
                            continue;
                        }

                        const auto &other = result.structure.fields[i];
                        const sval_t other_end =
                                other.offset + static_cast<sval_t>(other.size);
                        if (access.offset < other.offset || access_end > other_end) {
                            continue;
                        }

                        return true;
                    }

                    if (extra_accesses) {
                        for (const auto &extra : *extra_accesses) {
                            const sval_t extra_end =
                                    extra.offset + static_cast<sval_t>(extra.size);
                            if (access.offset >= extra.offset && access_end <= extra_end) {
                                return true;
                            }
                        }
                    }

                    return false;
                };

                for (const auto &access : pattern.all_accesses) {
                    if (!access_covered_in_region(access)) {
                        return false;
                    }
                }

                return true;
            };

    auto field_covers_access = [&](const FieldAccess &access) {
        const sval_t access_end = access.offset + static_cast<sval_t>(access.size);
        for (const auto &field : result.structure.fields) {
            const sval_t field_end = field.offset + static_cast<sval_t>(field.size);
            if (access.offset >= field.offset && access_end <= field_end) {
                return true;
            }
        }
        return false;
    };

    const sval_t boundary_split_slop = static_cast<sval_t>(
            std::max<std::uint32_t>(get_ptr_size(), config_.default_alignment));

    auto extend_subobject_tail_from_overlap =
            [&](sval_t sub_offset, const SynthField &field,
                    std::uint32_t current_size) -> std::optional<std::uint32_t> {
        if (field.is_padding || field.source_accesses.empty()) {
            return std::nullopt;
        }

        const sval_t sub_end = sub_offset + static_cast<sval_t>(current_size);
        const sval_t field_end = field.offset + static_cast<sval_t>(field.size);
        if (field.offset >= sub_end || field_end <= sub_end) {
            return std::nullopt;
        }

        sval_t next_outside_offset = std::numeric_limits<sval_t>::max();
        bool has_inside_coverage = false;
        for (const auto &access : field.source_accesses) {
            const sval_t access_end =
                    access.offset + static_cast<sval_t>(access.size);
            if (access_end <= sub_end) {
                has_inside_coverage = true;
                continue;
            }

            if (access.offset >= sub_end) {
                next_outside_offset = std::min(next_outside_offset, access.offset);
            } else {
                has_inside_coverage = true;
            }
        }

        if (!has_inside_coverage ||
                next_outside_offset == std::numeric_limits<sval_t>::max()) {
            return std::nullopt;
        }

        const sval_t gap = next_outside_offset - sub_end;
        const sval_t max_gap = static_cast<sval_t>(
                std::max<std::uint32_t>(get_ptr_size(), config_.default_alignment));
        if (gap <= 0 || gap > max_gap) {
            return std::nullopt;
        }

        return static_cast<std::uint32_t>(next_outside_offset - sub_offset);
    };

    for (sval_t delta : ordered_deltas) {
        bool covered_by_parent_subobject = false;
        for (const auto &existing_sub : result.sub_structs) {
            const sval_t existing_end =
                existing_sub.parent_offset +
                static_cast<sval_t>(existing_sub.structure.size);
            if (delta > existing_sub.parent_offset && delta < existing_end) {
                covered_by_parent_subobject = true;
                break;
            }
        }
        if (covered_by_parent_subobject) {
            continue;
        }

        auto group_it = groups.find(delta);
        if (group_it == groups.end()) {
            continue;
        }
        auto &group = group_it->second;

        if (synth_debug_enabled()) {
            detail::synth_log("[Structor] detect_subobjects: delta=0x%llX funcs=",
                                                static_cast<unsigned long long>(delta));
            bool first_func = true;
            for (const auto &fn_pattern : group.patterns) {
                if (!first_func) {
                    detail::synth_log(", ");
                }
                first_func = false;
                detail::synth_log("%s(var=%d)",
                                                    utils::get_func_name(fn_pattern.func_ea).c_str(),
                                                    fn_pattern.var_idx);
            }
            detail::synth_log("\n");
        }

        AccessPattern sub_pattern;
        sub_pattern.func_ea = group.patterns.front().func_ea;
        sub_pattern.var_name = make_substruct_field_name(delta);
        for (const auto &fn_pattern : group.patterns) {
            if (type_has_named_udt_details(fn_pattern.original_type)) {
                sub_pattern.original_type = fn_pattern.original_type;
                break;
            }
        }
        if (!type_has_named_udt_details(sub_pattern.original_type)) {
            sub_pattern.original_type.clear();
            for (const auto &fn_pattern : group.patterns) {
                cfuncptr_t helper_cfunc = utils::get_cfunc(fn_pattern.func_ea);
                lvars_t *helper_lvars = helper_cfunc
                    ? helper_cfunc->get_lvars()
                    : nullptr;
                if (helper_lvars == nullptr || fn_pattern.var_idx < 0 ||
                    static_cast<size_t>(fn_pattern.var_idx) >=
                        helper_lvars->size()) {
                    continue;
                }

                tinfo_t helper_type =
                    helper_lvars->at(fn_pattern.var_idx).type();
                if (type_has_named_udt_details(helper_type)) {
                    sub_pattern.original_type = helper_type;
                    break;
                }
            }
        }

        for (const auto &fn_pattern : group.patterns) {
            for (const auto &access : fn_pattern.accesses) {
                sub_pattern.add_access(FieldAccess(access));
            }
        }

        if (sub_pattern.accesses.empty() ||
                static_cast<int>(sub_pattern.access_count()) < opts.min_accesses) {
            continue;
        }

        qstring suggested_type_name;
        qstring suggested_field_name;
        int sub_source_var_idx = group.patterns.front().var_idx;
        sub_pattern.var_idx = sub_source_var_idx;
        SynthesisResult sub_result;
        bool have_sub_result = false;

        if (auto recursive_seed = choose_recursive_seed(group)) {
            if (recursive_seed->func_ea == result.structure.source_func) {
                continue;
            }
            if (recursive_seed->original_type.empty() &&
                    !sub_pattern.original_type.empty()) {
                recursive_seed->original_type = sub_pattern.original_type;
            }
            sub_source_var_idx = recursive_seed->var_idx;

            suggested_type_name =
                    suggest_subobject_type_name(recursive_seed->func_ea);
            suggested_field_name =
                    suggest_subobject_field_name(recursive_seed->func_ea);

            if (synth_debug_enabled()) {
                detail::synth_log(
                        "[Structor] detect_subobjects: recursive seed=%s delta=0x%llX\n",
                        utils::get_func_name(recursive_seed->func_ea).c_str(),
                        static_cast<unsigned long long>(delta));
            }

            SynthOptions child_opts = opts;
            child_opts.propagate_to_callers = false;
            child_opts.max_propagation_depth =
                    std::max(1, child_opts.max_propagation_depth - 1);
            sub_result = recursive_sub_synth.synthesize(*recursive_seed, child_opts);
            have_sub_result = sub_result.success();
        }

        if (!have_sub_result) {
            // Recursive recovery may have selected a seed in another
            // function. Flat fallback is rooted at the front pattern, so
            // restore the function/index pair as one identity.
            sub_pattern.func_ea = group.patterns.front().func_ea;
            sub_source_var_idx = group.patterns.front().var_idx;
            sub_pattern.var_idx = sub_source_var_idx;
            if (suggested_type_name.empty()) {
                suggested_type_name = suggest_subobject_type_name(sub_pattern.func_ea);
            }
            if (suggested_field_name.empty()) {
                suggested_field_name =
                        suggest_subobject_field_name(sub_pattern.func_ea);
            }
            sub_result = flat_sub_synth.synthesize(sub_pattern, opts);
            have_sub_result = sub_result.success();
        }

        if (!have_sub_result)
            continue;

        int sub_non_padding_fields = 0;
        bool sub_has_nested_fields = false;
        for (const auto &field : sub_result.structure.fields) {
            if (field.is_padding) {
                continue;
            }
            ++sub_non_padding_fields;
            if (field.semantic == SemanticType::NestedStruct) {
                sub_has_nested_fields = true;
            }
        }
        if (!sub_has_nested_fields && sub_non_padding_fields < 2) {
            continue;
        }

        if (synth_debug_enabled()) {
            detail::synth_log("[Structor] detect_subobjects: sub_result name=%s "
                                                "size=%u fields=%zu\n",
                                                sub_result.structure.name.c_str(),
                                                sub_result.structure.size,
                                                sub_result.structure.fields.size());
        }

        if (!suggested_type_name.empty()) {
            set_adopted_name(sub_result.structure.name, sub_result.structure.naming,
                                             suggested_type_name, GeneratedNameKind::RootStruct,
                                             NameOrigin::HeuristicRole, NameConfidence::Medium,
                                             false);
        } else {
            const qstring fallback_type_name = make_substruct_type_name(
                    result.structure.name, make_substruct_field_name(delta), delta);
            set_generated_name(sub_result.structure.name, sub_result.structure.naming,
                                                 fallback_type_name, GeneratedNameKind::RootStruct,
                                                 NameConfidence::Medium);
        }

        adopt_field_names_from_original_type(sub_result.structure,
                                                                                 sub_pattern.original_type);
        adopt_field_names_from_access_contexts(sub_result.structure,
                                                                                     sub_pattern.accesses);

        qvector<FieldAccess> overlay_accesses;
        for (const auto &access : pattern.all_accesses) {
            const sval_t access_end =
                    access.offset + static_cast<sval_t>(access.size);
            if (access.offset < delta ||
                    access_end > delta + static_cast<sval_t>(sub_result.structure.size)) {
                continue;
            }

            FieldAccess rebased = access;
            rebased.offset -= delta;
            overlay_accesses.push_back(std::move(rebased));
        }
        if (!overlay_accesses.empty()) {
            apply_inner_scalar_overlay_recovery(sub_result.structure,
                                                                                    overlay_accesses);
            adopt_field_names_from_access_contexts(sub_result.structure,
                                                                                         overlay_accesses);
        }

        std::uint32_t sub_size = sub_result.structure.size;
        if (sub_size == 0)
            continue;

        bool conflict = false;
        bool retry_overlap_resolution = false;
        bool extended_sub_tail = false;
        qvector<size_t> remove_indices;
        qvector<SynthField> replacement_fields;

        do {
            retry_overlap_resolution = false;
            conflict = false;
            remove_indices.clear();
            replacement_fields.clear();

            const sval_t sub_end = delta + static_cast<sval_t>(sub_size);
            for (size_t i = 0; i < result.structure.fields.size(); ++i) {
                const auto &field = result.structure.fields[i];
                sval_t field_end = field.offset + static_cast<sval_t>(field.size);

                if (field_end <= delta || field.offset >= sub_end) {
                    continue;
                }

                bool removable = field.offset >= delta && field_end <= sub_end;

                if (!removable) {
                    bool mixed_width_sources = false;
                    bool struct_like_source = false;
                    for (const auto &access : field.source_accesses) {
                        if (access.size < field.size) {
                            mixed_width_sources = true;
                        }
                        if (!access.inferred_type.empty() &&
                                (access.inferred_type.is_struct() ||
                                 access.inferred_type.is_array())) {
                            struct_like_source = true;
                        }
                    }

                    const bool aggregate_like =
                            (!field.type.empty() &&
                             (field.type.is_struct() || field.type.is_array())) ||
                            field.semantic == SemanticType::NestedStruct ||
                            field.source_accesses.size() <= 1 || mixed_width_sources ||
                            struct_like_source;

                    if (aggregate_like) {
                        qvector<FieldAccess> leftover_accesses;
                        for (const auto &access : field.source_accesses) {
                            const sval_t access_end =
                                    access.offset + static_cast<sval_t>(access.size);
                            if (access_end <= delta || access.offset >= sub_end) {
                                if (!access_covered_by_other_fields(access, i)) {
                                    leftover_accesses.push_back(access);
                                }
                            }
                        }

                        const bool generated_boundary_cross =
                                is_generated_name(field.name, &field.naming) &&
                                field.offset < sub_end && field_end > sub_end &&
                                field.offset >= sub_end - boundary_split_slop &&
                                !leftover_accesses.empty();

                        if (generated_boundary_cross) {
                            removable = true;
                        } else {
                            const sval_t left_start = field.offset;
                            const sval_t left_end = std::min(field_end, delta);
                            const sval_t right_start = std::max(field.offset, sub_end);
                            const sval_t right_end = field_end;

                            const bool left_ok = region_covered_by_other_fields(
                                    left_start, left_end, i, &leftover_accesses);
                            const bool right_ok = region_covered_by_other_fields(
                                    right_start, right_end, i, &leftover_accesses);
                            removable = left_ok && right_ok;
                        }

                        if (!removable && !extended_sub_tail) {
                            if (auto extended_size = extend_subobject_tail_from_overlap(
                                            delta, field, sub_size);
                                    extended_size.has_value() && *extended_size > sub_size) {
                                if (synth_debug_enabled()) {
                                    detail::synth_log(
                                            "[Structor] detect_subobjects: extending delta=0x%llX "
                                            "size=%u -> %u to honor overlap boundary\n",
                                            static_cast<unsigned long long>(delta), sub_size,
                                            *extended_size);
                                }
                                sub_size = *extended_size;
                                extended_sub_tail = true;
                                retry_overlap_resolution = true;
                                break;
                            }
                        }

                        if (removable && !leftover_accesses.empty()) {
                            std::sort(leftover_accesses.begin(), leftover_accesses.end());

                            size_t pos = 0;
                            while (pos < leftover_accesses.size()) {
                                qvector<FieldAccess> group_accesses;
                                sval_t group_offset = leftover_accesses[pos].offset;
                                sval_t group_end =
                                        leftover_accesses[pos].offset +
                                        static_cast<sval_t>(leftover_accesses[pos].size);
                                group_accesses.push_back(leftover_accesses[pos]);
                                ++pos;

                                while (pos < leftover_accesses.size()) {
                                    const auto &next = leftover_accesses[pos];
                                    const sval_t next_end =
                                            next.offset + static_cast<sval_t>(next.size);
                                    if (next.offset >= group_end) {
                                        break;
                                    }

                                    group_end = std::max(group_end, next_end);
                                    group_accesses.push_back(next);
                                    ++pos;
                                }

                                SynthField replacement;
                                replacement.offset = group_offset;
                                replacement.size =
                                        static_cast<std::uint32_t>(group_end - group_offset);
                                replacement.source_accesses = group_accesses;
                                replacement.type = select_best_type(group_accesses);
                                replacement.semantic = select_best_semantic(group_accesses);
                                (void)detail::retain_array_fragment_type(field, replacement);
                                replacement.confidence = TypeConfidence::Medium;
                                replacement_fields.push_back(std::move(replacement));
                            }
                        }
                    }
                }

                if (retry_overlap_resolution) {
                    break;
                }

                if (removable) {
                    remove_indices.push_back(i);
                } else {
                    if (synth_debug_enabled()) {
                        detail::synth_log(
                                "[Structor] detect_subobjects: overlap field=%s off=0x%llX "
                                "size=%u prevents delta=0x%llX size=%u\n",
                                field.name.c_str(),
                                static_cast<unsigned long long>(field.offset), field.size,
                                static_cast<unsigned long long>(delta), sub_size);
                    }
                    conflict = true;
                    break;
                }
            }
        } while (retry_overlap_resolution);

        if (conflict) {
            if (synth_debug_enabled()) {
                detail::synth_log("[Structor] detect_subobjects: rejected delta=0x%llX "
                                                    "due to overlap conflict\n",
                                                    static_cast<unsigned long long>(delta));
            }
            continue;
        }

        // Remove in reverse order to keep indices valid
        for (size_t idx = remove_indices.size(); idx > 0; --idx) {
            size_t remove_idx = remove_indices[idx - 1];
            result.structure.fields.erase(result.structure.fields.begin() +
                                                                        static_cast<sval_t>(remove_idx));
        }

        for (auto &replacement : replacement_fields) {
            result.structure.fields.push_back(std::move(replacement));
        }

        SynthField sub_field;
        sub_field.offset = delta;
        sub_field.size = sub_size;
        sub_field.semantic = SemanticType::NestedStruct;
        sub_field.confidence = TypeConfidence::Medium;
        if (!suggested_field_name.empty() &&
                !is_placeholder_identifier(suggested_field_name)) {
            set_adopted_name(sub_field.name, sub_field.naming, suggested_field_name,
                                             GeneratedNameKind::SubStructField,
                                             NameOrigin::HeuristicRole, NameConfidence::Medium,
                                             false);
        } else {
            set_generated_name(
                    sub_field.name, sub_field.naming, make_substruct_field_name(delta),
                    GeneratedNameKind::SubStructField, NameConfidence::Medium);
        }

        result.structure.fields.push_back(sub_field);

        if (sub_result.structure.size < sub_size) {
            sub_result.structure.size = sub_size;
        }

        SubStructInfo info;
        info.structure = std::move(sub_result.structure);
        info.parent_offset = delta;
        info.source_var_idx = sub_source_var_idx;
        if (info.structure.source_func != BADADDR && sub_source_var_idx >= 0) {
            cfuncptr_t source_cfunc =
                utils::get_cfunc(info.structure.source_func);
            lvars_t* source_lvars = source_cfunc
                ? source_cfunc->get_lvars()
                : nullptr;
            if (source_lvars != nullptr &&
                static_cast<size_t>(sub_source_var_idx) < source_lvars->size()) {
                info.source_locator = static_cast<const lvar_locator_t&>(
                    source_lvars->at(
                        static_cast<size_t>(sub_source_var_idx)));
            }
        }
        info.field_name = sub_field.name;
        info.field_naming = sub_field.naming;
        info.children = std::move(sub_result.sub_structs);
        result.sub_structs.push_back(std::move(info));

        if (synth_debug_enabled()) {
            detail::synth_log("[Structor] detect_subobjects: accepted delta=0x%llX "
                                                "field=%s type=%s size=%u\n",
                                                static_cast<unsigned long long>(delta),
                                                sub_field.name.c_str(),
                                                sub_result.structure.name.c_str(), sub_size);
        }
    }

    const qvector<SubStructInfo> explicit_sub_structs = result.sub_structs;

    // Reuse the same recovered child layout for sibling windows of equal
    // size after all explicit flow-edge-derived children have been attempted.
    for (const auto &existing_sub : explicit_sub_structs) {
        const std::uint32_t sub_size = existing_sub.structure.size;
        if (sub_size == 0) {
            continue;
        }

        int non_padding_fields = 0;
        bool has_nested_fields = false;
        for (const auto &field : existing_sub.structure.fields) {
            if (field.is_padding) {
                continue;
            }
            ++non_padding_fields;
            if (field.semantic == SemanticType::NestedStruct) {
                has_nested_fields = true;
            }
        }
        if (!has_nested_fields && non_padding_fields < 2) {
            continue;
        }

        for (auto &field : result.structure.fields) {
            if (field.offset == existing_sub.parent_offset || field.is_padding ||
                    field.is_array || field.is_union_candidate) {
                continue;
            }
            if (field.size != sub_size ||
                    field.semantic == SemanticType::NestedStruct) {
                continue;
            }

            bool already_present = false;
            for (const auto &sub : result.sub_structs) {
                if (sub.parent_offset == field.offset) {
                    already_present = true;
                    break;
                }
            }
            if (already_present) {
                continue;
            }

            int covered_accesses = 0;
            bool has_whole_region_access = false;
            const sval_t sibling_end = field.offset + static_cast<sval_t>(field.size);
            for (const auto &access : pattern.all_accesses) {
                const sval_t access_end =
                        access.offset + static_cast<sval_t>(access.size);
                if (access.offset >= field.offset && access_end <= sibling_end) {
                    ++covered_accesses;
                    if (access.offset == field.offset && access.size == field.size) {
                        has_whole_region_access = true;
                    }
                }
            }

            if (covered_accesses < opts.min_accesses && !has_whole_region_access) {
                continue;
            }

            field.semantic = SemanticType::NestedStruct;
            set_generated_name(
                    field.name, field.naming, make_substruct_field_name(field.offset),
                    GeneratedNameKind::SubStructField, NameConfidence::Medium);

            SubStructInfo sibling = existing_sub;
            sibling.parent_offset = field.offset;
            sibling.field_name = field.name;
            sibling.field_naming = field.naming;
            result.sub_structs.push_back(std::move(sibling));
        }
    }

    auto field_has_local_write = [&](const SynthField &field) {
        for (const auto &access : field.source_accesses) {
            if (access.source_func_ea != result.structure.source_func) {
                continue;
            }
            if (access.access_type == AccessType::Write ||
                    access.access_type == AccessType::ReadWrite) {
                return true;
            }
        }
        return false;
    };

    auto field_is_inline_anchor = [&](const SynthField &field) {
        if (field.is_padding || field.is_array || field.is_union_candidate ||
                field.is_bitfield || field.semantic == SemanticType::NestedStruct) {
            return false;
        }
        if (field.offset <= 0 || field.size != get_ptr_size()) {
            return false;
        }
        return field_has_local_write(field);
    };

    auto make_inline_window_substruct =
            [&](const qvector<SynthField> &window_fields, sval_t start,
                    sval_t end) -> std::optional<SubStructInfo> {
        if (window_fields.empty() || start >= end) {
            return std::nullopt;
        }

        int non_padding_fields = 0;
        int locally_written_fields = 0;
        qvector<FieldAccess> window_accesses;

        SynthStruct child;
        child.alignment = result.structure.alignment;
        child.source_func = result.structure.source_func;
        child.add_provenance(result.structure.source_func);

        for (const auto &original : window_fields) {
            SynthField copied = original;
            const sval_t old_offset = copied.offset;
            copied.offset -= start;
            for (auto &access : copied.source_accesses) {
                access.offset -= start;
                window_accesses.push_back(access);
            }
            rebase_field_name(copied, old_offset);
            child.fields.push_back(std::move(copied));

            if (!original.is_padding) {
                ++non_padding_fields;
                if (field_has_local_write(original)) {
                    ++locally_written_fields;
                }
            }
        }

        if (non_padding_fields < 2 || locally_written_fields < 2) {
            return std::nullopt;
        }

        child.size = static_cast<std::uint32_t>(end - start);
        qstring field_name = make_substruct_field_name(start);
        qstring inferred_stem;

    for (const auto &access : window_accesses) {
      if (access.access_type == AccessType::Write &&
          !access.observed_constants.empty()) {
        for (auto val : access.observed_constants) {
          qstring name;
          if (get_name(&name, static_cast<ea_t>(val)) > 0 && !name.empty()) {
            qstring stem = normalize_symbolic_stem(name);
            if (!stem.empty() && !is_placeholder_identifier(stem)) {
              if (starts_with_text(stem, "vftable_")) {
                stem = qstring(stem.c_str() + strlen("vftable_"));
              }
                            if (starts_with_text(stem, "off_") ||
                                    starts_with_text(stem, "unk_")) {
                                continue;
                            }
                            if (starts_with_text(stem, "s_") && stem.length() > 2) {
                                stem = qstring(stem.c_str() + 2);
                            } else if (starts_with_text(stem, "c_") && stem.length() > 2) {
                                stem = qstring(stem.c_str() + 2);
                            }
                            inferred_stem = stem;
                            break;
                        }
                    }
                }
            }
            if (!inferred_stem.empty())
                break;
    }

    if (!inferred_stem.empty()) {
      field_name = inferred_stem;
    }

        qstring type_name;
        if (!inferred_stem.empty()) {
            type_name.sprnt("auto_%s", inferred_stem.c_str());
        } else {
            type_name = make_substruct_type_name(
                    result.structure.name, field_name, start);
        }

        set_generated_name(
                child.name, child.naming, type_name, GeneratedNameKind::RootStruct,
                inferred_stem.empty() ? NameConfidence::Medium : NameConfidence::High);

        apply_inner_scalar_overlay_recovery(child, window_accesses);
        adopt_field_names_from_access_contexts(child, window_accesses);
        generate_field_names(child);
        compute_struct_size(child);
        if (child.size < static_cast<std::uint32_t>(end - start)) {
            child.size = static_cast<std::uint32_t>(end - start);
        }

        SubStructInfo info;
        info.structure = std::move(child);
        info.parent_offset = start;
        set_generated_name(info.field_name, info.field_naming, field_name,
                                             GeneratedNameKind::SubStructField,
                                             inferred_stem.empty() ? NameConfidence::Medium
                                                                                         : NameConfidence::High);
        return info;
    };

    {
        qvector<SynthField> sorted_fields = result.structure.fields;
        std::sort(sorted_fields.begin(), sorted_fields.end(),
                            [](const SynthField &a, const SynthField &b) {
                                if (a.offset != b.offset)
                                    return a.offset < b.offset;
                                if (a.is_bitfield != b.is_bitfield)
                                    return a.is_bitfield;
                                return a.bit_offset < b.bit_offset;
                            });

        qvector<SynthField> rebuilt_fields;
        qvector<SubStructInfo> inline_sub_structs;

        size_t index = 0;
        while (index < sorted_fields.size()) {
            if (sorted_fields[index].semantic == SemanticType::NestedStruct) {
                rebuilt_fields.push_back(sorted_fields[index]);
                ++index;
                continue;
            }

            const size_t run_start = index;
            while (index < sorted_fields.size() &&
                         sorted_fields[index].semantic != SemanticType::NestedStruct) {
                ++index;
            }
            const size_t run_end = index;

            qvector<size_t> anchors;
            for (size_t i = run_start; i < run_end; ++i) {
                if (field_is_inline_anchor(sorted_fields[i])) {
                    anchors.push_back(i);
                }
            }

            if (anchors.size() < 2) {
                for (size_t i = run_start; i < run_end; ++i) {
                    rebuilt_fields.push_back(sorted_fields[i]);
                }
                continue;
            }

            qvector<SubStructInfo> run_subs;
            bool valid_run = true;
            for (size_t anchor_idx = 0; anchor_idx < anchors.size(); ++anchor_idx) {
                const size_t first = anchors[anchor_idx];
                const size_t limit =
                        anchor_idx + 1 < anchors.size() ? anchors[anchor_idx + 1] : run_end;
                const sval_t window_start = sorted_fields[first].offset;
                const SynthField &last_field = sorted_fields[limit - 1];
                const sval_t window_end =
                        anchor_idx + 1 < anchors.size()
                                ? sorted_fields[anchors[anchor_idx + 1]].offset
                                : last_field.offset + static_cast<sval_t>(last_field.size);

                qvector<SynthField> window_fields;
                for (size_t i = first; i < limit; ++i) {
                    window_fields.push_back(sorted_fields[i]);
                }

                auto maybe_sub = make_inline_window_substruct(window_fields,
                                                                                                            window_start, window_end);
                if (!maybe_sub.has_value()) {
                    valid_run = false;
                    break;
                }
                run_subs.push_back(std::move(*maybe_sub));
            }

            if (!valid_run || run_subs.size() < 2) {
                for (size_t i = run_start; i < run_end; ++i) {
                    rebuilt_fields.push_back(sorted_fields[i]);
                }
                continue;
            }

            for (size_t i = run_start; i < anchors.front(); ++i) {
                rebuilt_fields.push_back(sorted_fields[i]);
            }

            for (auto &sub : run_subs) {
                SynthField nested;
                nested.offset = sub.parent_offset;
                nested.size = sub.structure.size;
                nested.semantic = SemanticType::NestedStruct;
                nested.confidence = TypeConfidence::Medium;
                nested.name = sub.field_name;
                nested.naming = sub.field_naming;
                rebuilt_fields.push_back(std::move(nested));
                inline_sub_structs.push_back(std::move(sub));
            }
        }

        if (!inline_sub_structs.empty()) {
            result.structure.fields = std::move(rebuilt_fields);
            for (auto &sub : inline_sub_structs) {
                result.sub_structs.push_back(std::move(sub));
            }
        }
    }

    if (!result.structure.fields.empty()) {
        const AccessPattern *source_pattern = nullptr;
        for (const auto &fn_pattern : pattern.per_function_patterns) {
            if (fn_pattern.func_ea == result.structure.source_func) {
                source_pattern = &fn_pattern;
                break;
            }
        }

        if (source_pattern) {
            sval_t first_field_offset = result.structure.fields.front().offset;
            for (const auto &field : result.structure.fields) {
                first_field_offset = std::min(first_field_offset, field.offset);
            }

            qvector<FieldAccess> prefix_accesses;
            for (const auto &access : source_pattern->accesses) {
                const sval_t access_end =
                        access.offset + static_cast<sval_t>(access.size);
                if (access_end > first_field_offset) {
                    continue;
                }
                if (!field_covers_access(access)) {
                    prefix_accesses.push_back(access);
                }
            }

            if (!prefix_accesses.empty()) {
                std::sort(prefix_accesses.begin(), prefix_accesses.end());

                size_t pos = 0;
                while (pos < prefix_accesses.size()) {
                    qvector<FieldAccess> group_accesses;
                    sval_t group_offset = prefix_accesses[pos].offset;
                    sval_t group_end = prefix_accesses[pos].offset +
                                                         static_cast<sval_t>(prefix_accesses[pos].size);
                    group_accesses.push_back(prefix_accesses[pos]);
                    ++pos;

                    while (pos < prefix_accesses.size()) {
                        const auto &next = prefix_accesses[pos];
                        if (next.offset > group_end) {
                            break;
                        }

                        group_end = std::max(group_end,
                                                                 next.offset + static_cast<sval_t>(next.size));
                        group_accesses.push_back(next);
                        ++pos;
                    }

                    SynthField prefix_field;
                    prefix_field.offset = group_offset;
                    prefix_field.size =
                            static_cast<std::uint32_t>(group_end - group_offset);
                    prefix_field.source_accesses = group_accesses;
                    prefix_field.type = select_best_type(group_accesses);
                    prefix_field.semantic = select_best_semantic(group_accesses);
                    prefix_field.confidence = TypeConfidence::Medium;
                    set_generated_name(prefix_field.name, prefix_field.naming,
                                                         generate_field_name(prefix_field.offset,
                                                                                                 prefix_field.semantic,
                                                                                                 prefix_field.size),
                                                         GeneratedNameKind::Field, NameConfidence::Medium);
                    result.structure.fields.push_back(std::move(prefix_field));
                }
            }
        }
    }

    generate_field_names(result.structure);

    std::sort(result.structure.fields.begin(), result.structure.fields.end(),
                        [](const SynthField &a, const SynthField &b) {
                            if (a.offset != b.offset)
                                return a.offset < b.offset;
                            if (a.is_bitfield != b.is_bitfield)
                                return a.is_bitfield;
                            return a.bit_offset < b.bit_offset;
                        });

    compute_struct_size(result.structure);
}

tinfo_t
LayoutSynthesizer::select_best_type(const qvector<FieldAccess> &accesses) {
    tinfo_t best;
    uint32_t widest_size = 0;
    const FieldAccess *widest_access = nullptr;

    for (const auto &access : accesses) {
        if (access.size > widest_size) {
            widest_size = access.size;
            widest_access = &access;
        }

        if (access.inferred_type.empty())
            continue;

        if (best.empty()) {
            best = access.inferred_type;
            continue;
        }

        best = resolve_type_conflict(best, access.inferred_type);
    }

    if (!best.empty()) {
        const size_t best_size = best.get_size();
        const bool scalar_like = !best.is_array() && !best.is_struct() &&
                                                         !best.is_union() && !best.is_func();
        if (scalar_like && best_size != BADSIZE && widest_size > 0 &&
                best_size < widest_size && widest_access) {
            tinfo_t widened = make_scalar_type_for_access(*widest_access);
            if (!widened.empty()) {
                best = widened;
            }
        }
    }

    if (best.empty() && widest_access) {
        best = make_scalar_type_for_access(*widest_access);
    }

    return best;
}

SemanticType
LayoutSynthesizer::select_best_semantic(const qvector<FieldAccess> &accesses) {
    SemanticType best = SemanticType::Unknown;
    int best_priority = 0;

    for (const auto &access : accesses) {
        int priority = semantic_priority(access.semantic_type);
        if (priority > best_priority) {
            best_priority = priority;
            best = access.semantic_type;
        }
    }

    return best;
}

z3::Z3Config LayoutSynthesizer::make_z3_config() const {
    z3::Z3Config cfg;
    cfg.timeout_ms = config_.z3_timeout_ms;
    cfg.max_memory_mb = config_.z3_memory_mb;
    cfg.produce_unsat_cores = config_.enable_unsat_core;
    cfg.pointer_size = get_ptr_size();
    cfg.default_alignment = config_.default_alignment;
    cfg.max_struct_size = config_.max_struct_size;
    cfg.max_candidates = config_.max_candidates;
    cfg.max_fields = config_.max_fields;
    cfg.max_array_elements = config_.max_array_elements;
    return cfg;
}

z3::LayoutConstraintConfig LayoutSynthesizer::make_layout_config() const {
    z3::LayoutConstraintConfig cfg;
    cfg.default_alignment = config_.default_alignment;
    cfg.model_packing = config_.infer_packing;
    cfg.allow_unions = config_.create_unions;
    cfg.detect_arrays = config_.detect_arrays;
    cfg.min_array_elements = config_.min_array_elements;
    cfg.detect_symbolic_arrays = config_.detect_symbolic_arrays;
    cfg.max_array_stride = config_.max_array_stride;
    cfg.max_union_alternatives = config_.max_union_alternatives;
    cfg.weight_coverage = config_.weight_coverage;
    cfg.weight_type_consistency = config_.weight_type_consistency;
    cfg.weight_alignment = config_.weight_alignment;
    cfg.weight_minimize_fields = config_.weight_minimize_fields;
    cfg.weight_minimize_padding = config_.weight_minimize_padding;
    cfg.weight_prefer_non_union = config_.weight_prefer_non_union;
    cfg.weight_prefer_arrays = config_.weight_prefer_arrays;
    cfg.max_struct_size = config_.max_struct_size;
    cfg.max_accesses = config_.max_accesses;
    cfg.max_candidates = config_.max_candidates;
    cfg.max_fields = config_.max_fields;
    cfg.max_array_elements = config_.max_array_elements;
    cfg.max_constraint_pairs = config_.max_constraint_pairs;
    cfg.enable_maxsmt = config_.enable_maxsmt;
    cfg.relax_on_unsat = config_.relax_on_unsat;
    cfg.max_relaxation_iterations = config_.max_relaxation_iterations;
    return cfg;
}

z3::CandidateGenerationConfig LayoutSynthesizer::make_candidate_config() const {
    z3::CandidateGenerationConfig cfg;
    cfg.generate_array_candidates = config_.detect_arrays;
    cfg.min_array_elements = config_.min_array_elements;
    cfg.detect_symbolic_arrays = config_.detect_symbolic_arrays;
    cfg.max_array_stride = config_.max_array_stride;
    cfg.max_accesses = config_.max_accesses;
    cfg.max_candidates = config_.max_candidates;
    cfg.max_array_elements = config_.max_array_elements;
    cfg.max_structure_size = config_.max_struct_size;
    cfg.min_confidence_percent = config_.min_confidence_percent;
    return cfg;
}

SynthesisResult
LayoutSynthesizer::synthesize_with_type_inference(cfunc_t *cfunc, int var_idx,
                                                                                                    const SynthOptions &opts) {
    SynthesisResult result;
    last_type_inference_.reset();

    if (!cfunc) {
        result.error = SynthError::InvalidVariable;
        result.error_message = "null cfunc";
        return result;
    }

    if (!config_.use_type_inference ||
        !config_.type_inference_config.enable_experimental_pipeline) {
        result.error = SynthError::ExperimentalFeatureDisabled;
        result.error_message =
            "experimental type inference requires explicit opt-in through both "
            "LayoutSynthConfig::use_type_inference and "
            "TypeInferenceConfig::enable_experimental_pipeline";
        return result;
    }

    if (config_.z3_memory_mb != 0 &&
        (config_.enable_maxsmt || config_.use_type_inference)) {
        return resource_limit_result(
            ResourceLimitKind::SolverMemory,
            config_.z3_memory_mb,
            0,
            "solver_configuration",
            "configured per-instance memory limit is unavailable for an enabled optimizer");
    }

    auto start_time = std::chrono::steady_clock::now();

    // Step 1: Run the explicitly enabled experimental type inference adjunct.
    detail::synth_log("[Structor] Running experimental type inference for function 0x%llX...\n",
                      static_cast<unsigned long long>(cfunc->entry_ea));

    z3::Z3Config z3_config = make_z3_config();
    z3_ctx_ = std::make_unique<z3::Z3Context>(z3_config);

    z3::TypeInferenceEngine engine(*z3_ctx_, config_.type_inference_config);
    z3::FunctionTypeInferenceResult infer_result = engine.infer_function(cfunc);

    if (!infer_result.success) {
        detail::synth_log("[Structor] Experimental type inference failed: %s\n",
                                            infer_result.error_message.c_str());
        result.error = SynthError::InternalError;
        result.error_message = infer_result.error_message;
        return result;
    }

    detail::synth_log(
            "[Structor] Experimental type inference completed: %zu variables typed\n",
            infer_result.local_types.size());
    last_type_inference_ = std::move(infer_result);

    // Step 2: Collect access pattern for the variable
    AccessCollector collector;
    AccessPattern pattern = collector.collect(cfunc, var_idx);

    if (pattern.accesses.empty()) {
        detail::synth_log("[Structor] No accesses found for variable %d\n",
                                            var_idx);
        result.error = SynthError::NoAccessesFound;
        result.error_message = "no dereferences found for variable";
        return result;
    }

    // The adjunct's memory records use absolute data origins. The selected
    // local pointer has no established absolute value here, so those records
    // cannot refine its relative field offsets. A function EA is not a data
    // origin for the selected pointer.

    // Step 3: Run structure synthesis
    result = synthesize(pattern, opts);

    auto end_time = std::chrono::steady_clock::now();
    result.synthesis_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time);

    return result;
}

z3::TypeApplicationResult
LayoutSynthesizer::apply_synthesis_result(cfunc_t *cfunc, int var_idx,
                                                                                    const SynthesisResult &result) {
    z3::TypeApplicationResult app_result;

    if (!cfunc || result.structure.fields.empty()) {
        return app_result;
    }

    // Step 1: Create and persist the synthesized structure
    StructurePersistence persistence;
    auto persistence_transaction = persistence.begin_transaction();
    if (!persistence_transaction.has_value()) {
        detail::synth_log("[Structor] Failed to begin persistence transaction\n");
        return app_result;
    }
    SynthStruct synth_copy =
            result.structure; // create_struct may modify the name
    qvector<SubStructInfo> sub_structs = result.sub_structs;
    tid_t struct_tid =
            sub_structs.empty()
                    ? persistence.create_struct(synth_copy)
                    : persistence.create_struct_with_substructs(synth_copy, sub_structs);

    if (struct_tid == BADADDR) {
        const bool rollback_succeeded = persistence_transaction->rollback();
        detail::synth_log("[Structor] Failed to create structure in IDA\n");
        if (!rollback_succeeded) {
            detail::synth_log(
                "[Structor] CRITICAL: persistence transaction rollback failed\n");
        }
        return app_result;
    }

    detail::synth_log("[Structor] Created structure '%s' with tid 0x%llX\n",
                      synth_copy.name.c_str(),
                      static_cast<unsigned long long>(struct_tid));

    // Step 2: Create pointer type to the struct
    tinfo_t struct_type;
    if (!struct_type.get_type_by_tid(struct_tid)) {
        const bool rollback_succeeded = persistence_transaction->rollback();
        detail::synth_log("[Structor] Failed to reload persisted structure type\n");
        if (!rollback_succeeded) {
            detail::synth_log(
                "[Structor] CRITICAL: persistence transaction rollback failed\n");
        }
        return app_result;
    }

    tinfo_t ptr_type;
    ptr_type.create_ptr(struct_type);

    // Step 3: Apply the struct pointer type to the variable
    z3::TypeApplicator applicator(config_.type_application_config);

    // Create an InferredType for the struct pointer
    z3::InferredType inferred_ptr =
            z3::InferredType::make_ptr(z3::InferredType::make_struct(struct_tid));

    // Construct and reserve all required result state before mutating the lvar
    // or committing named types. Once commit succeeds, no allocation failure
    // may translate durable success into an empty/error result.
    app_result.applied.reserve(1);
    app_result.failed.reserve(1);
    app_result.propagation.sites.reserve(MAX_FIELDS);
    app_result.total_variables = 1;
    const ea_t source_func_ea = cfunc->entry_ea;
    std::optional<lvar_locator_t> source_locator;
    std::vector<std::optional<lvar_locator_t>> inferred_locators;
    z3::TypeApplicationResult::AppliedType applied_record;
    applied_record.var_idx = var_idx;
    applied_record.inferred = inferred_ptr;
    applied_record.applied = ptr_type;
    applied_record.confidence = z3::TypeConfidence::High;
    z3::TypeApplicationResult::FailedType failed_record;
    failed_record.var_idx = var_idx;
    failed_record.inferred = inferred_ptr;
    if (lvars_t* lvars = cfunc->get_lvars(); lvars != nullptr &&
        var_idx >= 0 && static_cast<size_t>(var_idx) < lvars->size()) {
        source_locator = static_cast<const lvar_locator_t&>(
            lvars->at(static_cast<size_t>(var_idx)));
        applied_record.var_name = lvars->at(var_idx).name;
        failed_record.var_name = applied_record.var_name;
        if (last_type_inference_.has_value()) {
            inferred_locators.reserve(
                last_type_inference_->local_types.size());
            for (const auto& inferred : last_type_inference_->local_types) {
                if (inferred.var_idx >= 0 &&
                    static_cast<size_t>(inferred.var_idx) < lvars->size()) {
                    inferred_locators.emplace_back(
                        static_cast<const lvar_locator_t&>(
                            lvars->at(static_cast<size_t>(inferred.var_idx))));
                } else {
                    inferred_locators.emplace_back(std::nullopt);
                }
            }
        }
    }

    qstring reason;
    tinfo_t prior_var_type;
    if (lvars_t* lvars = cfunc->get_lvars(); lvars != nullptr &&
        var_idx >= 0 && static_cast<size_t>(var_idx) < lvars->size()) {
        prior_var_type = lvars->at(var_idx).type();
    }
    const bool inject_apply_failure =
        persistence_invariants::persistence_fault_requested(
            "required_source_apply");
    bool applied = !inject_apply_failure &&
        applicator.apply_variable(cfunc, var_idx, inferred_ptr,
                                  z3::TypeConfidence::High, &reason);

    if (applied && !persistence_transaction->commit()) {
        TypePropagator restorer;
        cfuncptr_t restore_cfunc = utils::get_cfunc(source_func_ea);
        int restore_var_idx = -1;
        if (restore_cfunc && source_locator.has_value()) {
            lvars_t* restore_lvars = restore_cfunc->get_lvars();
            if (restore_lvars != nullptr &&
                restore_lvars->find(*source_locator) != nullptr) {
                for (size_t i = 0; i < restore_lvars->size(); ++i) {
                    if (static_cast<const lvar_locator_t&>(
                            restore_lvars->at(i)) == *source_locator) {
                        restore_var_idx = static_cast<int>(i);
                        break;
                    }
                }
            }
        }
        const bool restored = restore_cfunc && restore_var_idx >= 0 &&
            !prior_var_type.empty() && restorer.apply_exact_type(
                restore_cfunc, restore_var_idx, prior_var_type);
        applied = false;
        reason = restored
            ? "persistence commit failed; prior variable type restored"
            : "persistence commit failed and prior variable type could not be restored";
    }

    if (applied) {
        app_result.applied.push_back(std::move(applied_record));
        app_result.applied_count++;

        detail::synth_log("[Structor] Applied struct type to variable %d\n",
                                            var_idx);
    } else {
        bool rollback_succeeded = true;
        if (persistence_transaction->active()) {
            if (!inject_apply_failure &&
                applicator.last_application_rollback_failed()) {
                qstring retained_reason = reason;
                qstring retention_failed_reason = reason;
                if (!retained_reason.empty()) {
                    retained_reason.append("; ");
                    retention_failed_reason.append("; ");
                }
                retained_reason.append(
                    "persisted types retained because lvar rollback failed");
                retention_failed_reason.append(
                    "failed to retain persisted types after lvar rollback failure; "
                    "persistence transaction rollback failed");
                rollback_succeeded = persistence_transaction->commit();
                reason.swap(rollback_succeeded
                    ? retained_reason
                    : retention_failed_reason);
            } else {
                qstring rollback_failed_reason = reason;
                if (!rollback_failed_reason.empty()) {
                    rollback_failed_reason.append("; ");
                }
                rollback_failed_reason.append(
                    "persistence transaction rollback failed");
                rollback_succeeded = persistence_transaction->rollback();
                if (!rollback_succeeded) {
                    reason.swap(rollback_failed_reason);
                }
            }
        }
        failed_record.reason = std::move(reason);
        app_result.failed.push_back(std::move(failed_record));
        app_result.failed_count++;

        detail::synth_log("[Structor] Failed to apply type: %s\n",
                          app_result.failed.back().reason.c_str());
        if (!rollback_succeeded) {
            detail::synth_log(
                "[Structor] CRITICAL: persistence transaction rollback failed\n");
        }
    }

    // Step 4: Apply any additional inferred types if we have type inference
    // results
    try {
    if (applied && config_.apply_inferred_types && last_type_inference_.has_value()) {
        cfuncptr_t infer_cfunc = utils::get_cfunc(source_func_ea);
        if (!infer_cfunc) {
            throw std::runtime_error(
                "failed to re-decompile before inferred-type application");
        }
        z3::FunctionTypeInferenceResult remapped_inference =
            *last_type_inference_;
        lvars_t* infer_lvars = infer_cfunc->get_lvars();
        for (size_t i = 0; i < remapped_inference.local_types.size(); ++i) {
            int resolved_idx = -1;
            if (infer_lvars != nullptr && i < inferred_locators.size() &&
                inferred_locators[i].has_value() &&
                infer_lvars->find(*inferred_locators[i]) != nullptr) {
                for (size_t current = 0; current < infer_lvars->size(); ++current) {
                    if (static_cast<const lvar_locator_t&>(
                            infer_lvars->at(current)) == *inferred_locators[i]) {
                        resolved_idx = static_cast<int>(current);
                        break;
                    }
                }
            }
            remapped_inference.local_types[i].var_idx = resolved_idx;
        }
        qvector<z3::InferredVariableType> non_source_inference;
        non_source_inference.reserve(remapped_inference.local_types.size());
        for (size_t i = 0; i < remapped_inference.local_types.size(); ++i) {
            const bool is_source = source_locator.has_value() &&
                i < inferred_locators.size() &&
                inferred_locators[i].has_value() &&
                *inferred_locators[i] == *source_locator;
            if (!is_source) {
                non_source_inference.push_back(
                    std::move(remapped_inference.local_types[i]));
            }
        }
        remapped_inference.local_types = std::move(non_source_inference);
        app_result.total_variables += static_cast<unsigned>(
            remapped_inference.local_types.size());
        z3::TypeApplicationResult infer_app = z3::apply_inferred_types(
                infer_cfunc, remapped_inference,
                config_.type_application_config);

        // Merge results (skip the variable we just typed)
        for (auto &at : infer_app.applied) {
            app_result.applied.push_back(std::move(at));
            app_result.applied_count++;
        }
        for (auto &ft : infer_app.failed) {
            app_result.failed.push_back(std::move(ft));
            app_result.failed_count++;
        }
        for (auto &st : infer_app.skipped) {
            app_result.skipped.push_back(std::move(st));
            app_result.skipped_count++;
        }
        app_result.signature_requested =
            app_result.signature_requested || infer_app.signature_requested;
        app_result.signature_applied =
            app_result.signature_applied || infer_app.signature_applied;
        app_result.signature_failed =
            app_result.signature_failed || infer_app.signature_failed;
        app_result.signature_rollback_failed =
            app_result.signature_rollback_failed ||
            infer_app.signature_rollback_failed;
        app_result.incomplete = app_result.incomplete || infer_app.incomplete;
        if (app_result.error_message.empty() &&
            !infer_app.error_message.empty()) {
            app_result.error_message = infer_app.error_message;
        }
        for (auto& site : infer_app.propagation.sites) {
            if (!app_result.propagation.can_record_site()) {
                app_result.propagation.mark_incomplete(
                    "combined propagation site limit exceeded");
                app_result.incomplete = true;
                break;
            }
            app_result.propagation.sites.push_back(std::move(site));
        }
        app_result.propagation.success_count +=
            infer_app.propagation.success_count;
        app_result.propagation.failure_count +=
            infer_app.propagation.failure_count;
        if (infer_app.propagation.incomplete) {
            app_result.propagation.mark_incomplete(
                infer_app.propagation.error_message.empty()
                    ? "nested inferred-type propagation incomplete"
                    : infer_app.propagation.error_message.c_str());
            app_result.incomplete = true;
        }
        app_result.propagated_count += infer_app.propagated_count;
    }
    } catch (...) {
        app_result.incomplete = true;
        try {
            if (app_result.error_message.empty()) {
                app_result.error_message =
                    "optional inferred-type application raised";
            }
        } catch (...) {}
        detail::synth_log(
            "[Structor] Optional post-commit inferred-type application failed\n");
    }

    // Step 5: Propagate types if configured
    if (config_.type_application_config.propagate_types && applied) {
        cfuncptr_t propagation_cfunc = utils::get_cfunc(source_func_ea);
        int propagation_var_idx = -1;
        if (propagation_cfunc && source_locator.has_value()) {
            lvars_t* propagation_lvars = propagation_cfunc->get_lvars();
            if (propagation_lvars != nullptr &&
                propagation_lvars->find(*source_locator) != nullptr) {
                for (size_t i = 0; i < propagation_lvars->size(); ++i) {
                    if (static_cast<const lvar_locator_t&>(
                            propagation_lvars->at(i)) == *source_locator) {
                        propagation_var_idx = static_cast<int>(i);
                        break;
                    }
                }
            }
        }
        if (!propagation_cfunc || propagation_var_idx < 0) {
            app_result.incomplete = true;
            app_result.error_message =
                "source locator no longer resolves before propagation";
            return app_result;
        }
        TypePropagator propagator;
        PropagationResult prop = propagator.propagate(
                source_func_ea, propagation_var_idx,
                ptr_type, PropagationDirection::Both);

        for (auto& site : prop.sites) {
            if (!app_result.propagation.can_record_site()) {
                app_result.propagation.mark_incomplete(
                    "combined propagation site limit exceeded");
                app_result.incomplete = true;
                break;
            }
            app_result.propagation.sites.push_back(std::move(site));
        }
        app_result.propagation.success_count += prop.success_count;
        app_result.propagation.failure_count += prop.failure_count;
        app_result.propagated_count += prop.success_count;
        if (prop.incomplete) {
            app_result.propagation.mark_incomplete(
                prop.error_message.empty()
                    ? "source propagation incomplete"
                    : prop.error_message.c_str());
            app_result.incomplete = true;
        }

        if (prop.success_count > 0) {
            detail::synth_log("[Structor] Propagated type to %d locations\n",
                                                prop.success_count);
        }
    }

    // Step 6: Refresh decompiler
    if (cfuncptr_t refresh_cfunc = utils::get_cfunc(source_func_ea)) {
        applicator.refresh_decompiler(refresh_cfunc);
    }

    return app_result;
}

} // namespace structor
