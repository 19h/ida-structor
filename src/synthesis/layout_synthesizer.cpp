/// @file layout_synthesizer.cpp
/// @brief Structure layout synthesis implementation

#include <structor/layout_synthesizer.hpp>
#include <structor/naming.hpp>

#include <string>

namespace structor {

namespace {

bool is_generated_padding_name(const qstring& name) {
    return name.find("__pad_") == 0;
}

bool ends_with_text(const qstring& value, const char* suffix) {
    const size_t value_len = value.length();
    const size_t suffix_len = strlen(suffix);
    if (suffix_len > value_len) {
        return false;
    }

    return strcmp(value.c_str() + value_len - suffix_len, suffix) == 0;
}

qstring qstring_slice(const char* text, size_t len) {
    std::string tmp(text, len);
    qstring out;
    out = tmp.c_str();
    return out;
}

qstring erase_suffix(const qstring& value, size_t suffix_len) {
    std::string tmp = value.c_str();
    tmp.erase(tmp.size() - suffix_len, suffix_len);
    qstring out;
    out = tmp.c_str();
    return out;
}

qstring suggest_subobject_stem(ea_t func_ea) {
    qstring func_name = utils::get_func_name(func_ea);
    if (func_name.empty() || is_placeholder_identifier(func_name)) {
        return qstring();
    }

    const char* raw = func_name.c_str();
    const char* scope = strstr(raw, "::");
    qstring stem_source;
    bool member_owner = false;
    if (scope != nullptr && scope != raw) {
        stem_source = qstring_slice(raw, static_cast<size_t>(scope - raw));
        member_owner = true;
    } else {
        stem_source = func_name;
    }

    qstring stem = sanitize_identifier(stem_source, "");
    if (stem.empty()) {
        return qstring();
    }

    bool recognized_factory = member_owner;
    constexpr const char* kFactorySuffixes[] = {
        "_copy_params",
        "_copyparams",
        "_constructor",
        "_construct",
        "_ctor",
        "_init",
        "_copy",
    };
    for (const char* suffix : kFactorySuffixes) {
        if (!ends_with_text(stem, suffix)) {
            continue;
        }
        stem = erase_suffix(stem, strlen(suffix));
        recognized_factory = true;
        break;
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

bool should_rebase_generated_name(const SynthField& field, sval_t old_offset) {
    if (field.name.empty()) {
        return true;
    }

    if (field.naming.is_generated() || is_generated_name(field.name, &field.naming)) {
        return true;
    }

    return field.is_padding && is_generated_padding_name(field.name);
}

void rebase_field_name(SynthField& field, sval_t old_offset) {
    if (!should_rebase_generated_name(field, old_offset)) {
        return;
    }

    if (field.is_padding && is_generated_padding_name(field.name)) {
        field.name.sprnt("__pad_%s", make_offset_suffix(field.offset).c_str());
        return;
    }

    if (field.naming.kind == GeneratedNameKind::SubStructField ||
        field.semantic == SemanticType::NestedStruct) {
        set_generated_name(field.name,
                           field.naming,
                           make_substruct_field_name(field.offset),
                           GeneratedNameKind::SubStructField,
                           field.naming.confidence);
        return;
    }

    if (field.is_array || field.naming.kind == GeneratedNameKind::ArrayField) {
        tinfo_t elem_type = field.type;
        array_type_data_t atd;
        if (elem_type.is_array() && elem_type.get_array_details(&atd)) {
            elem_type = atd.elem_type;
        }
        const size_t elem_size = elem_type.get_size();
        set_generated_name(field.name,
                           field.naming,
                           make_array_field_name(field.offset,
                                                 elem_type,
                                                 field.semantic,
                                                 static_cast<std::uint32_t>(elem_size == BADSIZE ? 0 : elem_size)),
                           GeneratedNameKind::ArrayField,
                           field.naming.confidence);
        return;
    }

    set_generated_name(field.name,
                       field.naming,
                       generate_field_name(field.offset, field.semantic, field.size),
                       field.naming.kind == GeneratedNameKind::Unknown ? GeneratedNameKind::Field : field.naming.kind,
                       field.naming.confidence);
}

void rebase_negative_offsets(SynthStruct& structure, qvector<SubStructInfo>* sub_structs) {
    sval_t min_offset = 0;
    bool found = false;
    for (const auto& field : structure.fields) {
        min_offset = found ? std::min(min_offset, field.offset) : field.offset;
        found = true;
    }

    if (!found || min_offset >= 0) {
        return;
    }

    const sval_t delta = -min_offset;
    for (auto& field : structure.fields) {
        const sval_t old_offset = field.offset;
        field.offset += delta;
        for (auto& access : field.source_accesses) {
            access.offset += delta;
        }

        rebase_field_name(field, old_offset);
    }

    if (sub_structs) {
        for (auto& sub : *sub_structs) {
            const sval_t old_parent_offset = sub.parent_offset;
            sub.parent_offset += delta;
            if (is_generated_name(sub.field_name, &sub.field_naming) || old_parent_offset < 0) {
                if (sub.field_naming.kind == GeneratedNameKind::SubStructField ||
                    sub.field_naming.kind == GeneratedNameKind::Unknown) {
                    sub.field_name = make_substruct_field_name(sub.parent_offset);
                    sub.field_naming.kind = GeneratedNameKind::SubStructField;
                    sub.field_naming.origin = NameOrigin::GeneratedFallback;
                } else {
                    sub.field_name = rebase_textual_generated_name(sub.field_name, sub.parent_offset);
                }
            }
            rebase_negative_offsets(sub.structure, nullptr);
        }
    }

    if (!extract_shifted_view_delta(structure.name).has_value()) {
        structure.name = make_shifted_view_type_name(structure.name, delta);
    }
}

tinfo_t make_scalar_type_for_access(const FieldAccess& access) {
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

void prune_intermediate_positive_delta_patterns(ea_t source_func,
                                                UnifiedAccessPattern& unified_pattern) {
    auto source_it = unified_pattern.function_deltas.find(source_func);
    if (source_it == unified_pattern.function_deltas.end()) {
        return;
    }

    const sval_t source_delta = source_it->second;
    if (source_delta <= 0) {
        return;
    }

    bool has_negative_helper = false;
    for (const auto& fn_pattern : unified_pattern.per_function_patterns) {
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

    for (auto& fn_pattern : unified_pattern.per_function_patterns) {
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
        std::move(kept_patterns),
        unified_pattern.function_deltas);

    for (const auto& edge : unified_pattern.flow_edges) {
        if (kept_funcs.contains(edge.caller_ea) && kept_funcs.contains(edge.callee_ea)) {
            pruned.flow_edges.push_back(edge);
        }
    }

    unified_pattern = std::move(pruned);
}

void recompute_unified_bounds(UnifiedAccessPattern& unified_pattern) {
    if (unified_pattern.all_accesses.empty()) {
        unified_pattern.global_min_offset = 0;
        unified_pattern.global_max_offset = 0;
        return;
    }

    bool first = true;
    for (const auto& access : unified_pattern.all_accesses) {
        const sval_t access_end = access.offset + static_cast<sval_t>(access.size);
        if (first) {
            unified_pattern.global_min_offset = access.offset;
            unified_pattern.global_max_offset = access_end;
            first = false;
            continue;
        }

        unified_pattern.global_min_offset = std::min(unified_pattern.global_min_offset, access.offset);
        unified_pattern.global_max_offset = std::max(unified_pattern.global_max_offset, access_end);
    }
}

void reanchor_source_window_accesses(ea_t source_func,
                                     UnifiedAccessPattern& unified_pattern) {
    auto source_it = unified_pattern.function_deltas.find(source_func);
    if (source_it == unified_pattern.function_deltas.end()) {
        return;
    }

    const sval_t source_delta = source_it->second;
    if (source_delta <= 0) {
        return;
    }

    bool has_negative_helper = false;
    for (const auto& fn_pattern : unified_pattern.per_function_patterns) {
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

    bool changed = false;
    for (auto& access : unified_pattern.all_accesses) {
        if (access.source_func_ea != source_func) {
            continue;
        }

        access.offset -= source_delta;
        changed = true;
    }

    if (!changed) {
        return;
    }

    std::sort(unified_pattern.all_accesses.begin(), unified_pattern.all_accesses.end(),
              [](const FieldAccess& a, const FieldAccess& b) {
                  if (a.offset != b.offset) return a.offset < b.offset;
                  if (a.size != b.size) return a.size < b.size;
                  if (a.source_func_ea != b.source_func_ea) return a.source_func_ea < b.source_func_ea;
                  return a.insn_ea < b.insn_ea;
              });

    recompute_unified_bounds(unified_pattern);
}

bool field_already_covers_exact_access(const SynthStruct& structure,
                                       const FieldAccess& access) {
    for (const auto& field : structure.fields) {
        if (field.offset == access.offset && field.size == access.size) {
            return true;
        }

        if (field.is_union_candidate) {
            for (const auto& member : field.union_members) {
                if (field.offset + member.offset == access.offset && member.size == access.size) {
                    return true;
                }
            }
        }
    }

    return false;
}

void apply_inner_scalar_overlay_recovery(SynthStruct& structure,
                                         const qvector<FieldAccess>& accesses) {
    for (const auto& access : accesses) {
        if (access.size == 0 || field_already_covers_exact_access(structure, access)) {
            continue;
        }

        const sval_t access_end = access.offset + static_cast<sval_t>(access.size);
        for (auto& field : structure.fields) {
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
            for (const auto& member : field.union_members) {
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
                overlay.name = make_overlay_member_name(field.name,
                                                        field.size,
                                                        rel_offset,
                                                        access.size);
            } else {
                overlay.name = generate_field_name(access.offset, access.semantic_type, access.size);
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

void adopt_field_names_from_original_type(SynthStruct& structure, const tinfo_t& original_type) {
    tinfo_t udt_type = original_type;
    if (udt_type.is_ptr()) {
        udt_type = udt_type.get_pointed_object();
    }

    (void)refine_struct_names_from_udt(structure, udt_type, NameOrigin::OriginalType);
}

void adopt_field_names_from_access_contexts(SynthStruct& structure,
                                            const qvector<FieldAccess>& accesses) {
    (void)refine_struct_names_from_accesses(structure, accesses, NameOrigin::AccessContext);
}

bool type_has_named_udt_details(const tinfo_t& type) {
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

LayoutSynthesizer::LayoutSynthesizer(const LayoutSynthConfig& config)
    : config_(config) {}

LayoutSynthesizer::LayoutSynthesizer(const SynthOptions& opts)
    : config_() {
    // Map SynthOptions to LayoutSynthConfig
    config_.z3_timeout_ms = opts.z3.timeout_ms;
    config_.z3_memory_mb = opts.z3.memory_limit_mb;
    config_.use_z3 = opts.z3.mode != Z3SynthesisMode::Disabled;
    config_.fallback_to_heuristics = opts.z3.mode != Z3SynthesisMode::Required;
    config_.default_alignment = opts.alignment;
    config_.cross_function = opts.z3.cross_function;
    config_.cross_function_depth = opts.max_propagation_depth;
    config_.emit_substructs = opts.emit_substructs;
    config_.min_array_elements = static_cast<int>(opts.z3.min_array_elements);
    config_.create_unions = opts.z3.allow_unions;
    config_.relax_alignment_on_unsat = opts.z3.relax_on_unsat;
    config_.relax_types_on_unsat = opts.z3.relax_on_unsat;
    config_.weight_minimize_padding = opts.z3.weight_minimize_padding;
    config_.weight_prefer_non_union = opts.z3.weight_prefer_non_union;
}


SynthesisResult LayoutSynthesizer::synthesize(
    const AccessPattern& pattern,
    const SynthOptions& opts)
{
    auto start_time = std::chrono::steady_clock::now();
    conflicts_.clear();

    SynthesisResult result;
    result.structure.source_func = pattern.func_ea;
    result.structure.source_var = pattern.var_name;
    result.structure.alignment = config_.default_alignment;
    set_generated_name(result.structure.name,
                       result.structure.naming,
                       make_auto_root_type_name(pattern.func_ea, pattern.var_name),
                       GeneratedNameKind::RootStruct,
                       NameConfidence::Medium);
    result.structure.add_provenance(pattern.func_ea);

    if (pattern.accesses.empty()) {
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
        result.functions_analyzed = static_cast<int>(
            analyzer.equivalence_class().variables.size());
        prune_intermediate_positive_delta_patterns(pattern.func_ea, unified_pattern);
        reanchor_source_window_accesses(pattern.func_ea, unified_pattern);
    } else {
        // Single-function mode
        AccessPattern mutable_pattern = pattern;
        unified_pattern = UnifiedAccessPattern::from_single(std::move(mutable_pattern));
        result.functions_analyzed = 1;
    }

    // Synthesize from unified pattern
    SynthesisResult synth_result = synthesize(unified_pattern);

    // Copy metadata
    synth_result.structure.source_func = pattern.func_ea;
    synth_result.structure.source_var = pattern.var_name;
    set_generated_name(synth_result.structure.name,
                       synth_result.structure.naming,
                       make_auto_root_type_name(pattern.func_ea, pattern.var_name),
                       GeneratedNameKind::RootStruct,
                       NameConfidence::Medium);
    synth_result.functions_analyzed = result.functions_analyzed;

    sval_t source_delta = 0;
    if (auto it = unified_pattern.function_deltas.find(pattern.func_ea);
        it != unified_pattern.function_deltas.end()) {
        source_delta = it->second;
    }

    if (config_.emit_substructs) {
        detect_subobjects(unified_pattern, opts, synth_result);
    }
    apply_bitfield_recovery(unified_pattern, synth_result.structure);
    synth_result.unified_pattern = unified_pattern;
    rebase_negative_offsets(synth_result.structure, &synth_result.sub_structs);
    if (source_delta > 0 && !extract_shifted_view_delta(synth_result.structure.name).has_value()) {
        synth_result.structure.name = make_shifted_view_type_name(synth_result.structure.name,
                                                                  source_delta);
    }
    compute_struct_size(synth_result.structure);

    auto end_time = std::chrono::steady_clock::now();
    synth_result.synthesis_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time);

    conflicts_ = synth_result.conflicts;
    return synth_result;
}

SynthesisResult LayoutSynthesizer::synthesize(const AccessPattern& pattern) {
    return synthesize(pattern, Config::instance().options());
}

SynthesisResult LayoutSynthesizer::synthesize(
    const UnifiedAccessPattern& unified_pattern)
{
    auto start_time = std::chrono::steady_clock::now();

    SynthesisResult result;

    if (unified_pattern.all_accesses.empty()) {
        return result;
    }

    // Try Z3 synthesis first if enabled
    if (config_.use_z3) {
        auto z3_result = synthesize_z3(unified_pattern);
        if (z3_result.has_value()) {
            result = std::move(*z3_result);
            result.used_z3 = true;

            auto end_time = std::chrono::steady_clock::now();
            result.synthesis_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                end_time - start_time);
            return result;
        }
    }

    // Fallback to heuristic synthesis
    if (config_.fallback_to_heuristics) {
        result = synthesize_heuristic(unified_pattern);
        result.fell_back_to_heuristic = true;
        if (result.fallback_reason.empty()) {
            result.fallback_reason = "Z3 disabled or failed";
        }
    }

    auto end_time = std::chrono::steady_clock::now();
    result.synthesis_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time);

    return result;
}

std::optional<SynthesisResult> LayoutSynthesizer::synthesize_z3(
    const UnifiedAccessPattern& pattern)
{
    SynthesisResult result;

    detail::synth_log("[Structor] Starting Z3-based structure synthesis...\n");

    try {
        // Create Z3 context
        z3::Z3Config z3_config = make_z3_config();
        z3_ctx_ = std::make_unique<z3::Z3Context>(z3_config);

        // Generate field candidates
        z3::CandidateGenerationConfig cand_config = make_candidate_config();
        z3::FieldCandidateGenerator generator(*z3_ctx_, cand_config);
        auto candidates = generator.generate(pattern);

        detail::synth_log("[Structor] Generated %zu field candidates from %zu accesses\n",
                          candidates.size(), pattern.all_accesses.size());

        if (candidates.empty()) {
            detail::synth_log("[Structor] No field candidates - falling back to heuristics\n");
            result.fallback_reason = "No field candidates generated";
            return std::nullopt;
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
            result.arrays_detected = static_cast<int>(builder.detected_arrays().size());
            result.unions_created = static_cast<int>(builder.union_resolutions().size());

            // Handle relaxed constraints
            if (z3_result.has_dropped_constraints()) {
                result.had_relaxation = true;
                result.dropped_constraints = z3_result.dropped_constraints;
                detail::synth_log("[Structor] Z3 synthesis completed with %zu relaxed constraints\n",
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

            // Set struct metadata
            result.structure.alignment = config_.default_alignment;
            if (result.inferred_packing) {
                result.structure.alignment = std::min(
                    result.structure.alignment, *result.inferred_packing);
            }

            return result;
        }
        else if (z3_result.is_unsat()) {
            detail::synth_log("[Structor] Z3 returned UNSAT - constraints unsatisfiable\n");
            // Try relaxation if configured
            if (config_.relax_alignment_on_unsat || config_.relax_types_on_unsat) {
                return try_relaxed_solve(builder, z3_result, result);
            }

            result.unsat_core = z3_result.unsat_core;
            result.fallback_reason = "Z3 UNSAT: ";
            if (!z3_result.unsat_core.empty()) {
                result.fallback_reason.append(z3_result.unsat_core[0].description.c_str());
            }
            detail::synth_log("[Structor] Falling back to heuristic synthesis\n");
            return std::nullopt;
        }
        else {
            // Unknown or error
            detail::synth_log("[Structor] Z3 returned unknown/timeout - falling back to heuristics\n");
            result.fallback_reason = "Z3 ";
            result.fallback_reason.append(z3_result.status_string());
            if (!z3_result.error_message.empty()) {
                result.fallback_reason.append(": ");
                result.fallback_reason.append(z3_result.error_message.c_str());
            }
            return std::nullopt;
        }
    }
    catch (const std::exception& e) {
        detail::synth_log("[Structor] Z3 exception: %s\n", e.what());
        result.fallback_reason = "Z3 exception: ";
        result.fallback_reason.append(e.what());
        return std::nullopt;
    }
    catch (...) {
        detail::synth_log("[Structor] Unknown Z3 exception\n");
        result.fallback_reason = "Unknown Z3 exception";
        return std::nullopt;
    }
}

std::optional<SynthesisResult> LayoutSynthesizer::try_relaxed_solve(
    z3::LayoutConstraintBuilder& builder,
    const z3::Z3Result& initial_result,
    SynthesisResult& result)
{
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
        result.dropped_constraints = initial_result.dropped_constraints;
    }

    // Record the UNSAT core for diagnostics
    result.unsat_core = initial_result.unsat_core;

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

    // Return nullopt to trigger heuristic fallback
    return std::nullopt;
}

SynthesisResult LayoutSynthesizer::synthesize_heuristic(
    const UnifiedAccessPattern& pattern)
{
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

    detail::synth_log("[Structor] Heuristic synthesis completed: %zu fields, %u bytes\n",
                      result.structure.fields.size(), result.structure.size);
    if (!conflicts_.empty()) {
        detail::synth_log("[Structor] Warning: %zu conflicts detected\n", conflicts_.size());
    }

    return result;
}

void LayoutSynthesizer::group_accesses_heuristic(
    const UnifiedAccessPattern& pattern,
    qvector<OffsetGroup>& groups)
{
    // Sort accesses by offset
    qvector<FieldAccess> sorted = pattern.all_accesses;
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

void LayoutSynthesizer::resolve_conflicts_heuristic(qvector<OffsetGroup>& groups) {
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
                conflict.description.sprnt("Conflicting access sizes at offset 0x%X",
                    static_cast<unsigned>(off));

                for (auto* acc : acc_list) {
                    conflict.conflicting_accesses.push_back(*acc);
                }

                conflicts_.push_back(std::move(conflict));
                group.is_union = true;
            }
        }
    }
}

void LayoutSynthesizer::generate_fields_heuristic(
    const qvector<OffsetGroup>& groups,
    SynthStruct& result)
{
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

void LayoutSynthesizer::insert_padding_heuristic(SynthStruct& result) {
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

void LayoutSynthesizer::infer_field_types_heuristic(
    SynthStruct& result,
    const UnifiedAccessPattern& pattern)
{
    std::uint32_t ptr_size = get_ptr_size();

    for (auto& field : result.fields) {
        if (field.is_padding) continue;
        if (!field.type.empty()) continue;

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
                field.type = utils::create_basic_type(field.size, SemanticType::UnsignedInteger);
                break;

            case SemanticType::Integer:
            case SemanticType::Unknown:
            default:
                if (field.size == ptr_size) {
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

void LayoutSynthesizer::generate_field_names(SynthStruct& result) {
    const SynthOptions& opts = Config::instance().options();

    for (auto& field : result.fields) {
        if (field.is_padding) continue;
        if (!field.name.empty()) continue;

        if (!field.is_array && !field.is_union_candidate && !field.type.empty() &&
            (field.type.is_struct() || field.type.is_union() || field.semantic == SemanticType::NestedStruct)) {
            set_generated_name(field.name,
                               field.naming,
                               make_substruct_field_name(field.offset),
                               GeneratedNameKind::SubStructField,
                               NameConfidence::Medium);
        } else if (field.is_array) {
            tinfo_t elem_type = field.type;
            array_type_data_t atd;
            if (elem_type.is_array() && elem_type.get_array_details(&atd)) {
                elem_type = atd.elem_type;
            }
            const size_t elem_size = elem_type.get_size();
            set_generated_name(field.name,
                               field.naming,
                               make_array_field_name(field.offset,
                                                     elem_type,
                                                     field.semantic,
                                                     static_cast<std::uint32_t>(elem_size == BADSIZE ? 0 : elem_size)),
                               GeneratedNameKind::ArrayField,
                               NameConfidence::Medium);
        } else {
            set_generated_name(field.name,
                               field.naming,
                               generate_field_name(field.offset, field.semantic, field.size),
                               field.is_array ? GeneratedNameKind::ArrayField : GeneratedNameKind::Field,
                               NameConfidence::Medium);
        }

    }

    apply_role_based_field_names(result);

    if (!opts.generate_comments) {
        return;
    }

    for (auto& field : result.fields) {
        if (field.is_padding) {
            continue;
        }

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

void LayoutSynthesizer::compute_struct_size(SynthStruct& result) {
    if (result.fields.empty()) {
        result.size = 0;
        return;
    }

    const auto& last_field = result.fields.back();
    sval_t end = last_field.offset + last_field.size;

    // Align to structure alignment
    result.size = align_offset(end, result.alignment);
}

void LayoutSynthesizer::apply_bitfield_recovery(
    const UnifiedAccessPattern& pattern,
    SynthStruct& result)
{
    if (pattern.all_accesses.empty() || result.fields.empty()) return;

    std::unordered_map<uint64_t, qvector<BitfieldInfo>> by_field;
    for (const auto& access : pattern.all_accesses) {
        if (access.bitfields.empty()) continue;
        uint64_t key = (static_cast<uint64_t>(access.offset) << 32) |
                       static_cast<uint64_t>(access.size);
        auto& list = by_field[key];
        for (const auto& bf : access.bitfields) {
            bool found = false;
            for (const auto& existing : list) {
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

    if (by_field.empty()) return;

    auto make_base_type = [](uint32_t size) {
        tinfo_t type;
        switch (size) {
            case 1: type.create_simple_type(BT_INT8 | BTMT_USIGNED); break;
            case 2: type.create_simple_type(BT_INT16 | BTMT_USIGNED); break;
            case 4: type.create_simple_type(BT_INT32 | BTMT_USIGNED); break;
            case 8: type.create_simple_type(BT_INT64 | BTMT_USIGNED); break;
            default: type.create_simple_type(BT_INT8 | BTMT_USIGNED); break;
        }
        return type;
    };

    qvector<SynthField> updated;
    updated.reserve(result.fields.size());

    for (const auto& field : result.fields) {
        uint64_t key = (static_cast<uint64_t>(field.offset) << 32) |
                       static_cast<uint64_t>(field.size);
        auto it = by_field.find(key);
        if (it == by_field.end() || field.is_padding || field.is_array || field.is_union_candidate) {
            updated.push_back(field);
            continue;
        }

        // Hex-Rays handles packed misaligned scalar fields much more reliably as
        // plain storage than as synthetic C bitfields. Converting those fields
        // into bitfields tends to skew later member accesses back into casts.
        if (field.size > 1 && field.offset >= 0 && (field.offset % static_cast<sval_t>(field.size)) != 0) {
            updated.push_back(field);
            continue;
        }

        const auto& bfs = it->second;
        bool valid = true;
        for (const auto& bf : bfs) {
            if (static_cast<unsigned>(bf.bit_offset + bf.bit_size) > field.size * 8) {
                valid = false;
                break;
            }
        }

        if (!valid || bfs.empty()) {
            updated.push_back(field);
            continue;
        }

        for (const auto& bf : bfs) {
            SynthField bf_field = SynthField::create_bitfield(
                field.offset, field.size, bf.bit_offset, bf.bit_size);
            bf_field.type = field.type.empty() ? make_base_type(field.size) : field.type;
            updated.push_back(std::move(bf_field));
        }
    }

    std::sort(updated.begin(), updated.end(), [](const SynthField& a, const SynthField& b) {
        if (a.offset != b.offset) return a.offset < b.offset;
        if (a.is_bitfield != b.is_bitfield) return a.is_bitfield;
        return a.bit_offset < b.bit_offset;
    });

    result.fields = std::move(updated);
    compute_struct_size(result);
}

void LayoutSynthesizer::detect_subobjects(
    const UnifiedAccessPattern& pattern,
    const SynthOptions& opts,
    SynthesisResult& result)
{
    if (!config_.emit_substructs || !config_.cross_function) return;
    if (pattern.per_function_patterns.empty()) return;

    struct SubGroup {
        sval_t offset = 0;
        qvector<AccessPattern> patterns;
        std::unordered_set<ea_t> funcs;
    };

    std::unordered_map<sval_t, SubGroup> groups;
    if (!pattern.flow_edges.empty()) {
        for (const auto& edge : pattern.flow_edges) {
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

            for (const auto& fn_pattern : pattern.per_function_patterns) {
                if (fn_pattern.func_ea == result.structure.source_func &&
                    edge.callee_ea == result.structure.source_func) {
                    continue;
                }
                if (fn_pattern.func_ea != edge.callee_ea || fn_pattern.var_idx != edge.callee_param_idx) {
                    continue;
                }

                auto delta_it = pattern.function_deltas.find(fn_pattern.func_ea);
                const sval_t group_delta =
                    delta_it != pattern.function_deltas.end() ? delta_it->second : edge.delta;
                if (group_delta <= 0) {
                    continue;
                }

                auto& group = groups[group_delta];
                group.offset = group_delta;
                group.patterns.push_back(fn_pattern);
                group.funcs.insert(fn_pattern.func_ea);
            }
        }
    }

    if (groups.empty()) {
        for (const auto& fn_pattern : pattern.per_function_patterns) {
            if (fn_pattern.func_ea == result.structure.source_func) {
                continue;
            }

            auto it = pattern.function_deltas.find(fn_pattern.func_ea);
            sval_t delta = it != pattern.function_deltas.end() ? it->second : 0;
            if (delta <= 0) continue;

            auto& group = groups[delta];
            group.offset = delta;
            group.patterns.push_back(fn_pattern);
            group.funcs.insert(fn_pattern.func_ea);
        }
    }

    if (groups.empty()) return;

    qvector<sval_t> ordered_deltas;
    ordered_deltas.reserve(groups.size());
    for (const auto& [delta, _] : groups) {
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

    auto choose_recursive_seed = [](const SubGroup& group) -> std::optional<AccessPattern> {
        const AccessPattern* best = nullptr;
        int best_score = -1;
        for (const auto& candidate : group.patterns) {
            if (candidate.var_idx < 0 || candidate.accesses.empty()) {
                continue;
            }

            int score = static_cast<int>(candidate.accesses.size());
            if (type_has_named_udt_details(candidate.original_type)) {
                score += 1000;
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

    auto access_covered_by_other_fields = [&](const FieldAccess& access, size_t skip_index) {
        const sval_t access_end = access.offset + static_cast<sval_t>(access.size);
        for (size_t i = 0; i < result.structure.fields.size(); ++i) {
            if (i == skip_index) {
                continue;
            }

            const auto& other = result.structure.fields[i];
            const sval_t other_end = other.offset + static_cast<sval_t>(other.size);
            if (access.offset >= other.offset && access_end <= other_end) {
                return true;
            }
        }
        return false;
    };

    auto region_covered_by_other_fields = [&](sval_t start,
                                              sval_t end,
                                              size_t skip_index,
                                              const qvector<FieldAccess>* extra_accesses = nullptr) {
        if (start >= end) {
            return true;
        }

        auto access_covered_in_region = [&](const FieldAccess& access) {
            const sval_t access_end = access.offset + static_cast<sval_t>(access.size);
            if (access.offset >= end || access_end <= start) {
                return true;
            }

            for (size_t i = 0; i < result.structure.fields.size(); ++i) {
                if (i == skip_index) {
                    continue;
                }

                const auto& other = result.structure.fields[i];
                const sval_t other_end = other.offset + static_cast<sval_t>(other.size);
                if (access.offset < other.offset || access_end > other_end) {
                    continue;
                }

                return true;
            }

            if (extra_accesses) {
                for (const auto& extra : *extra_accesses) {
                    const sval_t extra_end = extra.offset + static_cast<sval_t>(extra.size);
                    if (access.offset >= extra.offset && access_end <= extra_end) {
                        return true;
                    }
                }
            }

            return false;
        };

        for (const auto& access : pattern.all_accesses) {
            if (!access_covered_in_region(access)) {
                return false;
            }
        }

        return true;
    };

    auto field_covers_access = [&](const FieldAccess& access) {
        const sval_t access_end = access.offset + static_cast<sval_t>(access.size);
        for (const auto& field : result.structure.fields) {
            const sval_t field_end = field.offset + static_cast<sval_t>(field.size);
            if (access.offset >= field.offset && access_end <= field_end) {
                return true;
            }
        }
        return false;
    };

    for (sval_t delta : ordered_deltas) {
        auto group_it = groups.find(delta);
        if (group_it == groups.end()) {
            continue;
        }
        auto& group = group_it->second;

        AccessPattern sub_pattern;
        sub_pattern.func_ea = group.patterns.front().func_ea;
        sub_pattern.var_name = make_substruct_field_name(delta);
        for (const auto& fn_pattern : group.patterns) {
            if (type_has_named_udt_details(fn_pattern.original_type)) {
                sub_pattern.original_type = fn_pattern.original_type;
                break;
            }
        }
        if (!type_has_named_udt_details(sub_pattern.original_type)) {
            sub_pattern.original_type.clear();
            cfuncptr_t helper_cfunc = utils::get_cfunc(sub_pattern.func_ea);
            if (helper_cfunc) {
                lvars_t* helper_lvars = helper_cfunc->get_lvars();
                if (helper_lvars) {
                    for (const auto& fn_pattern : group.patterns) {
                        if (fn_pattern.var_idx < 0 ||
                            static_cast<size_t>(fn_pattern.var_idx) >= helper_lvars->size()) {
                            continue;
                        }

                        tinfo_t helper_type = helper_lvars->at(fn_pattern.var_idx).type();
                        if (type_has_named_udt_details(helper_type)) {
                            sub_pattern.original_type = helper_type;
                            break;
                        }
                    }
                }
            }
        }

        for (const auto& fn_pattern : group.patterns) {
            for (const auto& access : fn_pattern.accesses) {
                sub_pattern.add_access(FieldAccess(access));
            }
        }

        if (sub_pattern.accesses.empty() ||
            static_cast<int>(sub_pattern.access_count()) < opts.min_accesses) {
            continue;
        }

        qstring suggested_type_name;
        qstring suggested_field_name;
        SynthesisResult sub_result;
        bool have_sub_result = false;

        if (auto recursive_seed = choose_recursive_seed(group)) {
            if (recursive_seed->original_type.empty() && !sub_pattern.original_type.empty()) {
                recursive_seed->original_type = sub_pattern.original_type;
            }

            suggested_type_name = suggest_subobject_type_name(recursive_seed->func_ea);
            suggested_field_name = suggest_subobject_field_name(recursive_seed->func_ea);

            SynthOptions child_opts = opts;
            child_opts.propagate_to_callers = false;
            child_opts.max_propagation_depth = std::max(1, child_opts.max_propagation_depth - 1);
            sub_result = recursive_sub_synth.synthesize(*recursive_seed, child_opts);
            have_sub_result = sub_result.success();
        }

        if (!have_sub_result) {
            if (suggested_type_name.empty()) {
                suggested_type_name = suggest_subobject_type_name(sub_pattern.func_ea);
            }
            if (suggested_field_name.empty()) {
                suggested_field_name = suggest_subobject_field_name(sub_pattern.func_ea);
            }
            sub_result = flat_sub_synth.synthesize(sub_pattern, opts);
            have_sub_result = sub_result.success();
        }

        if (!have_sub_result) continue;

        if (!suggested_type_name.empty()) {
            set_adopted_name(sub_result.structure.name,
                             sub_result.structure.naming,
                             suggested_type_name,
                             GeneratedNameKind::RootStruct,
                             NameOrigin::HeuristicRole,
                             NameConfidence::Medium,
                             false);
        }

        adopt_field_names_from_original_type(sub_result.structure, sub_pattern.original_type);
        adopt_field_names_from_access_contexts(sub_result.structure, sub_pattern.accesses);

        qvector<FieldAccess> overlay_accesses;
        for (const auto& access : pattern.all_accesses) {
            const sval_t access_end = access.offset + static_cast<sval_t>(access.size);
            if (access.offset < delta || access_end > delta + static_cast<sval_t>(sub_result.structure.size)) {
                continue;
            }

            FieldAccess rebased = access;
            rebased.offset -= delta;
            overlay_accesses.push_back(std::move(rebased));
        }
        if (!overlay_accesses.empty()) {
            apply_inner_scalar_overlay_recovery(sub_result.structure, overlay_accesses);
            adopt_field_names_from_access_contexts(sub_result.structure, overlay_accesses);
        }

        std::uint32_t sub_size = sub_result.structure.size;
        if (sub_size == 0) continue;

        sval_t sub_end = delta + static_cast<sval_t>(sub_size);
        bool conflict = false;
        qvector<size_t> remove_indices;
        qvector<SynthField> replacement_fields;

        for (size_t i = 0; i < result.structure.fields.size(); ++i) {
            const auto& field = result.structure.fields[i];
            sval_t field_end = field.offset + static_cast<sval_t>(field.size);

            if (field_end <= delta || field.offset >= sub_end) {
                continue;
            }

            bool removable = field.offset >= delta && field_end <= sub_end;

            if (!removable) {
                bool mixed_width_sources = false;
                bool struct_like_source = false;
                for (const auto& access : field.source_accesses) {
                    if (access.size < field.size) {
                        mixed_width_sources = true;
                    }
                    if (!access.inferred_type.empty() &&
                        (access.inferred_type.is_struct() || access.inferred_type.is_array())) {
                        struct_like_source = true;
                    }
                }

                const bool aggregate_like =
                    (!field.type.empty() && (field.type.is_struct() || field.type.is_array())) ||
                    field.semantic == SemanticType::NestedStruct ||
                    field.source_accesses.size() <= 1 ||
                    mixed_width_sources ||
                    struct_like_source;

                if (aggregate_like) {
                    qvector<FieldAccess> leftover_accesses;
                    for (const auto& access : field.source_accesses) {
                        const sval_t access_end = access.offset + static_cast<sval_t>(access.size);
                        if (access_end <= delta || access.offset >= sub_end) {
                            if (!access_covered_by_other_fields(access, i)) {
                                leftover_accesses.push_back(access);
                            }
                        }
                    }

                    const sval_t left_start = field.offset;
                    const sval_t left_end = std::min(field_end, delta);
                    const sval_t right_start = std::max(field.offset, sub_end);
                    const sval_t right_end = field_end;

                    const bool left_ok = region_covered_by_other_fields(left_start, left_end, i, &leftover_accesses);
                    const bool right_ok = region_covered_by_other_fields(right_start, right_end, i, &leftover_accesses);
                    removable = left_ok && right_ok;

                    if (removable && !leftover_accesses.empty()) {
                        std::sort(leftover_accesses.begin(), leftover_accesses.end());

                        size_t pos = 0;
                        while (pos < leftover_accesses.size()) {
                            qvector<FieldAccess> group_accesses;
                            sval_t group_offset = leftover_accesses[pos].offset;
                            sval_t group_end = leftover_accesses[pos].offset + static_cast<sval_t>(leftover_accesses[pos].size);
                            group_accesses.push_back(leftover_accesses[pos]);
                            ++pos;

                            while (pos < leftover_accesses.size()) {
                                const auto& next = leftover_accesses[pos];
                                const sval_t next_end = next.offset + static_cast<sval_t>(next.size);
                                if (next.offset >= group_end) {
                                    break;
                                }

                                group_end = std::max(group_end, next_end);
                                group_accesses.push_back(next);
                                ++pos;
                            }

                            SynthField replacement;
                            replacement.offset = group_offset;
                            replacement.size = static_cast<std::uint32_t>(group_end - group_offset);
                            replacement.source_accesses = group_accesses;
                            replacement.type = select_best_type(group_accesses);
                            replacement.semantic = select_best_semantic(group_accesses);
                            replacement.confidence = TypeConfidence::Medium;
                            replacement_fields.push_back(std::move(replacement));
                        }
                    }
                }
            }

            if (removable) {
                remove_indices.push_back(i);
            } else {
                conflict = true;
                break;
            }
        }

        if (conflict) {
            continue;
        }

        // Remove in reverse order to keep indices valid
        for (size_t idx = remove_indices.size(); idx > 0; --idx) {
            size_t remove_idx = remove_indices[idx - 1];
            result.structure.fields.erase(result.structure.fields.begin() + static_cast<sval_t>(remove_idx));
        }

        for (auto& replacement : replacement_fields) {
            result.structure.fields.push_back(std::move(replacement));
        }

        SynthField sub_field;
        sub_field.offset = delta;
        sub_field.size = sub_size;
        sub_field.semantic = SemanticType::NestedStruct;
        sub_field.confidence = TypeConfidence::Medium;
        if (!suggested_field_name.empty() && !is_placeholder_identifier(suggested_field_name)) {
            set_adopted_name(sub_field.name,
                             sub_field.naming,
                             suggested_field_name,
                             GeneratedNameKind::SubStructField,
                             NameOrigin::HeuristicRole,
                             NameConfidence::Medium,
                             false);
        } else {
            set_generated_name(sub_field.name,
                               sub_field.naming,
                               make_substruct_field_name(delta),
                               GeneratedNameKind::SubStructField,
                               NameConfidence::Medium);
        }

        result.structure.fields.push_back(sub_field);

        SubStructInfo info;
        info.structure = std::move(sub_result.structure);
        info.parent_offset = delta;
        info.field_name = sub_field.name;
        info.field_naming = sub_field.naming;
        info.children = std::move(sub_result.sub_structs);
        result.sub_structs.push_back(std::move(info));
    }

    const qvector<SubStructInfo> explicit_sub_structs = result.sub_structs;

    // Reuse the same recovered child layout for sibling windows of equal
    // size after all explicit flow-edge-derived children have been attempted.
    for (const auto& existing_sub : explicit_sub_structs) {
        const std::uint32_t sub_size = existing_sub.structure.size;
        if (sub_size == 0) {
            continue;
        }

        for (auto& field : result.structure.fields) {
            if (field.offset == existing_sub.parent_offset ||
                field.is_padding ||
                field.is_array ||
                field.is_union_candidate) {
                continue;
            }
            if (field.size != sub_size || field.semantic == SemanticType::NestedStruct) {
                continue;
            }

            bool already_present = false;
            for (const auto& sub : result.sub_structs) {
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
            for (const auto& access : pattern.all_accesses) {
                const sval_t access_end = access.offset + static_cast<sval_t>(access.size);
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
            set_generated_name(field.name,
                               field.naming,
                               make_substruct_field_name(field.offset),
                               GeneratedNameKind::SubStructField,
                               NameConfidence::Medium);

            SubStructInfo sibling = existing_sub;
            sibling.parent_offset = field.offset;
            sibling.field_name = field.name;
            sibling.field_naming = field.naming;
            result.sub_structs.push_back(std::move(sibling));
        }
    }

    if (!result.structure.fields.empty()) {
        const AccessPattern* source_pattern = nullptr;
        for (const auto& fn_pattern : pattern.per_function_patterns) {
            if (fn_pattern.func_ea == result.structure.source_func) {
                source_pattern = &fn_pattern;
                break;
            }
        }

        if (source_pattern) {
            sval_t first_field_offset = result.structure.fields.front().offset;
            for (const auto& field : result.structure.fields) {
                first_field_offset = std::min(first_field_offset, field.offset);
            }

            qvector<FieldAccess> prefix_accesses;
            for (const auto& access : source_pattern->accesses) {
                const sval_t access_end = access.offset + static_cast<sval_t>(access.size);
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
                        const auto& next = prefix_accesses[pos];
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
                    prefix_field.size = static_cast<std::uint32_t>(group_end - group_offset);
                    prefix_field.source_accesses = group_accesses;
                    prefix_field.type = select_best_type(group_accesses);
                    prefix_field.semantic = select_best_semantic(group_accesses);
                    prefix_field.confidence = TypeConfidence::Medium;
                    set_generated_name(prefix_field.name,
                                       prefix_field.naming,
                                       generate_field_name(prefix_field.offset,
                                                           prefix_field.semantic,
                                                           prefix_field.size),
                                       GeneratedNameKind::Field,
                                       NameConfidence::Medium);
                    result.structure.fields.push_back(std::move(prefix_field));
                }
            }
        }
    }

    std::sort(result.structure.fields.begin(), result.structure.fields.end(),
              [](const SynthField& a, const SynthField& b) {
                  if (a.offset != b.offset) return a.offset < b.offset;
                  if (a.is_bitfield != b.is_bitfield) return a.is_bitfield;
                  return a.bit_offset < b.bit_offset;
              });

    compute_struct_size(result.structure);
}

tinfo_t LayoutSynthesizer::select_best_type(const qvector<FieldAccess>& accesses) {
    tinfo_t best;
    uint32_t widest_size = 0;
    const FieldAccess* widest_access = nullptr;

    for (const auto& access : accesses) {
        if (access.size > widest_size) {
            widest_size = access.size;
            widest_access = &access;
        }

        if (access.inferred_type.empty()) continue;

        if (best.empty()) {
            best = access.inferred_type;
            continue;
        }

        best = resolve_type_conflict(best, access.inferred_type);
    }

    if (!best.empty()) {
        const size_t best_size = best.get_size();
        const bool scalar_like =
            !best.is_array() && !best.is_struct() && !best.is_union() && !best.is_func();
        if (scalar_like && best_size != BADSIZE && widest_size > 0 && best_size < widest_size && widest_access) {
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

SemanticType LayoutSynthesizer::select_best_semantic(const qvector<FieldAccess>& accesses) {
    SemanticType best = SemanticType::Unknown;
    int best_priority = 0;

    for (const auto& access : accesses) {
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
    cfg.pointer_size = get_ptr_size();
    cfg.default_alignment = config_.default_alignment;
    return cfg;
}

z3::LayoutConstraintConfig LayoutSynthesizer::make_layout_config() const {
    z3::LayoutConstraintConfig cfg;
    cfg.default_alignment = config_.default_alignment;
    cfg.model_packing = config_.infer_packing;
    cfg.allow_unions = config_.create_unions;
    cfg.max_union_alternatives = config_.max_union_alternatives;
    cfg.weight_coverage = config_.weight_coverage;
    cfg.weight_type_consistency = config_.weight_type_consistency;
    cfg.weight_alignment = config_.weight_alignment;
    cfg.weight_minimize_fields = config_.weight_minimize_fields;
    cfg.weight_minimize_padding = config_.weight_minimize_padding;
    cfg.weight_prefer_non_union = config_.weight_prefer_non_union;
    cfg.weight_prefer_arrays = config_.weight_prefer_arrays;
    return cfg;
}

z3::CandidateGenerationConfig LayoutSynthesizer::make_candidate_config() const {
    z3::CandidateGenerationConfig cfg;
    cfg.min_array_elements = config_.min_array_elements;
    return cfg;
}

SynthesisResult LayoutSynthesizer::synthesize_with_type_inference(
    cfunc_t* cfunc,
    int var_idx,
    const SynthOptions& opts)
{
    SynthesisResult result;
    
    if (!cfunc) {
        return result;
    }
    
    auto start_time = std::chrono::steady_clock::now();
    
    // Step 1: Run type inference if enabled
    if (config_.use_type_inference) {
        detail::synth_log("[Structor] Running type inference for function %a...\n", cfunc->entry_ea);
        
        // Create Z3 context for type inference
        z3::Z3Config z3_config = make_z3_config();
        z3_ctx_ = std::make_unique<z3::Z3Context>(z3_config);
        
        // Run type inference
        z3::TypeInferenceEngine engine(*z3_ctx_, config_.type_inference_config);
        z3::FunctionTypeInferenceResult infer_result = engine.infer_function(cfunc);
        
        if (infer_result.success) {
            detail::synth_log("[Structor] Type inference completed: %zu variables typed\n",
                             infer_result.local_types.size());
            last_type_inference_ = std::move(infer_result);
        } else {
            detail::synth_log("[Structor] Type inference failed: %s\n",
                             infer_result.error_message.c_str());
        }
    }
    
    // Step 2: Collect access pattern for the variable
    AccessCollector collector;
    AccessPattern pattern = collector.collect(cfunc, var_idx);
    
    if (pattern.accesses.empty()) {
        detail::synth_log("[Structor] No accesses found for variable %d\n", var_idx);
        return result;
    }
    
    // Step 3: Enhance access pattern with type inference results
    if (last_type_inference_.has_value() && last_type_inference_->success) {
        // Get inferred type for the target variable
        auto var_type = last_type_inference_->get_var_type(var_idx);
        if (var_type.has_value()) {
            detail::synth_log("[Structor] Using inferred type for variable %d: %s\n",
                             var_idx, var_type->to_string().c_str());
            
            // If it's a pointer type, this confirms our target is a pointer to struct
            if (var_type->is_pointer()) {
                // Enhance field accesses with inferred pointee types
                for (auto& access : pattern.accesses) {
                    // Check if we have inferred memory type at this offset
                    auto mem_type = last_type_inference_->get_mem_type(
                        cfunc->entry_ea, access.offset);
                    if (mem_type.has_value()) {
                        // Use inferred type if we don't have a better one
                        if (access.inferred_type.empty() || access.inferred_type.is_void()) {
                            access.inferred_type = mem_type->to_tinfo();
                        }
                    }
                }
            }
        }
    }
    
    // Step 4: Run structure synthesis
    result = synthesize(pattern, opts);
    
    // Step 5: Apply type inference results to improve field types
    if (last_type_inference_.has_value() && last_type_inference_->success) {
        for (auto& field : result.structure.fields) {
            if (field.is_padding) continue;
            
            // Look for inferred memory type at this field's offset
            auto mem_type = last_type_inference_->get_mem_type(
                cfunc->entry_ea, field.offset);
            if (mem_type.has_value() && !mem_type->is_unknown()) {
                tinfo_t inferred = mem_type->to_tinfo();
                
                // Use inferred type if current type is generic
                if (field.type.empty() || field.type.is_ptr_or_array()) {
                    // For pointers, use the more specific type
                    if (field.type.is_ptr() && inferred.is_ptr()) {
                        tinfo_t current_pointee = field.type.get_pointed_object();
                        tinfo_t inferred_pointee = inferred.get_pointed_object();
                        
                        // Prefer non-void pointee
                        if (current_pointee.is_void() && !inferred_pointee.is_void()) {
                            field.type = inferred;
                        }
                    } else if (field.type.empty()) {
                        field.type = inferred;
                    }
                }
            }
        }
    }
    
    auto end_time = std::chrono::steady_clock::now();
    result.synthesis_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time);
    
    return result;
}

z3::TypeApplicationResult LayoutSynthesizer::apply_synthesis_result(
    cfunc_t* cfunc,
    int var_idx,
    const SynthesisResult& result)
{
    z3::TypeApplicationResult app_result;
    
    if (!cfunc || result.structure.fields.empty()) {
        return app_result;
    }
    
    // Step 1: Create and persist the synthesized structure
    StructurePersistence persistence;
    SynthStruct synth_copy = result.structure;  // create_struct may modify the name
    qvector<SubStructInfo> sub_structs = result.sub_structs;
    tid_t struct_tid = sub_structs.empty()
        ? persistence.create_struct(synth_copy)
        : persistence.create_struct_with_substructs(synth_copy, sub_structs);
    
    if (struct_tid == BADADDR) {
        detail::synth_log("[Structor] Failed to create structure in IDA\n");
        return app_result;
    }
    
    detail::synth_log("[Structor] Created structure '%s' with tid %a\n",
                     synth_copy.name.c_str(), struct_tid);
    
    // Step 2: Create pointer type to the struct
    tinfo_t struct_type;
    if (!struct_type.get_type_by_tid(struct_tid)) {
        return app_result;
    }
    
    tinfo_t ptr_type;
    ptr_type.create_ptr(struct_type);
    
    // Step 3: Apply the struct pointer type to the variable
    z3::TypeApplicator applicator(config_.type_application_config);
    
    // Create an InferredType for the struct pointer
    z3::InferredType inferred_ptr = z3::InferredType::make_ptr(
        z3::InferredType::make_struct(struct_tid)
    );
    
    qstring reason;
    bool applied = applicator.apply_variable(
        cfunc, var_idx, inferred_ptr, z3::TypeConfidence::High, &reason);
    
    if (applied) {
        z3::TypeApplicationResult::AppliedType at;
        at.var_idx = var_idx;
        at.inferred = inferred_ptr;
        at.applied = ptr_type;
        at.confidence = z3::TypeConfidence::High;
        
        lvars_t* lvars = cfunc->get_lvars();
        if (lvars && var_idx >= 0 && static_cast<size_t>(var_idx) < lvars->size()) {
            at.var_name = (*lvars)[var_idx].name;
        }
        
        app_result.applied.push_back(std::move(at));
        app_result.applied_count++;
        
        detail::synth_log("[Structor] Applied struct type to variable %d\n", var_idx);
    } else {
        z3::TypeApplicationResult::FailedType ft;
        ft.var_idx = var_idx;
        ft.inferred = inferred_ptr;
        ft.reason = reason;
        app_result.failed.push_back(std::move(ft));
        app_result.failed_count++;
        
        detail::synth_log("[Structor] Failed to apply type: %s\n", reason.c_str());
    }
    
    // Step 4: Apply any additional inferred types if we have type inference results
    if (config_.apply_inferred_types && last_type_inference_.has_value()) {
        z3::TypeApplicationResult infer_app = z3::apply_inferred_types(
            cfunc, *last_type_inference_, config_.type_application_config);
        
        // Merge results (skip the variable we just typed)
        for (auto& at : infer_app.applied) {
            if (at.var_idx != var_idx) {
                app_result.applied.push_back(std::move(at));
                app_result.applied_count++;
            }
        }
        for (auto& ft : infer_app.failed) {
            if (ft.var_idx != var_idx) {
                app_result.failed.push_back(std::move(ft));
                app_result.failed_count++;
            }
        }
        for (auto& st : infer_app.skipped) {
            if (st.var_idx != var_idx) {
                app_result.skipped.push_back(std::move(st));
                app_result.skipped_count++;
            }
        }
    }
    
    // Step 5: Propagate types if configured
    if (config_.type_application_config.propagate_types && applied) {
        TypePropagator propagator;
        PropagationResult prop = propagator.propagate(
            cfunc->entry_ea, var_idx, ptr_type, PropagationDirection::Both);

        app_result.propagation = prop;
        app_result.propagated_count = prop.success_count;
        
        if (prop.success_count > 0) {
            detail::synth_log("[Structor] Propagated type to %d locations\n", 
                             prop.success_count);
        }
    }
    
    // Step 6: Refresh decompiler
    applicator.refresh_decompiler(cfunc);
    
    return app_result;
}

} // namespace structor
