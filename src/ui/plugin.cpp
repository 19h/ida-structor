/// @file plugin.cpp
/// @brief Main plugin entry point for Structor

#include <structor/synth_types.hpp>
#include <structor/config.hpp>
#include <structor/host_integration.hpp>
#include <structor/ui_integration.hpp>
#include <structor/api.hpp>
#include <structor/type_fixer.hpp>
#if defined(STRUCTOR_LIVE_TEST_HOOKS)
#include "type_matcher_live_checks.hpp"
#include "type_application_live_checks.hpp"
#include "signature_abi_live_checks.hpp"
#include "type_query_status_live_checks.hpp"
#include "type_lattice_live_checks.hpp"
#include "../../integration_tests/assignment_order_ctree_probe.hpp"
#include "../../integration_tests/alias_flow_ctree_probe.hpp"
#endif
#include <expr.hpp>
#include <auto.hpp>
#include <name.hpp>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace structor {

namespace {

constexpr const char* kResultExportEnv = "STRUCTOR_EXPORT_LAST_RESULT";
constexpr const char* kApiCommandEnv = "STRUCTOR_AUTO_API";
constexpr const char* kApiResultExportEnv = "STRUCTOR_EXPORT_API_RESULT";

static std::string json_escape(const char* text) {
    if (!text) {
        return std::string();
    }

    std::string escaped;
    for (const unsigned char ch : std::string(text)) {
        switch (ch) {
            case '\\': escaped += "\\\\"; break;
            case '"':  escaped += "\\\""; break;
            case '\b': escaped += "\\b"; break;
            case '\f': escaped += "\\f"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default:
                if (ch < 0x20) {
                    char buf[7] = {0};
                    std::snprintf(buf, sizeof(buf), "\\u%04x", ch);
                    escaped += buf;
                } else {
                    escaped += static_cast<char>(ch);
                }
                break;
        }
    }

    return escaped;
}

static void append_json_string(std::string& out, const char* text) {
    out += '"';
    out += json_escape(text);
    out += '"';
}

static void append_json_string(std::string& out, const qstring& text) {
    append_json_string(out, text.c_str());
}

static void append_json_bool(std::string& out, bool value) {
    out += value ? "true" : "false";
}

static qstring render_type_decl(const tinfo_t& type) {
    qstring decl;
    if (!type.empty()) {
        type.print(&decl);
    }
    return decl;
}

static qstring render_func_name(ea_t ea) {
    qstring name;
    if (ea != BADADDR) {
        get_func_name(&name, ea);
    }
    return name;
}

static void append_field_json(std::string& out, const SynthField& field) {
    out += '{';

    out += "\"name\":";
    append_json_string(out, field.name);
    out += ",\"offset\":" + std::to_string(static_cast<long long>(field.offset));
    out += ",\"size\":" + std::to_string(field.size);
    out += ",\"semantic\":";
    append_json_string(out, semantic_type_str(field.semantic));
    out += ",\"type\":";
    append_json_string(out, render_type_decl(field.type));
    out += ",\"confidence\":";
    append_json_string(out, type_confidence_str(field.confidence));
    out += ",\"is_padding\":";
    append_json_bool(out, field.is_padding);
    out += ",\"is_array\":";
    append_json_bool(out, field.is_array);
    out += ",\"array_count\":" + std::to_string(field.array_count);
    out += ",\"is_union_candidate\":";
    append_json_bool(out, field.is_union_candidate);
    out += ",\"is_bitfield\":";
    append_json_bool(out, field.is_bitfield);
    out += ",\"bit_offset\":" + std::to_string(field.bit_offset);
    out += ",\"bit_size\":" + std::to_string(field.bit_size);

    out += ",\"union_members\":[";
    for (size_t i = 0; i < field.union_members.size(); ++i) {
        if (i != 0) {
            out += ',';
        }

        const auto& member = field.union_members[i];
        out += '{';
        out += "\"name\":";
        append_json_string(out, member.name);
        out += ",\"offset\":" + std::to_string(static_cast<long long>(member.offset));
        out += ",\"size\":" + std::to_string(member.size);
        out += ",\"type\":";
        append_json_string(out, render_type_decl(member.type));
        out += '}';
    }
    out += ']';

    out += '}';
}

static void append_ea_list_json(std::string& out, const qvector<ea_t>& addrs) {
    out += '[';
    for (size_t i = 0; i < addrs.size(); ++i) {
        if (i != 0) {
            out += ',';
        }

        const ea_t ea = addrs[i];
        out += '{';
        out += "\"ea\":" + std::to_string(static_cast<unsigned long long>(ea));
        out += ",\"name\":";
        append_json_string(out, render_func_name(ea));
        out += '}';
    }
    out += ']';
}

static void append_access_json(std::string& out, const FieldAccess& access) {
    out += '{';
    out += "\"ea\":" + std::to_string(static_cast<unsigned long long>(access.insn_ea));
    out += ",\"offset\":" + std::to_string(static_cast<long long>(access.offset));
    out += ",\"size\":" + std::to_string(access.size);
    out += ",\"access_type\":";
    append_json_string(out, access_type_str(access.access_type));
    out += ",\"semantic_type\":";
    append_json_string(out, semantic_type_str(access.semantic_type));
    out += ",\"type\":";
    append_json_string(out, render_type_decl(access.inferred_type));
    out += ",\"is_vtable_access\":";
    append_json_bool(out, access.is_vtable_access);
    out += ",\"vtable_slot\":" + std::to_string(static_cast<long long>(access.vtable_slot));
    out += '}';
}

static void append_access_pattern_json(std::string& out, const AccessPattern& pattern) {
    out += '{';
    out += "\"func_ea\":" + std::to_string(static_cast<unsigned long long>(pattern.func_ea));
    out += ",\"func_name\":";
    append_json_string(out, render_func_name(pattern.func_ea));
    out += ",\"var_name\":";
    append_json_string(out, pattern.var_name);
    out += ",\"var_idx\":" + std::to_string(pattern.var_idx);
    out += ",\"access_count\":" + std::to_string(pattern.accesses.size());
    out += ",\"min_offset\":" + std::to_string(static_cast<long long>(pattern.min_offset));
    out += ",\"max_offset\":" + std::to_string(static_cast<long long>(pattern.max_offset));
    out += ",\"has_vtable\":";
    append_json_bool(out, pattern.has_vtable);
    out += ",\"vtable_offset\":" + std::to_string(static_cast<long long>(pattern.vtable_offset));
    out += ",\"accesses\":[";
    for (size_t i = 0; i < pattern.accesses.size(); ++i) {
        if (i != 0) {
            out += ',';
        }
        append_access_json(out, pattern.accesses[i]);
    }
    out += ']';
    out += '}';
}

static void append_unified_pattern_json(std::string& out, const UnifiedAccessPattern& pattern) {
    out += '{';
    out += "\"access_count\":" + std::to_string(pattern.all_accesses.size());
    out += ",\"unique_access_locations\":" + std::to_string(pattern.unique_access_locations());
    out += ",\"estimated_size\":" + std::to_string(static_cast<long long>(pattern.estimated_size()));
    out += ",\"has_vtable\":";
    append_json_bool(out, pattern.has_vtable);
    out += ",\"vtable_offset\":" + std::to_string(static_cast<long long>(pattern.vtable_offset));
    out += ",\"contributing_functions\":";
    append_ea_list_json(out, pattern.contributing_functions);
    out += ",\"accesses\":[";
    for (size_t i = 0; i < pattern.all_accesses.size(); ++i) {
        if (i != 0) {
            out += ',';
        }
        append_access_json(out, pattern.all_accesses[i]);
    }
    out += ']';
    out += ",\"per_function_patterns\":[";
    for (size_t i = 0; i < pattern.per_function_patterns.size(); ++i) {
        if (i != 0) {
            out += ',';
        }
        append_access_pattern_json(out, pattern.per_function_patterns[i]);
    }
    out += ']';
    out += ",\"function_deltas\":[";
    bool first_delta = true;
    for (const auto& [func_ea, delta] : pattern.function_deltas) {
        if (!first_delta) {
            out += ',';
        }
        first_delta = false;
        out += '{';
        out += "\"func_ea\":" + std::to_string(static_cast<unsigned long long>(func_ea));
        out += ",\"func_name\":";
        append_json_string(out, render_func_name(func_ea));
        out += ",\"delta\":" + std::to_string(static_cast<long long>(delta));
        out += '}';
    }
    out += ']';
    out += ",\"flow_edges\":[";
    for (size_t i = 0; i < pattern.flow_edges.size(); ++i) {
        if (i != 0) {
            out += ',';
        }
        const auto& edge = pattern.flow_edges[i];
        out += '{';
        out += "\"caller_ea\":" + std::to_string(static_cast<unsigned long long>(edge.caller_ea));
        out += ",\"caller_name\":";
        append_json_string(out, render_func_name(edge.caller_ea));
        out += ",\"callee_ea\":" + std::to_string(static_cast<unsigned long long>(edge.callee_ea));
        out += ",\"callee_name\":";
        append_json_string(out, render_func_name(edge.callee_ea));
        out += ",\"call_site\":" + std::to_string(static_cast<unsigned long long>(edge.call_site));
        out += ",\"caller_var_idx\":" + std::to_string(edge.caller_var_idx);
        out += ",\"callee_param_idx\":" + std::to_string(edge.callee_param_idx);
        out += ",\"delta\":" + std::to_string(static_cast<long long>(edge.delta));
        out += ",\"is_direct_call\":";
        append_json_bool(out, edge.is_direct_call);
        out += '}';
    }
    out += ']';
    out += '}';
}

static void append_z3_json(std::string& out, const Z3SynthesisInfo& info) {
    out += '{';
    out += "\"status\":";
    append_json_string(out, z3_status_str(info.status));
    out += ",\"used_z3\":";
    append_json_bool(out, info.used_z3());
    out += ",\"used_fallback\":";
    append_json_bool(out, info.used_fallback());
    out += ",\"solve_time_ms\":" + std::to_string(info.solve_time_ms);
    out += ",\"candidates_selected\":" + std::to_string(info.candidates_selected);
    out += ",\"constraints_hard\":" + std::to_string(info.constraints_hard);
    out += ",\"constraints_soft\":" + std::to_string(info.constraints_soft);
    out += ",\"constraints_relaxed\":" + std::to_string(info.constraints_relaxed);
    out += ",\"arrays_detected\":" + std::to_string(info.arrays_detected);
    out += ",\"unions_created\":" + std::to_string(info.unions_created);
    out += ",\"cross_func_merged\":" + std::to_string(info.cross_func_merged);
    out += '}';
}

static void append_resource_limit_json(
    std::string& out,
    const std::optional<ResourceLimitViolation>& violation) {
    if (!violation) {
        out += "null";
        return;
    }
    out += '{';
    out += "\"kind\":";
    append_json_string(out, resource_limit_kind_str(violation->kind));
    out += ",\"configured_limit\":" +
        std::to_string(violation->configured_limit);
    out += ",\"observed_value\":" +
        std::to_string(violation->observed_value);
    out += ",\"phase\":";
    append_json_string(out, violation->phase);
    out += '}';
}

static void append_vtable_json(std::string& out, const SynthVTable& vtable) {
    out += '{';
    out += "\"name\":";
    append_json_string(out, vtable.name);
    out += ",\"tid\":" + std::to_string(static_cast<unsigned long long>(vtable.tid));
    out += ",\"slot_count\":" + std::to_string(vtable.slot_count());
    out += ",\"slots\":[";
    for (size_t i = 0; i < vtable.slots.size(); ++i) {
        if (i != 0) {
            out += ',';
        }
        const auto& slot = vtable.slots[i];
        out += '{';
        out += "\"index\":" + std::to_string(slot.index);
        out += ",\"offset\":" + std::to_string(static_cast<long long>(slot.offset));
        out += ",\"name\":";
        append_json_string(out, slot.name);
        out += ",\"signature_hint\":";
        append_json_string(out, slot.signature_hint);
        out += ",\"type\":";
        append_json_string(out, render_type_decl(slot.func_type));
        out += '}';
    }
    out += ']';
    out += '}';
}

static void append_synth_struct_json(std::string& out, const SynthStruct& synth) {
    out += '{';
    out += "\"name\":";
    append_json_string(out, synth.name);
    out += ",\"size\":" + std::to_string(synth.size);
    out += ",\"alignment\":" + std::to_string(synth.alignment);
    out += ",\"packing\":";
    if (synth.packing) {
        out += std::to_string(*synth.packing);
    } else {
        out += "null";
    }
    out += ",\"source_func_ea\":" + std::to_string(static_cast<unsigned long long>(synth.source_func));
    out += ",\"source_func_name\":";
    append_json_string(out, render_func_name(synth.source_func));
    out += ",\"source_var\":";
    append_json_string(out, synth.source_var);
    out += ",\"provenance\":";
    append_ea_list_json(out, synth.provenance);

    size_t non_padding_count = 0;
    for (const auto& field : synth.fields) {
        if (!field.is_padding) {
            ++non_padding_count;
        }
    }
    out += ",\"field_count\":" + std::to_string(synth.fields.size());
    out += ",\"non_padding_field_count\":" + std::to_string(non_padding_count);
    out += ",\"fields\":[";
    for (size_t i = 0; i < synth.fields.size(); ++i) {
        if (i != 0) {
            out += ',';
        }
        append_field_json(out, synth.fields[i]);
    }
    out += ']';
    out += ",\"vtable\":";
    if (synth.vtable.has_value()) {
        append_vtable_json(out, *synth.vtable);
    } else {
        out += "null";
    }
    out += '}';
}

static void append_synth_result_json(std::string& out, const SynthResult& result) {
    out += '{';
    out += "\"success\":";
    append_json_bool(out, result.success());
    out += ",\"error\":";
    append_json_string(out, synth_error_str(result.error));
    out += ",\"error_message\":";
    append_json_string(out, result.error_message);
    out += ",\"struct_tid\":" + std::to_string(static_cast<unsigned long long>(result.struct_tid));
    out += ",\"vtable_tid\":" + std::to_string(static_cast<unsigned long long>(result.vtable_tid));
    out += ",\"fields_created\":" + std::to_string(result.fields_created);
    out += ",\"vtable_slots\":" + std::to_string(result.vtable_slots);
    out += ",\"z3\":";
    append_z3_json(out, result.z3_info);
    out += ",\"resource_limit\":";
    append_resource_limit_json(out, result.resource_limit);
    out += ",\"propagated_to\":";
    append_ea_list_json(out, result.propagated_to);
    out += ",\"failed_sites\":";
    append_ea_list_json(out, result.failed_sites);
    out += ",\"structure\":";
    if (result.synthesized_struct) {
        append_synth_struct_json(out, *result.synthesized_struct);
    } else {
        out += "null";
    }
    out += '}';
}

static void append_variable_descriptor_json(std::string& out, const VariableDescriptor& variable) {
    out += '{';
    out += "\"func_ea\":" + std::to_string(static_cast<unsigned long long>(variable.func_ea));
    out += ",\"func_name\":";
    append_json_string(out, render_func_name(variable.func_ea));
    out += ",\"var_idx\":" + std::to_string(variable.var_idx);
    out += ",\"var_name\":";
    append_json_string(out, variable.var_name);
    out += ",\"is_argument\":";
    append_json_bool(out, variable.is_argument);
    out += ",\"current_type\":";
    append_json_string(out, render_type_decl(variable.current_type));
    out += '}';
}

static void append_type_comparison_json(std::string& out, const TypeComparisonResult& comparison) {
    out += '{';
    out += "\"difference\":";
    append_json_string(out, type_difference_str(comparison.difference));
    out += ",\"primary_reason\":";
    append_json_string(out, difference_reason_str(comparison.primary_reason));
    out += ",\"confidence\":";
    append_json_string(out, type_confidence_str(comparison.confidence));
    out += ",\"description\":";
    append_json_string(out, comparison.description);
    out += ",\"original_type\":";
    append_json_string(out, render_type_decl(comparison.original_type));
    out += ",\"inferred_type\":";
    append_json_string(out, render_type_decl(comparison.inferred_type));
    out += '}';
}

static void write_json_file(const char* path, const std::string& json) {
    if (!path || !*path) {
        return;
    }

    std::FILE* fp = std::fopen(path, "wb");
    if (!fp) {
        msg("Structor: Failed to open result export path: %s\n", path);
        return;
    }

    const size_t written = std::fwrite(json.data(), 1, json.size(), fp);
    std::fclose(fp);
    if (written != json.size()) {
        msg("Structor: Failed to write full result export: %s\n", path);
    }
}

static void append_variable_analysis_json(std::string& out, const VariableStructureAnalysisResult& analysis) {
    out += '{';
    out += "\"success\":";
    append_json_bool(out, analysis.success());
    out += ",\"error\":";
    append_json_string(out, synth_error_str(analysis.error));
    out += ",\"error_message\":";
    append_json_string(out, analysis.error_message);
    out += ",\"variable\":";
    append_variable_descriptor_json(out, analysis.variable);
    out += ",\"local_pattern\":";
    append_access_pattern_json(out, analysis.local_pattern);
    out += ",\"unified_pattern\":";
    if (analysis.unified_pattern.has_value()) {
        append_unified_pattern_json(out, *analysis.unified_pattern);
    } else {
        out += "null";
    }
    out += ",\"synthesis\":";
    append_synth_result_json(out, make_result_from_synthesis(analysis.synthesis));
    out += '}';
}

static void append_global_analysis_json(std::string& out, const GlobalStructureAnalysisResult& analysis) {
    out += '{';
    out += "\"success\":";
    append_json_bool(out, analysis.success());
    out += ",\"error\":";
    append_json_string(out, synth_error_str(analysis.error));
    out += ",\"error_message\":";
    append_json_string(out, analysis.error_message);
    out += ",\"global_ea\":" + std::to_string(static_cast<unsigned long long>(analysis.global_ea));
    out += ",\"global_name\":";
    append_json_string(out, analysis.global_name);
    out += ",\"touched_functions\":";
    append_ea_list_json(out, analysis.analysis.touched_functions);
    out += ",\"zero_delta_variables\":[";
    for (size_t i = 0; i < analysis.analysis.zero_delta_variables.size(); ++i) {
        if (i != 0) {
            out += ',';
        }
        const auto& var = analysis.analysis.zero_delta_variables[i];
        out += '{';
        out += "\"func_ea\":" + std::to_string(static_cast<unsigned long long>(var.func_ea));
        out += ",\"func_name\":";
        append_json_string(out, render_func_name(var.func_ea));
        out += ",\"var_idx\":" + std::to_string(var.var_idx);
        out += ",\"base_delta\":" + std::to_string(static_cast<long long>(var.base_delta));
        out += '}';
    }
    out += ']';
    out += ",\"pointer_alias_globals\":[";
    bool first = true;
    for (const auto& [alias_ea, delta] : analysis.analysis.pointer_alias_globals) {
        if (!first) {
            out += ',';
        }
        first = false;
        out += '{';
        out += "\"ea\":" + std::to_string(static_cast<unsigned long long>(alias_ea));
        out += ",\"name\":";
        qstring alias_name;
        get_name(&alias_name, alias_ea);
        append_json_string(out, alias_name);
        out += ",\"delta\":" + std::to_string(static_cast<long long>(delta));
        out += '}';
    }
    out += ']';
    out += ",\"pattern\":";
    append_unified_pattern_json(out, analysis.analysis.pattern);
    out += ",\"synthesis\":";
    append_synth_result_json(out, make_result_from_synthesis(analysis.synthesis));
    out += '}';
}

static void append_propagation_result_json(std::string& out, const PropagationResult& propagation) {
    out += '{';
    out += "\"success_count\":" + std::to_string(propagation.success_count);
    out += ",\"failure_count\":" + std::to_string(propagation.failure_count);
    out += ",\"incomplete\":";
    append_json_bool(out, propagation.incomplete);
    out += ",\"error_message\":";
    append_json_string(out, propagation.error_message);
    out += ",\"sites\":[";
    for (size_t i = 0; i < propagation.sites.size(); ++i) {
        if (i != 0) {
            out += ',';
        }
        const auto& site = propagation.sites[i];
        out += '{';
        out += "\"func_ea\":" + std::to_string(static_cast<unsigned long long>(site.func_ea));
        out += ",\"func_name\":";
        append_json_string(out, render_func_name(site.func_ea));
        out += ",\"var_idx\":" + std::to_string(site.var_idx);
        out += ",\"var_name\":";
        append_json_string(out, site.var_name);
        out += ",\"direction\":";
        append_json_string(out,
            site.direction == PropagationDirection::Forward ? "forward" :
            site.direction == PropagationDirection::Backward ? "backward" : "both");
        out += ",\"success\":";
        append_json_bool(out, site.success);
        out += ",\"old_type\":";
        append_json_string(out, render_type_decl(site.old_type));
        out += ",\"new_type\":";
        append_json_string(out, render_type_decl(site.new_type));
        out += ",\"failure_reason\":";
        append_json_string(out, site.failure_reason);
        out += '}';
    }
    out += ']';
    out += '}';
}

static void append_type_fix_result_json(std::string& out, const TypeFixResult& result) {
    out += '{';
    out += "\"success\":";
    append_json_bool(out, result.success());
    out += ",\"func_ea\":" + std::to_string(static_cast<unsigned long long>(result.func_ea));
    out += ",\"func_name\":";
    append_json_string(out, result.func_name);
    out += ",\"total_variables\":" + std::to_string(result.total_variables);
    out += ",\"analyzed\":" + std::to_string(result.analyzed);
    out += ",\"differences_found\":" + std::to_string(result.differences_found);
    out += ",\"fixes_applied\":" + std::to_string(result.fixes_applied);
    out += ",\"fixes_skipped\":" + std::to_string(result.fixes_skipped);
    out += ",\"structures_synthesized\":" + std::to_string(result.structures_synthesized);
    out += ",\"propagated_count\":" + std::to_string(result.propagated_count);
    out += ",\"warnings\":[";
    for (size_t i = 0; i < result.warnings.size(); ++i) {
        if (i != 0) {
            out += ',';
        }
        append_json_string(out, result.warnings[i]);
    }
    out += ']';
    out += ",\"diagnostics\":[";
    for (size_t i = 0; i < result.diagnostics.size(); ++i) {
        if (i != 0) {
            out += ',';
        }
        append_json_string(out, result.diagnostics[i]);
    }
    out += ']';
    out += ",\"variable_fixes\":[";
    for (size_t i = 0; i < result.variable_fixes.size(); ++i) {
        if (i != 0) {
            out += ',';
        }
        const auto& fix = result.variable_fixes[i];
        out += '{';
        out += "\"var_idx\":" + std::to_string(fix.var_idx);
        out += ",\"var_name\":";
        append_json_string(out, fix.var_name);
        out += ",\"applied\":";
        append_json_bool(out, fix.applied);
        out += ",\"skip_reason\":";
        append_json_string(out, fix.skip_reason);
        out += ",\"synthesized_struct_tid\":" + std::to_string(static_cast<unsigned long long>(fix.synthesized_struct_tid));
        out += ",\"comparison\":";
        append_type_comparison_json(out, fix.comparison);
        out += '}';
    }
    out += ']';
    out += '}';
}

static void append_rewrite_result_json(std::string& out, const RewriteResult& result) {
    out += '{';
    out += "\"success_count\":" + std::to_string(result.success_count);
    out += ",\"failure_count\":" + std::to_string(result.failure_count);
    out += ",\"refresh_required\":";
    append_json_bool(out, result.refresh_required);
    out += ",\"transforms\":[";
    for (size_t i = 0; i < result.transforms.size(); ++i) {
        if (i != 0) {
            out += ',';
        }
        const auto& transform = result.transforms[i];
        out += '{';
        out += "\"ea\":" + std::to_string(static_cast<unsigned long long>(transform.insn_ea));
        out += ",\"original_expr\":";
        append_json_string(out, transform.original_expr);
        out += ",\"rewritten_expr\":";
        append_json_string(out, transform.rewritten_expr);
        out += ",\"success\":";
        append_json_bool(out, transform.success);
        out += ",\"failure_reason\":";
        append_json_string(out, transform.failure_reason);
        out += '}';
    }
    out += ']';
    out += '}';
}

static void append_function_structure_analysis_json(std::string& out, const FunctionStructureAnalysisResult& result) {
    out += '{';
    out += "\"success\":";
    append_json_bool(out, result.success());
    out += ",\"error\":";
    append_json_string(out, synth_error_str(result.error));
    out += ",\"error_message\":";
    append_json_string(out, result.error_message);
    out += ",\"func_ea\":" + std::to_string(static_cast<unsigned long long>(result.func_ea));
    out += ",\"func_name\":";
    append_json_string(out, result.func_name);
    out += ",\"total_variables\":" + std::to_string(result.total_variables);
    out += ",\"analyzed\":" + std::to_string(result.analyzed);
    out += ",\"succeeded\":" + std::to_string(result.succeeded);
    out += ",\"failed\":" + std::to_string(result.failed);
    out += ",\"variables\":[";
    for (size_t i = 0; i < result.variables.size(); ++i) {
        if (i != 0) {
            out += ',';
        }
        append_variable_analysis_json(out, result.variables[i]);
    }
    out += ']';
    out += '}';
}

static void append_function_structure_synthesis_json(std::string& out, const FunctionStructureSynthesisResult& result) {
    out += '{';
    out += "\"success\":";
    append_json_bool(out, result.success());
    out += ",\"error\":";
    append_json_string(out, synth_error_str(result.error));
    out += ",\"error_message\":";
    append_json_string(out, result.error_message);
    out += ",\"func_ea\":" + std::to_string(static_cast<unsigned long long>(result.func_ea));
    out += ",\"func_name\":";
    append_json_string(out, result.func_name);
    out += ",\"mode\":";
    append_json_string(out, materialization_mode_str(result.mode));
    out += ",\"total_variables\":" + std::to_string(result.total_variables);
    out += ",\"attempted\":" + std::to_string(result.attempted);
    out += ",\"succeeded\":" + std::to_string(result.succeeded);
    out += ",\"failed\":" + std::to_string(result.failed);
    out += ",\"skipped\":" + std::to_string(result.skipped);
    out += ",\"variables\":[";
    for (size_t i = 0; i < result.variables.size(); ++i) {
        if (i != 0) {
            out += ',';
        }
        out += '{';
        out += "\"variable\":";
        append_variable_descriptor_json(out, result.variables[i].variable);
        out += ",\"synthesis\":";
        append_synth_result_json(out, result.variables[i].synthesis);
        out += '}';
    }
    out += ']';
    out += '}';
}

static void maybe_export_last_result(const SynthResult& result, const char* mode) {
    const char* path = std::getenv(kResultExportEnv);
    if (!path || !*path) {
        return;
    }

    std::string json;
    json.reserve(4096);
    json += '{';
    json += "\"version\":1";
    json += ",\"mode\":";
    append_json_string(json, mode ? mode : "unknown");
    json += ",\"success\":";
    append_json_bool(json, result.success());
    json += ",\"error\":";
    append_json_string(json, synth_error_str(result.error));
    json += ",\"error_message\":";
    append_json_string(json, result.error_message);
    json += ",\"struct_tid\":" + std::to_string(static_cast<unsigned long long>(result.struct_tid));
    json += ",\"vtable_tid\":" + std::to_string(static_cast<unsigned long long>(result.vtable_tid));
    json += ",\"fields_created\":" + std::to_string(result.fields_created);
    json += ",\"vtable_slots\":" + std::to_string(result.vtable_slots);

    json += ",\"z3\":{";
    json += "\"status\":";
    append_json_string(json, z3_status_str(result.z3_info.status));
    json += ",\"used_z3\":";
    append_json_bool(json, result.z3_info.used_z3());
    json += ",\"used_fallback\":";
    append_json_bool(json, result.z3_info.used_fallback());
    json += ",\"solve_time_ms\":" + std::to_string(result.z3_info.solve_time_ms);
    json += ",\"candidates_generated\":" + std::to_string(result.z3_info.candidates_generated);
    json += ",\"candidates_selected\":" + std::to_string(result.z3_info.candidates_selected);
    json += ",\"constraints_hard\":" + std::to_string(result.z3_info.constraints_hard);
    json += ",\"constraints_soft\":" + std::to_string(result.z3_info.constraints_soft);
    json += ",\"constraints_relaxed\":" + std::to_string(result.z3_info.constraints_relaxed);
    json += ",\"arrays_detected\":" + std::to_string(result.z3_info.arrays_detected);
    json += ",\"unions_created\":" + std::to_string(result.z3_info.unions_created);
    json += ",\"cross_func_merged\":" + std::to_string(result.z3_info.cross_func_merged);
    json += '}';

    json += ",\"resource_limit\":";
    append_resource_limit_json(json, result.resource_limit);

    json += ",\"propagated_to\":";
    append_ea_list_json(json, result.propagated_to);
    json += ",\"failed_sites\":";
    append_ea_list_json(json, result.failed_sites);

    json += ",\"structure\":";
    if (!result.synthesized_struct) {
        json += "null";
    } else {
        const SynthStruct& synth = *result.synthesized_struct;
        json += '{';
        json += "\"name\":";
        append_json_string(json, synth.name);
        json += ",\"size\":" + std::to_string(synth.size);
        json += ",\"alignment\":" + std::to_string(synth.alignment);
        json += ",\"packing\":";
        if (synth.packing) {
            json += std::to_string(*synth.packing);
        } else {
            json += "null";
        }
        json += ",\"source_func_ea\":" + std::to_string(static_cast<unsigned long long>(synth.source_func));
        json += ",\"source_func_name\":";
        append_json_string(json, render_func_name(synth.source_func));
        json += ",\"source_var\":";
        append_json_string(json, synth.source_var);
        json += ",\"provenance\":";
        append_ea_list_json(json, synth.provenance);

        size_t non_padding_count = 0;
        for (const auto& field : synth.fields) {
            if (!field.is_padding) {
                ++non_padding_count;
            }
        }
        json += ",\"field_count\":" + std::to_string(synth.fields.size());
        json += ",\"non_padding_field_count\":" + std::to_string(non_padding_count);

        json += ",\"fields\":[";
        for (size_t i = 0; i < synth.fields.size(); ++i) {
            if (i != 0) {
                json += ',';
            }
            append_field_json(json, synth.fields[i]);
        }
        json += ']';

        json += ",\"vtable\":";
        if (!synth.vtable.has_value()) {
            json += "null";
        } else {
            const SynthVTable& vtable = *synth.vtable;
            json += '{';
            json += "\"name\":";
            append_json_string(json, vtable.name);
            json += ",\"tid\":" + std::to_string(static_cast<unsigned long long>(vtable.tid));
            json += ",\"slot_count\":" + std::to_string(vtable.slot_count());
            json += ",\"slots\":[";
            for (size_t i = 0; i < vtable.slots.size(); ++i) {
                if (i != 0) {
                    json += ',';
                }

                const auto& slot = vtable.slots[i];
                json += '{';
                json += "\"index\":" + std::to_string(slot.index);
                json += ",\"offset\":" + std::to_string(static_cast<long long>(slot.offset));
                json += ",\"name\":";
                append_json_string(json, slot.name);
                json += ",\"signature_hint\":";
                append_json_string(json, slot.signature_hint);
                json += ",\"type\":";
                append_json_string(json, render_type_decl(slot.func_type));
                json += '}';
            }
            json += ']';
            json += '}';
        }

        json += '}';
    }

    json += '}';
    json += '\n';
    write_json_file(path, json);
}

static bool resolve_function_target(const qstring& requested_name, ea_t& resolved_ea) {
    resolved_ea = BADADDR;
    if (requested_name.empty()) {
        return false;
    }

    resolved_ea = get_name_ea(BADADDR, requested_name.c_str());
    if (resolved_ea != BADADDR) {
        return true;
    }

    if (requested_name[0] != '_') {
        qstring alt_name("_");
        alt_name.append(requested_name);
        resolved_ea = get_name_ea(BADADDR, alt_name.c_str());
        if (resolved_ea != BADADDR) {
            return true;
        }
    }

    return false;
}

static bool resolve_function_spec(const qstring& requested, ea_t& resolved_ea) {
    resolved_ea = BADADDR;
    if (requested.empty()) {
        return false;
    }

    char* endptr = nullptr;
    unsigned long long parsed = strtoull(requested.c_str(), &endptr, 0);
    if (endptr && *endptr == '\0') {
        resolved_ea = static_cast<ea_t>(parsed);
        return true;
    }

    return resolve_function_target(requested, resolved_ea);
}

static bool resolve_global_spec(const qstring& requested, ea_t& resolved_ea) {
    resolved_ea = BADADDR;
    if (requested.empty()) {
        return false;
    }

    char* endptr = nullptr;
    unsigned long long parsed = strtoull(requested.c_str(), &endptr, 0);
    if (endptr && *endptr == '\0') {
        resolved_ea = static_cast<ea_t>(parsed);
        return true;
    }

    resolved_ea = lookup_global_symbol_ea(requested.c_str());
    return resolved_ea != BADADDR;
}

static std::vector<std::string> split_command(const char* text, char delim) {
    std::vector<std::string> parts;
    if (!text) {
        return parts;
    }

    const char* start = text;
    const char* cursor = text;
    while (*cursor) {
        if (*cursor == delim) {
            parts.emplace_back(start, static_cast<size_t>(cursor - start));
            start = cursor + 1;
        }
        ++cursor;
    }
    parts.emplace_back(start, static_cast<size_t>(cursor - start));
    return parts;
}

static bool parse_selector(cfunc_t* cfunc, const std::string& selector, int& var_idx, qstring& error) {
    var_idx = -1;
    error.clear();
    if (!cfunc || selector.empty()) {
        error = "Missing variable selector";
        return false;
    }

    char* endptr = nullptr;
    long parsed = std::strtol(selector.c_str(), &endptr, 0);
    if (endptr && *endptr == '\0') {
        var_idx = static_cast<int>(parsed);
        lvars_t* lvars = cfunc->get_lvars();
        if (!lvars || var_idx < 0 || static_cast<size_t>(var_idx) >= lvars->size()) {
            error = "Invalid variable index";
            return false;
        }
        return true;
    }

    lvar_t* var = utils::find_lvar_by_name(cfunc, selector.c_str());
    if (!var) {
        error.sprnt("Variable '%s' not found", selector.c_str());
        return false;
    }

    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars) {
        error = "Failed to get local variables";
        return false;
    }

    for (size_t i = 0; i < lvars->size(); ++i) {
        if (&lvars->at(i) == var) {
            var_idx = static_cast<int>(i);
            return true;
        }
    }

    error = "Variable index lookup failed";
    return false;
}

static bool parse_materialization_mode(const std::string& text, MaterializationMode& mode) {
    if (text == "preview") {
        mode = MaterializationMode::Preview;
        return true;
    }
    if (text == "persist") {
        mode = MaterializationMode::Persist;
        return true;
    }
    if (text == "apply" || text == "persist_and_apply") {
        mode = MaterializationMode::PersistAndApply;
        return true;
    }
    return false;
}

static void maybe_export_api_json(const std::string& json) {
    const char* path = std::getenv(kApiResultExportEnv);
    if (!path || !*path) {
        return;
    }
    write_json_file(path, json);
}

static void export_api_error(const char* command, const qstring& error_message) {
    std::string json;
    json += '{';
    json += "\"version\":1";
    json += ",\"command\":";
    append_json_string(json, command ? command : "unknown");
    json += ",\"success\":false";
    json += ",\"error_message\":";
    append_json_string(json, error_message);
    json += '}';
    json += '\n';
    maybe_export_api_json(json);
}

static void export_api_json(const char* command, const std::string& payload) {
    std::string json;
    json += '{';
    json += "\"version\":1";
    json += ",\"command\":";
    append_json_string(json, command ? command : "unknown");
    if (!payload.empty()) {
        json += ',';
        json += payload;
    }
    json += '}';
    json += '\n';
    maybe_export_api_json(json);
}

static bool run_pending_api_command_impl(const qstring& command_text) {
    std::vector<std::string> parts = split_command(command_text.c_str(), '|');
    if (parts.empty() || parts[0].empty()) {
        export_api_error("unknown", "Empty API command");
        return false;
    }

    const std::string& command = parts[0];
    StructorAPI& api = StructorAPI::instance();
    SynthOptions opts = Config::instance().options();
    opts.interactive_mode = false;
    opts.auto_open_struct = false;
    opts.highlight_changes = false;

    auto_wait();

    auto resolve_var_target = [&](qstring& func_name, ea_t& func_ea, int& var_idx) -> bool {
        qstring error;
        if (parts.size() < 3) {
            export_api_error(command.c_str(), "Missing function or variable selector");
            return false;
        }

        func_name = parts[1].c_str();
        if (!resolve_function_spec(func_name, func_ea)) {
            error.sprnt("Function '%s' not found", func_name.c_str());
            export_api_error(command.c_str(), error);
            return false;
        }

        cfuncptr_t cfunc = utils::get_cfunc(func_ea);
        if (!cfunc) {
            export_api_error(command.c_str(), "Failed to decompile function");
            return false;
        }

        if (!parse_selector(cfunc, parts[2], var_idx, error)) {
            export_api_error(command.c_str(), error);
            return false;
        }
        return true;
    };

    auto resolve_global_target = [&](qstring& global_name, ea_t& global_ea) -> bool {
        if (parts.size() < 2) {
            export_api_error(command.c_str(), "Missing global target");
            return false;
        }

        global_name = parts[1].c_str();
        if (!resolve_global_spec(global_name, global_ea)) {
            qstring error;
            error.sprnt("Global '%s' not found", global_name.c_str());
            export_api_error(command.c_str(), error);
            return false;
        }
        return true;
    };

    if (command == "collect_accesses") {
        qstring func_name;
        ea_t func_ea = BADADDR;
        int var_idx = -1;
        if (!resolve_var_target(func_name, func_ea, var_idx)) {
            return false;
        }

        AccessPattern pattern = api.collect_accesses(func_ea, var_idx);
        std::string payload = "\"success\":true,\"pattern\":";
        append_access_pattern_json(payload, pattern);
        export_api_json(command.c_str(), payload);
        return true;
    }

    if (command == "collect_unified") {
        qstring func_name;
        ea_t func_ea = BADADDR;
        int var_idx = -1;
        if (!resolve_var_target(func_name, func_ea, var_idx)) {
            return false;
        }

        UnifiedAccessPattern pattern = api.collect_unified_accesses(func_ea, var_idx, &opts);
        std::string payload = "\"success\":true,\"pattern\":";
        append_unified_pattern_json(payload, pattern);
        export_api_json(command.c_str(), payload);
        return true;
    }

    if (command == "detect_vtable") {
        qstring func_name;
        ea_t func_ea = BADADDR;
        int var_idx = -1;
        if (!resolve_var_target(func_name, func_ea, var_idx)) {
            return false;
        }

        AccessPattern pattern = api.collect_accesses(func_ea, var_idx);
        auto vtable = api.detect_vtable(pattern, func_ea);
        std::string payload = "\"success\":";
        append_json_bool(payload, vtable.has_value());
        payload += ",\"pattern\":";
        append_access_pattern_json(payload, pattern);
        payload += ",\"vtable\":";
        if (vtable.has_value()) {
            append_vtable_json(payload, *vtable);
        } else {
            payload += "null";
        }
        export_api_json(command.c_str(), payload);
        return vtable.has_value();
    }

    if (command == "synthesize_layout_local") {
        qstring func_name;
        ea_t func_ea = BADADDR;
        int var_idx = -1;
        if (!resolve_var_target(func_name, func_ea, var_idx)) {
            return false;
        }

        AccessPattern pattern = api.collect_accesses(func_ea, var_idx);
        SynthStruct layout = api.synthesize_layout(pattern, &opts);
        std::string payload = "\"success\":";
        append_json_bool(payload, !layout.fields.empty());
        payload += ",\"pattern\":";
        append_access_pattern_json(payload, pattern);
        payload += ",\"structure\":";
        if (!layout.fields.empty()) {
            append_synth_struct_json(payload, layout);
        } else {
            payload += "null";
        }
        export_api_json(command.c_str(), payload);
        return !layout.fields.empty();
    }

    if (command == "synthesize_layout_unified") {
        qstring func_name;
        ea_t func_ea = BADADDR;
        int var_idx = -1;
        if (!resolve_var_target(func_name, func_ea, var_idx)) {
            return false;
        }

        UnifiedAccessPattern pattern = api.collect_unified_accesses(func_ea, var_idx, &opts);
        SynthesisResult synthesis = api.synthesize_layout(pattern, &opts);
        std::string payload = "\"success\":";
        append_json_bool(payload, synthesis.success());
        payload += ",\"pattern\":";
        append_unified_pattern_json(payload, pattern);
        payload += ",\"result\":";
        append_synth_result_json(payload, make_result_from_synthesis(synthesis));
        export_api_json(command.c_str(), payload);
        return synthesis.success();
    }

    if (command == "analyze_structure") {
        qstring func_name;
        ea_t func_ea = BADADDR;
        int var_idx = -1;
        if (!resolve_var_target(func_name, func_ea, var_idx)) {
            return false;
        }

        VariableStructureAnalysisResult analysis = api.analyze_structure(func_ea, var_idx, &opts);
        std::string payload = "\"success\":";
        append_json_bool(payload, analysis.success());
        payload += ",\"analysis\":";
        append_variable_analysis_json(payload, analysis);
        export_api_json(command.c_str(), payload);
        return analysis.success();
    }

    if (command == "synthesize_structure") {
        qstring func_name;
        ea_t func_ea = BADADDR;
        int var_idx = -1;
        if (!resolve_var_target(func_name, func_ea, var_idx)) {
            return false;
        }
        if (parts.size() < 4) {
            export_api_error(command.c_str(), "Missing materialization mode");
            return false;
        }

        MaterializationMode mode;
        if (!parse_materialization_mode(parts[3], mode)) {
            export_api_error(command.c_str(), "Invalid materialization mode");
            return false;
        }

        VariableDescriptor variable;
        if (cfuncptr_t cfunc = utils::get_cfunc(func_ea)) {
            variable = make_variable_descriptor(cfunc, var_idx);
        }
        SynthResult synth = api.synthesize_structure(func_ea, var_idx, mode, &opts);
        std::string payload = "\"mode\":";
        append_json_string(payload, materialization_mode_str(mode));
        payload += ",\"variable\":";
        append_variable_descriptor_json(payload, variable);
        payload += ",\"result\":";
        append_synth_result_json(payload, synth);
        export_api_json(command.c_str(), payload);
        return synth.success();
    }

    if (command == "analyze_function_structures") {
        if (parts.size() < 2) {
            export_api_error(command.c_str(), "Missing function target");
            return false;
        }
        qstring func_name = parts[1].c_str();
        ea_t func_ea = BADADDR;
        if (!resolve_function_spec(func_name, func_ea)) {
            qstring error;
            error.sprnt("Function '%s' not found", func_name.c_str());
            export_api_error(command.c_str(), error);
            return false;
        }

        FunctionStructureAnalysisResult result = api.analyze_function_structures(func_ea, &opts);
        std::string payload = "\"result\":";
        append_function_structure_analysis_json(payload, result);
        export_api_json(command.c_str(), payload);
        return result.success();
    }

    if (command == "synthesize_function_structures") {
        if (parts.size() < 3) {
            export_api_error(command.c_str(), "Missing function target or mode");
            return false;
        }
        qstring func_name = parts[1].c_str();
        ea_t func_ea = BADADDR;
        if (!resolve_function_spec(func_name, func_ea)) {
            qstring error;
            error.sprnt("Function '%s' not found", func_name.c_str());
            export_api_error(command.c_str(), error);
            return false;
        }

        MaterializationMode mode;
        if (!parse_materialization_mode(parts[2], mode)) {
            export_api_error(command.c_str(), "Invalid materialization mode");
            return false;
        }

        FunctionStructureSynthesisResult result = api.synthesize_function_structures(func_ea, mode, &opts);
        std::string payload = "\"result\":";
        append_function_structure_synthesis_json(payload, result);
        export_api_json(command.c_str(), payload);
        return result.success();
    }

    if (command == "analyze_global_structure") {
        qstring global_name;
        ea_t global_ea = BADADDR;
        if (!resolve_global_target(global_name, global_ea)) {
            return false;
        }

        GlobalStructureAnalysisResult analysis = api.analyze_global_structure(global_ea, &opts);
        std::string payload = "\"analysis\":";
        append_global_analysis_json(payload, analysis);
        export_api_json(command.c_str(), payload);
        return analysis.success();
    }

    if (command == "synthesize_global_structure") {
        qstring global_name;
        ea_t global_ea = BADADDR;
        if (!resolve_global_target(global_name, global_ea)) {
            return false;
        }
        if (parts.size() < 3) {
            export_api_error(command.c_str(), "Missing materialization mode");
            return false;
        }

        MaterializationMode mode;
        if (!parse_materialization_mode(parts[2], mode)) {
            export_api_error(command.c_str(), "Invalid materialization mode");
            return false;
        }

        SynthResult synth = api.synthesize_global_structure(global_ea, mode, &opts);
        std::string payload = "\"mode\":";
        append_json_string(payload, materialization_mode_str(mode));
        payload += ",\"global_ea\":" + std::to_string(static_cast<unsigned long long>(global_ea));
        payload += ",\"global_name\":";
        append_json_string(payload, global_name);
        payload += ",\"result\":";
        append_synth_result_json(payload, synth);
        export_api_json(command.c_str(), payload);
        return synth.success();
    }

#if defined(STRUCTOR_LIVE_TEST_HOOKS)
    if (command == "inspect_array_layout") {
        if (parts.size() != 2 ||
            (parts[1] != "independent" && parts[1] != "overlay" &&
             parts[1] != "overlay_reverse" && parts[1] != "sparse" &&
             parts[1] != "interior_conflict" &&
             parts[1] != "unsat" && parts[1] != "unsat_relaxation")) {
            export_api_error(command.c_str(), "Expected independent, overlay, overlay_reverse, sparse, interior_conflict, unsat, or unsat_relaxation");
            return false;
        }
        UnifiedAccessPattern pattern;
        const auto add_access = [&](sval_t offset, bool floating) {
            FieldAccess access;
            access.offset = offset;
            access.size = 4;
            access.access_type = AccessType::Read;
            access.semantic_type = floating ? SemanticType::Float : SemanticType::Integer;
            access.inferred_type.create_simple_type(floating ? BTF_FLOAT : BTF_INT32);
            pattern.all_accesses.push_back(access);
            pattern.global_max_offset = std::max(pattern.global_max_offset, offset + 4);
        };
        const bool expect_unsat = parts[1] == "unsat" || parts[1] == "unsat_relaxation";
        if (expect_unsat) {
            add_access(0, false);
            add_access(0, true);
        } else if (parts[1] == "sparse") {
            for (const sval_t offset : {0, 4, 12}) add_access(offset, false);
        } else if (parts[1] == "interior_conflict") {
            for (const sval_t offset : {0, 4, 8}) add_access(offset, false);
            add_access(8, true);
        } else {
            for (const sval_t offset : {0, 4, 8}) add_access(offset, false);
            const sval_t base = parts[1] == "independent" ? 12 : 0;
            for (const sval_t offset : {0, 4, 8}) add_access(base + offset, true);
        }
        if (parts[1] == "overlay_reverse") {
            std::reverse(pattern.all_accesses.begin(), pattern.all_accesses.end());
        }
        opts.z3.mode = Z3SynthesisMode::Required;
        opts.z3.detect_arrays = true;
        opts.z3.allow_unions = true;
        opts.z3.cross_function = false;
        opts.vtable_detection = false;
        if (expect_unsat) {
            opts.z3.detect_arrays = false;
            opts.z3.allow_unions = false;
            opts.z3.relax_on_unsat = parts[1] == "unsat_relaxation";
        }
        const auto synthesis = api.synthesize_layout(pattern, &opts);
        const auto detached = [](const auto& diagnostics) {
            return std::all_of(diagnostics.begin(), diagnostics.end(), [](const auto& diagnostic) {
                return !diagnostic.tracking_literal.has_value();
            });
        };
        const bool diagnostics_detached =
            detached(synthesis.unsat_core) && detached(synthesis.dropped_constraints);
        if (parts[1] == "interior_conflict") {
            bool first_integer = false, second_integer = false;
            bool union_integer = false, union_float = false;
            std::size_t storage_fields = 0;
            for (const auto& field : synthesis.structure.fields) {
                if (field.is_padding) continue;
                ++storage_fields;
                if (field.size != 4) continue;
                if (field.offset == 0 && field.type.is_integral()) first_integer = true;
                if (field.offset == 4 && field.type.is_integral()) second_integer = true;
                if (field.offset == 8 && field.is_union_candidate) {
                    for (const auto& member : field.union_members) {
                        if (member.offset != 0 || member.size != 4) continue;
                        union_integer |= member.type.is_integral();
                        union_float |= member.type.is_floating();
                    }
                }
            }
            const bool shape_valid = storage_fields == 3 && first_integer &&
                second_integer && union_integer && union_float;
            const bool success = diagnostics_detached && synthesis.success() &&
                synthesis.used_z3 && !synthesis.fell_back_to_heuristic && shape_valid;
            std::string payload = "\"success\":";
            append_json_bool(payload, success);
            payload += ",\"layout_shape_valid\":";
            append_json_bool(payload, shape_valid);
            payload += ",\"diagnostics_detached\":";
            append_json_bool(payload, diagnostics_detached);
            payload += ",\"dropped_constraints\":[";
            bool first = true;
            for (const auto& diagnostic : synthesis.dropped_constraints) {
                if (!first) payload += ',';
                first = false;
                append_json_string(payload, diagnostic.description.c_str());
            }
            payload += "],\"result\":";
            append_synth_result_json(payload, make_result_from_synthesis(synthesis));
            export_api_json(command.c_str(), payload);
            return success;
        }
        if (expect_unsat) {
            // The temporary API-owned synthesizer/context is already gone.
            // Copies and destruction must be safe for actual UNSAT diagnostics.
            const auto copy = synthesis;
            const bool success = diagnostics_detached &&
                copy.error == SynthError::Z3Unsat && !copy.unsat_core.empty() &&
                !copy.unsat_core[0].description.empty() && !copy.success();
            std::string payload = "\"success\":";
            append_json_bool(payload, success);
            payload += ",\"diagnostics_detached\":";
            append_json_bool(payload, diagnostics_detached);
            payload += ",\"unsat_core_count\":" + std::to_string(copy.unsat_core.size());
            payload += ",\"result\":";
            append_synth_result_json(payload, make_result_from_synthesis(copy));
            export_api_json(command.c_str(), payload);
            return success;
        }
        const auto array_view = [](const tinfo_t& type, uint32_t count, bool floating) {
            array_type_data_t array;
            return type.get_array_details(&array) && array.nelems == count &&
                array.elem_type.get_size() == 4 &&
                array.elem_type.is_floating() == floating &&
                (floating || array.elem_type.is_integral());
        };
        bool integer_array = false, float_array = false;
        const uint32_t count = parts[1] == "sparse" ? 4 : 3;
        for (const auto& field : synthesis.structure.fields) {
            if (field.is_padding) continue;
            if (field.offset == 0 && field.size == count * 4 &&
                field.is_array && field.array_count == count &&
                array_view(field.type, count, false)) integer_array = true;
            if (field.offset == 12 && field.size == 12 &&
                field.is_array && field.array_count == 3 &&
                array_view(field.type, 3, true)) float_array = true;
            if (field.offset == 0 && field.size == 12 && field.is_union_candidate) {
                for (const auto& member : field.union_members) {
                    if (member.offset != 0 || member.size != 12) continue;
                    integer_array |= array_view(member.type, 3, false);
                    float_array |= array_view(member.type, 3, true);
                }
            }
        }
        const bool shape_valid = integer_array && (parts[1] == "sparse" || float_array);
        const bool success = diagnostics_detached && synthesis.success() && synthesis.used_z3 &&
            !synthesis.fell_back_to_heuristic && shape_valid;
        std::string payload = "\"success\":";
        append_json_bool(payload, success);
        payload += ",\"layout_shape_valid\":";
        append_json_bool(payload, shape_valid);
        payload += ",\"diagnostics_detached\":";
        append_json_bool(payload, diagnostics_detached);
        payload += ",\"result\":";
        append_synth_result_json(payload, make_result_from_synthesis(synthesis));
        export_api_json(command.c_str(), payload);
        return success;
    }

    if (command == "inspect_type_application_identity") {
        if (parts.size() != 4) {
            export_api_error(command.c_str(), "Expected target function, source function, and case");
            return false;
        }
        ea_t target_ea = BADADDR;
        ea_t source_ea = BADADDR;
        if (!resolve_function_spec(qstring(parts[1].c_str()), target_ea) ||
            !resolve_function_spec(qstring(parts[2].c_str()), source_ea) ||
            target_ea == source_ea) {
            export_api_error(command.c_str(), "Expected two distinct functions");
            return false;
        }
        cfuncptr_t cfunc = utils::get_cfunc(target_ea);
        const auto checks = detail::run_live_type_application_check(cfunc, source_ea, parts[3]);
        const bool success = !checks.empty() &&
            std::all_of(checks.begin(), checks.end(), [](const auto& check) { return check.second; });
        std::string payload = "\"success\":";
        append_json_bool(payload, success);
        payload += ",\"checks\":{";
        bool first = true;
        for (const auto& [name, passed] : checks) {
            if (!first) payload += ',';
            first = false;
            append_json_string(payload, name);
            payload += ':';
            append_json_bool(payload, passed);
        }
        payload += '}';
        export_api_json(command.c_str(), payload);
        return success;
    }

    if (command == "inspect_existing_type_matcher") {
        const auto checks = detail::run_live_existing_type_checks();
        const bool success = !checks.empty() &&
            std::all_of(checks.begin(), checks.end(), [](const auto& check) {
                return check.second;
            });
        std::string payload = "\"success\":";
        append_json_bool(payload, success);
        payload += ",\"checks\":{";
        bool first = true;
        for (const auto& [name, passed] : checks) {
            if (!first) payload += ',';
            first = false;
            append_json_string(payload, name);
            payload += ':';
            append_json_bool(payload, passed);
        }
        payload += '}';
        export_api_json(command.c_str(), payload);
        return success;
    }
#endif

#if defined(STRUCTOR_LIVE_TEST_HOOKS)
    if (command == "check_type_lattice_materialization") {
        const auto checks = detail::run_live_type_lattice_checks();
        const bool success = !checks.empty() &&
            std::all_of(checks.begin(), checks.end(), [](const auto& check) {
                return check.second;
            });
        std::string payload = "\"success\":";
        append_json_bool(payload, success);
        payload += ",\"checks\":{";
        bool first = true;
        for (const auto& [name, passed] : checks) {
            if (!first) payload += ',';
            first = false;
            append_json_string(payload, name);
            payload += ':';
            append_json_bool(payload, passed);
        }
        payload += '}';
        export_api_json(command.c_str(), payload);
        return success;
    }

    if (command == "check_assignment_order_ctree") {
        if (parts.size() != 2) {
            export_api_error(command.c_str(), "Expected carrier function");
            return false;
        }
        ea_t func_ea = BADADDR;
        if (!resolve_function_spec(qstring(parts[1].c_str()), func_ea)) {
            export_api_error(command.c_str(), "Carrier function not found");
            return false;
        }
        cfuncptr_t cfunc = utils::get_cfunc(func_ea);
        const auto observations = testing::probe_assignment_order_ctree(cfunc);
        bool success = true;
        std::string payload = "\"evidence\":\"constructed SDK ctree\",\"cases\":[";
        for (size_t i = 0; i < observations.size(); ++i) {
            const auto& observation = observations[i];
            const bool passed = observation.matches_expected &&
                observation.original_body_restored && observation.error.empty();
            success &= passed;
            if (i != 0) payload += ',';
            payload += "{\"name\":";
            append_json_string(payload, observation.name.c_str());
            payload += ",\"passed\":";
            append_json_bool(payload, passed);
            payload += ",\"original_body_restored\":";
            append_json_bool(payload, observation.original_body_restored);
            payload += ",\"error\":";
            append_json_string(payload, observation.error.c_str());
            payload += ",\"pattern\":";
            append_access_pattern_json(payload, observation.pattern);
            payload += '}';
        }
        payload += "],\"success\":";
        append_json_bool(payload, success);
        export_api_json(command.c_str(), payload);
        return success;
    }

    if (command == "inspect_symbolic_query_status") {
        if (parts.size() != 2) {
            export_api_error(command.c_str(), "Expected function");
            return false;
        }
        ea_t function_ea = BADADDR;
        if (!resolve_function_spec(qstring(parts[1].c_str()), function_ea)) {
            export_api_error(command.c_str(), "Function not found");
            return false;
        }
        cfuncptr_t function = utils::get_cfunc(function_ea);
        if (!function) {
            export_api_error(command.c_str(), "Failed to decompile function");
            return false;
        }
        const auto* original_body = function->body.cblock;
        const auto original_arguments = function->argidx;
        std::vector<tinfo_t> original_local_types;
        for (const auto& local : *function->get_lvars()) original_local_types.push_back(local.type());
        tinfo_t original_saved_type;
        const bool had_saved_type = get_tinfo(&original_saved_type, function_ea);
        const auto observations = z3::TypeInferenceQueryStatusTestAccess::collect(function);
        bool unchanged = original_body == function->body.cblock &&
            original_arguments == function->argidx &&
            original_local_types.size() == function->get_lvars()->size();
        for (std::size_t index = 0; unchanged && index < original_local_types.size(); ++index) {
            unchanged &= original_local_types[index].equals_to((*function->get_lvars())[index].type());
        }
        tinfo_t saved_type;
        const bool has_saved_type = get_tinfo(&saved_type, function_ea);
        unchanged &= had_saved_type == has_saved_type &&
            (!has_saved_type || saved_type.equals_to(original_saved_type));
        std::string payload = "\"success\":true,\"function_unchanged\":";
        append_json_bool(payload, unchanged);
        payload += ",\"cases\":[";
        bool first = true;
        for (const auto& observation : observations) {
            if (!first) payload += ',';
            first = false;
            const auto& result = observation.result;
            payload += "{\"name\":";
            append_json_string(payload, observation.name);
            payload += ",\"status\":" + std::to_string(static_cast<unsigned>(result.status));
            payload += ",\"success\":";
            append_json_bool(payload, result.success);
            payload += ",\"inferred_type_matches\":";
            append_json_bool(payload, observation.inferred_type_matches);
            payload += ",\"used_symbolic_bounds\":";
            append_json_bool(payload, result.used_bounded_symbolic_queries);
            payload += ",\"used_explicit_candidates\":";
            append_json_bool(payload, result.used_explicit_symbolic_candidates);
            payload += ",\"bounds\":";
            if (result.symbolic_query_bounds) {
                const auto bounds = *result.symbolic_query_bounds;
                payload += "{\"depth\":" + std::to_string(bounds.max_depth) +
                    ",\"list_length\":" + std::to_string(bounds.max_list_length) +
                    ",\"expansions\":" + std::to_string(bounds.max_expansions) + '}';
            } else payload += "null";
            payload += ",\"error\":";
            append_json_string(payload, result.error_message);
            payload += ",\"solve_iterations\":" + std::to_string(result.stats.solve_iterations);
            payload += ",\"local_type_count\":" + std::to_string(result.local_types.size());
            payload += ",\"memory_type_count\":" + std::to_string(result.memory_types.size()) + '}';
        }
        payload += ']';
        export_api_json(command.c_str(), payload);
        return true;
    }

    if (command == "inspect_signature_mapping") {
        if (parts.size() != 3) {
            export_api_error(command.c_str(), "Expected function and mapping scenario");
            return false;
        }
        ea_t func_ea = BADADDR;
        if (!resolve_function_spec(qstring(parts[1].c_str()), func_ea)) {
            export_api_error(command.c_str(), "Function not found");
            return false;
        }
        cfuncptr_t cfunc = utils::get_cfunc(func_ea);
        const auto evidence = detail::run_live_signature_mapping_check(cfunc, parts[2]);
        const bool success = evidence.error.empty() && !evidence.checks.empty() &&
            std::all_of(evidence.checks.begin(), evidence.checks.end(),
                [](const auto& check) { return check.second; });
        std::string payload = "\"success\":";
        append_json_bool(payload, success);
        payload += ",\"error\":";
        append_json_string(payload, evidence.error);
        payload += ",\"checks\":{";
        bool first = true;
        for (const auto& [name, passed] : evidence.checks) {
            if (!first) payload += ',';
            first = false;
            append_json_string(payload, name);
            payload += ':';
            append_json_bool(payload, passed);
        }
        payload += "},\"argument_indexes\":[";
        first = true;
        for (const auto index : evidence.argument_indexes) {
            if (!first) payload += ',';
            first = false;
            payload += std::to_string(index);
        }
        payload += "],\"parameter_types\":[";
        first = true;
        for (const auto& type : evidence.parameter_types) {
            if (!first) payload += ',';
            first = false;
            append_json_string(payload, type);
        }
        payload += "],\"constraints\":[";
        first = true;
        for (const auto& fact : evidence.constraints) {
            if (!first) payload += ',';
            first = false;
            payload += "{\"local_index\":" + std::to_string(fact.local_index);
            payload += ",\"type\":";
            append_json_string(payload, fact.type);
            payload += ",\"is_soft\":";
            append_json_bool(payload, fact.is_soft);
            payload += ",\"weight\":" + std::to_string(fact.weight) + '}';
        }
        payload += ']';
        export_api_json(command.c_str(), payload);
        return success;
    }

    if (command == "inspect_target_calling_convention") {
        if (parts.size() != 2) {
            export_api_error(command.c_str(), "Expected function");
            return false;
        }
        ea_t func_ea = BADADDR;
        if (!resolve_function_spec(qstring(parts[1].c_str()), func_ea)) {
            export_api_error(command.c_str(), "Function not found");
            return false;
        }
        cfuncptr_t cfunc = utils::get_cfunc(func_ea);
        if (!cfunc) {
            export_api_error(command.c_str(), "Failed to decompile function");
            return false;
        }
        z3::Z3Context context;
        z3::CallingConventionDetector detector(context);
        const auto convention = detector.detect(cfunc);
        const auto detection = detector.detect_with_evidence(cfunc);
        qstring database_abi;
        const auto abi_length = get_abi_name(&database_abi);
        tinfo_t prototype;
        const bool has_prototype = cfunc->get_func_type(&prototype);
        const auto* processor = get_ph();
        std::string payload = "\"success\":true,\"convention\":";
        append_json_string(payload, detail::calling_convention_name(convention));
        payload += ",\"convention_evidence\":";
        append_json_string(payload,
            detection.evidence == z3::CallingConventionEvidence::TargetDefault ? "target_default" :
            (detection.evidence == z3::CallingConventionEvidence::RecoveredPrototype
                ? "recovered_prototype" : "unavailable"));
        payload += ",\"location_assumption\":\"standard_fixed_prototype_complete_abi_arguments\"";
        payload += ",\"processor_id\":" + std::to_string(processor ? processor->id : -1);
        payload += ",\"bitness\":" + std::to_string(inf_is_64bit() ? 64 :
            (inf_is_32bit_exactly() ? 32 : 16));
        payload += ",\"filetype\":" + std::to_string(inf_get_filetype());
        payload += ",\"database_abi\":";
        append_json_string(payload, database_abi);
        payload += ",\"abi_name_available\":";
        append_json_bool(payload, abi_length >= 0);
        payload += ",\"signature_cc\":" + std::to_string(
            has_prototype ? static_cast<unsigned>(prototype.get_cc()) : 0);
        payload += ",\"prototype_arguments\":[";
        func_type_data_t prototype_details;
        if (has_prototype && prototype.get_func_details(&prototype_details)) {
            for (std::size_t index = 0; index < prototype_details.size(); ++index) {
                if (index != 0) payload += ',';
                const auto& argument = prototype_details[index];
                payload += "{\"type\":";
                append_json_string(payload, argument.type.dstr());
                char location[256] = {};
                print_argloc(location, sizeof(location), argument.argloc,
                    static_cast<int>(argument.type.get_size()), PRALOC_STKOFF);
                payload += ",\"location\":";
                append_json_string(payload, location);
                payload += '}';
            }
        }
        payload += ']';
        qvector<z3::InferredType> scalar_model;
        scalar_model.push_back(z3::InferredType::make_base(z3::BaseType::Int32));
        scalar_model.push_back(z3::InferredType::make_base(z3::BaseType::Float64));
        scalar_model.push_back(z3::InferredType::make_ptr(z3::InferredType::make_base(z3::BaseType::Int8)));
        scalar_model.push_back(z3::InferredType::make_base(z3::BaseType::Float32));
        scalar_model.push_back(z3::InferredType::make_base(z3::BaseType::Int32));
        scalar_model.push_back(z3::InferredType::make_base(z3::BaseType::Float64));
        const auto locations = detector.get_param_locations(convention, scalar_model,
            z3::ParameterPassingMode::FixedPrototype);
        payload += ",\"scalar_model_locations\":[";
        bool first = true;
        for (const auto& location : locations) {
            if (!first) payload += ',';
            first = false;
            payload += "{\"register\":";
            if (location.is_register) append_json_string(payload, location.reg_name);
            else payload += "null";
            payload += ",\"stack_offset\":" + std::to_string(location.stack_offset) + '}';
        }
        payload += "],\"unspecified_location_count\":" + std::to_string(
            detector.get_param_locations(convention, scalar_model).size());
        export_api_json(command.c_str(), payload);
        return true;
    }

    if (command == "check_alias_flow_ctree") {
        if (parts.size() != 2) {
            export_api_error(command.c_str(), "Expected carrier function");
            return false;
        }
        ea_t func_ea = BADADDR;
        if (!resolve_function_spec(qstring(parts[1].c_str()), func_ea)) {
            export_api_error(command.c_str(), "Carrier function not found");
            return false;
        }
        cfuncptr_t cfunc = utils::get_cfunc(func_ea);
        const auto observations = testing::probe_alias_flow_ctree(cfunc);
        bool success = true;
        std::string payload = "\"evidence\":\"constructed SDK ctree\",\"cases\":[";
        for (size_t i = 0; i < observations.size(); ++i) {
            const auto& observation = observations[i];
            const bool passed = observation.matches_expected &&
                observation.original_body_restored && observation.error.empty();
            success &= passed;
            if (i != 0) payload += ',';
            payload += "{\"name\":";
            append_json_string(payload, observation.name.c_str());
            payload += ",\"passed\":";
            append_json_bool(payload, passed);
            payload += ",\"original_body_restored\":";
            append_json_bool(payload, observation.original_body_restored);
            payload += ",\"error\":";
            append_json_string(payload, observation.error.c_str());
            payload += ",\"pattern\":";
            append_access_pattern_json(payload, observation.pattern);
            payload += '}';
        }
        payload += "],\"success\":";
        append_json_bool(payload, success);
        export_api_json(command.c_str(), payload);
        return success;
    }

    if (command == "inspect_base_inference") {
        if (parts.size() < 3 || parts.size() > 4 ||
            (parts.size() == 4 && parts[3] != "ctree")) {
            export_api_error(command.c_str(), "Expected function and parameter index");
            return false;
        }
        ea_t func_ea = BADADDR;
        if (!resolve_function_spec(qstring(parts[1].c_str()), func_ea)) {
            export_api_error(command.c_str(), "Function not found");
            return false;
        }
        cfuncptr_t cfunc = utils::get_cfunc(func_ea);
        char* end = nullptr;
        const long parameter = std::strtol(parts[2].c_str(), &end, 10);
        if (!cfunc || parts[2].empty() || !end || *end != '\0' ||
            parameter < 0 || static_cast<size_t>(parameter) >= cfunc->argidx.size()) {
            export_api_error(command.c_str(), "Invalid parameter index");
            return false;
        }
        const int var_idx = cfunc->argidx[parameter];
        TypeFixerConfig fix_config;
        fix_config.dry_run = true;
        fix_config.synthesize_structures = false;
        fix_config.propagate_fixes = false;
        TypeFixer fixer(fix_config);
        const TypeComparisonResult comparison = fixer.analyze_variable(cfunc, var_idx);
        const AccessPattern pattern = api.collect_accesses(func_ea, var_idx);
        const auto pointer_depth = [](tinfo_t type) {
            unsigned depth = 0;
            while (type.is_ptr()) {
                ++depth;
                type = type.get_pointed_object();
            }
            return depth;
        };
        std::string payload = "\"success\":";
        append_json_bool(payload, !comparison.inferred_type.empty());
        payload += ",\"original_type\":";
        append_json_string(payload, render_type_decl(comparison.original_type));
        payload += ",\"inferred_type\":";
        append_json_string(payload, render_type_decl(comparison.inferred_type));
        payload += ",\"original_pointer_depth\":" +
            std::to_string(pointer_depth(comparison.original_type));
        payload += ",\"inferred_pointer_depth\":" +
            std::to_string(pointer_depth(comparison.inferred_type));
        payload += ",\"inferred_pointee_size\":" + std::to_string(
            comparison.inferred_type.is_ptr()
                ? comparison.inferred_type.get_pointed_object().get_size() : BADSIZE);
        payload += ",\"preserves_original\":";
        append_json_bool(payload,
            comparison.inferred_type.equals_to(comparison.original_type));
        payload += ",\"confidence\":";
        append_json_string(payload, type_confidence_str(comparison.confidence));
        payload += ",\"pattern\":";
        append_access_pattern_json(payload, pattern);
        if (parts.size() == 4) {
            // Optional diagnostic evidence for alias/data-flow witnesses.
            // Record actual ctree identities and parents; pseudocode alone
            // does not show whether Hex-Rays split two source-level locals.
            struct TreeEvidenceVisitor final : ctree_visitor_t {
                cfunc_t* owner;
                std::string nodes;
                std::unordered_map<const citem_t*, size_t> ids;
                bool truncated = false;

                explicit TreeEvidenceVisitor(cfunc_t* function)
                    : ctree_visitor_t(CV_PARENTS), owner(function) {}

                int record(citem_t* item, cexpr_t* expression) {
                    if (ids.size() >= 4096) {
                        truncated = true;
                        return 1;
                    }
                    const size_t id = ids.size();
                    ids.emplace(item, id);
                    if (!nodes.empty()) nodes += ',';
                    nodes += "{\"id\":" + std::to_string(id);
                    nodes += ",\"parent\":";
                    const auto parent = ids.find(parent_item());
                    nodes += parent == ids.end() ? "null" : std::to_string(parent->second);
                    nodes += ",\"opcode\":" + std::to_string(item->op);
                    nodes += ",\"expression\":";
                    append_json_bool(nodes, expression != nullptr);
                    if (expression != nullptr) {
                        nodes += ",\"operation\":";
                        append_json_string(nodes, utils::cot_name(expression->op));
                        nodes += ",\"text\":";
                        append_json_string(nodes, utils::expr_to_string(expression, owner));
                        nodes += ",\"type\":";
                        append_json_string(nodes, render_type_decl(expression->type));
                        if (expression->op == cot_var) {
                            nodes += ",\"var_idx\":" + std::to_string(expression->v.idx);
                        }
                        if (expression->op == cot_call && expression->a) {
                            nodes += ",\"arguments\":[";
                            bool first = true;
                            for (const auto& argument : *expression->a) {
                                if (!first) nodes += ',';
                                first = false;
                                nodes += "{\"text\":";
                                append_json_string(nodes, utils::expr_to_string(&argument, owner));
                                nodes += ",\"type\":";
                                append_json_string(nodes, render_type_decl(argument.type));
                                nodes += ",\"formal_type\":";
                                append_json_string(nodes, render_type_decl(argument.formal_type));
                                nodes += '}';
                            }
                            nodes += ']';
                        }
                    }
                    nodes += '}';
                    return 0;
                }
                int idaapi visit_expr(cexpr_t* expression) override {
                    return record(expression, expression);
                }
                int idaapi visit_insn(cinsn_t* instruction) override {
                    return record(instruction, nullptr);
                }
            } tree(cfunc);
            tree.apply_to(&cfunc->body, nullptr);
            payload += ",\"ctree\":[" + tree.nodes + ']';
            payload += ",\"ctree_truncated\":";
            append_json_bool(payload, tree.truncated);
        }
        export_api_json(command.c_str(), payload);
        return !comparison.inferred_type.empty();
    }
    if (command == "inspect_instruction_semantics_identity") {
        ea_t function_ea = BADADDR;
        if (parts.size() != 2 ||
            !resolve_function_spec(qstring(parts[1].c_str()), function_ea)) {
            export_api_error(command.c_str(), "Expected a function");
            return false;
        }
        cfuncptr_t cfunc = utils::get_cfunc(function_ea);
        if (!cfunc) {
            export_api_error(command.c_str(), "Failed to decompile identity fixture");
            return false;
        }
        z3::Z3Context context;
        z3::InstructionSemanticsExtractor extractor(context);
        const auto extracted = extractor.extract(cfunc);
        const bool full_extraction = extracted.hard_count() > 0 &&
            extracted.total_count() > 0 && extractor.stats().expressions_analyzed > 0;
        z3::TypeLatticeEncoder second_encoder(context);
        const bool shared_sorts =
            ::z3::eq(extractor.type_encoder().base_type_sort(), second_encoder.base_type_sort()) &&
            ::z3::eq(extractor.type_encoder().type_sort(), second_encoder.type_sort());

        const auto integer = z3::TypeVariable::for_temp(7, function_ea, "same label");
        const auto floating = z3::TypeVariable::for_temp(7, function_ea, "same label");
        z3::TypeConstraintSet independent(context);
        independent.add(z3::TypeConstraint::make_is_base(integer, z3::BaseType::Int32));
        independent.add(z3::TypeConstraint::make_is_base(floating, z3::BaseType::Float32));
        auto solver = context.make_solver();
        solver.add(independent.to_z3_hard(second_encoder));
        const bool independent_variables = independent.variables().size() == 2 &&
            solver.check() == ::z3::sat;

        z3::TypeInferenceConfig inference_config;
        inference_config.enable_experimental_pipeline = true;
        inference_config.phase_alias_analysis = false;
        inference_config.phase_soft_constraints = false;
        z3::TypeInferenceEngine engine(context, inference_config);
        const auto inference = engine.infer_function(cfunc);
        const bool engine_extraction =
            inference.status != z3::TypeInferenceStatus::InternalError &&
            inference.stats.type_constraints_hard > 0 &&
            inference.stats.variables_typed > 0;
        const bool success = full_extraction && shared_sorts &&
            independent_variables && engine_extraction;
        std::string payload = "\"success\":";
        append_json_bool(payload, success);
        payload += ",\"full_extraction\":";
        append_json_bool(payload, full_extraction);
        payload += ",\"shared_sorts\":";
        append_json_bool(payload, shared_sorts);
        payload += ",\"independent_variables\":";
        append_json_bool(payload, independent_variables);
        payload += ",\"engine_extraction\":";
        append_json_bool(payload, engine_extraction);
        payload += ",\"constraints\":" + std::to_string(extracted.total_count());
        payload += ",\"expressions\":" + std::to_string(extractor.stats().expressions_analyzed);
        payload += ",\"engine_status\":" + std::to_string(static_cast<int>(inference.status));
        payload += ",\"engine_error\":";
        append_json_string(payload, inference.error_message.c_str());
        export_api_json(command.c_str(), payload);
        return success;
    }

    if (command == "fault_global_tinfo_rollback") {
        qstring global_name;
        ea_t global_ea = BADADDR;
        if (!resolve_global_target(global_name, global_ea)) {
            return false;
        }

        tinfo_t baseline;
        baseline.create_simple_type(BTF_UINT64);
        try {
            (void)set_tinfo(global_ea, &baseline);
        } catch (...) {
        }

        tinfo_t baseline_observed;
        const bool baseline_ready =
            get_tinfo(&baseline_observed, global_ea) &&
            baseline_observed.equals_to(baseline);
        if (!baseline_ready) {
            export_api_error(command.c_str(), "Failed to establish rollback baseline type");
            return false;
        }

        const ea_t item_head_before = get_item_head(global_ea);
        const asize_t item_size_before = item_head_before == BADADDR
            ? 0
            : get_item_size(item_head_before);
        const flags64_t address_flags_before = get_flags(global_ea);
        const flags64_t head_flags_before = item_head_before == BADADDR
            ? 0
            : get_flags(item_head_before);

        tinfo_t byte_type;
        byte_type.create_simple_type(BTF_UINT8);
        tinfo_t requested;
        requested.create_ptr(byte_type);

        const bool application_reported_success =
            detail::apply_global_tinfo_transaction(
                global_ea,
                requested,
                +[](const tinfo_t&, const tinfo_t&) -> bool {
                    return false;
                });

        tinfo_t restored;
        const bool tinfo_restored =
            get_tinfo(&restored, global_ea) && restored.equals_to(baseline);
        const ea_t item_head_after = get_item_head(global_ea);
        const bool data_item_restored =
            item_head_after == item_head_before &&
            (item_head_after == BADADDR ||
             get_item_size(item_head_after) == item_size_before) &&
            get_flags(global_ea) == address_flags_before &&
            (item_head_after == BADADDR ||
             get_flags(item_head_after) == head_flags_before);
        const bool success =
            !application_reported_success &&
            tinfo_restored &&
            data_item_restored;

        std::string payload = "\"success\":";
        append_json_bool(payload, success);
        payload += ",\"application_reported_success\":";
        append_json_bool(payload, application_reported_success);
        payload += ",\"tinfo_restored\":";
        append_json_bool(payload, tinfo_restored);
        payload += ",\"data_item_restored\":";
        append_json_bool(payload, data_item_restored);
        export_api_json(command.c_str(), payload);
        return success;
    }
#endif

    if (command == "analyze_variable_type") {
        qstring func_name;
        ea_t func_ea = BADADDR;
        int var_idx = -1;
        if (!resolve_var_target(func_name, func_ea, var_idx)) {
            return false;
        }

        VariableDescriptor variable;
        if (cfuncptr_t cfunc = utils::get_cfunc(func_ea)) {
            variable = make_variable_descriptor(cfunc, var_idx);
        }
        TypeComparisonResult comparison = api.analyze_variable_type(func_ea, var_idx);
        std::string payload = "\"variable\":";
        append_variable_descriptor_json(payload, variable);
        payload += ",\"comparison\":";
        append_type_comparison_json(payload, comparison);
        export_api_json(command.c_str(), payload);
        return true;
    }

    if (command == "fix_variable_type") {
        qstring func_name;
        ea_t func_ea = BADADDR;
        int var_idx = -1;
        if (!resolve_var_target(func_name, func_ea, var_idx)) {
            return false;
        }

        VariableTypeFix fix = api.fix_variable_type(func_ea, var_idx);
        std::string payload = "\"applied\":";
        append_json_bool(payload, fix.applied);
        payload += ",\"skip_reason\":";
        append_json_string(payload, fix.skip_reason);
        payload += ",\"comparison\":";
        append_type_comparison_json(payload, fix.comparison);
        payload += ",\"propagation\":";
        append_propagation_result_json(payload, fix.propagation);
        export_api_json(command.c_str(), payload);
        return true;
    }

    if (command == "analyze_function_types") {
        if (parts.size() < 2) {
            export_api_error(command.c_str(), "Missing function target");
            return false;
        }
        qstring func_name = parts[1].c_str();
        ea_t func_ea = BADADDR;
        if (!resolve_function_spec(func_name, func_ea)) {
            qstring error;
            error.sprnt("Function '%s' not found", func_name.c_str());
            export_api_error(command.c_str(), error);
            return false;
        }

        TypeFixResult result = api.analyze_function_types(func_ea);
        std::string payload = "\"result\":";
        append_type_fix_result_json(payload, result);
        export_api_json(command.c_str(), payload);
        return result.success();
    }

    if (command == "fix_function_types") {
        if (parts.size() < 2) {
            export_api_error(command.c_str(), "Missing function target");
            return false;
        }
        qstring func_name = parts[1].c_str();
        ea_t func_ea = BADADDR;
        if (!resolve_function_spec(func_name, func_ea)) {
            qstring error;
            error.sprnt("Function '%s' not found", func_name.c_str());
            export_api_error(command.c_str(), error);
            return false;
        }

        TypeFixResult result = api.fix_function_types(func_ea);
        std::string payload = "\"result\":";
        append_type_fix_result_json(payload, result);
        export_api_json(command.c_str(), payload);
        return result.success();
    }

    if (command == "apply_synthesized_type" ||
        command == "propagate_local_synthesized_type" ||
        command == "propagate_synthesized_type" ||
        command == "rewrite_preview_structure") {
        qstring func_name;
        ea_t func_ea = BADADDR;
        int var_idx = -1;
        if (!resolve_var_target(func_name, func_ea, var_idx)) {
            return false;
        }

        if (command == "rewrite_preview_structure") {
            VariableStructureAnalysisResult analysis = api.analyze_structure(func_ea, var_idx, &opts);
            RewriteResult rewrite;
            if (analysis.success()) {
                rewrite = api.rewrite_pseudocode(func_ea, var_idx, analysis.synthesis.structure, &opts);
            }
            std::string payload = "\"analysis\":";
            append_variable_analysis_json(payload, analysis);
            payload += ",\"rewrite\":";
            append_rewrite_result_json(payload, rewrite);
            export_api_json(command.c_str(), payload);
            return analysis.success();
        }

        SynthResult synth = api.synthesize_structure(func_ea, var_idx, MaterializationMode::Persist, &opts);
        if (!synth.success() || synth.struct_tid == BADADDR) {
            std::string payload = "\"result\":";
            append_synth_result_json(payload, synth);
            export_api_json(command.c_str(), payload);
            return false;
        }

        tinfo_t type;
        if (!type.get_type_by_tid(synth.struct_tid)) {
            export_api_error(command.c_str(), "Failed to load synthesized type");
            return false;
        }

        if (command == "apply_synthesized_type") {
            bool applied = api.apply_type(func_ea, var_idx, type, &opts);
            std::string payload = "\"applied\":";
            append_json_bool(payload, applied);
            payload += ",\"result\":";
            append_synth_result_json(payload, synth);
            export_api_json(command.c_str(), payload);
            return applied;
        }

        PropagationResult propagation = command == "propagate_local_synthesized_type"
            ? api.propagate_type_local(func_ea, var_idx, type, &opts)
            : api.propagate_type(func_ea, var_idx, type, PropagationDirection::Both);
        std::string payload = "\"result\":";
        append_synth_result_json(payload, synth);
        payload += ",\"propagation\":";
        append_propagation_result_json(payload, propagation);
        export_api_json(command.c_str(), payload);
        return propagation.success_count > 0;
    }

    export_api_error(command.c_str(), "Unknown API command");
    return false;
}

static bool run_pending_api_command(const qstring& command_text) {
    try {
        return run_pending_api_command_impl(command_text);
    } catch (const vd_failure_t& e) {
        try { export_api_error("exception", e.desc()); } catch (...) {}
        return false;
    } catch (const std::exception& e) {
        try { export_api_error("exception", e.what()); } catch (...) {}
        return false;
    } catch (...) {
        try {
            export_api_error("exception", "API command raised an unknown exception");
        } catch (...) {}
        return false;
    }
}

} // namespace

// Thread-local storage for last result info (must be defined before use)
static thread_local qstring g_last_error;
static thread_local int g_last_field_count = 0;
static thread_local tid_t g_last_vtable_tid = BADADDR;

// IDC function: structor_synthesize(func_ea, var_idx) -> tid_t
static error_t idaapi idc_structor_synthesize(idc_value_t* argv, idc_value_t* res) {
    ea_t func_ea = argv[0].vtype == VT_INT64 ? argv[0].i64 : static_cast<ea_t>(argv[0].num);
    int var_idx = static_cast<int>(argv[1].num);

    // Use non-interactive options for IDC calls
    SynthOptions opts = Config::instance().options();
    opts.interactive_mode = false;
    opts.auto_open_struct = false;
    opts.highlight_changes = false;

    SynthResult result = StructorAPI::instance().synthesize_structure(func_ea, var_idx, &opts);

    // Store results for helper functions
    g_last_error = result.error_message;
    g_last_field_count = result.fields_created;
    g_last_vtable_tid = result.vtable_tid;

    if (result.success()) {
        res->set_int64(result.struct_tid);
    } else {
        if (g_last_error.empty()) {
            g_last_error = synth_error_str(result.error);
        }
        res->set_int64(BADADDR);
    }
    return eOk;
}

// IDC function: structor_synthesize_by_name(func_ea, var_name) -> tid_t
static error_t idaapi idc_structor_synthesize_by_name(idc_value_t* argv, idc_value_t* res) {
    ea_t func_ea = argv[0].vtype == VT_INT64 ? argv[0].i64 : static_cast<ea_t>(argv[0].num);
    const char* var_name = argv[1].c_str();

    SynthOptions opts = Config::instance().options();
    opts.interactive_mode = false;
    opts.auto_open_struct = false;
    opts.highlight_changes = false;
    SynthResult result = StructorAPI::instance().synthesize_structure(
        func_ea, var_name, MaterializationMode::PersistAndApply, &opts);

    // Store results for helper functions
    g_last_error = result.error_message;
    g_last_field_count = result.fields_created;
    g_last_vtable_tid = result.vtable_tid;

    if (result.success()) {
        res->set_int64(result.struct_tid);
    } else {
        if (g_last_error.empty()) {
            g_last_error = synth_error_str(result.error);
        }
        res->set_int64(BADADDR);
    }
    return eOk;
}

// IDC function: structor_synthesize_global(global_ea) -> tid_t
static error_t idaapi idc_structor_synthesize_global(idc_value_t* argv, idc_value_t* res) {
    ea_t global_ea = argv[0].vtype == VT_INT64 ? argv[0].i64 : static_cast<ea_t>(argv[0].num);

    SynthOptions opts = Config::instance().options();
    opts.interactive_mode = false;
    opts.auto_open_struct = false;
    opts.highlight_changes = false;

    SynthResult result = StructorAPI::instance().synthesize_global_structure(global_ea, &opts);

    g_last_error = result.error_message;
    g_last_field_count = result.fields_created;
    g_last_vtable_tid = result.vtable_tid;

    if (result.success()) {
        res->set_int64(result.struct_tid);
    } else {
        if (g_last_error.empty()) {
            g_last_error = synth_error_str(result.error);
        }
        res->set_int64(BADADDR);
    }
    return eOk;
}

// IDC function: structor_synthesize_global_by_name(global_name) -> tid_t
static error_t idaapi idc_structor_synthesize_global_by_name(idc_value_t* argv, idc_value_t* res) {
    const char* global_name = argv[0].c_str();

    SynthOptions opts = Config::instance().options();
    opts.interactive_mode = false;
    opts.auto_open_struct = false;
    opts.highlight_changes = false;

    SynthResult result = StructorAPI::instance().synthesize_global_structure(global_name, &opts);

    g_last_error = result.error_message;
    g_last_field_count = result.fields_created;
    g_last_vtable_tid = result.vtable_tid;

    if (result.success()) {
        res->set_int64(result.struct_tid);
    } else {
        if (g_last_error.empty()) {
            g_last_error = synth_error_str(result.error);
        }
        res->set_int64(BADADDR);
    }
    return eOk;
}

// IDC function: structor_get_error() -> string
static error_t idaapi idc_structor_get_error(idc_value_t* /*argv*/, idc_value_t* res) {
    res->set_string(g_last_error);
    return eOk;
}

// IDC function: structor_get_field_count() -> long
static error_t idaapi idc_structor_get_field_count(idc_value_t* /*argv*/, idc_value_t* res) {
    res->set_long(g_last_field_count);
    return eOk;
}

// IDC function: structor_get_vtable_tid() -> tid_t
static error_t idaapi idc_structor_get_vtable_tid(idc_value_t* /*argv*/, idc_value_t* res) {
    res->set_int64(g_last_vtable_tid);
    return eOk;
}

// Thread-local storage for type fix results
static thread_local int g_last_fix_count = 0;
static thread_local int g_last_fix_applied = 0;
static thread_local int g_last_fix_skipped = 0;
static thread_local qvector<qstring> g_last_fix_warnings;
static thread_local qvector<qstring> g_last_fix_diagnostics;

static void print_type_fix_messages(const TypeFixResult& result, bool include_diagnostics) {
    for (const auto& warning : result.warnings) {
        msg("Structor: %s\n", warning.c_str());
    }

    if (!include_diagnostics) {
        return;
    }

    for (const auto& diagnostic : result.diagnostics) {
        msg("Structor: diagnostic: %s\n", diagnostic.c_str());
    }
}

static void store_last_type_fix_result(const TypeFixResult& result, int applied_value, int skipped_value) {
    g_last_error = result.errors.empty() ? qstring() : result.errors[0];
    g_last_fix_count = result.analyzed;
    g_last_fix_applied = applied_value;
    g_last_fix_skipped = skipped_value;
    g_last_fix_warnings = result.warnings;
    g_last_fix_diagnostics = result.diagnostics;
}

static error_t idaapi idc_structor_get_fix_warning_count(idc_value_t* /*argv*/, idc_value_t* res) {
    res->set_long(static_cast<long>(g_last_fix_warnings.size()));
    return eOk;
}

static error_t idaapi idc_structor_get_fix_warning(idc_value_t* argv, idc_value_t* res) {
    int idx = static_cast<int>(argv[0].num);
    if (idx < 0 || static_cast<size_t>(idx) >= g_last_fix_warnings.size()) {
        res->set_string(qstring());
        return eOk;
    }

    res->set_string(g_last_fix_warnings[static_cast<size_t>(idx)]);
    return eOk;
}

static error_t idaapi idc_structor_get_fix_diagnostic_count(idc_value_t* /*argv*/, idc_value_t* res) {
    res->set_long(static_cast<long>(g_last_fix_diagnostics.size()));
    return eOk;
}

static error_t idaapi idc_structor_get_fix_diagnostic(idc_value_t* argv, idc_value_t* res) {
    int idx = static_cast<int>(argv[0].num);
    if (idx < 0 || static_cast<size_t>(idx) >= g_last_fix_diagnostics.size()) {
        res->set_string(qstring());
        return eOk;
    }

    res->set_string(g_last_fix_diagnostics[static_cast<size_t>(idx)]);
    return eOk;
}

// IDC function: structor_fix_function_types(func_ea) -> long (number of fixes applied)
static error_t idaapi idc_structor_fix_function_types(idc_value_t* argv, idc_value_t* res) {
    ea_t func_ea = argv[0].vtype == VT_INT64 ? argv[0].i64 : static_cast<ea_t>(argv[0].num);

    TypeFixResult result = StructorAPI::instance().fix_function_types(func_ea);

    print_type_fix_messages(result, true);

    store_last_type_fix_result(result, result.fixes_applied, result.fixes_skipped);

    res->set_long(result.fixes_applied);
    return eOk;
}

// IDC function: structor_fix_variable_type(func_ea, var_idx) -> long (1 if fixed, 0 otherwise)
static error_t idaapi idc_structor_fix_variable_type(idc_value_t* argv, idc_value_t* res) {
    ea_t func_ea = argv[0].vtype == VT_INT64 ? argv[0].i64 : static_cast<ea_t>(argv[0].num);
    int var_idx = static_cast<int>(argv[1].num);

    VariableTypeFix result = StructorAPI::instance().fix_variable_type(func_ea, var_idx);

    g_last_error = result.skip_reason;
    res->set_long(result.applied ? 1 : 0);
    return eOk;
}

// IDC function: structor_fix_variable_by_name(func_ea, var_name) -> long (1 if fixed, 0 otherwise)
static error_t idaapi idc_structor_fix_variable_by_name(idc_value_t* argv, idc_value_t* res) {
    ea_t func_ea = argv[0].vtype == VT_INT64 ? argv[0].i64 : static_cast<ea_t>(argv[0].num);
    const char* var_name = argv[1].c_str();

    VariableTypeFix result = StructorAPI::instance().fix_variable_type(func_ea, var_name);

    g_last_error = result.skip_reason;
    res->set_long(result.applied ? 1 : 0);
    return eOk;
}

// IDC function: structor_analyze_function_types(func_ea) -> long (number of differences found)
static error_t idaapi idc_structor_analyze_function_types(idc_value_t* argv, idc_value_t* res) {
    ea_t func_ea = argv[0].vtype == VT_INT64 ? argv[0].i64 : static_cast<ea_t>(argv[0].num);

    TypeFixResult result = StructorAPI::instance().analyze_function_types(func_ea);

    print_type_fix_messages(result, true);

    store_last_type_fix_result(result, result.differences_found, 0);

    res->set_long(result.differences_found);
    return eOk;
}

// IDC function: structor_get_fix_count() -> long
static error_t idaapi idc_structor_get_fix_count(idc_value_t* /*argv*/, idc_value_t* res) {
    res->set_long(g_last_fix_count);
    return eOk;
}

// IDC function: structor_get_fixes_applied() -> long
static error_t idaapi idc_structor_get_fixes_applied(idc_value_t* /*argv*/, idc_value_t* res) {
    res->set_long(g_last_fix_applied);
    return eOk;
}

// IDC function: structor_get_fixes_skipped() -> long
static error_t idaapi idc_structor_get_fixes_skipped(idc_value_t* /*argv*/, idc_value_t* res) {
    res->set_long(g_last_fix_skipped);
    return eOk;
}

// Argument type arrays for IDC functions
static const char args_synthesize[] = { VT_INT64, VT_LONG, 0 };
static const char args_synthesize_by_name[] = { VT_INT64, VT_STR, 0 };
static const char args_global_synthesize[] = { VT_INT64, 0 };
static const char args_global_synthesize_by_name[] = { VT_STR, 0 };
static const char args_no_args[] = { 0 };
static const char args_func_ea[] = { VT_INT64, 0 };
static const char args_index[] = { VT_LONG, 0 };

template <idc_func_t* Callback>
static error_t idaapi guarded_idc_callback(
    idc_value_t* argv,
    idc_value_t* res) noexcept
{
    try {
        return Callback(argv, res);
    } catch (const vd_failure_t& e) {
        try { g_last_error = e.desc(); } catch (...) {}
    } catch (const std::exception& e) {
        try { g_last_error = e.what(); } catch (...) {}
    } catch (...) {
        try { g_last_error = "IDC callback raised an unknown exception"; }
        catch (...) {}
    }
    try {
        if (res != nullptr) {
            res->set_int64(BADADDR);
        }
    } catch (...) {}
    return eOk;
}

static const ext_idcfunc_t idc_funcs[] = {
    { "structor_synthesize", guarded_idc_callback<idc_structor_synthesize>, args_synthesize, nullptr, 0, EXTFUN_BASE },
    { "structor_synthesize_by_name", guarded_idc_callback<idc_structor_synthesize_by_name>, args_synthesize_by_name, nullptr, 0, EXTFUN_BASE },
    { "structor_synthesize_global", guarded_idc_callback<idc_structor_synthesize_global>, args_global_synthesize, nullptr, 0, EXTFUN_BASE },
    { "structor_synthesize_global_by_name", guarded_idc_callback<idc_structor_synthesize_global_by_name>, args_global_synthesize_by_name, nullptr, 0, EXTFUN_BASE },
    { "structor_get_error", guarded_idc_callback<idc_structor_get_error>, args_no_args, nullptr, 0, EXTFUN_BASE },
    { "structor_get_field_count", guarded_idc_callback<idc_structor_get_field_count>, args_no_args, nullptr, 0, EXTFUN_BASE },
    { "structor_get_vtable_tid", guarded_idc_callback<idc_structor_get_vtable_tid>, args_no_args, nullptr, 0, EXTFUN_BASE },
    // Type fixing functions
    { "structor_fix_function_types", guarded_idc_callback<idc_structor_fix_function_types>, args_func_ea, nullptr, 0, EXTFUN_BASE },
    { "structor_fix_variable_type", guarded_idc_callback<idc_structor_fix_variable_type>, args_synthesize, nullptr, 0, EXTFUN_BASE },
    { "structor_fix_variable_by_name", guarded_idc_callback<idc_structor_fix_variable_by_name>, args_synthesize_by_name, nullptr, 0, EXTFUN_BASE },
    { "structor_analyze_function_types", guarded_idc_callback<idc_structor_analyze_function_types>, args_func_ea, nullptr, 0, EXTFUN_BASE },
    { "structor_get_fix_count", guarded_idc_callback<idc_structor_get_fix_count>, args_no_args, nullptr, 0, EXTFUN_BASE },
    { "structor_get_fixes_applied", guarded_idc_callback<idc_structor_get_fixes_applied>, args_no_args, nullptr, 0, EXTFUN_BASE },
    { "structor_get_fixes_skipped", guarded_idc_callback<idc_structor_get_fixes_skipped>, args_no_args, nullptr, 0, EXTFUN_BASE },
    { "structor_get_fix_warning_count", guarded_idc_callback<idc_structor_get_fix_warning_count>, args_no_args, nullptr, 0, EXTFUN_BASE },
    { "structor_get_fix_warning", guarded_idc_callback<idc_structor_get_fix_warning>, args_index, nullptr, 0, EXTFUN_BASE },
    { "structor_get_fix_diagnostic_count", guarded_idc_callback<idc_structor_get_fix_diagnostic_count>, args_no_args, nullptr, 0, EXTFUN_BASE },
    { "structor_get_fix_diagnostic", guarded_idc_callback<idc_structor_get_fix_diagnostic>, args_index, nullptr, 0, EXTFUN_BASE },
};

static constexpr std::size_t kIdcFuncCount =
    sizeof(idc_funcs) / sizeof(idc_funcs[0]);
static bool g_idc_func_registered[kIdcFuncCount] = {};

static bool unregister_idc_funcs() {
    bool removed = true;
    for (std::size_t i = kIdcFuncCount; i > 0; --i) {
        const std::size_t index = i - 1;
        if (g_idc_func_registered[index] &&
            del_idc_func(idc_funcs[index].name)) {
            g_idc_func_registered[index] = false;
        }
        removed = !g_idc_func_registered[index] && removed;
    }
    return removed;
}

static bool register_idc_funcs() {
    for (bool registered : g_idc_func_registered) {
        if (registered) {
            return false;
        }
    }
    for (std::size_t i = 0; i < kIdcFuncCount; ++i) {
        if (!add_idc_func(idc_funcs[i])) {
            (void)unregister_idc_funcs();
            return false;
        }
        g_idc_func_registered[i] = true;
    }
    return true;
}

// IDC functions and UI actions are process-global host registrations. Keep
// their lifetime independent of any one PLUGIN_MULTI database instance.
static std::size_t g_shared_service_refcount = 0;

/// Per-database plugin instance. Process-global UI/IDC registrations are
/// reference-counted separately.
class StructorPlugin : public plugmod_t, public event_listener_t {
public:
    StructorPlugin();
    ~StructorPlugin() override;

    bool idaapi run(size_t arg) override;
    ssize_t idaapi on_event(ssize_t code, va_list va) override;
    [[nodiscard]] bool initialized() const noexcept { return initialized_; }

private:
    void cleanup();
    void run_pending_auto_synth();

    HostIntegration host_integration_;
    bool initialized_ = false;
    bool cleaned_up_ = false;
    bool ui_listener_hooked_ = false;
    bool pending_shared_registration_ = false;

    // Pending auto-synthesis from env var
    ea_t pending_synth_ea_ = BADADDR;
    qstring pending_synth_func_name_;
    int pending_synth_var_idx_ = 0;
    qstring pending_synth_var_name_;
    ea_t pending_global_synth_ea_ = BADADDR;
    qstring pending_global_synth_name_;
    qstring pending_api_command_;
    bool auto_synth_done_ = false;
};

StructorPlugin::StructorPlugin() {
    try {
    // Load configuration
    if (!Config::instance().load()) {
        msg("Structor: configuration rejected; retaining the previous valid options\n");
    }

    // Hook UI notifications to cleanup before widget destruction.
    if (!hook_event_listener(HT_UI, this)) {
        throw std::runtime_error("failed to install UI event listener");
    }
    ui_listener_hooked_ = true;

    // Install Hex-Rays callback for automatic type fixing/global rewrites
    if (!host_integration_.install_hexrays_hooks()) {
        throw std::runtime_error("failed to install Hex-Rays callback");
    }
    msg("Structor: Hex-Rays callback installed (auto_fix_types=%s)\n",
        Config::instance().options().auto_fix_types ? "true" : "false");

    if (g_shared_service_refcount == 0) {
        if (!register_idc_funcs()) {
            throw std::runtime_error("failed to register IDC functions");
        }
        pending_shared_registration_ = true;
        if (!ui::initialize()) {
            throw std::runtime_error("failed to initialize UI");
        }
    }
    ++g_shared_service_refcount;
    pending_shared_registration_ = false;
    initialized_ = true;
    msg("Structor %s: Plugin initialized (hotkey: %s)\n",
        PLUGIN_VERSION, Config::instance().hotkey());

    const char* api_env = getenv(kApiCommandEnv);
    if (api_env && *api_env) {
        pending_api_command_ = api_env;
        host_integration_.set_auto_type_fixing_suppressed(true);
        auto_synth_done_ = true;
        msg("Structor: Running auto API command: %s\n", pending_api_command_.c_str());
        (void)run_pending_api_command(pending_api_command_);
    }

    // Check for auto-synthesis env var:
    // STRUCTOR_AUTO_SYNTH=func_ea or func_ea:var_idx or func_ea:var_name
    // STRUCTOR_AUTO_SYNTH=func_name or func_name:var_idx or func_name:var_name
    const char* env = getenv("STRUCTOR_AUTO_SYNTH");
    if (env && *env) {
        host_integration_.set_auto_type_fixing_suppressed(true);
        qstring requested = env;
        qstring target = requested;
        const char* selector = nullptr;

        char* endptr = nullptr;
        pending_synth_ea_ = BADADDR;
        pending_synth_func_name_.clear();
        pending_synth_var_name_.clear();
        pending_synth_var_idx_ = 0;

        const char* colon = std::strchr(env, ':');
        if (colon) {
            target = qstring(env, static_cast<size_t>(colon - env));
            selector = colon + 1;
        }

        unsigned long long parsed = strtoull(target.c_str(), &endptr, 0);
        if (endptr && *endptr == '\0') {
            pending_synth_ea_ = static_cast<ea_t>(parsed);
        } else {
            pending_synth_func_name_ = target;
        }

        if (selector && *selector) {
            char* idx_end = nullptr;
            long idx = std::strtol(selector, &idx_end, 0);
            if (idx_end && *idx_end == '\0') {
                pending_synth_var_idx_ = static_cast<int>(idx);
            } else {
                pending_synth_var_name_ = selector;
            }
        }

        if (pending_synth_ea_ != BADADDR || !pending_synth_func_name_.empty()) {
            // Run synthesis immediately (auto_wait() is called internally)
            run_pending_auto_synth();
        }
    }

    // Check for global/static auto-synthesis env var: STRUCTOR_AUTO_SYNTH_GLOBAL=ea_or_name
    const char* global_env = getenv("STRUCTOR_AUTO_SYNTH_GLOBAL");
    if (global_env && *global_env) {
        host_integration_.set_auto_type_fixing_suppressed(true);
        char* endptr = nullptr;
        pending_global_synth_ea_ = strtoull(global_env, &endptr, 0);
        if (!endptr || *endptr != '\0') {
            pending_global_synth_ea_ = BADADDR;
            pending_global_synth_name_ = global_env;
        }
        run_pending_auto_synth();
    }
    } catch (const vd_failure_t& e) {
        msg("Structor: initialization failed: %s\n", e.desc().c_str());
    } catch (const std::exception& e) {
        msg("Structor: initialization failed: %s\n", e.what());
    } catch (...) {
        msg("Structor: initialization raised an unknown exception\n");
    }

    if (!initialized_) {
        // Constructor failures must not leak callbacks or IDC registrations;
        // a partially constructed plugmod_t has no destructor callback yet.
        bool registrations_removed = true;
        if (pending_shared_registration_ || g_shared_service_refcount == 0) {
            try {
                const bool ui_removed = ui::shutdown();
                const bool idc_removed = unregister_idc_funcs();
                registrations_removed = ui_removed && idc_removed;
            } catch (...) {
                registrations_removed = false;
            }
            pending_shared_registration_ = false;
        }
        try { host_integration_.shutdown(); } catch (...) {}
        if (ui_listener_hooked_) {
            try {
                if (unhook_event_listener(HT_UI, this)) {
                    ui_listener_hooked_ = false;
                }
            } catch (...) {}
        }
        cleaned_up_ = true;
        if (!registrations_removed || ui_listener_hooked_) {
            msg("Structor: CRITICAL: retained host registration after failed "
                "initialization\n");
            std::terminate();
        }
    }
}

void StructorPlugin::run_pending_auto_synth() {
    if (auto_synth_done_) return;
    if (pending_synth_ea_ == BADADDR
        && pending_synth_func_name_.empty()
        && pending_global_synth_ea_ == BADADDR
        && pending_global_synth_name_.empty()) {
        return;
    }
    try {
        auto_synth_done_ = true;

    // Wait for auto-analysis to complete
    auto_wait();

    if (!pending_global_synth_name_.empty()) {
        msg("Structor: Running auto global synthesis for name=%s\n",
            pending_global_synth_name_.c_str());
    } else if (pending_global_synth_ea_ != BADADDR) {
        msg("Structor: Running auto global synthesis for ea=0x%llx\n",
            (unsigned long long)pending_global_synth_ea_);
    } else if (!pending_synth_func_name_.empty() && !pending_synth_var_name_.empty()) {
        msg("Structor: Running auto-synthesis for func=%s var_name=%s\n",
            pending_synth_func_name_.c_str(), pending_synth_var_name_.c_str());
    } else if (!pending_synth_func_name_.empty()) {
        msg("Structor: Running auto-synthesis for func=%s var_idx=%d\n",
            pending_synth_func_name_.c_str(), pending_synth_var_idx_);
    } else if (!pending_synth_var_name_.empty()) {
        msg("Structor: Running auto-synthesis for func=0x%llx var_name=%s\n",
            (unsigned long long)pending_synth_ea_, pending_synth_var_name_.c_str());
    } else {
        msg("Structor: Running auto-synthesis for func=0x%llx var_idx=%d\n",
            (unsigned long long)pending_synth_ea_, pending_synth_var_idx_);
    }

    SynthOptions opts = Config::instance().options();
    opts.interactive_mode = false;
    opts.auto_open_struct = false;
    opts.highlight_changes = false;

    SynthResult result;
    ea_t synth_ea = pending_synth_ea_;
    if (synth_ea == BADADDR && !pending_synth_func_name_.empty()) {
        if (!resolve_function_target(pending_synth_func_name_, synth_ea)) {
            qstring err;
            err.sprnt("Function '%s' not found", pending_synth_func_name_.c_str());
            result = SynthResult::make_error(SynthError::InternalError, err);
            g_last_error = result.error_message;
            g_last_field_count = 0;
            g_last_vtable_tid = BADADDR;
            maybe_export_last_result(result, "auto");
            msg("Structor: Auto-synthesis FAILED - %s\n", result.error_message.c_str());
            return;
        }
    }

    if (!pending_global_synth_name_.empty()) {
        result = StructorAPI::instance().synthesize_global_structure(
            pending_global_synth_name_.c_str(), &opts);
    } else if (pending_global_synth_ea_ != BADADDR) {
        result = StructorAPI::instance().synthesize_global_structure(
            pending_global_synth_ea_, &opts);
    } else if (pending_synth_var_name_.empty()) {
        result = StructorAPI::instance().synthesize_structure(
            synth_ea, pending_synth_var_idx_, &opts);
    } else {
        result = StructorAPI::instance().synthesize_structure(
            synth_ea, pending_synth_var_name_.c_str(), &opts);
    }

    g_last_error = result.error_message;
    g_last_field_count = result.fields_created;
    g_last_vtable_tid = result.vtable_tid;
    maybe_export_last_result(result, "auto");

        if (result.success()) {
            msg("Structor: Auto-synthesis OK - tid=0x%llx fields=%d\n",
                (unsigned long long)result.struct_tid, result.fields_created);
        } else {
            msg("Structor: Auto-synthesis FAILED - %s\n",
                result.error_message.empty() ? synth_error_str(result.error) : result.error_message.c_str());
        }
    } catch (const vd_failure_t& e) {
        g_last_error = e.desc();
        g_last_field_count = 0;
        g_last_vtable_tid = BADADDR;
        msg("Structor: Auto-synthesis failed: %s\n", e.desc().c_str());
    } catch (const std::exception& e) {
        g_last_error = e.what();
        g_last_field_count = 0;
        g_last_vtable_tid = BADADDR;
        msg("Structor: Auto-synthesis failed: %s\n", e.what());
    } catch (...) {
        g_last_error = "Auto-synthesis raised an unknown exception";
        g_last_field_count = 0;
        g_last_vtable_tid = BADADDR;
        msg("Structor: Auto-synthesis raised an unknown exception\n");
    }
}

StructorPlugin::~StructorPlugin() {
    cleanup();
    if (ui_listener_hooked_) {
        // A non-global event listener may already have been removed by the
        // kernel during database close. The single-listener API reports false
        // in that valid state, so use the documented idempotent all-databases
        // removal operation instead of treating false as retained state.
        remove_event_listener(this);
        ui_listener_hooked_ = false;
    }
    term_hexrays_plugin();
}

void StructorPlugin::cleanup() {
    if (cleaned_up_) return;
    cleaned_up_ = true;

    host_integration_.shutdown();

    if (initialized_) {
        if (g_shared_service_refcount > 0) {
            --g_shared_service_refcount;
        }
        if (g_shared_service_refcount == 0) {
            const bool ui_removed = ui::shutdown();
            const bool idc_removed = unregister_idc_funcs();
            if (!ui_removed || !idc_removed) {
                msg("Structor: CRITICAL: retained process-global host "
                    "registration during shutdown\n");
                std::terminate();
            }
        }

        // Save configuration if dirty
        if (Config::instance().is_dirty()) {
            Config::instance().save();
        }
        initialized_ = false;
    }
}

ssize_t StructorPlugin::on_event(ssize_t code, va_list /*va*/) {
    try {
        switch (code) {
            case ui_database_closed:
                // Database closed - cleanup before Qt widgets are destroyed
                cleanup();
                break;
            default:
                break;
        }
    } catch (const std::exception& e) {
        msg("Structor: UI event cleanup failed: %s\n", e.what());
    } catch (...) {
        msg("Structor: UI event cleanup raised an unknown exception\n");
    }
    return 0;
}

bool StructorPlugin::run(size_t arg) {
    try {
        if (!initialized_) {
            warning("Structor plugin not properly initialized");
            return false;
        }

        // Get current vdui if in pseudocode view
        TWidget* widget = get_current_widget();
        vdui_t* vdui = get_widget_vdui(widget);

        if (!vdui) {
            info("Structor: Please place cursor on a variable in the pseudocode view\n"
                 "and use %s or right-click -> '%s'",
                 Config::instance().hotkey(), ACTION_LABEL);
            return true;
        }

        SynthResult result = ui::execute_synthesis(vdui);

        if (result.success()) {
            if (Config::instance().interactive_mode()) {
                ui::show_result_dialog(result);
            }
        } else {
            qstring errmsg;
            errmsg.sprnt("Structure synthesis failed: %s", synth_error_str(result.error));
            if (!result.error_message.empty()) {
                errmsg.cat_sprnt("\n%s", result.error_message.c_str());
            }
            warning("%s", errmsg.c_str());
        }

        return true;
    } catch (const vd_failure_t& e) {
        warning("Structor: plugin action failed: %s", e.desc().c_str());
    } catch (const std::exception& e) {
        warning("Structor: plugin action failed: %s", e.what());
    } catch (...) {
        warning("Structor: plugin action raised an unknown exception");
    }
    return false;
}

// Plugin information
static plugmod_t* idaapi init() {
    bool hexrays_initialized = false;
    try {
        // Check for Hex-Rays decompiler
        if (!init_hexrays_plugin()) {
            msg("Structor: Hex-Rays decompiler not found\n");
            return nullptr;
        }
        hexrays_initialized = true;

        std::unique_ptr<StructorPlugin> plugin =
            std::make_unique<StructorPlugin>();
        if (!plugin->initialized()) {
            return nullptr;
        }
        plugmod_t* result = plugin.release();
        hexrays_initialized = false;
        return result;
    } catch (const std::exception& e) {
        if (hexrays_initialized) {
            term_hexrays_plugin();
            hexrays_initialized = false;
        }
        msg("Structor: plugin initialization failed: %s\n", e.what());
    } catch (...) {
        if (hexrays_initialized) {
            term_hexrays_plugin();
            hexrays_initialized = false;
        }
        msg("Structor: plugin initialization raised an unknown exception\n");
    }
    return nullptr;
}

} // namespace structor

// Plugin export
plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI,                           // Plugin flags
    structor::init,                         // Initialize
    nullptr,                                // Terminate (handled by destructor)
    nullptr,                                // Run (handled by plugmod_t::run)
    structor::PLUGIN_NAME,                  // Comment
    "Structure synthesis from access patterns",  // Help
    structor::PLUGIN_NAME,                  // Wanted name
    structor::DEFAULT_HOTKEY                // Wanted hotkey
};
