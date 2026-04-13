#pragma once

#include "synth_types.hpp"
#include "naming.hpp"
#include "config.hpp"
#include "access_collector.hpp"
#include "global_object_analyzer.hpp"
#include "layout_synthesizer.hpp"
#include "vtable_detector.hpp"
#include "type_propagator.hpp"
#include "pseudocode_rewriter.hpp"
#include "structure_persistence.hpp"
#include "ui_integration.hpp"
#include "type_fixer.hpp"

namespace structor {

enum class MaterializationMode : std::uint8_t {
    Preview = 0,
    Persist,
    PersistAndApply,
};

[[nodiscard]] inline const char* materialization_mode_str(MaterializationMode mode) noexcept {
    switch (mode) {
        case MaterializationMode::Preview:         return "preview";
        case MaterializationMode::Persist:         return "persist";
        case MaterializationMode::PersistAndApply: return "persist_and_apply";
        default:                                   return "unknown";
    }
}

struct VariableDescriptor {
    ea_t func_ea = BADADDR;
    int var_idx = -1;
    qstring var_name;
    bool is_argument = false;
    tinfo_t current_type;

    [[nodiscard]] bool valid() const noexcept {
        return func_ea != BADADDR && var_idx >= 0;
    }
};

struct VariableStructureAnalysisResult {
    SynthError error = SynthError::Success;
    qstring error_message;
    VariableDescriptor variable;
    AccessPattern local_pattern;
    std::optional<UnifiedAccessPattern> unified_pattern;
    SynthesisResult synthesis;

    [[nodiscard]] bool success() const noexcept {
        return error == SynthError::Success && synthesis.success();
    }
};

struct GlobalStructureAnalysisResult {
    SynthError error = SynthError::Success;
    qstring error_message;
    ea_t global_ea = BADADDR;
    qstring global_name;
    GlobalObjectAnalysis analysis;
    SynthesisResult synthesis;

    [[nodiscard]] bool success() const noexcept {
        return error == SynthError::Success && synthesis.success();
    }
};

struct FunctionStructureAnalysisResult {
    SynthError error = SynthError::Success;
    qstring error_message;
    ea_t func_ea = BADADDR;
    qstring func_name;
    unsigned total_variables = 0;
    unsigned analyzed = 0;
    unsigned succeeded = 0;
    unsigned failed = 0;
    qvector<VariableStructureAnalysisResult> variables;

    [[nodiscard]] bool success() const noexcept {
        return error == SynthError::Success;
    }
};

struct VariableStructureSynthesisResult {
    VariableDescriptor variable;
    SynthResult synthesis;
};

struct FunctionStructureSynthesisResult {
    SynthError error = SynthError::Success;
    qstring error_message;
    ea_t func_ea = BADADDR;
    qstring func_name;
    MaterializationMode mode = MaterializationMode::PersistAndApply;
    unsigned total_variables = 0;
    unsigned attempted = 0;
    unsigned succeeded = 0;
    unsigned failed = 0;
    unsigned skipped = 0;
    qvector<VariableStructureSynthesisResult> variables;

    [[nodiscard]] bool success() const noexcept {
        return error == SynthError::Success;
    }
};

/// Primary API for programmatic structure synthesis
class StructorAPI {
public:
    static StructorAPI& instance() {
        static StructorAPI api;
        return api;
    }

    /// Main entry point: synthesize structure for a variable
    [[nodiscard]] SynthResult synthesize_structure(
        ea_t func_ea,
        lvar_t* var,
        SynthOptions* opts = nullptr);

    /// Main entry point with explicit materialization mode
    [[nodiscard]] SynthResult synthesize_structure(
        ea_t func_ea,
        lvar_t* var,
        MaterializationMode mode,
        SynthOptions* opts);

    /// Synthesize structure by variable index
    [[nodiscard]] SynthResult synthesize_structure(
        ea_t func_ea,
        int var_idx,
        SynthOptions* opts = nullptr);

    /// Synthesize structure by variable index with explicit materialization mode
    [[nodiscard]] SynthResult synthesize_structure(
        ea_t func_ea,
        int var_idx,
        MaterializationMode mode,
        SynthOptions* opts = nullptr);

    /// Synthesize structure by variable name
    [[nodiscard]] SynthResult synthesize_structure(
        ea_t func_ea,
        const char* var_name,
        SynthOptions* opts = nullptr);

    /// Synthesize structure by variable name with explicit materialization mode
    [[nodiscard]] SynthResult synthesize_structure(
        ea_t func_ea,
        const char* var_name,
        MaterializationMode mode,
        SynthOptions* opts = nullptr);

    /// Synthesize structure for a global/static storage address
    [[nodiscard]] SynthResult synthesize_global_structure(
        ea_t global_ea,
        SynthOptions* opts = nullptr);

    /// Synthesize structure for a global/static storage address with explicit materialization mode
    [[nodiscard]] SynthResult synthesize_global_structure(
        ea_t global_ea,
        MaterializationMode mode,
        SynthOptions* opts = nullptr);

    /// Synthesize structure for a global/static storage symbol
    [[nodiscard]] SynthResult synthesize_global_structure(
        const char* global_name,
        SynthOptions* opts = nullptr);

    /// Synthesize structure for a global/static storage symbol with explicit materialization mode
    [[nodiscard]] SynthResult synthesize_global_structure(
        const char* global_name,
        MaterializationMode mode,
        SynthOptions* opts = nullptr);

    /// Analyze structure recovery for a variable without persisting changes
    [[nodiscard]] VariableStructureAnalysisResult analyze_structure(
        ea_t func_ea,
        lvar_t* var,
        SynthOptions* opts = nullptr);

    /// Analyze structure recovery by variable index without persisting changes
    [[nodiscard]] VariableStructureAnalysisResult analyze_structure(
        ea_t func_ea,
        int var_idx,
        SynthOptions* opts = nullptr);

    /// Analyze structure recovery by variable name without persisting changes
    [[nodiscard]] VariableStructureAnalysisResult analyze_structure(
        ea_t func_ea,
        const char* var_name,
        SynthOptions* opts = nullptr);

    /// Analyze all variables in a function for structure recovery without persisting changes
    [[nodiscard]] FunctionStructureAnalysisResult analyze_function_structures(
        ea_t func_ea,
        SynthOptions* opts = nullptr);

    /// Synthesize structures for all variables in a function
    [[nodiscard]] FunctionStructureSynthesisResult synthesize_function_structures(
        ea_t func_ea,
        MaterializationMode mode = MaterializationMode::PersistAndApply,
        SynthOptions* opts = nullptr);

    /// Analyze a global/static object without persisting changes
    [[nodiscard]] GlobalStructureAnalysisResult analyze_global_structure(
        ea_t global_ea,
        SynthOptions* opts = nullptr);

    /// Analyze a global/static object by symbol without persisting changes
    [[nodiscard]] GlobalStructureAnalysisResult analyze_global_structure(
        const char* global_name,
        SynthOptions* opts = nullptr);

    /// Collect access patterns without synthesizing
    [[nodiscard]] AccessPattern collect_accesses(
        ea_t func_ea,
        int var_idx);

    /// Collect access patterns by variable name without synthesizing
    [[nodiscard]] AccessPattern collect_accesses(
        ea_t func_ea,
        const char* var_name);

    /// Collect cross-function access patterns without synthesizing
    [[nodiscard]] UnifiedAccessPattern collect_unified_accesses(
        ea_t func_ea,
        int var_idx,
        SynthOptions* opts = nullptr);

    /// Collect cross-function access patterns by variable name without synthesizing
    [[nodiscard]] UnifiedAccessPattern collect_unified_accesses(
        ea_t func_ea,
        const char* var_name,
        SynthOptions* opts = nullptr);

    /// Synthesize layout from pattern without persisting
    [[nodiscard]] SynthStruct synthesize_layout(
        const AccessPattern& pattern,
        SynthOptions* opts = nullptr);

    /// Synthesize layout from unified pattern without persisting
    [[nodiscard]] SynthesisResult synthesize_layout(
        const UnifiedAccessPattern& pattern,
        SynthOptions* opts = nullptr);

    /// Detect vtable in pattern
    [[nodiscard]] std::optional<SynthVTable> detect_vtable(
        const AccessPattern& pattern,
        ea_t func_ea);

    /// Detect vtable in unified cross-function pattern
    [[nodiscard]] std::optional<SynthVTable> detect_vtable(
        const UnifiedAccessPattern& pattern,
        SynthOptions* opts = nullptr);

    /// Propagate type to related functions
    [[nodiscard]] PropagationResult propagate_type(
        ea_t func_ea,
        int var_idx,
        const tinfo_t& type,
        PropagationDirection direction = PropagationDirection::Both);

    /// Propagate type only within the local function
    [[nodiscard]] PropagationResult propagate_type_local(
        ea_t func_ea,
        int var_idx,
        const tinfo_t& type,
        SynthOptions* opts = nullptr);

    /// Apply a type to a variable without further propagation
    [[nodiscard]] bool apply_type(
        ea_t func_ea,
        int var_idx,
        const tinfo_t& type,
        SynthOptions* opts = nullptr);

    /// Apply a type to a global/static object
    [[nodiscard]] bool apply_global_type(
        ea_t global_ea,
        const tinfo_t& type);

    /// Fix types for all variables in a function
    /// Analyzes access patterns and applies inferred types when significantly different
    [[nodiscard]] TypeFixResult fix_function_types(
        ea_t func_ea,
        const TypeFixerConfig* config = nullptr);

    /// Fix types for a specific variable in a function
    [[nodiscard]] VariableTypeFix fix_variable_type(
        ea_t func_ea,
        int var_idx,
        const TypeFixerConfig* config = nullptr);

    /// Fix types for a variable by name
    [[nodiscard]] VariableTypeFix fix_variable_type(
        ea_t func_ea,
        const char* var_name,
        const TypeFixerConfig* config = nullptr);

    /// Analyze a specific variable type without fixing it
    [[nodiscard]] TypeComparisonResult analyze_variable_type(
        ea_t func_ea,
        int var_idx,
        const TypeFixerConfig* config = nullptr);

    /// Analyze a specific variable type by name without fixing it
    [[nodiscard]] TypeComparisonResult analyze_variable_type(
        ea_t func_ea,
        const char* var_name,
        const TypeFixerConfig* config = nullptr);

    /// Rewrite pseudocode using a synthesized structure without creating new types
    [[nodiscard]] RewriteResult rewrite_pseudocode(
        ea_t func_ea,
        int var_idx,
        const SynthStruct& synth_struct,
        SynthOptions* opts = nullptr);

    /// Analyze types without fixing (dry run)
    [[nodiscard]] TypeFixResult analyze_function_types(ea_t func_ea);

    /// Get current configuration
    [[nodiscard]] const SynthOptions& get_options() const {
        return Config::instance().options();
    }

    /// Set configuration options
    void set_options(const SynthOptions& opts) {
        Config::instance().mutable_options() = opts;
    }

private:
    StructorAPI() = default;
    ~StructorAPI() = default;
    StructorAPI(const StructorAPI&) = delete;
    StructorAPI& operator=(const StructorAPI&) = delete;

    VariableStructureAnalysisResult do_analyze_structure(ea_t func_ea, int var_idx, const SynthOptions& opts);
    GlobalStructureAnalysisResult do_analyze_global_structure(ea_t global_ea, const SynthOptions& opts);
    SynthResult do_synthesis(ea_t func_ea, int var_idx, const SynthOptions& opts, MaterializationMode mode);
    SynthResult do_global_synthesis(ea_t global_ea, const SynthOptions& opts, MaterializationMode mode);
};

// ============================================================================
// Implementation
// ============================================================================

[[nodiscard]] inline bool apply_global_tinfo(ea_t ea, const tinfo_t& type) {
#ifndef STRUCTOR_TESTING
    auto apply_decl = [&](const tinfo_t& decl_type) {
        qstring symbol_name;
        get_name(&symbol_name, ea);
        if (symbol_name.empty()) {
            return false;
        }

        qstring type_name;
        qstring decl;
        if ((decl_type.is_struct() || decl_type.is_union()) && decl_type.get_type_name(&type_name) && !type_name.empty()) {
            decl.sprnt("%s %s;", type_name.c_str(), symbol_name.c_str());
            return apply_cdecl(nullptr, ea, decl.c_str(), TINFO_STRICT);
        }

        if ((decl_type.is_ptr() || decl_type.is_funcptr()) && decl_type.is_ptr()) {
            tinfo_t pointed = decl_type.get_pointed_object();
            if (!pointed.empty() && pointed.get_type_name(&type_name) && !type_name.empty()) {
                decl.sprnt("%s *%s;", type_name.c_str(), symbol_name.c_str());
                return apply_cdecl(nullptr, ea, decl.c_str(), TINFO_STRICT);
            }
        }

        return false;
    };

    bool prepared = false;
    bool set_ok = false;
    bool apply_ok = false;
    bool decl_ok = false;
    const bool aggregate_type = type.is_struct() || type.is_union();

    if (!aggregate_type) {
        try {
            const size_t type_size = type.get_size();
            if ((type.is_ptr() || type.is_funcptr()) && type_size != BADSIZE && type_size > 0) {
                const asize_t ptr_size = static_cast<asize_t>(get_ptr_size());
                if (ptr_size == 8) {
                    prepared = create_qword(ea, ptr_size, true) || prepared;
                } else if (ptr_size == 4) {
                    prepared = create_dword(ea, ptr_size, true) || prepared;
                }
            }
        } catch (...) {
        }
    }

    try {
        set_ok = set_tinfo(ea, &type);
    } catch (...) {
    }
    if (type.is_ptr() || type.is_funcptr()) {
        try {
            apply_ok = apply_tinfo(ea, type, TINFO_DEFINITE | TINFO_STRICT);
        } catch (...) {
        }
        try {
            decl_ok = apply_decl(type);
        } catch (...) {
        }
    }

    return prepared || set_ok || apply_ok || decl_ok;
#else
    (void)ea;
    (void)type;
    return true;
#endif
}

[[nodiscard]] inline bool symbol_name_matches(const qstring& candidate, const qstring& target) {
    if (candidate.empty() || target.empty()) {
        return false;
    }
    if (candidate == target) {
        return true;
    }
    if (candidate[0] == '_' && candidate.substr(1) == target) {
        return true;
    }
    if (target[0] == '_' && target.substr(1) == candidate) {
        return true;
    }
    return false;
}

[[nodiscard]] inline ea_t lookup_global_symbol_ea(const char* global_name) {
#ifndef STRUCTOR_TESTING
    if (!global_name || !*global_name) {
        return BADADDR;
    }

    ea_t global_ea = get_name_ea(BADADDR, global_name);
    if (global_ea != BADADDR) {
        return global_ea;
    }

    qstring target(global_name);
    if (global_name[0] != '_') {
        qstring alt_name("_");
        alt_name.append(global_name);
        global_ea = get_name_ea(BADADDR, alt_name.c_str());
        if (global_ea != BADADDR) {
            return global_ea;
        }
    }

    const size_t name_count = get_nlist_size();
    for (size_t idx = 0; idx < name_count; ++idx) {
        ea_t ea = get_nlist_ea(idx);
        if (ea == BADADDR) {
            continue;
        }

        const char* raw_name = get_nlist_name(idx);
        if (raw_name && symbol_name_matches(qstring(raw_name), target)) {
            return ea;
        }

        qstring short_name;
        get_short_name(&short_name, ea);
        if (symbol_name_matches(short_name, target)) {
            return ea;
        }

        qstring long_name;
        get_long_name(&long_name, ea);
        if (symbol_name_matches(long_name, target)) {
            return ea;
        }
    }
#else
    (void)global_name;
#endif

    return BADADDR;
}

inline void populate_z3_info_from_synthesis(SynthResult& dst, const SynthesisResult& src) {
    dst.z3_info.solve_time_ms = static_cast<std::uint32_t>(src.z3_solve_time.count());
    dst.z3_info.candidates_selected = static_cast<std::uint32_t>(src.structure.fields.size());
    dst.z3_info.constraints_hard = src.z3_stats.hard_constraints;
    dst.z3_info.constraints_soft = src.z3_stats.soft_constraints;
    dst.z3_info.constraints_relaxed = src.z3_stats.relaxations_performed;
    dst.z3_info.arrays_detected = static_cast<std::uint32_t>(src.arrays_detected);
    dst.z3_info.unions_created = static_cast<std::uint32_t>(src.unions_created);
    dst.z3_info.cross_func_merged = static_cast<std::uint32_t>(src.functions_analyzed);

    if (!src.used_z3) {
        dst.z3_info.status = Z3SynthesisStatus::NotUsed;
    } else if (src.fell_back_to_heuristic) {
        dst.z3_info.status = Z3SynthesisStatus::FallbackHeuristic;
    } else if (src.raw_bytes_regions > 0) {
        dst.z3_info.status = Z3SynthesisStatus::FallbackRawBytes;
    } else if (src.had_relaxation) {
        dst.z3_info.status = Z3SynthesisStatus::SuccessRelaxed;
    } else {
        dst.z3_info.status = Z3SynthesisStatus::Success;
    }
}

[[nodiscard]] inline VariableDescriptor make_variable_descriptor(cfunc_t* cfunc, int var_idx) {
    VariableDescriptor descriptor;
    if (!cfunc) {
        return descriptor;
    }

    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars || var_idx < 0 || static_cast<size_t>(var_idx) >= lvars->size()) {
        return descriptor;
    }

    const lvar_t& var = lvars->at(static_cast<size_t>(var_idx));
    descriptor.func_ea = cfunc->entry_ea;
    descriptor.var_idx = var_idx;
    descriptor.var_name = var.name;
    descriptor.is_argument = var.is_arg_var();
    descriptor.current_type = var.type();
    return descriptor;
}

[[nodiscard]] inline bool resolve_var_index(cfunc_t* cfunc, lvar_t* var, int& out_var_idx) {
    out_var_idx = -1;
    if (!cfunc || !var) {
        return false;
    }

    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars) {
        return false;
    }

    for (size_t i = 0; i < lvars->size(); ++i) {
        if (&lvars->at(i) == var) {
            out_var_idx = static_cast<int>(i);
            return true;
        }
    }

    return false;
}

[[nodiscard]] inline bool resolve_var_index(cfunc_t* cfunc, const char* var_name, int& out_var_idx) {
    out_var_idx = -1;
    if (!cfunc || !var_name || !*var_name) {
        return false;
    }

    lvar_t* var = utils::find_lvar_by_name(cfunc, var_name);
    return resolve_var_index(cfunc, var, out_var_idx);
}

[[nodiscard]] inline SynthResult make_result_from_synthesis(const SynthesisResult& synthesis) {
    SynthResult result;
    result.error = SynthError::Success;
    result.conflicts = synthesis.conflicts;
    populate_z3_info_from_synthesis(result, synthesis);

    if (!synthesis.structure.fields.empty()) {
        result.fields_created = static_cast<int>(synthesis.structure.field_count());
        if (synthesis.structure.has_vtable()) {
            result.vtable_slots = static_cast<int>(synthesis.structure.vtable->slot_count());
        }
        result.synthesized_struct = std::make_unique<SynthStruct>(synthesis.structure);
    }

    return result;
}

[[nodiscard]] inline bool try_reuse_generated_struct(cfunc_t* cfunc, int var_idx, SynthResult& result) {
    if (!cfunc) {
        return false;
    }

    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars || var_idx < 0 || static_cast<size_t>(var_idx) >= lvars->size()) {
        return false;
    }

    const lvar_t& var = lvars->at(static_cast<size_t>(var_idx));
    tinfo_t current_type = var.type();
    tinfo_t current_struct = current_type;
    if (current_struct.is_ptr()) {
        current_struct = current_struct.get_pointed_object();
    }

    qstring current_name;
    current_struct.get_type_name(&current_name);
    qstring current_decl;
    current_type.print(&current_decl);
    if ((!current_name.empty() && (current_name.find("synth_struct_") == 0 || current_name.find("auto_") == 0)) ||
        (!current_decl.empty() &&
         (current_decl.find("synth_struct_") != qstring::npos || current_decl.find("auto_") != qstring::npos))) {
        tid_t existing_tid = current_struct.get_tid();
        if (existing_tid != BADADDR) {
            result.struct_tid = existing_tid;
            result.error = SynthError::Success;

            udt_type_data_t udt;
            if (current_struct.get_udt_details(&udt)) {
                result.fields_created = static_cast<int>(udt.size());
            }
            return true;
        }
    }

    return false;
}

inline SynthResult StructorAPI::synthesize_structure(
    ea_t func_ea,
    lvar_t* var,
    SynthOptions* opts)
{
    return synthesize_structure(func_ea, var, MaterializationMode::PersistAndApply, opts);
}

inline SynthResult StructorAPI::synthesize_structure(
    ea_t func_ea,
    lvar_t* var,
    MaterializationMode mode,
    SynthOptions* opts)
{
    if (!var) {
        return SynthResult::make_error(SynthError::InvalidVariable, "Null variable pointer");
    }

    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) {
        return SynthResult::make_error(SynthError::InternalError, "Failed to decompile function");
    }

    int var_idx = -1;
    if (!resolve_var_index(cfunc, var, var_idx)) {
        return SynthResult::make_error(SynthError::InvalidVariable, "Variable not found in function");
    }

    return synthesize_structure(func_ea, var_idx, mode, opts);
}

inline SynthResult StructorAPI::synthesize_structure(
    ea_t func_ea,
    int var_idx,
    SynthOptions* opts)
{
    return synthesize_structure(func_ea, var_idx, MaterializationMode::PersistAndApply, opts);
}

inline SynthResult StructorAPI::synthesize_structure(
    ea_t func_ea,
    int var_idx,
    MaterializationMode mode,
    SynthOptions* opts)
{
    const SynthOptions& options = opts ? *opts : Config::instance().options();
    return do_synthesis(func_ea, var_idx, options, mode);
}

inline SynthResult StructorAPI::synthesize_structure(
    ea_t func_ea,
    const char* var_name,
    SynthOptions* opts)
{
    return synthesize_structure(func_ea, var_name, MaterializationMode::PersistAndApply, opts);
}

inline SynthResult StructorAPI::synthesize_structure(
    ea_t func_ea,
    const char* var_name,
    MaterializationMode mode,
    SynthOptions* opts)
{
    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) {
        return SynthResult::make_error(SynthError::InternalError, "Failed to decompile function");
    }

    int var_idx = -1;
    if (!resolve_var_index(cfunc, var_name, var_idx)) {
        qstring msg;
        msg.sprnt("Variable '%s' not found in function", var_name ? var_name : "");
        return SynthResult::make_error(SynthError::InvalidVariable, msg);
    }

    return synthesize_structure(func_ea, var_idx, mode, opts);
}

inline SynthResult StructorAPI::synthesize_global_structure(
    ea_t global_ea,
    SynthOptions* opts)
{
    return synthesize_global_structure(global_ea, MaterializationMode::PersistAndApply, opts);
}

inline SynthResult StructorAPI::synthesize_global_structure(
    ea_t global_ea,
    MaterializationMode mode,
    SynthOptions* opts)
{
    const SynthOptions& options = opts ? *opts : Config::instance().options();
    return do_global_synthesis(global_ea, options, mode);
}

inline SynthResult StructorAPI::synthesize_global_structure(
    const char* global_name,
    SynthOptions* opts)
{
    return synthesize_global_structure(global_name, MaterializationMode::PersistAndApply, opts);
}

inline SynthResult StructorAPI::synthesize_global_structure(
    const char* global_name,
    MaterializationMode mode,
    SynthOptions* opts)
{
    if (!global_name || !*global_name) {
        return SynthResult::make_error(SynthError::InvalidVariable, "Global name is empty");
    }

    ea_t global_ea = lookup_global_symbol_ea(global_name);
    if (global_ea == BADADDR) {
        qstring msg;
        msg.sprnt("Global '%s' not found", global_name);
        return SynthResult::make_error(SynthError::InvalidVariable, msg);
    }

    return synthesize_global_structure(global_ea, mode, opts);
}

inline VariableStructureAnalysisResult StructorAPI::analyze_structure(
    ea_t func_ea,
    lvar_t* var,
    SynthOptions* opts)
{
    VariableStructureAnalysisResult result;
    if (!var) {
        result.error = SynthError::InvalidVariable;
        result.error_message = "Null variable pointer";
        return result;
    }

    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) {
        result.error = SynthError::InternalError;
        result.error_message = "Failed to decompile function";
        return result;
    }

    int var_idx = -1;
    if (!resolve_var_index(cfunc, var, var_idx)) {
        result.error = SynthError::InvalidVariable;
        result.error_message = "Variable not found in function";
        return result;
    }

    return analyze_structure(func_ea, var_idx, opts);
}

inline VariableStructureAnalysisResult StructorAPI::analyze_structure(
    ea_t func_ea,
    int var_idx,
    SynthOptions* opts)
{
    const SynthOptions& options = opts ? *opts : Config::instance().options();
    return do_analyze_structure(func_ea, var_idx, options);
}

inline VariableStructureAnalysisResult StructorAPI::analyze_structure(
    ea_t func_ea,
    const char* var_name,
    SynthOptions* opts)
{
    VariableStructureAnalysisResult result;
    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) {
        result.error = SynthError::InternalError;
        result.error_message = "Failed to decompile function";
        return result;
    }

    int var_idx = -1;
    if (!resolve_var_index(cfunc, var_name, var_idx)) {
        result.error = SynthError::InvalidVariable;
        result.error_message.sprnt("Variable '%s' not found in function", var_name ? var_name : "");
        return result;
    }

    return analyze_structure(func_ea, var_idx, opts);
}

inline FunctionStructureAnalysisResult StructorAPI::analyze_function_structures(
    ea_t func_ea,
    SynthOptions* opts)
{
    FunctionStructureAnalysisResult result;
    result.func_ea = func_ea;
    get_func_name(&result.func_name, func_ea);

    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) {
        result.error = SynthError::InternalError;
        result.error_message = "Failed to decompile function";
        return result;
    }

    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars) {
        result.error = SynthError::InternalError;
        result.error_message = "Failed to get local variables";
        return result;
    }

    result.total_variables = static_cast<unsigned>(lvars->size());
    for (size_t i = 0; i < lvars->size(); ++i) {
        VariableStructureAnalysisResult entry = analyze_structure(func_ea, static_cast<int>(i), opts);
        ++result.analyzed;
        if (entry.success()) {
            ++result.succeeded;
        } else {
            ++result.failed;
        }
        result.variables.push_back(std::move(entry));
    }

    return result;
}

inline FunctionStructureSynthesisResult StructorAPI::synthesize_function_structures(
    ea_t func_ea,
    MaterializationMode mode,
    SynthOptions* opts)
{
    FunctionStructureSynthesisResult result;
    result.func_ea = func_ea;
    result.mode = mode;
    get_func_name(&result.func_name, func_ea);

    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) {
        result.error = SynthError::InternalError;
        result.error_message = "Failed to decompile function";
        return result;
    }

    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars) {
        result.error = SynthError::InternalError;
        result.error_message = "Failed to get local variables";
        return result;
    }

    result.total_variables = static_cast<unsigned>(lvars->size());
    for (size_t i = 0; i < lvars->size(); ++i) {
        VariableStructureSynthesisResult entry;
        entry.variable = make_variable_descriptor(cfunc, static_cast<int>(i));
        entry.synthesis = synthesize_structure(func_ea, static_cast<int>(i), mode, opts);

        ++result.attempted;
        if (entry.synthesis.success()) {
            ++result.succeeded;
        } else if (entry.synthesis.error == SynthError::NoAccessesFound ||
                   entry.synthesis.error == SynthError::InsufficientAccesses) {
            ++result.skipped;
        } else {
            ++result.failed;
        }

        result.variables.push_back(std::move(entry));
    }

    return result;
}

inline GlobalStructureAnalysisResult StructorAPI::analyze_global_structure(
    ea_t global_ea,
    SynthOptions* opts)
{
    const SynthOptions& options = opts ? *opts : Config::instance().options();
    return do_analyze_global_structure(global_ea, options);
}

inline GlobalStructureAnalysisResult StructorAPI::analyze_global_structure(
    const char* global_name,
    SynthOptions* opts)
{
    GlobalStructureAnalysisResult result;
    if (!global_name || !*global_name) {
        result.error = SynthError::InvalidVariable;
        result.error_message = "Global name is empty";
        return result;
    }

    ea_t global_ea = lookup_global_symbol_ea(global_name);
    if (global_ea == BADADDR) {
        result.error = SynthError::InvalidVariable;
        result.error_message.sprnt("Global '%s' not found", global_name);
        return result;
    }

    return analyze_global_structure(global_ea, opts);
}

inline AccessPattern StructorAPI::collect_accesses(ea_t func_ea, int var_idx) {
    AccessCollector collector;
    return collector.collect(func_ea, var_idx);
}

inline AccessPattern StructorAPI::collect_accesses(ea_t func_ea, const char* var_name) {
    AccessCollector collector;
    return collector.collect(func_ea, var_name);
}

inline UnifiedAccessPattern StructorAPI::collect_unified_accesses(
    ea_t func_ea,
    int var_idx,
    SynthOptions* opts)
{
    const SynthOptions& options = opts ? *opts : Config::instance().options();
    CrossFunctionAnalyzer analyzer;
    return analyzer.analyze(func_ea, var_idx, options);
}

inline UnifiedAccessPattern StructorAPI::collect_unified_accesses(
    ea_t func_ea,
    const char* var_name,
    SynthOptions* opts)
{
    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) {
        return UnifiedAccessPattern();
    }

    int var_idx = -1;
    if (!resolve_var_index(cfunc, var_name, var_idx)) {
        return UnifiedAccessPattern();
    }

    return collect_unified_accesses(func_ea, var_idx, opts);
}

inline SynthStruct StructorAPI::synthesize_layout(
    const AccessPattern& pattern,
    SynthOptions* opts)
{
    const SynthOptions& options = opts ? *opts : Config::instance().options();
    LayoutSynthesizer synthesizer(options);
    return synthesizer.synthesize(pattern, options).structure;
}

inline SynthesisResult StructorAPI::synthesize_layout(
    const UnifiedAccessPattern& pattern,
    SynthOptions* opts)
{
    const SynthOptions& options = opts ? *opts : Config::instance().options();
    LayoutSynthesizer synthesizer(options);
    return synthesizer.synthesize(pattern);
}

inline std::optional<SynthVTable> StructorAPI::detect_vtable(
    const AccessPattern& pattern,
    ea_t func_ea)
{
    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) {
        return std::nullopt;
    }

    VTableDetector detector;
    return detector.detect(pattern, cfunc);
}

inline std::optional<SynthVTable> StructorAPI::detect_vtable(
    const UnifiedAccessPattern& pattern,
    SynthOptions* opts)
{
    const SynthOptions& options = opts ? *opts : Config::instance().options();
    VTableDetector detector(options);
    return detector.detect(pattern);
}

inline PropagationResult StructorAPI::propagate_type(
    ea_t func_ea,
    int var_idx,
    const tinfo_t& type,
    PropagationDirection direction)
{
    TypePropagator propagator;
    return propagator.propagate(func_ea, var_idx, type, direction);
}

inline PropagationResult StructorAPI::propagate_type_local(
    ea_t func_ea,
    int var_idx,
    const tinfo_t& type,
    SynthOptions* opts)
{
    PropagationResult result;
    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) {
        return result;
    }

    const SynthOptions& options = opts ? *opts : Config::instance().options();
    TypePropagator propagator(options);
    return propagator.propagate_local(cfunc, var_idx, type);
}

inline bool StructorAPI::apply_type(
    ea_t func_ea,
    int var_idx,
    const tinfo_t& type,
    SynthOptions* opts)
{
    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) {
        return false;
    }

    const SynthOptions& options = opts ? *opts : Config::instance().options();
    TypePropagator propagator(options);
    return propagator.apply_type(cfunc, var_idx, type);
}

inline bool StructorAPI::apply_global_type(
    ea_t global_ea,
    const tinfo_t& type)
{
    return apply_global_tinfo(global_ea, type);
}

inline TypeFixResult StructorAPI::fix_function_types(
    ea_t func_ea,
    const TypeFixerConfig* config)
{
    TypeFixerConfig cfg = config ? *config : TypeFixerConfig();
    TypeFixer fixer(cfg);
    return fixer.fix_function_types(func_ea);
}

inline VariableTypeFix StructorAPI::fix_variable_type(
    ea_t func_ea,
    int var_idx,
    const TypeFixerConfig* config)
{
    VariableTypeFix result;
    result.var_idx = var_idx;

    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) {
        result.skip_reason = "Failed to decompile function";
        return result;
    }

    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars || var_idx < 0 || static_cast<size_t>(var_idx) >= lvars->size()) {
        result.skip_reason = "Invalid variable index";
        return result;
    }

    result.var_name = lvars->at(var_idx).name;
    result.is_argument = lvars->at(var_idx).is_arg_var();

    TypeFixerConfig cfg = config ? *config : TypeFixerConfig();
    TypeFixer fixer(cfg);
    result.comparison = fixer.analyze_variable(cfunc, var_idx);

    if (result.comparison.is_significant() && !cfg.dry_run) {
        PropagationResult prop;
        if (fixer.apply_fix(cfunc, var_idx, result.comparison.inferred_type,
                            cfg.propagate_fixes ? &prop : nullptr)) {
            result.applied = true;
            result.propagation = std::move(prop);
        } else {
            result.skip_reason = "Failed to apply type";
        }
    } else if (!result.comparison.is_significant()) {
        result.skip_reason.sprnt("Not significant (%s)",
                                 type_difference_str(result.comparison.difference));
    } else {
        result.skip_reason = "Dry run mode";
    }

    return result;
}

inline VariableTypeFix StructorAPI::fix_variable_type(
    ea_t func_ea,
    const char* var_name,
    const TypeFixerConfig* config)
{
    VariableTypeFix result;

    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) {
        result.skip_reason = "Failed to decompile function";
        return result;
    }

    int var_idx = -1;
    if (!resolve_var_index(cfunc, var_name, var_idx)) {
        result.skip_reason.sprnt("Variable '%s' not found", var_name ? var_name : "");
        return result;
    }

    return fix_variable_type(func_ea, var_idx, config);
}

inline TypeComparisonResult StructorAPI::analyze_variable_type(
    ea_t func_ea,
    int var_idx,
    const TypeFixerConfig* config)
{
    TypeComparisonResult result;
    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) {
        result.description = "Failed to decompile function";
        return result;
    }

    TypeFixerConfig cfg = config ? *config : TypeFixerConfig();
    cfg.dry_run = true;
    TypeFixer fixer(cfg);
    return fixer.analyze_variable(cfunc, var_idx);
}

inline TypeComparisonResult StructorAPI::analyze_variable_type(
    ea_t func_ea,
    const char* var_name,
    const TypeFixerConfig* config)
{
    TypeComparisonResult result;
    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) {
        result.description = "Failed to decompile function";
        return result;
    }

    int var_idx = -1;
    if (!resolve_var_index(cfunc, var_name, var_idx)) {
        result.description.sprnt("Variable '%s' not found", var_name ? var_name : "");
        return result;
    }

    return analyze_variable_type(func_ea, var_idx, config);
}

inline RewriteResult StructorAPI::rewrite_pseudocode(
    ea_t func_ea,
    int var_idx,
    const SynthStruct& synth_struct,
    SynthOptions* opts)
{
    RewriteResult result;
    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) {
        return result;
    }

    const SynthOptions& options = opts ? *opts : Config::instance().options();
    PseudocodeRewriter rewriter(options);
    return rewriter.rewrite(cfunc, var_idx, synth_struct);
}

inline TypeFixResult StructorAPI::analyze_function_types(ea_t func_ea) {
    TypeFixerConfig cfg;
    cfg.dry_run = true;
    TypeFixer fixer(cfg);
    return fixer.fix_function_types(func_ea);
}

inline VariableStructureAnalysisResult StructorAPI::do_analyze_structure(
    ea_t func_ea,
    int var_idx,
    const SynthOptions& opts)
{
    VariableStructureAnalysisResult result;
    try {
        cfuncptr_t cfunc = utils::get_cfunc(func_ea);
        if (!cfunc) {
            result.error = SynthError::InternalError;
            result.error_message = "Failed to decompile function";
            return result;
        }

        result.variable = make_variable_descriptor(cfunc, var_idx);
        if (!result.variable.valid()) {
            result.error = SynthError::InvalidVariable;
            result.error_message = "Invalid variable index";
            return result;
        }

        AccessCollector collector(opts);
        result.local_pattern = collector.collect(cfunc, var_idx);

        if (result.local_pattern.accesses.empty()) {
            result.error = SynthError::NoAccessesFound;
            result.error_message = "No dereferences found for variable";
            return result;
        }

        if (static_cast<int>(result.local_pattern.access_count()) < opts.min_accesses) {
            result.error = SynthError::InsufficientAccesses;
            result.error_message.sprnt("Only %zu accesses found (minimum: %d)",
                                       result.local_pattern.access_count(),
                                       opts.min_accesses);
            return result;
        }

        LayoutSynthesizer synthesizer(opts);
        result.synthesis = synthesizer.synthesize(result.local_pattern, opts);
        result.unified_pattern = result.synthesis.unified_pattern;

        if (result.synthesis.structure.fields.empty()) {
            result.error = SynthError::TypeCreationFailed;
            result.error_message = "Failed to synthesize structure fields";
            return result;
        }

        result.synthesis.structure.source_func = func_ea;
        result.synthesis.structure.source_var = result.variable.var_name;

        if (opts.vtable_detection) {
            VTableDetector detector(opts);
            std::optional<SynthVTable> vtable;
            if (result.synthesis.unified_pattern.has_value() && result.synthesis.unified_pattern->has_vtable) {
                vtable = detector.detect(*result.synthesis.unified_pattern);
            } else if (result.local_pattern.has_vtable) {
                vtable = detector.detect(result.local_pattern, cfunc);
            }
            if (vtable) {
                result.synthesis.structure.vtable = std::move(vtable);
            }
        }

        result.error = SynthError::Success;
        return result;
    } catch (const vd_interr_t& e) {
        result.error = SynthError::InternalError;
        result.error_message = e.desc();
        return result;
    } catch (const vd_failure_t& e) {
        result.error = SynthError::InternalError;
        result.error_message = e.desc();
        return result;
    } catch (const std::exception& e) {
        result.error = SynthError::InternalError;
        result.error_message = e.what();
        return result;
    } catch (...) {
        result.error = SynthError::InternalError;
        result.error_message = "Structure analysis raised an unexpected exception";
        return result;
    }
}

inline GlobalStructureAnalysisResult StructorAPI::do_analyze_global_structure(
    ea_t global_ea,
    const SynthOptions& opts)
{
    GlobalStructureAnalysisResult result;
    result.global_ea = global_ea;
    get_name(&result.global_name, global_ea);

    try {
        GlobalObjectAnalyzer analyzer(opts);
        result.analysis = analyzer.analyze(global_ea);
        result.global_name = result.analysis.root_name;

        if (result.analysis.pattern.all_accesses.empty()) {
            result.error = SynthError::NoAccessesFound;
            result.error_message = "No global/static structure accesses found";
            return result;
        }

        if (static_cast<int>(result.analysis.pattern.unique_access_locations()) < opts.min_accesses) {
            result.error = SynthError::InsufficientAccesses;
            result.error_message.sprnt("Only %zu accesses found (minimum: %d)",
                                       result.analysis.pattern.unique_access_locations(),
                                       opts.min_accesses);
            return result;
        }

        LayoutSynthesizer synthesizer(opts);
        result.synthesis = synthesizer.synthesize(result.analysis.pattern);
        if (result.synthesis.structure.fields.empty()) {
            result.error = SynthError::TypeCreationFailed;
            result.error_message = "Failed to synthesize structure fields";
            return result;
        }

        SynthStruct& synth_struct = result.synthesis.structure;
        synth_struct.source_var = result.analysis.root_name;
        set_generated_name(synth_struct.name,
                           synth_struct.naming,
                           make_auto_root_type_name(BADADDR, result.analysis.root_name),
                           GeneratedNameKind::RootStruct,
                           NameConfidence::Medium);

        if (!result.analysis.pattern.contributing_functions.empty()) {
            synth_struct.source_func = result.analysis.pattern.contributing_functions[0];
            for (ea_t func_ea : result.analysis.pattern.contributing_functions) {
                synth_struct.add_provenance(func_ea);
            }
        }

        if (opts.vtable_detection) {
            VTableDetector detector(opts);
            std::optional<SynthVTable> vtable = detector.detect(result.analysis.pattern);
            if (vtable) {
                result.synthesis.structure.vtable = std::move(vtable);
            }
        }

        result.error = SynthError::Success;
        return result;
    } catch (const vd_interr_t& e) {
        result.error = SynthError::InternalError;
        result.error_message = e.desc();
        return result;
    } catch (const vd_failure_t& e) {
        result.error = SynthError::InternalError;
        result.error_message = e.desc();
        return result;
    } catch (const std::exception& e) {
        result.error = SynthError::InternalError;
        result.error_message = e.what();
        return result;
    } catch (...) {
        result.error = SynthError::InternalError;
        result.error_message = "Global/static analysis raised an unexpected exception";
        return result;
    }
}

inline SynthResult StructorAPI::do_global_synthesis(
    ea_t global_ea,
    const SynthOptions& opts,
    MaterializationMode mode)
{
    if (mode == MaterializationMode::Preview) {
        GlobalStructureAnalysisResult analysis = do_analyze_global_structure(global_ea, opts);
        if (!analysis.success()) {
            return SynthResult::make_error(analysis.error, analysis.error_message);
        }
        return make_result_from_synthesis(analysis.synthesis);
    }

    try {
        GlobalObjectAnalyzer analyzer(opts);
        GlobalObjectAnalysis analysis = analyzer.analyze(global_ea);

        if (analysis.pattern.all_accesses.empty()) {
            return SynthResult::make_error(SynthError::NoAccessesFound,
                "No global/static structure accesses found");
        }

        if (static_cast<int>(analysis.pattern.unique_access_locations()) < opts.min_accesses) {
            qstring msg;
            msg.sprnt("Only %zu accesses found (minimum: %d)",
                      analysis.pattern.unique_access_locations(),
                      opts.min_accesses);
            return SynthResult::make_error(SynthError::InsufficientAccesses, msg);
        }

        LayoutSynthesizer synthesizer(opts);
        SynthesisResult synth_result = synthesizer.synthesize(analysis.pattern);
        SynthResult result;
        result.conflicts = synth_result.conflicts;
        populate_z3_info_from_synthesis(result, synth_result);
        SynthStruct synth_struct = std::move(synth_result.structure);
        qvector<SubStructInfo> sub_structs = std::move(synth_result.sub_structs);

        if (synth_struct.fields.empty()) {
            return SynthResult::make_error(SynthError::TypeCreationFailed,
                "Failed to synthesize structure fields");
        }

        synth_struct.source_var = analysis.root_name;
        set_generated_name(synth_struct.name,
                           synth_struct.naming,
                           make_auto_root_type_name(BADADDR, analysis.root_name),
                           GeneratedNameKind::RootStruct,
                           NameConfidence::Medium);

        if (!analysis.pattern.contributing_functions.empty()) {
            synth_struct.source_func = analysis.pattern.contributing_functions[0];
            for (ea_t func_ea : analysis.pattern.contributing_functions) {
                synth_struct.add_provenance(func_ea);
            }
        }

        StructurePersistence persistence(opts);
        tid_t struct_tid = sub_structs.empty()
            ? persistence.create_struct(synth_struct)
            : persistence.create_struct_with_substructs(synth_struct, sub_structs);
        if (struct_tid == BADADDR) {
            return SynthResult::make_error(SynthError::TypeCreationFailed,
                "Failed to create structure in IDB");
        }

        result.struct_tid = struct_tid;
        result.fields_created = synth_struct.field_count();
        if (synth_struct.has_vtable()) {
            result.vtable_tid = synth_struct.vtable->tid;
            result.vtable_slots = synth_struct.vtable->slot_count();
        }

        if (mode == MaterializationMode::Persist) {
            result.synthesized_struct = std::make_unique<SynthStruct>(std::move(synth_struct));
            result.error = SynthError::Success;
            return result;
        }

        tinfo_t struct_type;
        if (!struct_type.get_type_by_tid(struct_tid)) {
            return SynthResult::make_error(SynthError::TypeCreationFailed,
                "Failed to load synthesized structure type");
        }

        if (opts.debug_mode) {
            msg("Structor: applying synthesized global type at 0x%llX\n",
                static_cast<unsigned long long>(global_ea));
        }
        (void)apply_global_tinfo(global_ea, struct_type);

        TypePropagator propagator(opts);
        for (const auto& var : analysis.zero_delta_variables) {
            cfuncptr_t cfunc = utils::get_cfunc(var.func_ea);
            if (!cfunc) {
                result.failed_sites.push_back(var.func_ea);
                continue;
            }

            try {
                if (propagator.apply_type(cfunc, var.var_idx, struct_type)) {
                    if (std::find(result.propagated_to.begin(), result.propagated_to.end(), var.func_ea) == result.propagated_to.end()) {
                        result.propagated_to.push_back(var.func_ea);
                    }
                } else if (std::find(result.failed_sites.begin(), result.failed_sites.end(), var.func_ea) == result.failed_sites.end()) {
                    result.failed_sites.push_back(var.func_ea);
                }
            } catch (...) {
                if (std::find(result.failed_sites.begin(), result.failed_sites.end(), var.func_ea) == result.failed_sites.end()) {
                    result.failed_sites.push_back(var.func_ea);
                }
            }
        }

        tinfo_t ptr_type;
        ptr_type.create_ptr(struct_type);
        for (const auto& [alias_ea, delta] : analysis.pointer_alias_globals) {
            if (delta == 0) {
                (void)apply_global_tinfo(alias_ea, ptr_type);
            }
        }

        try {
            register_global_rewrite_info(analysis, synth_struct, struct_type);
            for (ea_t func_ea : analysis.touched_functions) {
                cfuncptr_t cfunc = utils::get_cfunc(func_ea);
                if (cfunc) {
                    (void)rewrite_registered_global_uses(cfunc);
                }
            }
        } catch (...) {
        }

        result.synthesized_struct = std::make_unique<SynthStruct>(std::move(synth_struct));
        result.error = SynthError::Success;
        return result;
    } catch (const vd_interr_t& e) {
        return SynthResult::make_error(SynthError::InternalError, e.desc());
    } catch (const vd_failure_t& e) {
        return SynthResult::make_error(SynthError::InternalError, e.desc());
    } catch (const std::exception& e) {
        return SynthResult::make_error(SynthError::InternalError, e.what());
    } catch (...) {
        return SynthResult::make_error(SynthError::InternalError,
            "Global/static synthesis raised an unexpected exception");
    }
}

inline SynthResult StructorAPI::do_synthesis(
    ea_t func_ea,
    int var_idx,
    const SynthOptions& opts,
    MaterializationMode mode)
{
    if (mode == MaterializationMode::Preview) {
        VariableStructureAnalysisResult analysis = do_analyze_structure(func_ea, var_idx, opts);
        if (!analysis.success()) {
            return SynthResult::make_error(analysis.error, analysis.error_message);
        }
        return make_result_from_synthesis(analysis.synthesis);
    }

    SynthResult result;
    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) {
        return SynthResult::make_error(SynthError::InternalError, "Failed to decompile function");
    }

    if (try_reuse_generated_struct(cfunc, var_idx, result)) {
        return result;
    }

    AccessCollector collector(opts);
    AccessPattern pattern = collector.collect(cfunc, var_idx);

    if (pattern.accesses.empty()) {
        return SynthResult::make_error(SynthError::NoAccessesFound,
            "No dereferences found for variable");
    }

    if (static_cast<int>(pattern.access_count()) < opts.min_accesses) {
        qstring msg_str;
        msg_str.sprnt("Only %zu accesses found (minimum: %d)", pattern.access_count(), opts.min_accesses);
        return SynthResult::make_error(SynthError::InsufficientAccesses, msg_str);
    }

    LayoutSynthesizer synthesizer(opts);
    SynthesisResult synth_result = synthesizer.synthesize(pattern, opts);
    populate_z3_info_from_synthesis(result, synth_result);
    SynthStruct synth_struct = std::move(synth_result.structure);
    qvector<SubStructInfo> sub_structs = std::move(synth_result.sub_structs);

    result.conflicts = synth_result.conflicts;

    if (synth_struct.fields.empty()) {
        return SynthResult::make_error(SynthError::TypeCreationFailed,
            "Failed to synthesize structure fields");
    }

    if (opts.vtable_detection) {
        VTableDetector vtable_detector(opts);
        std::optional<SynthVTable> vtable;
        if (synth_result.unified_pattern.has_value() && synth_result.unified_pattern->has_vtable) {
            vtable = vtable_detector.detect(*synth_result.unified_pattern);
        } else if (pattern.has_vtable) {
            vtable = vtable_detector.detect(pattern, cfunc);
        }
        if (vtable) {
            synth_struct.vtable = std::move(vtable);
        }
    }

    StructurePersistence persistence(opts);
    tid_t struct_tid = sub_structs.empty()
        ? persistence.create_struct(synth_struct)
        : persistence.create_struct_with_substructs(synth_struct, sub_structs);

    if (struct_tid == BADADDR) {
        return SynthResult::make_error(SynthError::TypeCreationFailed,
            "Failed to create structure in IDB");
    }

    result.struct_tid = struct_tid;
    result.fields_created = synth_struct.field_count();

    if (synth_struct.has_vtable()) {
        result.vtable_tid = synth_struct.vtable->tid;
        result.vtable_slots = synth_struct.vtable->slot_count();
    }

    if (mode == MaterializationMode::Persist) {
        result.synthesized_struct = std::make_unique<SynthStruct>(std::move(synth_struct));
        result.error = SynthError::Success;
        return result;
    }

    tinfo_t struct_type;
    if (struct_type.get_type_by_tid(struct_tid)) {
        TypePropagator propagator(opts);

        if (propagator.apply_type(cfunc, var_idx, struct_type)) {
            result.propagated_to.push_back(func_ea);
        }

        if (opts.auto_propagate) {
            PropagationResult prop_result = propagator.propagate(
                func_ea,
                var_idx,
                struct_type,
                PropagationDirection::Both);

            auto member_size = [](const udm_t& member) -> size_t {
                const size_t type_size = member.type.get_size();
                if (type_size != BADSIZE) {
                    return type_size;
                }
                return member.size / 8;
            };

            auto extract_semantic_donor = [&](const tinfo_t& candidate, tinfo_t& donor_type) {
                donor_type = candidate;
                if (donor_type.is_ptr()) {
                    donor_type = donor_type.get_pointed_object();
                }
                if (!(donor_type.is_struct() || donor_type.is_union())) {
                    return false;
                }

                udt_type_data_t udt;
                if (!donor_type.get_udt_details(&udt) || udt.empty()) {
                    return false;
                }

                for (const auto& member : udt) {
                    if (!member.name.empty() && !structor::is_generated_name(member.name)) {
                        return true;
                    }
                }

                return false;
            };

            auto matches_donor_layout = [&](const SynthStruct& target, const tinfo_t& donor_type) {
                udt_type_data_t udt;
                if (!donor_type.get_udt_details(&udt) || udt.empty()) {
                    return false;
                }

                const size_t donor_size = donor_type.get_size();
                if (donor_size != BADSIZE && donor_size != target.size) {
                    return false;
                }

                size_t field_count = 0;
                for (const auto& field : target.fields) {
                    if (field.is_padding) {
                        continue;
                    }

                    ++field_count;
                    bool matched = false;
                    for (const auto& member : udt) {
                        if (member.offset != static_cast<uint64>(field.offset) * 8) {
                            continue;
                        }
                        if (member_size(member) != field.size) {
                            continue;
                        }

                        matched = true;
                        break;
                    }

                    if (!matched) {
                        return false;
                    }
                }

                return udt.size() == field_count;
            };

            if (!sub_structs.empty()) {
                qvector<tinfo_t> donor_types;
                for (const auto& site : prop_result.sites) {
                    if (!site.success) {
                        continue;
                    }

                    tinfo_t donor_type;
                    if (!extract_semantic_donor(site.new_type, donor_type)) {
                        continue;
                    }

                    bool duplicate = false;
                    for (const auto& existing : donor_types) {
                        if (existing.equals_to(donor_type)) {
                            duplicate = true;
                            break;
                        }
                    }
                    if (!duplicate) {
                        donor_types.push_back(std::move(donor_type));
                    }
                }

                bool refined_substructs = false;
                for (auto& sub : sub_structs) {
                    if (sub.structure.tid == BADADDR || !struct_needs_name_refinement(sub.structure)) {
                        continue;
                    }

                    int match_count = 0;
                    tinfo_t matched_donor;
                    for (const auto& donor_type : donor_types) {
                        if (!matches_donor_layout(sub.structure, donor_type)) {
                            continue;
                        }

                        matched_donor = donor_type;
                        ++match_count;
                        if (match_count > 1) {
                            break;
                        }
                    }

                    if (match_count != 1) {
                        continue;
                    }

                    (void)refine_struct_names_from_udt(sub.structure,
                                                       matched_donor,
                                                       NameOrigin::PropagatedDonor);
                    if (persistence.update_struct(sub.structure.tid, sub.structure)) {
                        refined_substructs = true;
                    }
                }

                if (refined_substructs) {
                    for (const auto& sub : sub_structs) {
                        if (sub.structure.tid == BADADDR) {
                            continue;
                        }

                        tinfo_t sub_type;
                        if (!sub_type.get_type_by_tid(sub.structure.tid)) {
                            continue;
                        }

                        for (auto& field : synth_struct.fields) {
                            if (field.offset != sub.parent_offset) {
                                continue;
                            }
                            if (!field.name.empty() && field.name != sub.field_name) {
                                continue;
                            }

                            field.type = sub_type;
                            field.size = sub.structure.size;
                            field.semantic = SemanticType::NestedStruct;
                            if (field.name.empty()) {
                                field.name = sub.field_name;
                            }
                            break;
                        }
                    }

                    if (persistence.update_struct(struct_tid, synth_struct)) {
                        tinfo_t refreshed_type;
                        if (refreshed_type.get_type_by_tid(struct_tid)) {
                            (void)propagator.apply_type(cfunc, var_idx, refreshed_type);
                        }
                    }
                }
            }

            for (const auto& site : prop_result.sites) {
                if (site.success) {
                    result.propagated_to.push_back(site.func_ea);
                } else {
                    result.failed_sites.push_back(site.func_ea);
                }
            }
        }
    }

    result.synthesized_struct = std::make_unique<SynthStruct>(std::move(synth_struct));
    result.error = SynthError::Success;
    return result;
}

} // namespace structor
