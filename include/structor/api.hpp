#pragma once

#include "synth_types.hpp"
#include "naming.hpp"
#include "config.hpp"
#include "access_collector.hpp"
#include "global_object_analyzer.hpp"
#include "global_tinfo_transaction.hpp"
#include "layout_synthesizer.hpp"
#include "vtable_detector.hpp"
#include "type_propagator.hpp"
#include "pseudocode_rewriter.hpp"
#include "structure_persistence.hpp"
#include "type_fixer.hpp"
#include "optimized_algorithms.hpp"

#include <unordered_set>
#include <vector>

namespace structor {

namespace detail {

/// IDA and Hex-Rays objects are host-thread affine. Public API entry points
/// fail closed off the IDA main thread instead of allowing SDK calls to race.
[[nodiscard]] inline bool api_host_thread_available() noexcept {
#ifdef STRUCTOR_TESTING
    return true;
#else
    try {
        return is_main_thread();
    } catch (...) {
        return false;
    }
#endif
}

inline constexpr const char* API_MAIN_THREAD_ERROR =
    "StructorAPI requires IDA's main thread";

} // namespace detail

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

[[nodiscard]] inline constexpr bool is_valid_materialization_mode(
    MaterializationMode mode) noexcept {
    return mode == MaterializationMode::Preview ||
           mode == MaterializationMode::Persist ||
           mode == MaterializationMode::PersistAndApply;
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

/// Primary API for programmatic structure synthesis. Methods that inspect or
/// mutate IDA/Hex-Rays state are main-thread-only and fail closed when called
/// from a worker thread. Callers that need cross-thread orchestration must
/// marshal the complete operation with IDA's execute_sync().
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

    /// Apply a type to a global/static object transactionally. Must be called
    /// on IDA's main thread; off-thread calls fail without mutation.
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

    /// Produce diagnostic rewrite plans for expressions covered by a
    /// synthesized structure. This does not mutate ctree; durable rendering is
    /// obtained by applying the recovered type through the type APIs.
    [[nodiscard]] RewriteResult rewrite_pseudocode(
        ea_t func_ea,
        int var_idx,
        const SynthStruct& synth_struct,
        SynthOptions* opts = nullptr);

    /// Analyze types without fixing (dry run)
    [[nodiscard]] TypeFixResult analyze_function_types(ea_t func_ea);

    /// Get current configuration
    [[nodiscard]] const SynthOptions& get_options() const {
        if (!detail::api_host_thread_available()) {
            static const SynthOptions defaults;
            return defaults;
        }
        return Config::instance().options();
    }

    /// Set configuration options atomically. Invalid ABI alignment is rejected
    /// without changing the active configuration.
    [[nodiscard]] bool set_options(const SynthOptions& opts) {
        if (!detail::api_host_thread_available()) {
            return false;
        }
        return Config::instance().set_options(opts);
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
    dst.flow_diagnostics = src.flow_diagnostics;
    dst.arrays_suppressed_by_flow_budget = src.arrays_suppressed_by_flow_budget;
    dst.z3_info.solve_time_ms = static_cast<std::uint32_t>(src.z3_solve_time.count());
    dst.z3_info.candidates_selected = static_cast<std::uint32_t>(src.structure.fields.size());
    dst.z3_info.constraints_hard = src.z3_stats.hard_constraints;
    dst.z3_info.constraints_soft = src.z3_stats.soft_constraints;
    dst.z3_info.constraints_relaxed = src.z3_stats.relaxations_performed;
    dst.z3_info.arrays_detected = static_cast<std::uint32_t>(src.arrays_detected);
    dst.z3_info.unions_created = static_cast<std::uint32_t>(src.unions_created);
    dst.z3_info.cross_func_merged = static_cast<std::uint32_t>(src.functions_analyzed);

    if (src.error == SynthError::ResourceLimitExceeded) {
        // A configured ceiling is a deterministic resource-limit outcome;
        // preserve Timeout/OutOfMemory for unconfigured solver failures.
        // resource_limit.kind carries the precise configured limit category.
        dst.z3_info.status = Z3SynthesisStatus::ResourceLimit;
    } else if (src.error == SynthError::Z3Timeout) {
        dst.z3_info.status = Z3SynthesisStatus::Timeout;
    } else if (src.error == SynthError::Z3OutOfMemory) {
        dst.z3_info.status = Z3SynthesisStatus::OutOfMemory;
    } else if (src.error == SynthError::Z3Unsat) {
        dst.z3_info.status = Z3SynthesisStatus::Unsat;
    } else if (!src.used_z3) {
        dst.z3_info.status = Z3SynthesisStatus::NotUsed;
    } else if (src.fell_back_to_heuristic) {
        dst.z3_info.status = Z3SynthesisStatus::FallbackHeuristic;
    } else if (src.raw_bytes_regions > 0) {
        dst.z3_info.status = Z3SynthesisStatus::FallbackRawBytes;
    } else if (src.had_relaxation) {
        dst.z3_info.status = Z3SynthesisStatus::SuccessRelaxed;
    } else if (src.error != SynthError::Success) {
        dst.z3_info.status = Z3SynthesisStatus::Error;
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

[[nodiscard]] inline bool resolve_var_index(
    cfunc_t* cfunc,
    const lvar_locator_t& locator,
    int& out_var_idx) {
    out_var_idx = -1;
    if (!cfunc) {
        return false;
    }
    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars || lvars->find(locator) == nullptr) {
        return false;
    }
    for (size_t i = 0; i < lvars->size(); ++i) {
        if (static_cast<const lvar_locator_t&>(lvars->at(i)) == locator) {
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

inline void add_unique_site(qvector<ea_t>& sites, ea_t func_ea) {
    if (func_ea != BADADDR &&
        std::find(sites.begin(), sites.end(), func_ea) == sites.end()) {
        sites.push_back(func_ea);
    }
}

inline void apply_recovered_substruct_types(
    qvector<SubStructInfo>& recovered,
    TypePropagator& propagator,
    SynthResult& result)
{
    auto apply_deepest_first = [&](auto&& self,
                                   qvector<SubStructInfo>& entries) -> void {
        for (auto& sub : entries) {
            self(self, sub.children);

            // Inline-window children describe structure only. A nonnegative
            // source index explicitly denotes an apply-eligible seed.
            if (sub.structure.source_func == BADADDR ||
                sub.source_var_idx < 0) {
                continue;
            }
            if (sub.structure.tid == BADADDR ||
                !sub.source_locator.has_value()) {
                add_unique_site(
                    result.failed_sites, sub.structure.source_func);
                continue;
            }

            tinfo_t sub_type;
            if (!sub_type.get_type_by_tid(sub.structure.tid)) {
                add_unique_site(
                    result.failed_sites, sub.structure.source_func);
                continue;
            }

            cfuncptr_t sub_cfunc =
                utils::get_cfunc(sub.structure.source_func);
            int current_sub_idx = -1;
            if (!sub_cfunc || !resolve_var_index(
                    sub_cfunc, *sub.source_locator, current_sub_idx)) {
                add_unique_site(
                    result.failed_sites, sub.structure.source_func);
                continue;
            }

            if (propagator.apply_type(
                    sub_cfunc, current_sub_idx, sub_type)) {
                add_unique_site(
                    result.propagated_to, sub.structure.source_func);
            } else {
                add_unique_site(
                    result.failed_sites, sub.structure.source_func);
            }
        }
    };
    apply_deepest_first(apply_deepest_first, recovered);
}

[[nodiscard]] inline SynthResult make_result_from_synthesis(const SynthesisResult& synthesis) {
    SynthResult result;
    result.error = synthesis.error;
    result.error_message = synthesis.error_message;
    result.conflicts = synthesis.conflicts;
    result.resource_limit = synthesis.resource_limit;
    populate_z3_info_from_synthesis(result, synthesis);

    if (synthesis.error != SynthError::Success) {
        return result;
    }

    if (!synthesis.structure.fields.empty()) {
        result.fields_created = static_cast<int>(synthesis.structure.field_count());
        if (synthesis.structure.has_vtable()) {
            result.vtable_slots = static_cast<int>(synthesis.structure.vtable->slot_count());
        }
        result.synthesized_struct = std::make_unique<SynthStruct>(synthesis.structure);
    }

    return result;
}

[[nodiscard]] inline std::size_t synthesis_evidence_count(
    const AccessPattern& local_pattern,
    const std::optional<UnifiedAccessPattern>& unified_pattern)
{
    if (unified_pattern.has_value()) {
        return unified_pattern->unique_access_locations();
    }

    return local_pattern.access_count();
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
    if (!detail::api_host_thread_available()) {
        return SynthResult::make_error(
            SynthError::InternalError, detail::API_MAIN_THREAD_ERROR);
    }
    if (!var) {
        return SynthResult::make_error(SynthError::InvalidVariable, "Null variable pointer");
    }
    const lvar_locator_t locator = *var;

    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) {
        return SynthResult::make_error(SynthError::InternalError, "Failed to decompile function");
    }
    int var_idx = -1;
    if (!resolve_var_index(cfunc, locator, var_idx)) {
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
    if (!detail::api_host_thread_available()) {
        return SynthResult::make_error(
            SynthError::InternalError, detail::API_MAIN_THREAD_ERROR);
    }
    if (!is_valid_materialization_mode(mode)) {
        return SynthResult::make_error(
            SynthError::InternalError, "Invalid materialization mode");
    }
    const SynthOptions& options = opts ? *opts : Config::instance().options();
    try {
        return do_synthesis(func_ea, var_idx, options, mode);
    } catch (const vd_interr_t& e) {
        return SynthResult::make_error(SynthError::InternalError, e.desc());
    } catch (const vd_failure_t& e) {
        return SynthResult::make_error(SynthError::InternalError, e.desc());
    } catch (const std::exception& e) {
        return SynthResult::make_error(SynthError::InternalError, e.what());
    } catch (...) {
        return SynthResult::make_error(
            SynthError::InternalError,
            "Local synthesis raised an unexpected exception");
    }
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
    if (!detail::api_host_thread_available()) {
        return SynthResult::make_error(
            SynthError::InternalError, detail::API_MAIN_THREAD_ERROR);
    }
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
    if (!detail::api_host_thread_available()) {
        return SynthResult::make_error(
            SynthError::InternalError, detail::API_MAIN_THREAD_ERROR);
    }
    if (!is_valid_materialization_mode(mode)) {
        return SynthResult::make_error(
            SynthError::InternalError, "Invalid materialization mode");
    }
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
    if (!detail::api_host_thread_available()) {
        return SynthResult::make_error(
            SynthError::InternalError, detail::API_MAIN_THREAD_ERROR);
    }
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
    if (!detail::api_host_thread_available()) {
        result.error = SynthError::InternalError;
        result.error_message = detail::API_MAIN_THREAD_ERROR;
        return result;
    }
    if (!var) {
        result.error = SynthError::InvalidVariable;
        result.error_message = "Null variable pointer";
        return result;
    }
    const lvar_locator_t locator = *var;

    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) {
        result.error = SynthError::InternalError;
        result.error_message = "Failed to decompile function";
        return result;
    }

    int var_idx = -1;
    if (!resolve_var_index(cfunc, locator, var_idx)) {
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
    if (!detail::api_host_thread_available()) {
        VariableStructureAnalysisResult result;
        result.error = SynthError::InternalError;
        result.error_message = detail::API_MAIN_THREAD_ERROR;
        return result;
    }
    const SynthOptions& options = opts ? *opts : Config::instance().options();
    return do_analyze_structure(func_ea, var_idx, options);
}

inline VariableStructureAnalysisResult StructorAPI::analyze_structure(
    ea_t func_ea,
    const char* var_name,
    SynthOptions* opts)
{
    VariableStructureAnalysisResult result;
    if (!detail::api_host_thread_available()) {
        result.error = SynthError::InternalError;
        result.error_message = detail::API_MAIN_THREAD_ERROR;
        return result;
    }
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
    if (!detail::api_host_thread_available()) {
        result.error = SynthError::InternalError;
        result.error_message = detail::API_MAIN_THREAD_ERROR;
        return result;
    }
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
    if (!detail::api_host_thread_available()) {
        result.error = SynthError::InternalError;
        result.error_message = detail::API_MAIN_THREAD_ERROR;
        return result;
    }
    if (!is_valid_materialization_mode(mode)) {
        result.error = SynthError::InternalError;
        result.error_message = "Invalid materialization mode";
        return result;
    }
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

    struct StableVariableTarget {
        lvar_locator_t locator;
        VariableDescriptor initial_descriptor;
    };
    std::vector<StableVariableTarget> stable_targets;
    stable_targets.reserve(lvars->size());
    for (size_t i = 0; i < lvars->size(); ++i) {
        StableVariableTarget target;
        target.locator = static_cast<const lvar_locator_t&>(lvars->at(i));
        target.initial_descriptor =
            make_variable_descriptor(cfunc, static_cast<int>(i));
        stable_targets.push_back(std::move(target));
    }

    const SynthOptions& options = opts ? *opts : Config::instance().options();
    // AccessPattern contains host-owned tinfo_t/qstring state and production
    // layout decoding calls IDA type APIs. No SDK contract establishes those
    // operations as worker-thread safe, so function-wide preview remains on
    // the host thread. Parallelism belongs behind a future fully detached IR.
    const bool can_parallel_preview = false;

    if (can_parallel_preview) {
        struct PreviewWorkItem {
            VariableStructureSynthesisResult entry;
            AccessPattern pattern;
            bool needs_layout = false;
        };

        std::vector<PreviewWorkItem> work(lvars->size());
        AccessCollector collector(options);
        for (size_t i = 0; i < lvars->size(); ++i) {
            auto& item = work[i];
            item.entry.variable = make_variable_descriptor(cfunc, static_cast<int>(i));
            if (!item.entry.variable.valid()) {
                item.entry.synthesis = SynthResult::make_error(
                    SynthError::InvalidVariable,
                    "Invalid variable index");
                continue;
            }

            item.pattern = collector.collect(cfunc, static_cast<int>(i));
            if (item.pattern.accesses.empty()) {
                item.entry.synthesis = SynthResult::make_error(
                    SynthError::NoAccessesFound,
                    "No dereferences found for variable");
                continue;
            }

            item.needs_layout = true;
        }

        algorithms::parallel_for_chunks(work.size(), 2, [&](size_t begin, size_t end) {
            for (size_t i = begin; i < end; ++i) {
                auto& item = work[i];
                if (!item.needs_layout) {
                    continue;
                }

                LayoutSynthesizer synthesizer(options);
                SynthesisResult synthesis = synthesizer.synthesize(item.pattern, options);
                if (synthesis.error != SynthError::Success) {
                    item.entry.synthesis = make_result_from_synthesis(synthesis);
                    continue;
                }
                const std::size_t evidence_count =
                    synthesis_evidence_count(item.pattern, synthesis.unified_pattern);
                if (static_cast<int>(evidence_count) < options.min_accesses) {
                    qstring msg;
                    msg.sprnt("Only %zu accesses found (minimum: %d)",
                              evidence_count,
                              options.min_accesses);
                    item.entry.synthesis = SynthResult::make_error(
                        SynthError::InsufficientAccesses,
                        msg);
                    continue;
                }

                if (synthesis.structure.fields.empty()) {
                    item.entry.synthesis = SynthResult::make_error(
                        SynthError::TypeCreationFailed,
                        "Failed to synthesize structure fields");
                    continue;
                }

                synthesis.structure.source_func = func_ea;
                synthesis.structure.source_var = item.entry.variable.var_name;
                item.entry.synthesis = make_result_from_synthesis(synthesis);
            }
        });

        for (auto& item : work) {
            ++result.attempted;
            if (item.entry.synthesis.success()) {
                ++result.succeeded;
            } else if (item.entry.synthesis.error == SynthError::NoAccessesFound ||
                       item.entry.synthesis.error == SynthError::InsufficientAccesses) {
                ++result.skipped;
            } else {
                ++result.failed;
            }

            result.variables.push_back(std::move(item.entry));
        }

        return result;
    }

    for (const auto& target : stable_targets) {
        VariableStructureSynthesisResult entry;
        entry.variable = target.initial_descriptor;

        cfuncptr_t current_cfunc = utils::get_cfunc(func_ea);
        int current_index = -1;
        if (!current_cfunc ||
            !resolve_var_index(current_cfunc, target.locator, current_index)) {
            entry.synthesis = SynthResult::make_error(
                SynthError::InvalidVariable,
                "Stable variable locator no longer resolves after a prior materialization");
        } else {
            entry.variable = make_variable_descriptor(current_cfunc, current_index);
            entry.synthesis =
                synthesize_structure(func_ea, current_index, mode, opts);

            // Report the post-mutation descriptor only if the same SDK locator
            // still resolves. Never substitute a same-index replacement.
            cfuncptr_t observed_cfunc = utils::get_cfunc(func_ea);
            int observed_index = -1;
            if (observed_cfunc && resolve_var_index(
                    observed_cfunc, target.locator, observed_index)) {
                entry.variable =
                    make_variable_descriptor(observed_cfunc, observed_index);
            }
        }

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
    if (!detail::api_host_thread_available()) {
        GlobalStructureAnalysisResult result;
        result.global_ea = global_ea;
        result.error = SynthError::InternalError;
        result.error_message = detail::API_MAIN_THREAD_ERROR;
        return result;
    }
    const SynthOptions& options = opts ? *opts : Config::instance().options();
    return do_analyze_global_structure(global_ea, options);
}

inline GlobalStructureAnalysisResult StructorAPI::analyze_global_structure(
    const char* global_name,
    SynthOptions* opts)
{
    GlobalStructureAnalysisResult result;
    if (!detail::api_host_thread_available()) {
        result.error = SynthError::InternalError;
        result.error_message = detail::API_MAIN_THREAD_ERROR;
        return result;
    }
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
    if (!detail::api_host_thread_available()) {
        return AccessPattern();
    }
    try {
        AccessCollector collector;
        return collector.collect(func_ea, var_idx);
    } catch (...) {
        return AccessPattern();
    }
}

inline AccessPattern StructorAPI::collect_accesses(ea_t func_ea, const char* var_name) {
    if (!detail::api_host_thread_available()) {
        return AccessPattern();
    }
    try {
        AccessCollector collector;
        return collector.collect(func_ea, var_name);
    } catch (...) {
        return AccessPattern();
    }
}

inline UnifiedAccessPattern StructorAPI::collect_unified_accesses(
    ea_t func_ea,
    int var_idx,
    SynthOptions* opts)
{
    if (!detail::api_host_thread_available()) {
        return UnifiedAccessPattern();
    }
    try {
        const SynthOptions& options = opts ? *opts : Config::instance().options();
        CrossFunctionAnalyzer analyzer;
        return analyzer.analyze(func_ea, var_idx, options);
    } catch (...) {
        return UnifiedAccessPattern();
    }
}

inline UnifiedAccessPattern StructorAPI::collect_unified_accesses(
    ea_t func_ea,
    const char* var_name,
    SynthOptions* opts)
{
    if (!detail::api_host_thread_available()) {
        return UnifiedAccessPattern();
    }
    try {
        cfuncptr_t cfunc = utils::get_cfunc(func_ea);
        if (!cfunc) {
            return UnifiedAccessPattern();
        }

        int var_idx = -1;
        if (!resolve_var_index(cfunc, var_name, var_idx)) {
            return UnifiedAccessPattern();
        }

        return collect_unified_accesses(func_ea, var_idx, opts);
    } catch (...) {
        return UnifiedAccessPattern();
    }
}

inline SynthStruct StructorAPI::synthesize_layout(
    const AccessPattern& pattern,
    SynthOptions* opts)
{
    if (!detail::api_host_thread_available()) {
        return SynthStruct();
    }
    try {
        const SynthOptions& options = opts ? *opts : Config::instance().options();
        LayoutSynthesizer synthesizer(options);
        return synthesizer.synthesize(pattern, options).structure;
    } catch (...) {
        return SynthStruct();
    }
}

inline SynthesisResult StructorAPI::synthesize_layout(
    const UnifiedAccessPattern& pattern,
    SynthOptions* opts)
{
    if (!detail::api_host_thread_available()) {
        SynthesisResult result;
        result.error = SynthError::InternalError;
        result.error_message = detail::API_MAIN_THREAD_ERROR;
        return result;
    }
    try {
        const SynthOptions& options = opts ? *opts : Config::instance().options();
        LayoutSynthesizer synthesizer(options);
        return synthesizer.synthesize(pattern, options);
    } catch (const std::exception& e) {
        SynthesisResult result;
        result.error = SynthError::InternalError;
        result.error_message = e.what();
        return result;
    } catch (...) {
        SynthesisResult result;
        result.error = SynthError::InternalError;
        result.error_message = "Layout synthesis raised an unexpected exception";
        return result;
    }
}

inline std::optional<SynthVTable> StructorAPI::detect_vtable(
    const AccessPattern& pattern,
    ea_t func_ea)
{
    if (!detail::api_host_thread_available()) {
        return std::nullopt;
    }
    try {
        cfuncptr_t cfunc = utils::get_cfunc(func_ea);
        if (!cfunc) {
            return std::nullopt;
        }

        VTableDetector detector;
        return detector.detect(pattern, cfunc);
    } catch (...) {
        return std::nullopt;
    }
}

inline std::optional<SynthVTable> StructorAPI::detect_vtable(
    const UnifiedAccessPattern& pattern,
    SynthOptions* opts)
{
    if (!detail::api_host_thread_available()) {
        return std::nullopt;
    }
    try {
        const SynthOptions& options = opts ? *opts : Config::instance().options();
        VTableDetector detector(options);
        return detector.detect(pattern);
    } catch (...) {
        return std::nullopt;
    }
}

inline PropagationResult StructorAPI::propagate_type(
    ea_t func_ea,
    int var_idx,
    const tinfo_t& type,
    PropagationDirection direction)
{
    if (!detail::api_host_thread_available()) {
        return PropagationResult();
    }
    try {
        TypePropagator propagator;
        return propagator.propagate(func_ea, var_idx, type, direction);
    } catch (...) {
        return PropagationResult();
    }
}

inline PropagationResult StructorAPI::propagate_type_local(
    ea_t func_ea,
    int var_idx,
    const tinfo_t& type,
    SynthOptions* opts)
{
    PropagationResult result;
    if (!detail::api_host_thread_available()) {
        return result;
    }
    try {
        cfuncptr_t cfunc = utils::get_cfunc(func_ea);
        if (!cfunc) {
            return result;
        }

        const SynthOptions& options = opts ? *opts : Config::instance().options();
        TypePropagator propagator(options);
        return propagator.propagate_local(cfunc, var_idx, type);
    } catch (...) {
        return result;
    }
}

inline bool StructorAPI::apply_type(
    ea_t func_ea,
    int var_idx,
    const tinfo_t& type,
    SynthOptions* opts)
{
    if (!detail::api_host_thread_available()) {
        return false;
    }
    try {
        cfuncptr_t cfunc = utils::get_cfunc(func_ea);
        if (!cfunc) {
            return false;
        }

        const SynthOptions& options = opts ? *opts : Config::instance().options();
        TypePropagator propagator(options);
        return propagator.apply_type(cfunc, var_idx, type);
    } catch (...) {
        return false;
    }
}

inline bool StructorAPI::apply_global_type(
    ea_t global_ea,
    const tinfo_t& type)
{
    if (!detail::api_host_thread_available()) {
        return false;
    }
    return apply_global_tinfo(global_ea, type);
}

inline TypeFixResult StructorAPI::fix_function_types(
    ea_t func_ea,
    const TypeFixerConfig* config)
{
    if (!detail::api_host_thread_available()) {
        TypeFixResult result;
        result.func_ea = func_ea;
        result.errors.push_back(detail::API_MAIN_THREAD_ERROR);
        return result;
    }
    try {
        TypeFixerConfig cfg = config ? *config : TypeFixerConfig();
        TypeFixer fixer(cfg);
        return fixer.fix_function_types(func_ea);
    } catch (const vd_interr_t& e) {
        TypeFixResult result;
        result.func_ea = func_ea;
        result.errors.push_back(e.desc());
        return result;
    } catch (const vd_failure_t& e) {
        TypeFixResult result;
        result.errors.push_back(e.desc());
        return result;
    } catch (const std::exception& e) {
        TypeFixResult result;
        result.errors.push_back(e.what());
        return result;
    } catch (...) {
        TypeFixResult result;
        result.errors.push_back("Type fixing raised an unexpected exception");
        return result;
    }
}

inline VariableTypeFix StructorAPI::fix_variable_type(
    ea_t func_ea,
    int var_idx,
    const TypeFixerConfig* config)
{
    VariableTypeFix result;
    result.var_idx = var_idx;
    if (!detail::api_host_thread_available()) {
        result.skip_reason = detail::API_MAIN_THREAD_ERROR;
        return result;
    }

    try {

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
    } catch (const vd_interr_t& e) {
        result.skip_reason = e.desc();
    } catch (const vd_failure_t& e) {
        result.skip_reason = e.desc();
    } catch (const std::exception& e) {
        result.skip_reason = e.what();
    } catch (...) {
        result.skip_reason = "Variable type fixing raised an unexpected exception";
    }
    return result;
}

inline VariableTypeFix StructorAPI::fix_variable_type(
    ea_t func_ea,
    const char* var_name,
    const TypeFixerConfig* config)
{
    VariableTypeFix result;
    if (!detail::api_host_thread_available()) {
        result.skip_reason = detail::API_MAIN_THREAD_ERROR;
        return result;
    }

    try {

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
    } catch (const vd_interr_t& e) {
        result.skip_reason = e.desc();
    } catch (const vd_failure_t& e) {
        result.skip_reason = e.desc();
    } catch (const std::exception& e) {
        result.skip_reason = e.what();
    } catch (...) {
        result.skip_reason = "Variable lookup raised an unexpected exception";
    }
    return result;
}

inline TypeComparisonResult StructorAPI::analyze_variable_type(
    ea_t func_ea,
    int var_idx,
    const TypeFixerConfig* config)
{
    TypeComparisonResult result;
    if (!detail::api_host_thread_available()) {
        result.description = detail::API_MAIN_THREAD_ERROR;
        return result;
    }
    try {
    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) {
        result.description = "Failed to decompile function";
        return result;
    }

    TypeFixerConfig cfg = config ? *config : TypeFixerConfig();
    cfg.dry_run = true;
    TypeFixer fixer(cfg);
        return fixer.analyze_variable(cfunc, var_idx);
    } catch (const vd_interr_t& e) {
        result.description = e.desc();
    } catch (const vd_failure_t& e) {
        result.description = e.desc();
    } catch (const std::exception& e) {
        result.description = e.what();
    } catch (...) {
        result.description = "Variable analysis raised an unexpected exception";
    }
    return result;
}

inline TypeComparisonResult StructorAPI::analyze_variable_type(
    ea_t func_ea,
    const char* var_name,
    const TypeFixerConfig* config)
{
    TypeComparisonResult result;
    if (!detail::api_host_thread_available()) {
        result.description = detail::API_MAIN_THREAD_ERROR;
        return result;
    }
    try {
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
    } catch (const vd_interr_t& e) {
        result.description = e.desc();
    } catch (const vd_failure_t& e) {
        result.description = e.desc();
    } catch (const std::exception& e) {
        result.description = e.what();
    } catch (...) {
        result.description = "Variable lookup raised an unexpected exception";
    }
    return result;
}

inline RewriteResult StructorAPI::rewrite_pseudocode(
    ea_t func_ea,
    int var_idx,
    const SynthStruct& synth_struct,
    SynthOptions* opts)
{
    RewriteResult result;
    if (!detail::api_host_thread_available()) {
        ++result.failure_count;
        return result;
    }
    try {
        cfuncptr_t cfunc = utils::get_cfunc(func_ea);
        if (!cfunc) {
            return result;
        }

        const SynthOptions& options = opts ? *opts : Config::instance().options();
        PseudocodeRewriter rewriter(options);
        return rewriter.rewrite(cfunc, var_idx, synth_struct);
    } catch (...) {
        ++result.failure_count;
        return result;
    }
}

inline TypeFixResult StructorAPI::analyze_function_types(ea_t func_ea) {
    TypeFixerConfig cfg;
    cfg.dry_run = true;
    return fix_function_types(func_ea, &cfg);
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
            result.synthesis.error = result.error;
            result.synthesis.error_message = result.error_message;
            return result;
        }

        result.variable = make_variable_descriptor(cfunc, var_idx);
        if (!result.variable.valid()) {
            result.error = SynthError::InvalidVariable;
            result.error_message = "Invalid variable index";
            result.synthesis.error = result.error;
            result.synthesis.error_message = result.error_message;
            return result;
        }

        AccessCollector collector(opts);
        result.local_pattern = collector.collect(cfunc, var_idx);
        result.synthesis.flow_diagnostics.push_back({result.local_pattern.func_ea,
            result.local_pattern.var_idx, result.local_pattern.flow_analysis});

        if (result.local_pattern.accesses.empty()) {
            result.error = SynthError::NoAccessesFound;
            result.error_message = "No dereferences found for variable";
            result.synthesis.error = result.error;
            result.synthesis.error_message = result.error_message;
            return result;
        }

        LayoutSynthesizer synthesizer(opts);
        result.synthesis = synthesizer.synthesize(result.local_pattern, opts);
        result.unified_pattern = result.synthesis.unified_pattern;

        if (result.synthesis.error != SynthError::Success) {
            result.error = result.synthesis.error;
            result.error_message = result.synthesis.error_message;
            return result;
        }

        const std::size_t evidence_count =
            synthesis_evidence_count(result.local_pattern, result.unified_pattern);
        if (static_cast<int>(evidence_count) < opts.min_accesses) {
            result.error = SynthError::InsufficientAccesses;
            result.error_message.sprnt("Only %zu accesses found (minimum: %d)",
                                       evidence_count,
                                       opts.min_accesses);
            return result;
        }

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
        result.synthesis.flow_diagnostics = result.analysis.pattern.flow_diagnostics;

        if (result.analysis.pattern.all_accesses.empty()) {
            result.error = SynthError::NoAccessesFound;
            result.error_message = "No global/static structure accesses found";
            result.synthesis.error = result.error;
            result.synthesis.error_message = result.error_message;
            return result;
        }

        if (static_cast<int>(result.analysis.pattern.unique_access_locations()) < opts.min_accesses) {
            result.error = SynthError::InsufficientAccesses;
            result.error_message.sprnt("Only %zu accesses found (minimum: %d)",
                                       result.analysis.pattern.unique_access_locations(),
                                       opts.min_accesses);
            result.synthesis.error = result.error;
            result.synthesis.error_message = result.error_message;
            return result;
        }

        LayoutSynthesizer synthesizer(opts);
        const ea_t source_func_hint =
            result.analysis.pattern.contributing_functions.empty()
                ? BADADDR
                : result.analysis.pattern.contributing_functions.front();
        result.synthesis = synthesizer.synthesize(
            result.analysis.pattern, opts, source_func_hint);
        if (result.synthesis.error != SynthError::Success) {
            result.error = result.synthesis.error;
            result.error_message = result.synthesis.error_message;
            return result;
        }
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
            auto failure = SynthResult::make_error(analysis.error, analysis.error_message);
            populate_z3_info_from_synthesis(failure, analysis.synthesis);
            return failure;
        }
        return make_result_from_synthesis(analysis.synthesis);
    }

    try {
        GlobalObjectAnalyzer analyzer(opts);
        GlobalObjectAnalysis analysis = analyzer.analyze(global_ea);

        if (analysis.pattern.all_accesses.empty()) {
            auto failure = SynthResult::make_error(SynthError::NoAccessesFound,
                "No global/static structure accesses found");
            failure.flow_diagnostics = analysis.pattern.flow_diagnostics;
            return failure;
        }

        if (static_cast<int>(analysis.pattern.unique_access_locations()) < opts.min_accesses) {
            qstring msg;
            msg.sprnt("Only %zu accesses found (minimum: %d)",
                      analysis.pattern.unique_access_locations(),
                      opts.min_accesses);
            auto failure = SynthResult::make_error(SynthError::InsufficientAccesses, msg);
            failure.flow_diagnostics = analysis.pattern.flow_diagnostics;
            return failure;
        }

        // Global tinfo materialization can invalidate every contributing
        // cfunc. Capture variable identities before the first IDB mutation.
        std::vector<std::optional<lvar_locator_t>> zero_delta_locators;
        zero_delta_locators.reserve(analysis.zero_delta_variables.size());
        for (const auto& var : analysis.zero_delta_variables) {
            std::optional<lvar_locator_t> locator;
            cfuncptr_t cfunc = utils::get_cfunc(var.func_ea);
            lvars_t* lvars = cfunc ? cfunc->get_lvars() : nullptr;
            if (lvars != nullptr && var.var_idx >= 0 &&
                static_cast<size_t>(var.var_idx) < lvars->size()) {
                locator = static_cast<const lvar_locator_t&>(
                    lvars->at(static_cast<size_t>(var.var_idx)));
            }
            zero_delta_locators.push_back(std::move(locator));
        }

        LayoutSynthesizer synthesizer(opts);
        if (opts.debug_mode) {
            msg("Structor: global analysis produced %zu function delta(s), %zu flow edge(s)\n",
                analysis.pattern.function_deltas.size(),
                analysis.pattern.flow_edges.size());
            for (const auto& [func_ea, delta] : analysis.pattern.function_deltas) {
                qstring fname;
                get_func_name(&fname, func_ea);
                msg("Structor:   delta %s = 0x%llX\n",
                    fname.c_str(),
                    static_cast<unsigned long long>(delta));
            }
            for (const auto& edge : analysis.pattern.flow_edges) {
                qstring caller_name;
                qstring callee_name;
                get_func_name(&caller_name, edge.caller_ea);
                get_func_name(&callee_name, edge.callee_ea);
                msg("Structor:   edge %s -> %s delta=0x%llX param=%d\n",
                    caller_name.c_str(),
                    callee_name.c_str(),
                    static_cast<unsigned long long>(edge.delta),
                    edge.callee_param_idx);
            }
        }
        const ea_t source_func_hint =
            analysis.pattern.contributing_functions.empty()
                ? BADADDR
                : analysis.pattern.contributing_functions.front();
        SynthesisResult synth_result = synthesizer.synthesize(
            analysis.pattern, opts, source_func_hint);
        if (synth_result.error != SynthError::Success) {
            return make_result_from_synthesis(synth_result);
        }
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
        auto persistence_transaction = persistence.begin_transaction();
        if (!persistence_transaction.has_value()) {
            return SynthResult::make_error(SynthError::InternalError,
                "Failed to begin structure persistence transaction");
        }
        tid_t struct_tid = sub_structs.empty()
            ? persistence.create_struct(synth_struct)
            : persistence.create_struct_with_substructs(synth_struct, sub_structs);
        if (struct_tid == BADADDR) {
            const bool rollback_succeeded = persistence_transaction->rollback();
            if (!rollback_succeeded) {
                return SynthResult::make_error(SynthError::InternalError,
                    "Failed to create structure in IDB and persistence rollback failed");
            }
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
            if (!persistence_transaction->commit()) {
                result.struct_tid = BADADDR;
                result.vtable_tid = BADADDR;
                result.synthesized_struct->tid = BADADDR;
                if (result.synthesized_struct->vtable.has_value()) {
                    result.synthesized_struct->vtable->tid = BADADDR;
                }
                result.error = SynthError::InternalError;
                result.error_message =
                    "Persistence transaction was rejected and rolled back";
                return result;
            }
            result.error = SynthError::Success;
            return result;
        }

        tinfo_t struct_type;
        if (!struct_type.get_type_by_tid(struct_tid)) {
            const bool rollback_succeeded = persistence_transaction->rollback();
            if (!rollback_succeeded) {
                return SynthResult::make_error(SynthError::InternalError,
                    "Failed to load synthesized structure type and persistence rollback failed");
            }
            return SynthResult::make_error(SynthError::TypeCreationFailed,
                "Failed to load synthesized structure type");
        }

        if (opts.debug_mode) {
            msg("Structor: applying synthesized global type at 0x%llX\n",
                static_cast<unsigned long long>(global_ea));
        }
        const bool inject_apply_failure =
            persistence_invariants::persistence_fault_requested(
                "required_source_apply");
        const detail::GlobalTinfoApplyResult global_apply_result =
            inject_apply_failure
                ? detail::GlobalTinfoApplyResult::FailedRestored
                : apply_global_tinfo_detailed(global_ea, struct_type);
        if (global_apply_result != detail::GlobalTinfoApplyResult::Applied) {
            if (global_apply_result ==
                detail::GlobalTinfoApplyResult::RollbackFailed) {
                // The address may still reference the synthesized type. Retain
                // the named types instead of deleting a live TID.
                qstring retain_failed_message =
                    "Failed to apply the global type, global-tinfo rollback "
                    "failed, and the persistence transaction could not be retained";
                result.error = SynthError::InternalError;
                result.error_message =
                    "Failed to apply the global type and global-tinfo rollback "
                    "failed; persisted types were retained to preserve references";
                result.failed_sites.push_back(global_ea);
                result.synthesized_struct =
                    std::make_unique<SynthStruct>(std::move(synth_struct));
                const bool retained = persistence_transaction->commit();
                if (!retained) {
                    result.error_message.swap(retain_failed_message);
                }
                return result;
            }
            const bool rollback_succeeded = persistence_transaction->rollback();
            result.struct_tid = BADADDR;
            result.vtable_tid = BADADDR;
            synth_struct.tid = BADADDR;
            if (synth_struct.vtable.has_value()) {
                synth_struct.vtable->tid = BADADDR;
            }
            result.error = rollback_succeeded
                ? SynthError::PropagationFailed
                : SynthError::InternalError;
            result.error_message = rollback_succeeded
                ? "Failed to apply synthesized type to the global object; "
                  "persistence transaction rolled back"
                : "Failed to apply synthesized type to the global object; "
                  "persistence transaction rollback failed";
            result.synthesized_struct =
                std::make_unique<SynthStruct>(std::move(synth_struct));
            return result;
        }
        // Allocate the result payload before the commit point. After commit,
        // any optional propagation/rewrite failure must not be translated into
        // an overall error while durable IDB mutations remain.
        result.synthesized_struct = std::make_unique<SynthStruct>(synth_struct);
        result.error = SynthError::Success;
        if (!persistence_transaction->commit()) {
            result.struct_tid = BADADDR;
            result.vtable_tid = BADADDR;
            result.synthesized_struct->tid = BADADDR;
            if (result.synthesized_struct->vtable.has_value()) {
                result.synthesized_struct->vtable->tid = BADADDR;
            }
            result.error = SynthError::InternalError;
            result.error_message =
                "Persistence commit failed after global type application";
            result.failed_sites.push_back(global_ea);
            return result;
        }

        try {
        TypePropagator propagator(opts);
        apply_recovered_substruct_types(sub_structs, propagator, result);
        for (size_t var_index = 0;
             var_index < analysis.zero_delta_variables.size(); ++var_index) {
            const auto& var = analysis.zero_delta_variables[var_index];
            cfuncptr_t cfunc = utils::get_cfunc(var.func_ea);
            int current_var_idx = -1;
            if (!cfunc || !zero_delta_locators[var_index].has_value() ||
                !resolve_var_index(
                    cfunc, *zero_delta_locators[var_index],
                    current_var_idx)) {
                result.failed_sites.push_back(var.func_ea);
                continue;
            }

            try {
                if (propagator.apply_type(
                        cfunc, current_var_idx, struct_type)) {
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
            if (delta == 0 && !apply_global_tinfo(alias_ea, ptr_type)) {
                result.failed_sites.push_back(alias_ea);
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

        *result.synthesized_struct = std::move(synth_struct);
        } catch (...) {
            msg("Structor: Optional post-commit global propagation stopped after "
                "an exception; persisted root result remains successful\n");
        }
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
            auto failure = SynthResult::make_error(analysis.error, analysis.error_message);
            populate_z3_info_from_synthesis(failure, analysis.synthesis);
            return failure;
        }
        return make_result_from_synthesis(analysis.synthesis);
    }

    SynthResult result;
    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) {
        return SynthResult::make_error(SynthError::InternalError, "Failed to decompile function");
    }
    lvars_t* initial_lvars = cfunc->get_lvars();
    if (initial_lvars == nullptr || var_idx < 0 ||
        static_cast<size_t>(var_idx) >= initial_lvars->size()) {
        return SynthResult::make_error(
            SynthError::InvalidVariable, "Invalid source variable index");
    }
    const lvar_locator_t source_locator =
        static_cast<const lvar_locator_t&>(
            initial_lvars->at(static_cast<size_t>(var_idx)));

    AccessCollector collector(opts);
    AccessPattern pattern = collector.collect(cfunc, var_idx);

    if (pattern.accesses.empty()) {
        auto failure = SynthResult::make_error(SynthError::NoAccessesFound,
            "No dereferences found for variable");
        failure.flow_diagnostics.push_back({pattern.func_ea, pattern.var_idx, pattern.flow_analysis});
        return failure;
    }

    LayoutSynthesizer synthesizer(opts);
    SynthesisResult synth_result = synthesizer.synthesize(pattern, opts);
    if (synth_result.error != SynthError::Success) {
        return make_result_from_synthesis(synth_result);
    }
    const std::size_t evidence_count =
        synthesis_evidence_count(pattern, synth_result.unified_pattern);
    if (static_cast<int>(evidence_count) < opts.min_accesses) {
        qstring msg_str;
        msg_str.sprnt("Only %zu accesses found (minimum: %d)", evidence_count, opts.min_accesses);
        auto failure = SynthResult::make_error(SynthError::InsufficientAccesses, msg_str);
        populate_z3_info_from_synthesis(failure, synth_result);
        return failure;
    }

    // Preserve stable identities for the later post-propagation readback.
    // Unified-pattern indices belong to this pre-mutation decompilation
    // generation and cannot be reused after type/signature application.
    std::vector<std::optional<lvar_locator_t>> related_locators;
    if (synth_result.unified_pattern.has_value()) {
        related_locators.reserve(
            synth_result.unified_pattern->per_function_patterns.size());
        for (const auto& related :
             synth_result.unified_pattern->per_function_patterns) {
            std::optional<lvar_locator_t> locator;
            cfuncptr_t related_cfunc = related.func_ea == func_ea
                ? cfunc
                : utils::get_cfunc(related.func_ea);
            lvars_t* related_lvars = related_cfunc
                ? related_cfunc->get_lvars()
                : nullptr;
            if (related_lvars != nullptr && related.var_idx >= 0 &&
                static_cast<size_t>(related.var_idx) < related_lvars->size()) {
                locator = static_cast<const lvar_locator_t&>(
                    related_lvars->at(static_cast<size_t>(related.var_idx)));
            }
            related_locators.push_back(std::move(locator));
        }
    }

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
    auto persistence_transaction = persistence.begin_transaction();
    if (!persistence_transaction.has_value()) {
        return SynthResult::make_error(SynthError::InternalError,
            "Failed to begin structure persistence transaction");
    }
    tid_t struct_tid = sub_structs.empty()
        ? persistence.create_struct(synth_struct)
        : persistence.create_struct_with_substructs(synth_struct, sub_structs);

    if (struct_tid == BADADDR) {
        const bool rollback_succeeded = persistence_transaction->rollback();
        if (!rollback_succeeded) {
            return SynthResult::make_error(SynthError::InternalError,
                "Failed to create structure in IDB and persistence rollback failed");
        }
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
        if (!persistence_transaction->commit()) {
            result.struct_tid = BADADDR;
            result.vtable_tid = BADADDR;
            result.synthesized_struct->tid = BADADDR;
            if (result.synthesized_struct->vtable.has_value()) {
                result.synthesized_struct->vtable->tid = BADADDR;
            }
            result.error = SynthError::InternalError;
            result.error_message =
                "Persistence transaction was rejected and rolled back";
            return result;
        }
        result.error = SynthError::Success;
        return result;
    }

    tinfo_t struct_type;
    if (!struct_type.get_type_by_tid(struct_tid)) {
        const bool rollback_succeeded = persistence_transaction->rollback();
        result.struct_tid = BADADDR;
        result.vtable_tid = BADADDR;
        synth_struct.tid = BADADDR;
        if (synth_struct.vtable.has_value()) {
            synth_struct.vtable->tid = BADADDR;
        }
        result.error = rollback_succeeded
            ? SynthError::TypeCreationFailed
            : SynthError::InternalError;
        result.error_message = rollback_succeeded
            ? "Failed to reload persisted structure type; persistence transaction rolled back"
            : "Failed to reload persisted structure type; persistence transaction rollback failed";
        result.synthesized_struct =
            std::make_unique<SynthStruct>(std::move(synth_struct));
        return result;
    }

    TypePropagator propagator(opts, nullptr, &persistence);
    const bool inject_apply_failure =
        persistence_invariants::persistence_fault_requested(
            "required_source_apply");
    if (inject_apply_failure || !propagator.apply_type(cfunc, var_idx, struct_type)) {
        if (!inject_apply_failure &&
            propagator.last_application_rollback_failed()) {
            // The cached or persisted lvar may still reference the new type.
            // Retain the named types rather than creating a dangling TID.
            qstring retain_failed_message =
                "Failed to apply the source type, local-variable rollback "
                "failed, and the persistence transaction could not be retained";
            result.error = SynthError::InternalError;
            result.error_message =
                "Failed to apply the source type and local-variable rollback "
                "failed; persisted types were retained to preserve references";
            result.failed_sites.push_back(func_ea);
            result.synthesized_struct =
                std::make_unique<SynthStruct>(std::move(synth_struct));
            const bool retained = persistence_transaction->commit();
            if (!retained) {
                result.error_message.swap(retain_failed_message);
            }
            return result;
        }
        const bool rollback_succeeded = persistence_transaction->rollback();
        result.struct_tid = BADADDR;
        result.vtable_tid = BADADDR;
        synth_struct.tid = BADADDR;
        if (synth_struct.vtable.has_value()) {
            synth_struct.vtable->tid = BADADDR;
        }
        result.error = rollback_succeeded
            ? SynthError::PropagationFailed
            : SynthError::InternalError;
        result.error_message = rollback_succeeded
            ? "Failed to apply synthesized type to the source variable; "
              "persistence transaction rolled back"
            : "Failed to apply synthesized type to the source variable; "
              "persistence transaction rollback failed";
        result.failed_sites.push_back(func_ea);
        result.synthesized_struct =
            std::make_unique<SynthStruct>(std::move(synth_struct));
        return result;
    }
    result.synthesized_struct = std::make_unique<SynthStruct>(synth_struct);
    result.error = SynthError::Success;
    if (!persistence_transaction->commit()) {
        result.struct_tid = BADADDR;
        result.vtable_tid = BADADDR;
        result.synthesized_struct->tid = BADADDR;
        if (result.synthesized_struct->vtable.has_value()) {
            result.synthesized_struct->vtable->tid = BADADDR;
        }
        result.error = SynthError::InternalError;
        result.error_message =
            "Persistence commit failed after source-variable type application";
        result.failed_sites.push_back(func_ea);
        return result;
    }

    try {
    result.propagated_to.push_back(func_ea);

        // A folded machine call can provide enough evidence to recover a
        // nested layout while being absent from the caller ctree.  Apply each
        // persisted child type to the exact synthesis seed selected during
        // hierarchy recovery, deepest first, before ordinary graph propagation.
        apply_recovered_substruct_types(sub_structs, propagator, result);

        if (opts.auto_propagate) {
            cfuncptr_t propagation_cfunc = utils::get_cfunc(func_ea);
            int propagation_var_idx = -1;
            if (!propagation_cfunc || !resolve_var_index(
                    propagation_cfunc, source_locator,
                    propagation_var_idx)) {
                result.failed_sites.push_back(func_ea);
                return result;
            }
            PropagationResult prop_result = propagator.propagate(
                func_ea,
                propagation_var_idx,
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
                    if (sub.structure.naming.is_semantic() ||
                        sub.structure.naming.origin == NameOrigin::HeuristicRole) {
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
                            cfuncptr_t refreshed_cfunc = utils::get_cfunc(func_ea);
                            int refreshed_var_idx = -1;
                            if (refreshed_cfunc && resolve_var_index(
                                    refreshed_cfunc, source_locator,
                                    refreshed_var_idx)) {
                                if (!propagator.apply_type(
                                        refreshed_cfunc, refreshed_var_idx,
                                        refreshed_type)) {
                                    result.failed_sites.push_back(func_ea);
                                }
                            } else {
                                result.failed_sites.push_back(func_ea);
                            }
                        }
                    }
                }
            }

            for (const auto& site : prop_result.sites) {
                if (opts.debug_mode) {
                    qstring site_func_name;
                    get_func_name(&site_func_name, site.func_ea);
                    msg("Structor: propagation site func=%s var=%d success=%s reason=%s\n",
                        site_func_name.c_str(),
                        site.var_idx,
                        site.success ? "true" : "false",
                        site.failure_reason.c_str());
                }
                if (site.success) {
                    if (std::find(result.propagated_to.begin(),
                                  result.propagated_to.end(),
                                  site.func_ea) == result.propagated_to.end()) {
                        result.propagated_to.push_back(site.func_ea);
                    }
                } else {
                    if (std::find(result.failed_sites.begin(),
                                  result.failed_sites.end(),
                                  site.func_ea) == result.failed_sites.end()) {
                        result.failed_sites.push_back(site.func_ea);
                    }
                }
            }

            // Hex-Rays can propagate a changed callee signature through a
            // trivial forwarding wrapper on its own. Account for those
            // verified sites even when the wrapper call was folded out of the
            // caller ctree and therefore produced no explicit PropagationSite.
            if (synth_result.unified_pattern.has_value()) {
                tinfo_t expected_object = struct_type;
                if (expected_object.is_ptr()) {
                    expected_object = expected_object.get_pointed_object();
                }

                for (size_t related_index = 0;
                     related_index < synth_result.unified_pattern
                         ->per_function_patterns.size();
                     ++related_index) {
                    const auto& related = synth_result.unified_pattern
                        ->per_function_patterns[related_index];
                    if (related_index >= related_locators.size() ||
                        !related_locators[related_index].has_value()) {
                        continue;
                    }
                    cfuncptr_t related_cfunc = utils::get_cfunc(related.func_ea);
                    if (!related_cfunc) {
                        continue;
                    }

                    int related_var_idx = -1;
                    if (!resolve_var_index(
                            related_cfunc,
                            *related_locators[related_index],
                            related_var_idx)) {
                        continue;
                    }
                    lvars_t* related_lvars = related_cfunc->get_lvars();

                    tinfo_t observed_object =
                        related_lvars->at(related_var_idx).type();
                    if (observed_object.is_ptr()) {
                        observed_object = observed_object.get_pointed_object();
                    }

                    if (observed_object.empty() || expected_object.empty() ||
                        !observed_object.equals_to(expected_object)) {
                        continue;
                    }

                    if (std::find(result.propagated_to.begin(),
                                  result.propagated_to.end(),
                                  related.func_ea) == result.propagated_to.end()) {
                        result.propagated_to.push_back(related.func_ea);
                    }
                }
            }

            tinfo_t expected_forwarded_object = struct_type;
            if (expected_forwarded_object.is_ptr()) {
                expected_forwarded_object =
                    expected_forwarded_object.get_pointed_object();
            }

            auto has_expected_argument_type = [&](ea_t candidate_ea) {
                cfuncptr_t candidate_cfunc = utils::get_cfunc(candidate_ea);
                if (!candidate_cfunc) {
                    return false;
                }

                lvars_t* candidate_lvars = candidate_cfunc->get_lvars();
                if (!candidate_lvars) {
                    return false;
                }

                for (const auto& candidate_var : *candidate_lvars) {
                    if (!candidate_var.is_arg_var()) {
                        continue;
                    }

                    tinfo_t observed_object = candidate_var.type();
                    if (observed_object.is_ptr()) {
                        observed_object = observed_object.get_pointed_object();
                    }
                    if (!observed_object.empty() &&
                        !expected_forwarded_object.empty() &&
                        observed_object.equals_to(expected_forwarded_object)) {
                        return true;
                    }
                }
                return false;
            };

            // Tail-call wrappers may be typed automatically by Hex-Rays and
            // absent from explicit ctree call-site propagation. Discover only
            // callers whose argument type now exactly matches the synthesized
            // object, bounded by the configured propagation depth.
            qvector<std::pair<ea_t, int>> typed_worklist;
            std::unordered_set<ea_t> typed_visited;
            for (ea_t propagated_ea : result.propagated_to) {
                typed_worklist.push_back({propagated_ea, 0});
            }

            for (size_t work_index = 0; work_index < typed_worklist.size(); ++work_index) {
                const auto [typed_ea, typed_depth] = typed_worklist[work_index];
                if (!typed_visited.insert(typed_ea).second ||
                    typed_depth >= opts.max_propagation_depth) {
                    continue;
                }

                for (ea_t caller_ea : utils::get_callers(typed_ea)) {
                    if (!has_expected_argument_type(caller_ea)) {
                        continue;
                    }

                    if (std::find(result.propagated_to.begin(),
                                  result.propagated_to.end(),
                                  caller_ea) == result.propagated_to.end()) {
                        result.propagated_to.push_back(caller_ea);
                    }
                    typed_worklist.push_back({caller_ea, typed_depth + 1});
                }
            }
        }

    *result.synthesized_struct = std::move(synth_struct);
    } catch (...) {
        msg("Structor: Optional post-commit local propagation stopped after an "
            "exception; persisted source result remains successful\n");
    }
    return result;
}

} // namespace structor
