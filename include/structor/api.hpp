#pragma once

#include "synth_types.hpp"
#include "config.hpp"
#include "access_collector.hpp"
#include "layout_synthesizer.hpp"
#include "vtable_detector.hpp"
#include "type_propagator.hpp"
#include "pseudocode_rewriter.hpp"
#include "structure_persistence.hpp"
#include "ui_integration.hpp"
#include "type_fixer.hpp"

namespace structor {

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

    /// Synthesize structure by variable index
    [[nodiscard]] SynthResult synthesize_structure(
        ea_t func_ea,
        int var_idx,
        SynthOptions* opts = nullptr);

    /// Synthesize structure by variable name
    [[nodiscard]] SynthResult synthesize_structure(
        ea_t func_ea,
        const char* var_name,
        SynthOptions* opts = nullptr);

    /// Collect access patterns without synthesizing
    [[nodiscard]] AccessPattern collect_accesses(
        ea_t func_ea,
        int var_idx);

    /// Synthesize layout from pattern without persisting
    [[nodiscard]] SynthStruct synthesize_layout(
        const AccessPattern& pattern,
        SynthOptions* opts = nullptr);

    /// Detect vtable in pattern
    [[nodiscard]] std::optional<SynthVTable> detect_vtable(
        const AccessPattern& pattern,
        ea_t func_ea);

    /// Propagate type to related functions
    [[nodiscard]] PropagationResult propagate_type(
        ea_t func_ea,
        int var_idx,
        const tinfo_t& type,
        PropagationDirection direction = PropagationDirection::Both);

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

    SynthResult do_synthesis(ea_t func_ea, int var_idx, const SynthOptions& opts);
};

// ============================================================================
// Implementation
// ============================================================================

inline SynthResult StructorAPI::synthesize_structure(
    ea_t func_ea,
    lvar_t* var,
    SynthOptions* opts)
{
    if (!var) {
        return SynthResult::make_error(SynthError::InvalidVariable, "Null variable pointer");
    }

    // Find variable index
    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) {
        return SynthResult::make_error(SynthError::InternalError, "Failed to decompile function");
    }

    lvars_t& lvars = *cfunc->get_lvars();
    for (size_t i = 0; i < lvars.size(); ++i) {
        if (&lvars[i] == var) {
            return synthesize_structure(func_ea, static_cast<int>(i), opts);
        }
    }

    return SynthResult::make_error(SynthError::InvalidVariable, "Variable not found in function");
}

inline SynthResult StructorAPI::synthesize_structure(
    ea_t func_ea,
    int var_idx,
    SynthOptions* opts)
{
    const SynthOptions& options = opts ? *opts : Config::instance().options();
    return do_synthesis(func_ea, var_idx, options);
}

inline SynthResult StructorAPI::synthesize_structure(
    ea_t func_ea,
    const char* var_name,
    SynthOptions* opts)
{
    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) {
        return SynthResult::make_error(SynthError::InternalError, "Failed to decompile function");
    }

    lvar_t* var = utils::find_lvar_by_name(cfunc, var_name);
    if (!var) {
        qstring msg;
        msg.sprnt("Variable '%s' not found in function", var_name);
        return SynthResult::make_error(SynthError::InvalidVariable, msg);
    }

    lvars_t& lvars = *cfunc->get_lvars();
    for (size_t i = 0; i < lvars.size(); ++i) {
        if (&lvars[i] == var) {
            return synthesize_structure(func_ea, static_cast<int>(i), opts);
        }
    }

    return SynthResult::make_error(SynthError::InvalidVariable, "Variable index lookup failed");
}

inline AccessPattern StructorAPI::collect_accesses(ea_t func_ea, int var_idx) {
    AccessCollector collector;
    return collector.collect(func_ea, var_idx);
}

inline SynthStruct StructorAPI::synthesize_layout(
    const AccessPattern& pattern,
    SynthOptions* opts)
{
    const SynthOptions& options = opts ? *opts : Config::instance().options();
    LayoutSynthesizer synthesizer(options);
    return synthesizer.synthesize(pattern, options).structure;
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

inline PropagationResult StructorAPI::propagate_type(
    ea_t func_ea,
    int var_idx,
    const tinfo_t& type,
    PropagationDirection direction)
{
    TypePropagator propagator;
    return propagator.propagate(func_ea, var_idx, type, direction);
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
    
    // Analyze the variable
    result.comparison = fixer.analyze_variable(cfunc, var_idx);
    
    // Apply fix if significant and not dry run
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

    lvar_t* var = utils::find_lvar_by_name(cfunc, var_name);
    if (!var) {
        result.skip_reason.sprnt("Variable '%s' not found", var_name);
        return result;
    }

    lvars_t& lvars = *cfunc->get_lvars();
    for (size_t i = 0; i < lvars.size(); ++i) {
        if (&lvars[i] == var) {
            return fix_variable_type(func_ea, static_cast<int>(i), config);
        }
    }

    result.skip_reason = "Variable index lookup failed";
    return result;
}

inline TypeFixResult StructorAPI::analyze_function_types(ea_t func_ea) {
    TypeFixerConfig cfg;
    cfg.dry_run = true;  // Don't actually apply changes
    TypeFixer fixer(cfg);
    return fixer.fix_function_types(func_ea);
}

inline SynthResult StructorAPI::do_synthesis(ea_t func_ea, int var_idx, const SynthOptions& opts) {
    SynthResult result;

    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) {
        return SynthResult::make_error(SynthError::InternalError, "Failed to decompile function");
    }

    // Collect access patterns
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

    // Synthesize structure layout
    LayoutSynthesizer synthesizer(opts);
    SynthesisResult synth_result = synthesizer.synthesize(pattern, opts);
    SynthStruct synth_struct = std::move(synth_result.structure);
    qvector<SubStructInfo> sub_structs = std::move(synth_result.sub_structs);

    result.conflicts = synth_result.conflicts;

    if (synth_struct.fields.empty()) {
        return SynthResult::make_error(SynthError::TypeCreationFailed,
            "Failed to synthesize structure fields");
    }

    // Detect vtable if enabled
    if (opts.vtable_detection && pattern.has_vtable) {
        VTableDetector vtable_detector(opts);
        auto vtable = vtable_detector.detect(pattern, cfunc);
        if (vtable) {
            synth_struct.vtable = std::move(vtable);
        }
    }

    // Persist structure to IDB
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

    // Apply type to variable
    tinfo_t struct_type;
    if (struct_type.get_type_by_tid(struct_tid)) {
        TypePropagator propagator(opts);

        if (propagator.apply_type(cfunc, var_idx, struct_type)) {
            result.propagated_to.push_back(func_ea);
        }

        // Propagate if enabled
        if (opts.auto_propagate) {
            PropagationResult prop_result = propagator.propagate(
                func_ea,
                var_idx,
                struct_type,
                PropagationDirection::Both);

            for (const auto& site : prop_result.sites) {
                if (site.success) {
                    result.propagated_to.push_back(site.func_ea);
                } else {
                    result.failed_sites.push_back(site.func_ea);
                }
            }
        }
    }

    // Store synthesized struct in result
    result.synthesized_struct = std::make_unique<SynthStruct>(std::move(synth_struct));
    result.error = SynthError::Success;

    return result;
}

} // namespace structor
