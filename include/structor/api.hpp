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

inline PropagationResult StructorAPI::propagate_type(
    ea_t func_ea,
    int var_idx,
    const tinfo_t& type,
    PropagationDirection direction)
{
    TypePropagator propagator;
    return propagator.propagate(func_ea, var_idx, type, direction);
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
    SynthStruct synth_struct = synthesizer.synthesize(pattern);

    result.conflicts = synthesizer.conflicts();

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
    tid_t struct_tid = persistence.create_struct(synth_struct);

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
