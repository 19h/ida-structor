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

    /// Synthesize structure for a global/static storage address
    [[nodiscard]] SynthResult synthesize_global_structure(
        ea_t global_ea,
        SynthOptions* opts = nullptr);

    /// Synthesize structure for a global/static storage symbol
    [[nodiscard]] SynthResult synthesize_global_structure(
        const char* global_name,
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
    SynthResult do_global_synthesis(ea_t global_ea, const SynthOptions& opts);
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

inline SynthResult StructorAPI::synthesize_global_structure(
    ea_t global_ea,
    SynthOptions* opts)
{
    const SynthOptions& options = opts ? *opts : Config::instance().options();
    return do_global_synthesis(global_ea, options);
}

inline SynthResult StructorAPI::synthesize_global_structure(
    const char* global_name,
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

    return synthesize_global_structure(global_ea, opts);
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

inline SynthResult StructorAPI::do_global_synthesis(ea_t global_ea, const SynthOptions& opts) {
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

        SynthResult result;
        result.conflicts = synth_result.conflicts;

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
        if (opts.debug_mode) {
            msg("Structor: propagating global type to %zu zero-delta vars\n",
                analysis.zero_delta_variables.size());
        }
        for (const auto& var : analysis.zero_delta_variables) {
            if (opts.debug_mode) {
                qstring func_name;
                get_func_name(&func_name, var.func_ea);
                msg("Structor:   global propagate candidate %s var_idx=%d\n",
                    func_name.c_str(), var.var_idx);
            }
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
                } else {
                    if (std::find(result.failed_sites.begin(), result.failed_sites.end(), var.func_ea) == result.failed_sites.end()) {
                        result.failed_sites.push_back(var.func_ea);
                    }
                }
            } catch (...) {
                if (std::find(result.failed_sites.begin(), result.failed_sites.end(), var.func_ea) == result.failed_sites.end()) {
                    result.failed_sites.push_back(var.func_ea);
                }
            }
        }

        tinfo_t ptr_type;
        ptr_type.create_ptr(struct_type);
        if (opts.debug_mode) {
            msg("Structor: applying pointer aliases for %zu globals\n",
                analysis.pointer_alias_globals.size());
        }
        for (const auto& [alias_ea, delta] : analysis.pointer_alias_globals) {
            if (delta != 0) {
                continue;
            }
            if (opts.debug_mode) {
                msg("Structor:   applying pointer alias type at 0x%llX\n",
                    static_cast<unsigned long long>(alias_ea));
            }
            (void)apply_global_tinfo(alias_ea, ptr_type);
        }

        try {
            if (opts.debug_mode) {
                msg("Structor: registering global rewrite info for %s\n",
                    analysis.root_name.c_str());
            }
            register_global_rewrite_info(analysis, synth_struct, struct_type);
        } catch (...) {
        }
        // Avoid eager dirty-marking here. Some already-decompiled C++ helpers
        // raise Hex-Rays internal errors during immediate refresh even though
        // fresh decompilations pick up the applied global types correctly.

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

inline SynthResult StructorAPI::do_synthesis(ea_t func_ea, int var_idx, const SynthOptions& opts) {
    SynthResult result;

    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) {
        return SynthResult::make_error(SynthError::InternalError, "Failed to decompile function");
    }

    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars || var_idx < 0 || static_cast<size_t>(var_idx) >= lvars->size()) {
        return SynthResult::make_error(SynthError::InvalidVariable, "Invalid variable index");
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

            return result;
        }
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

    // Store synthesized struct in result
    result.synthesized_struct = std::make_unique<SynthStruct>(std::move(synth_struct));
    result.error = SynthError::Success;

    return result;
}

} // namespace structor
