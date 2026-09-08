#pragma once
#if !defined(STRUCTOR_LIVE_TEST_HOOKS)
#error "Flow precision probes require STRUCTOR_LIVE_TEST_HOOKS"
#endif

#include "alias_flow_ctree_probe.hpp"
#include "structor/layout_synthesizer.hpp"

namespace structor::testing {

struct FlowPrecisionObservation {
    std::string name;
    AccessPattern pattern;
    SynthesisResult synthesis;
    SynthesisResult reusable_control;
    bool original_body_restored = false;
    bool repeat_metadata_equal = false;
    std::string error;
};

inline bool same_flow_metadata(const FlowAnalysisInfo& lhs, const FlowAnalysisInfo& rhs) {
    if (lhs.started != rhs.started || lhs.invalid_limits != rhs.invalid_limits ||
        lhs.max_states != rhs.max_states || lhs.max_steps != rhs.max_steps ||
        lhs.executed_steps != rhs.executed_steps ||
        lhs.peak_candidate_states != rhs.peak_candidate_states ||
        lhs.widening_operations != rhs.widening_operations ||
        lhs.precision_events.size() != rhs.precision_events.size()) return false;
    for (size_t index = 0; index < lhs.precision_events.size(); ++index) {
        const auto& a = lhs.precision_events[index];
        const auto& b = rhs.precision_events[index];
        if (a.reason != b.reason || a.node_ordinal != b.node_ordinal || a.ea != b.ea ||
            a.label != b.label || a.occurrences != b.occurrences ||
            a.max_states_before != b.max_states_before) return false;
    }
    return true;
}

inline std::vector<FlowPrecisionObservation> probe_flow_precision_ctree(cfunc_t* cfunc) {
    using namespace alias_flow_detail;
    // Reuse the carrier validation before constructing any independent tree.
    (void)probe_alias_flow_ctree(cfunc, {}, "direct_alias_positive");
    std::array<int, 4> arguments{};
    for (size_t index = 0; index < arguments.size(); ++index) arguments[index] = cfunc->argidx[index];
    Builder builder(*cfunc, arguments);
    const auto original_body = cfunc->body.cblock;
    const auto collect_body = [&](Statement body, const FlowAnalysisOptions& flow) {
        builder.append(*body, builder.return_zero());
        ScopedBodySwap restore(*cfunc, *body);
        SynthOptions options;
        options.min_accesses = 1;
        options.vtable_detection = false;
        options.flow = flow;
        return AccessCollector(options).collect(cfunc, arguments[0]);
    };
    const auto prefix_body = [&] {
        auto body = builder.block();
        // Three direct accesses survive any budget. The fourth access requires
        // a later alias definition, so a step cutoff can expose a finite prefix.
        const auto type = cfunc->get_lvars()->at(arguments[0]).type();
        for (uint64 offset : {0, 4, 8}) {
            builder.append(*body, builder.load_alias(builder.binary(cot_add,
                builder.variable(0), builder.number64(offset), type)));
        }
        for (unsigned index = 0; index < 64; ++index) {
            builder.append(*body, builder.assign_flag(index));
        }
        builder.append(*body, builder.assign_alias_offset(0, 12));
        builder.append(*body, builder.load_alias());
        return body;
    };
    const auto opaque_body = [&] {
        auto body = builder.block();
        builder.append(*body, builder.assign_alias(0));
        builder.append(*body, builder.load_alias());
        auto opaque = builder.terminal(cit_asm);
        opaque->casm = new casm_t(cfunc->entry_ea);
        builder.append(*body, std::move(opaque));
        builder.append(*body, builder.load_alias());
        return body;
    };
    const AccessPattern complete_control = collect_body(prefix_body(), {});
    struct Case { std::string name; const char* source_case; FlowAnalysisOptions limits; };
    std::vector<Case> cases;
    for (std::uint32_t cap : {4U, 16U, 64U}) {
        for (const char* name : {"direct_alias_positive", "branch_overflow_forgets_offsets",
                "branch_overflow_strong_definition_recovers", "loop_offset_widening_avoids_truncated_array",
                "shared_label_budget_widens_before_observation"}) {
            cases.push_back({std::string(name) + "_states" + std::to_string(cap), name, {cap, 65536}});
        }
    }
    for (std::uint64_t steps : {UINT64_C(1), UINT64_C(16), UINT64_C(64), UINT64_C(65536), UINT64_C(131072)}) {
        cases.push_back({"finite_prefix_steps" + std::to_string(steps), nullptr, {16, steps}});
    }
    cases.push_back({"unknown_jump_entry", "shared_label_preserves_lexical_alias", {}});
    cases.push_back({"unknown_exception_entry", "wind_cleanup_does_not_replace_normal_alias", {}});
    cases.push_back({"opaque_assembly", nullptr, {}});
    cases.push_back({"invalid_state_limit", nullptr, {3, 65536}});
    cases.push_back({"invalid_step_limit", nullptr, {16, 0}});

    std::vector<FlowPrecisionObservation> observations;
    for (const auto& test : cases) {
        FlowPrecisionObservation observation;
        observation.name = test.name;
        try {
            const auto collect = [&] {
                if (!test.source_case) {
                    return collect_body(test.name == "opaque_assembly" ? opaque_body() : prefix_body(), test.limits);
                }
                auto selected = probe_alias_flow_ctree(cfunc, test.limits, test.source_case);
                if (selected.size() != 1 || !selected.front().error.empty() ||
                    !selected.front().original_body_restored) {
                    throw std::runtime_error("selected alias ctree case failed to collect or restore");
                }
                return std::move(selected.front().pattern);
            };
            observation.pattern = collect();
            const auto repeated = collect();
            observation.repeat_metadata_equal = same_flow_metadata(
                observation.pattern.flow_analysis, repeated.flow_analysis);
            SynthOptions options;
            options.min_accesses = 1;
            options.vtable_detection = false;
            options.emit_substructs = false;
            options.z3.mode = Z3SynthesisMode::Required;
            options.z3.cross_function = false;
            LayoutSynthesizer synthesizer(options);
            observation.synthesis = synthesizer.synthesize(observation.pattern, options);
            // A reusable synthesizer must restore aggregate inference after a
            // limited or failed call, rather than retaining its suppression.
            observation.reusable_control = synthesizer.synthesize(complete_control, options);
        } catch (const std::exception& error) {
            observation.error = error.what();
        } catch (...) {
            observation.error = "unknown exception in flow precision probe";
        }
        observation.original_body_restored = cfunc->body.op == cit_block && cfunc->body.cblock == original_body;
        observations.push_back(std::move(observation));
    }
    return observations;
}

struct EmptyFlowDiagnosticObservation {
    std::string name;
    UnifiedAccessPattern pattern;
    SynthesisResult synthesis;
    bool original_bodies_restored = false;
    bool reset_removed_old_diagnostic = false;
    std::string error;
};

inline std::vector<EmptyFlowDiagnosticObservation> probe_empty_flow_diagnostics(cfunc_t* cfunc) {
    using namespace alias_flow_detail;
    (void)probe_alias_flow_ctree(cfunc, {}, "direct_alias_positive");
    qstring current_name;
    get_func_name(&current_name, cfunc->entry_ea);
    const char* secondary_name = std::strstr(current_name.c_str(), "alias_pointer") != nullptr
        ? "alias_ctree_carrier" : "alias_pointer_ctree_carrier";
    ea_t secondary_ea = get_name_ea(BADADDR, secondary_name);
    if (secondary_ea == BADADDR) {
        qstring decorated;
        decorated.sprnt("_%s", secondary_name);
        secondary_ea = get_name_ea(BADADDR, decorated.c_str());
    }
    cfuncptr_t secondary = utils::get_cfunc(secondary_ea);
    (void)probe_alias_flow_ctree(secondary, {}, "direct_alias_positive");
    std::array<int, 4> arguments{}, secondary_arguments{};
    for (size_t index = 0; index < 4; ++index) {
        arguments[index] = cfunc->argidx[index];
        secondary_arguments[index] = secondary->argidx[index];
    }
    Builder builder(*cfunc, arguments), secondary_builder(*secondary, secondary_arguments);
    const auto original = cfunc->body.cblock;
    const auto secondary_original = secondary->body.cblock;
    CrossFunctionConfig cross_options;
    cross_options.follow_forward = false;
    cross_options.follow_backward = false;
    CrossFunctionAnalyzer analyzer(cross_options);
    SynthOptions options;
    options.flow.max_states = 4;
    options.min_accesses = 1;
    options.vtable_detection = false;
    options.emit_substructs = false;
    options.z3.mode = Z3SynthesisMode::Required;
    options.z3.cross_function = false;
    std::vector<EmptyFlowDiagnosticObservation> observations;
    try {
        auto empty_body = secondary_builder.block();
        auto chain = secondary_builder.assign_alias(1);
        for (unsigned index = 0; index < 18; ++index) {
            chain = secondary_builder.branch(secondary_builder.assign_alias_offset(0, index * 4),
                std::move(chain), cot_eq, index);
        }
        secondary_builder.append(*empty_body, std::move(chain));
        secondary_builder.append(*empty_body, secondary_builder.load_alias());
        secondary_builder.append(*empty_body, secondary_builder.return_zero());
        UnifiedAccessPattern empty;
        {
            ScopedBodySwap restore(*secondary, *empty_body);
            empty = analyzer.analyze(secondary->entry_ea, secondary_arguments[0], options);
        }
        auto complete_body = builder.block();
        const auto type = cfunc->get_lvars()->at(arguments[0]).type();
        for (uint64 offset : {0, 4, 8, 12}) {
            builder.append(*complete_body, builder.load_alias(builder.binary(cot_add,
                builder.variable(0), builder.number64(offset), type)));
        }
        builder.append(*complete_body, builder.return_zero());
        UnifiedAccessPattern complete;
        {
            ScopedBodySwap restore(*cfunc, *complete_body);
            complete = analyzer.analyze(cfunc->entry_ea, arguments[0], options);
        }
        const bool reset_clean = complete.flow_diagnostics.size() == 1 &&
            complete.flow_diagnostics.front().func_ea == cfunc->entry_ea &&
            !complete.flow_diagnostics.front().analysis.precision_lost();
        LayoutSynthesizer synthesizer(options);
        EmptyFlowDiagnosticObservation only;
        only.name = "empty_local_scan_is_reported";
        only.pattern = empty;
        only.synthesis = synthesizer.synthesize(empty, options);
        only.reset_removed_old_diagnostic = reset_clean;
        only.original_bodies_restored = cfunc->body.cblock == original && secondary->body.cblock == secondary_original;
        observations.push_back(std::move(only));
        // Only the precise source contributes fields. The omitted scan remains
        // in the independent report and prevents an unsupported finite extent.
        for (const auto& diagnostic : empty.flow_diagnostics) complete.flow_diagnostics.push_back(diagnostic);
        EmptyFlowDiagnosticObservation combined;
        combined.name = "empty_local_scan_suppresses_aggregate";
        combined.pattern = complete;
        combined.synthesis = synthesizer.synthesize(complete, options);
        combined.reset_removed_old_diagnostic = reset_clean;
        combined.original_bodies_restored = cfunc->body.cblock == original && secondary->body.cblock == secondary_original;
        observations.push_back(std::move(combined));
    } catch (const std::exception& error) {
        EmptyFlowDiagnosticObservation failure;
        failure.name = "empty_local_scan_is_reported";
        failure.error = error.what();
        observations.push_back(std::move(failure));
    }
    return observations;
}

} // namespace structor::testing
