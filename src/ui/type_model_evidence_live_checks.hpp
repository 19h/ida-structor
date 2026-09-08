#pragma once

#if defined(STRUCTOR_LIVE_TEST_HOOKS)

#include <structor/z3/type_applicator.hpp>
#include <structor/utils.hpp>
#include <algorithm>
#include <array>
#include <string_view>
#include <utility>
#include <vector>

namespace structor::z3 {

// Each application scenario runs in a separate disposable IDB. Rejection
// controls compare saved types and locals; positives require an actual write.
struct TypeInferenceModelEvidenceTestAccess {
    static std::vector<std::pair<const char*, bool>> run(
        cfunc_t* function, std::string_view scenario)
    {
        std::vector<std::pair<const char*, bool>> checks;
        constexpr std::array names{
            "hard_scalar", "hard_scalar_bounded_soft", "hard_compound", "hard_alias_chain", "soft_scalar",
            "size_only", "bounded_unique", "zero_query_budget", "zero_time_budget",
            "soft_deep", "hard_apply", "soft_apply_default", "soft_apply_optin",
            "bounded_apply_default", "budget_apply_default", "external_apply"};
        if (std::find(names.begin(), names.end(), scenario) == names.end() ||
            !function || !function->get_lvars() || function->argidx.empty()) return checks;
        const auto index = function->argidx[0];
        if (index < 0 || static_cast<std::size_t>(index) >= function->get_lvars()->size()) return checks;
        const auto function_ea = function->entry_ea;
        const auto original_locator = static_cast<const lvar_locator_t&>(function->get_lvars()->at(index));
        std::vector<std::pair<lvar_locator_t, tinfo_t>> original_locals;
        for (const auto& local : *function->get_lvars())
            original_locals.emplace_back(static_cast<const lvar_locator_t&>(local), local.type());
        tinfo_t saved_before;
        const bool had_saved_type = get_tinfo(&saved_before, function_ea);
        const auto* original_body = function->body.cblock;
        const auto original_arguments = function->argidx;

        const bool bounded = scenario == "bounded_unique" || scenario == "bounded_apply_default";
        const bool zero_queries = scenario == "zero_query_budget" || scenario == "budget_apply_default";
        const bool zero_time = scenario == "zero_time_budget";
        const bool application = scenario.find("apply") != std::string_view::npos;
        const bool soft = scenario.starts_with("soft_");
        const auto i32 = InferredType::make_base(BaseType::Int32);
        const auto f32 = InferredType::make_base(BaseType::Float32);
        auto expected = application ? InferredType::make_ptr(f32) : i32;
        if (bounded) expected = InferredType::make_ptr(i32);
        else if (scenario == "hard_compound")
            expected = InferredType::make_ptr(InferredType::make_array(
                InferredType::make_base(BaseType::UInt8), 3));
        else if (scenario == "hard_alias_chain") expected = InferredType::make_base(BaseType::Float64);
        else if (scenario == "soft_scalar") expected = f32;
        else if (scenario == "soft_deep") {
            std::vector<InferredType> parameters(17, i32);
            parameters.back() = f32;
            expected = InferredType::make_ptr(InferredType::make_func(
                InferredType::make_base(BaseType::UInt64), parameters));
        }

        FunctionTypeInferenceResult result;
        if (scenario == "external_apply") {
            result.func_ea = function_ea;
            result.success = true;
            result.status = TypeInferenceStatus::Success;
            InferredVariableType value;
            value.var_idx = index;
            value.type = expected;
            value.confidence = TypeConfidence::High;
            result.local_types.push_back(std::move(value));
        } else {
            Z3Config solver;
            solver.max_memory_mb = 0;
            if (bounded) {
                solver.max_symbolic_type_depth = 0;
                solver.max_symbolic_type_list_length = 0;
            }
            Z3Context context(solver);
            TypeInferenceConfig config;
            config.enable_experimental_pipeline = true;
            config.phase_constraint_extraction = false;
            config.phase_alias_analysis = false;
            config.phase_soft_constraints = false;
            config.solver_timeout_ms = 2000;
            if (zero_queries) config.model_evidence_budget.max_queries = 0;
            if (zero_time) config.model_evidence_budget.timeout_ms = 0;
            TypeInferenceEngine engine(context, config);
            engine.set_progress_callback([&](const char* phase, int, const char*) {
                if (std::string_view(phase) != "Building") return;
                const auto local = engine.get_type_var(index);
                if (scenario == "size_only") {
                    engine.current_constraints_.add(TypeConstraint::make_has_size(local, 4));
                } else if (bounded) {
                    const auto upper = TypeVariable::for_temp(1, function_ea, "model_evidence_upper");
                    engine.current_constraints_.add(TypeConstraint::make_one_of(upper, {expected}));
                    engine.current_constraints_.add(TypeConstraint::make_subtype(local, upper));
                    engine.current_constraints_.add(TypeConstraint::make_is_pointer(local));
                } else if (scenario == "hard_alias_chain") {
                    const auto first = TypeVariable::for_temp(1, function_ea, "model_evidence_first");
                    const auto second = TypeVariable::for_temp(2, function_ea, "model_evidence_second");
                    engine.current_constraints_.add(TypeConstraint::make_equal(local, first));
                    engine.current_constraints_.add(TypeConstraint::make_equal(first, second));
                    engine.current_constraints_.add(TypeConstraint::make_one_of(second, {expected}));
                } else {
                    auto concrete = TypeConstraint::make_one_of(local, {expected});
                    if (soft) concrete.soft(10);
                    engine.current_constraints_.add(std::move(concrete));
                    if (scenario == "hard_scalar_bounded_soft") {
                        const auto unrelated = TypeVariable::for_temp(8, function_ea, "model_evidence_soft_size");
                        engine.current_constraints_.add(TypeConstraint::make_has_size(unrelated, 4).soft(2));
                    }
                }
            });
            result = engine.infer_function(function);
        } // All exported candidates/evidence are inspected after context death.

        checks.emplace_back("public_inference_succeeded", result.success && result.local_types.size() == 1);
        if (!result.success || result.local_types.size() != 1) return checks;
        const auto& value = result.local_types[0];
        const bool ambiguous = soft || scenario == "size_only";
        const bool resource = zero_queries || zero_time;
        const bool qualified = bounded || scenario == "size_only";
        const auto expected_status = resource ? ModelValueStatus::ResourceLimit
            : ambiguous ? ModelValueStatus::AlternativeModelExists
                        : ModelValueStatus::DeterminedByHardConstraints;
        if (scenario != "external_apply") {
            checks.emplace_back("model_status", value.model_value_status == expected_status);
            checks.emplace_back("domain_qualification", value.evidence_query_bounds.has_value() == qualified);
            checks.emplace_back("alternative_witness", ambiguous
                ? value.alternative_type && *value.alternative_type != value.type
                : !value.alternative_type);
            checks.emplace_back("query_budget", result.stats.model_evidence_queries == (resource ? 0u : 1u));
            checks.emplace_back("confidence_category", value.confidence ==
                (ambiguous || resource || qualified ? TypeConfidence::Low : TypeConfidence::Medium));
        }
        if (scenario == "hard_scalar_bounded_soft")
            checks.emplace_back("soft_only_domain_is_separate", result.used_bounded_symbolic_queries &&
                !value.evidence_query_bounds);
        if (scenario != "size_only") checks.emplace_back("complete_candidate", value.type == expected);
        const bool default_applicable = !(ambiguous || resource || qualified);
        checks.emplace_back("default_conversion", result.to_ida_types().size() == (default_applicable ? 1u : 0u));
        if (scenario != "size_only") checks.emplace_back("explicit_candidate_conversion", result.to_ida_types(true).size() == 1);
        checks.emplace_back("inference_preserved_ctree", original_body == function->body.cblock &&
            original_arguments == function->argidx);

        if (application) {
            TypeApplicationConfig apply;
            apply.min_confidence = TypeConfidence::Low;
            apply.overwrite_existing = true;
            apply.force_refresh = false;
            apply.allow_model_candidates = scenario == "soft_apply_optin";
            TypeApplicator applicator(apply);
            const auto applied = applicator.apply(function, result);
            const bool positive = default_applicable || apply.allow_model_candidates;
            checks.emplace_back("application_decision", applied.applied_count == (positive ? 1u : 0u) &&
                applied.failed_count == 0 && applied.skipped_count == (positive ? 0u : 1u));
            tinfo_t saved_after;
            const bool has_saved_type = get_tinfo(&saved_after, function_ea);
            auto current = utils::get_cfunc(function_ea);
            if (positive) {
                const auto* local = current && current->get_lvars()
                    ? current->get_lvars()->find(original_locator) : nullptr;
                checks.emplace_back("actual_requested_type", local && local->type().equals_to(expected.to_tinfo()));
            } else {
                checks.emplace_back("saved_type_unchanged", had_saved_type == has_saved_type &&
                    (!had_saved_type || saved_before.equals_to(saved_after)));
                bool unchanged = current && current->get_lvars() && current->get_lvars()->size() == original_locals.size();
                for (const auto& [locator, type] : original_locals) {
                    if (!unchanged) break;
                    const auto* local = current->get_lvars()->find(locator);
                    unchanged = local && local->type().equals_to(type);
                }
                checks.emplace_back("locals_unchanged", unchanged);
            }
        }
        return checks;
    }
};

} // namespace structor::z3
#endif
