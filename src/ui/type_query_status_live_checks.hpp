#pragma once

#if defined(STRUCTOR_LIVE_TEST_HOOKS)

#include <structor/z3/type_inference_engine.hpp>

#include <string_view>
#include <utility>
#include <vector>

namespace structor::z3 {

struct TypeQueryStatusObservation {
    const char* name;
    FunctionTypeInferenceResult result;
    bool inferred_type_matches = true;
};

/// Exercise the production public engine status path with controlled actual
/// constraints. The cfunc supplies identity only; its body and types are intact.
struct TypeInferenceQueryStatusTestAccess {
    enum class Scenario { ExactArray, PreferredDeepArray, BoundedSize, MissingBoundedSize, Contradiction,
                          DefaultNestedArray, DefaultNestedPointer, DefaultLargeFunction };

    static bool default_positive(Scenario scenario) {
        return scenario == Scenario::DefaultNestedArray || scenario == Scenario::DefaultNestedPointer ||
               scenario == Scenario::DefaultLargeFunction;
    }

    static InferredType preferred_type(Scenario scenario) {
        const auto byte = InferredType::make_base(BaseType::UInt8);
        if (scenario == Scenario::DefaultNestedArray)
            return InferredType::make_array(InferredType::make_array(byte, 3), 2);
        if (scenario == Scenario::DefaultNestedPointer)
            return InferredType::make_ptr(InferredType::make_ptr(byte));
        std::vector<InferredType> parameters(17, InferredType::make_base(BaseType::Int32));
        parameters[16] = InferredType::make_base(BaseType::Float64);
        return InferredType::make_ptr(InferredType::make_func(
            InferredType::make_base(BaseType::UInt64), parameters));
    }

    static void inject(TypeInferenceEngine& engine, Scenario scenario) {
        if (default_positive(scenario)) {
            const auto variable = engine.get_type_var(engine.current_cfunc_->argidx.at(0));
            const auto type = preferred_type(scenario);
            engine.current_constraints_.add(TypeConstraint::make_one_of(variable, {type}).soft(10));
            engine.current_constraints_.add(TypeConstraint::make_has_size(variable, type.size(engine.ctx_.pointer_size())));
            return;
        }
        const auto variable = TypeVariable::for_temp(1, BADADDR, "query_status_probe");
        switch (scenario) {
            case Scenario::DefaultNestedArray:
            case Scenario::DefaultNestedPointer:
            case Scenario::DefaultLargeFunction:
                break;
            case Scenario::ExactArray:
                engine.current_constraints_.add(TypeConstraint::make_one_of(variable,
                    {InferredType::make_array(InferredType::make_base(BaseType::UInt8), 3)}));
                engine.current_constraints_.add(TypeConstraint::make_has_size(variable, 3));
                break;
            case Scenario::PreferredDeepArray:
                engine.current_constraints_.add(TypeConstraint::make_one_of(variable,
                    {InferredType::make_array(InferredType::make_array(
                        InferredType::make_base(BaseType::UInt8), 3), 2)}).soft(10));
                engine.current_constraints_.add(TypeConstraint::make_has_size(variable, 6));
                break;
            case Scenario::BoundedSize:
                engine.current_constraints_.add(TypeConstraint::make_has_size(variable, 4));
                break;
            case Scenario::MissingBoundedSize:
                engine.current_constraints_.add(TypeConstraint::make_has_size(variable, 3));
                break;
            case Scenario::Contradiction:
                engine.current_constraints_.add(TypeConstraint::make_is_base(variable, BaseType::Int32));
                engine.current_constraints_.add(TypeConstraint::make_is_base(variable, BaseType::Float32));
                break;
        }
    }

    static TypeInferenceConfig inference_config(bool enabled = true) {
        TypeInferenceConfig config;
        config.enable_experimental_pipeline = enabled;
        config.phase_constraint_extraction = false;
        config.phase_alias_analysis = false;
        config.phase_soft_constraints = false;
        config.solver_timeout_ms = 2000;
        return config;
    }

    static Z3Config solver_config(unsigned expansions = 256) {
        Z3Config config;
        config.max_memory_mb = 0;
        config.max_symbolic_type_depth = 0;
        config.max_symbolic_type_list_length = 0;
        config.max_symbolic_type_expansions = expansions;
        return config;
    }

    static FunctionTypeInferenceResult run(cfunc_t* cfunc, Scenario scenario,
                                           unsigned expansions = 256, bool enabled = true) {
        auto limits = solver_config(expansions);
        if (default_positive(scenario)) {
            limits = Z3Config();
            limits.max_memory_mb = 0;
        }
        Z3Context context(limits);
        TypeInferenceEngine engine(context, inference_config(enabled));
        engine.set_progress_callback([&](const char* phase, int, const char*) {
            if (std::string_view(phase) == "Building") inject(engine, scenario);
        });
        return engine.infer_function(cfunc);
    }

    static std::vector<TypeQueryStatusObservation> collect(cfunc_t* cfunc) {
        std::vector<TypeQueryStatusObservation> observations;
        observations.push_back({"disabled", run(cfunc, Scenario::BoundedSize, 256, false)});
        observations.push_back({"exact_array", run(cfunc, Scenario::ExactArray)});
        observations.push_back({"preferred_deep_array", run(cfunc, Scenario::PreferredDeepArray)});
        observations.push_back({"bounded_sat", run(cfunc, Scenario::BoundedSize)});
        observations.push_back({"bounded_unsat", run(cfunc, Scenario::MissingBoundedSize)});
        observations.push_back({"budget_exhausted", run(cfunc, Scenario::BoundedSize, 0)});
        observations.push_back({"exact_unsat", run(cfunc, Scenario::Contradiction)});

        Z3Context context(solver_config());
        TypeInferenceEngine reused(context, inference_config());
        auto scenario = Scenario::BoundedSize;
        reused.set_progress_callback([&](const char* phase, int, const char*) {
            if (std::string_view(phase) == "Building") inject(reused, scenario);
        });
        observations.push_back({"reused_bounded_sat", reused.infer_function(cfunc)});
        scenario = Scenario::Contradiction;
        observations.push_back({"reused_exact_unsat", reused.infer_function(cfunc)});
        for (const auto& [scenario, name] : {
                std::pair{Scenario::DefaultNestedArray, "default_nested_array"},
                std::pair{Scenario::DefaultNestedPointer, "default_nested_pointer"},
                std::pair{Scenario::DefaultLargeFunction, "default_large_function"}}) {
            auto result = run(cfunc, scenario);
            const bool matches = result.local_types.size() == 1 &&
                result.local_types[0].var_idx == cfunc->argidx.at(0) &&
                result.local_types[0].type == preferred_type(scenario);
            observations.push_back({name, std::move(result), matches});
        }
        return observations;
    }
};

} // namespace structor::z3

#endif
