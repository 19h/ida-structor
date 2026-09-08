#pragma once

#if defined(STRUCTOR_LIVE_TEST_HOOKS)
#include <structor/z3/type_inference_engine.hpp>
#include <array>
#include <string_view>
#include <vector>

namespace structor::z3 {
struct SourceEvidenceObservation {
    const char* name;
    FunctionTypeInferenceResult result;
};
struct SourceEvidenceChecks {
    std::vector<SourceEvidenceObservation> observations;
    std::array<unsigned, 6> native_origin_counts{};
};

/// Controlled actual constraints exercise public result extraction. The native
/// check additionally invokes the ordinary production phase emitters without
/// interpreting their origin metadata as accepted or causal model support.
struct TypeInferenceSourceTestAccess {
    enum class Scenario { Connected, Independent, InactiveBridge, Unspecified };

    static void inject(TypeInferenceEngine& engine, Scenario scenario) {
        const auto site = engine.current_cfunc_->entry_ea;
        const auto index = engine.current_cfunc_->argidx.at(0);
        const auto local = engine.get_type_var(index);
        auto base = TypeConstraint::make_is_base(local, BaseType::Int32, site);
        if (scenario != Scenario::Unspecified) base.sourced_from(TypeConstraintOrigin::InstructionUsage);
        else base.describe("signature decompiler alias usage words do not classify origin");
        engine.current_constraints_.add(base);
        if (scenario == Scenario::Unspecified) return;
        const auto other = TypeVariable::for_local(local.id, local.func_ea, local.var_idx);
        auto signature = TypeConstraint::make_one_of(other,
            {InferredType::make_base(BaseType::Float32)}, site + 4)
            .soft(1).sourced_from(TypeConstraintOrigin::FunctionSignature);
        engine.current_constraints_.add(signature);
        if (scenario == Scenario::Independent) return;
        auto relation = TypeConstraint::make_equal(local, other)
            .sourced_from(TypeConstraintOrigin::AliasRelation);
        if (scenario == Scenario::InactiveBridge) {
            engine.current_constraints_.add(relation.soft(0));
            engine.current_constraints_.add(relation.soft(-1));
            return;
        }
        engine.current_constraints_.add(relation);
        engine.current_constraints_.add(signature); // Correlated duplicate.
        engine.current_constraints_.add(TypeConstraint::make_one_of(other,
            {InferredType::make_base(BaseType::Int32)}, site + 8)
            .soft(10).sourced_from(TypeConstraintOrigin::DecompilerType));
        engine.current_constraints_.add(TypeConstraint::make_is_signed(local)
            .soft(5).sourced_from(TypeConstraintOrigin::Heuristic));
        engine.current_constraints_.add(TypeConstraint::make_is_integer(local));
    }

    static TypeInferenceConfig config() {
        TypeInferenceConfig result;
        result.enable_experimental_pipeline = true;
        result.phase_constraint_extraction = false;
        result.phase_alias_analysis = false;
        result.phase_soft_constraints = false;
        result.solver_timeout_ms = 2000;
        return result;
    }

    static SourceEvidenceChecks collect(cfunc_t* function) {
        if (!function || function->argidx.empty())
            throw std::invalid_argument("source evidence carrier requires an argument");
        Z3Config solver;
        solver.max_memory_mb = 0;
        SourceEvidenceChecks checks;
        for (const auto& [scenario, name] : {
                std::pair{Scenario::Connected, "connected"},
                std::pair{Scenario::Independent, "independent_identity"},
                std::pair{Scenario::InactiveBridge, "inactive_bridge"},
                std::pair{Scenario::Unspecified, "unspecified"}}) {
            Z3Context context(solver);
            TypeInferenceEngine engine(context, config());
            engine.set_progress_callback([&](const char* phase, int, const char*) {
                if (std::string_view(phase) == "Building") inject(engine, scenario);
            });
            checks.observations.push_back({name, engine.infer_function(function)});
        }
        Z3Context context(solver);
        TypeInferenceEngine native(context, config());
        native.current_cfunc_ = function;
        native.phase_constraint_extraction(function);
        native.phase_alias_analysis(function);
        native.phase_soft_constraints(function);
        for (const auto& constraint : native.current_constraints_.constraints()) {
            const auto origin = static_cast<unsigned>(constraint.origin);
            if (origin >= checks.native_origin_counts.size())
                throw std::runtime_error("invalid emitted constraint origin");
            ++checks.native_origin_counts[origin];
        }
        return checks;
    }
};
} // namespace structor::z3
#endif
