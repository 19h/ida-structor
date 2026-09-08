#include "structor/z3/model_value_evidence.hpp"

#include <algorithm>
#include <stdexcept>

namespace structor::z3 {

ModelValueEvidenceProbe::ModelValueEvidenceProbe(
        const ::z3::expr_vector& hard_constraints,
        const ::z3::model& selected_model,
        ModelEvidenceBudget budget)
    : solver_(hard_constraints.ctx()), selected_model_(selected_model), budget_(budget),
      deadline_(std::chrono::steady_clock::now() + std::chrono::milliseconds(budget.timeout_ms)) {
    if (&hard_constraints.ctx() != &selected_model.ctx()) {
        throw std::invalid_argument("model evidence requires one owning Z3 context");
    }
    for (const auto& constraint : hard_constraints) {
        if (!constraint.is_bool()) {
            throw std::invalid_argument("model evidence requires Boolean hard constraints");
        }
        solver_.add(constraint);
        if (!selected_model_.eval(constraint, true).is_true()) {
            model_satisfies_hard_constraints_ = false;
        }
    }
}

ModelValueEvidence ModelValueEvidenceProbe::inspect(
        const ::z3::expr& variable, const ::z3::expr& selected_value) {
    if (&variable.ctx() != &solver_.ctx() || &selected_value.ctx() != &solver_.ctx() ||
        !::z3::eq(variable.get_sort(), selected_value.get_sort())) {
        return {ModelValueStatus::InvalidModel, {}, "type value has a different context or sort"};
    }
    if (!model_satisfies_hard_constraints_ ||
        !::z3::eq(selected_value, selected_model_.eval(selected_value, true)) ||
        !selected_model_.eval(variable == selected_value, true).is_true()) {
        return {ModelValueStatus::InvalidModel, {},
            "selected model is inconsistent, or the selected value is not a concrete model value"};
    }
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline_ - std::chrono::steady_clock::now()).count();
    if (queries_used_ >= budget_.max_queries || remaining <= 0 || budget_.timeout_ms == 0) {
        return {ModelValueStatus::ResourceLimit, {}, "model evidence query budget exhausted"};
    }

    ::z3::params parameters(solver_.ctx());
    parameters.set("timeout", static_cast<unsigned>(std::max<std::int64_t>(1, remaining)));
    solver_.set(parameters);
    solver_.push();
    // The frame must be removed on a solver exception as well as all results.
    struct Frame {
        ::z3::solver& solver;
        ~Frame() { solver.pop(); }
    } frame{solver_};
    solver_.add(variable != selected_value);
    ++queries_used_;
    const auto result = solver_.check();
    if (result == ::z3::unsat) {
        return {ModelValueStatus::DeterminedByHardConstraints, {}, {}};
    }
    if (result == ::z3::sat) {
        auto other = solver_.get_model().eval(variable, true);
        return {ModelValueStatus::AlternativeModelExists, std::move(other), {}};
    }
    return {ModelValueStatus::SolverUnknown, {}, solver_.reason_unknown()};
}

} // namespace structor::z3
