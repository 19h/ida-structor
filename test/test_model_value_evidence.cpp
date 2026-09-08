#include "structor/z3/model_value_evidence.hpp"
#include <cassert>
#include <iostream>

using namespace structor::z3;

int main() {
    ::z3::context context;
    const auto x = context.int_const("x");
    const auto y = context.int_const("y");
    const auto solve = [&](const ::z3::expr_vector& constraints) {
        ::z3::solver solver(context);
        solver.add(constraints);
        assert(solver.check() == ::z3::sat);
        return solver.get_model();
    };
    {
        ::z3::expr_vector constraints(context);
        constraints.push_back(x == 7);
        const auto model = solve(constraints);
        ModelValueEvidenceProbe proof(constraints, model);
        assert(proof.inspect(x, context.int_val(7)).status == ModelValueStatus::DeterminedByHardConstraints);
        assert(proof.inspect(x, context.int_val(8)).status == ModelValueStatus::InvalidModel);
        assert(proof.inspect(x, x).status == ModelValueStatus::InvalidModel);
        // The preceding proof's x != 7 assumption must have been removed.
        assert(proof.inspect(x, context.int_val(7)).status == ModelValueStatus::DeterminedByHardConstraints);
        assert(proof.queries_used() == 2);
    }
    {
        ::z3::expr_vector constraints(context);
        constraints.push_back(x == 7 || x == 8);
        const auto model = solve(constraints);
        const auto value = model.eval(x, true);
        ModelValueEvidenceProbe proof(constraints, model);
        const auto evidence = proof.inspect(x, value);
        assert(evidence.status == ModelValueStatus::AlternativeModelExists);
        assert(evidence.alternative && (value != *evidence.alternative).simplify().is_true());
        ::z3::solver witness(context);
        witness.add(constraints);
        witness.add(x == *evidence.alternative);
        assert(witness.check() == ::z3::sat);
    }
    {
        ::z3::expr_vector constraints(context);
        constraints.push_back(x == y);
        constraints.push_back(y == 9);
        const auto model = solve(constraints);
        ModelValueEvidenceProbe proof(constraints, model);
        assert(proof.inspect(x, context.int_val(9)).status == ModelValueStatus::DeterminedByHardConstraints);
    }
    {
        ::z3::expr_vector constraints(context);
        ::z3::optimize optimizer(context);
        optimizer.add_soft(x == 7, 10);
        assert(optimizer.check() == ::z3::sat);
        const auto model = optimizer.get_model();
        ModelValueEvidenceProbe proof(constraints, model);
        assert(proof.inspect(x, context.int_val(7)).status == ModelValueStatus::AlternativeModelExists);
    }
    {
        ::z3::expr_vector constraints(context);
        constraints.push_back(x == 7);
        auto model = solve(constraints);
        ModelValueEvidenceProbe zero_queries(constraints, model, {0, 1000});
        ModelValueEvidenceProbe zero_time(constraints, model, {10, 0});
        assert(zero_queries.inspect(x, context.int_val(7)).status == ModelValueStatus::ResourceLimit);
        assert(zero_time.inspect(x, context.int_val(7)).status == ModelValueStatus::ResourceLimit);
        assert(zero_queries.queries_used() == 0 && zero_time.queries_used() == 0);
        ModelValueEvidenceProbe one_query(constraints, model, {1, 1000});
        assert(one_query.inspect(x, context.int_val(7)).status == ModelValueStatus::DeterminedByHardConstraints);
        assert(one_query.inspect(x, context.int_val(7)).status == ModelValueStatus::ResourceLimit);
    }
    {
        ::z3::expr_vector constraints(context);
        constraints.push_back(x == 7);
        auto model = solve(constraints);
        constraints.push_back(x == 8);
        ModelValueEvidenceProbe inconsistent(constraints, model);
        assert(inconsistent.inspect(x, context.int_val(7)).status == ModelValueStatus::InvalidModel);
    }
    {
        ::z3::expr_vector constraints(context);
        constraints.push_back(x == 7);
        auto model = solve(constraints);
        ModelValueEvidenceProbe proof(constraints, model);
        ::z3::context foreign;
        assert(proof.inspect(foreign.int_const("x"), foreign.int_val(7)).status == ModelValueStatus::InvalidModel);
        assert(proof.inspect(x, context.bool_val(true)).status == ModelValueStatus::InvalidModel);
    }
    std::cout << "Model evidence: hard uniqueness, alternative witness, equality flow, soft preference, budgets, invalid models, and context isolation PASS\n";
}
