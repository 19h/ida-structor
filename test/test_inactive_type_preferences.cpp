#include "structor/z3/instruction_semantics.hpp"

#include <cassert>
#include <iostream>

using namespace structor::z3;

namespace {
InferredType integer() { return InferredType::make_base(BaseType::Int32); }
InferredType floating() { return InferredType::make_base(BaseType::Float32); }
InferredType array3() { return InferredType::make_array(InferredType::make_base(BaseType::UInt8), 3); }

void check_inactive_weights_do_not_change_selected_objective() {
    Z3Context context;
    TypeLatticeEncoder encoder(context);
    const auto variable = TypeVariable::for_temp(1, BADADDR, "objective");
    TypeConstraintSet constraints(context);
    constraints.add(TypeConstraint::make_one_of(variable, {floating()}).soft(-1));
    constraints.add(TypeConstraint::make_one_of(variable, {InferredType::make_base(BaseType::UInt64)}).soft(0));
    constraints.add(TypeConstraint::make_one_of(variable, {integer()}).soft(10));
    ::z3::optimize optimizer(context.ctx());
    optimizer.add(constraints.to_z3_hard(encoder));
    const auto soft = constraints.to_z3_soft(encoder, true);
    assert(soft.size() == 1 && soft[0].second == 10);
    optimizer.add_soft(soft[0].first, soft[0].second);
    assert(optimizer.check() == ::z3::sat);
    assert(encoder.decode(constraints.get_z3_var(variable, encoder), optimizer.get_model()) == integer());
}

void check_inactive_candidates_cannot_extend_hard_domain() {
    for (int weight : {0, -1}) {
        Z3Config config;
        config.max_symbolic_type_depth = 0;
        config.max_symbolic_type_list_length = 0;
        Z3Context context(config);
        TypeLatticeEncoder encoder(context);
        const auto variable = TypeVariable::for_temp(1, BADADDR, "domain");
        TypeConstraintSet constraints(context);
        constraints.add(TypeConstraint::make_has_size(variable, 3));
        constraints.add(TypeConstraint::make_one_of(variable, {array3()}).soft(weight));
        ::z3::solver solver(context.ctx());
        solver.add(constraints.to_z3_hard(encoder));
        assert(constraints.to_z3_soft(encoder, true).empty());
        assert(encoder.bounded_symbolic_queries_used());
        assert(!encoder.explicit_candidate_queries_used());
        assert(solver.check() == ::z3::unsat);
    }
}

void check_inactive_predicates_use_no_generation_budget() {
    Z3Config config;
    config.max_symbolic_type_expansions = 0;
    Z3Context context(config);
    TypeLatticeEncoder encoder(context);
    const auto first = TypeVariable::for_temp(1, BADADDR, "first");
    const auto second = TypeVariable::for_temp(2, BADADDR, "second");
    TypeConstraintSet constraints(context);
    constraints.add(TypeConstraint::make_has_size(first, 4).soft(0));
    constraints.add(TypeConstraint::make_subtype(first, second).soft(-10));
    assert(constraints.to_z3_hard(encoder).empty());
    assert(constraints.to_z3_soft(encoder, true).empty());
    assert(!encoder.bounded_symbolic_queries_used() && !encoder.explicit_candidate_queries_used());
}

void check_positive_candidate_still_extends_hard_domain() {
    Z3Config config;
    config.max_symbolic_type_depth = 0;
    config.max_symbolic_type_list_length = 0;
    Z3Context context(config);
    TypeLatticeEncoder encoder(context);
    const auto variable = TypeVariable::for_temp(1, BADADDR, "positive");
    TypeConstraintSet constraints(context);
    constraints.add(TypeConstraint::make_has_size(variable, 3));
    constraints.add(TypeConstraint::make_one_of(variable, {array3()}).soft(10));
    ::z3::optimize optimizer(context.ctx());
    optimizer.add(constraints.to_z3_hard(encoder));
    const auto soft = constraints.to_z3_soft(encoder, true);
    assert(soft.size() == 1 && soft[0].second == 10);
    optimizer.add_soft(soft[0].first, soft[0].second);
    assert(encoder.bounded_symbolic_queries_used() && encoder.explicit_candidate_queries_used());
    assert(optimizer.check() == ::z3::sat);
    assert(encoder.decode(constraints.get_z3_var(variable, encoder), optimizer.get_model()) == array3());
}

void check_hard_constraints_ignore_the_stored_weight() {
    Z3Context context;
    TypeLatticeEncoder encoder(context);
    const auto variable = TypeVariable::for_temp(1, BADADDR, "hard");
    TypeConstraintSet constraints(context);
    auto hard = TypeConstraint::make_one_of(variable, {integer()});
    hard.weight = -1;
    constraints.add(hard);
    constraints.add(TypeConstraint::make_one_of(variable, {floating()}).soft(100));
    ::z3::optimize optimizer(context.ctx());
    optimizer.add(constraints.to_z3_hard(encoder));
    const auto soft = constraints.to_z3_soft(encoder, true);
    assert(soft.size() == 1);
    optimizer.add_soft(soft[0].first, soft[0].second);
    assert(optimizer.check() == ::z3::sat);
    assert(encoder.decode(constraints.get_z3_var(variable, encoder), optimizer.get_model()) == integer());
}

void check_active_hard_aliases_preserve_candidate_propagation() {
    Z3Config config;
    config.max_symbolic_type_depth = 0;
    config.max_symbolic_type_list_length = 0;
    Z3Context context(config);
    TypeLatticeEncoder encoder(context);
    const auto local = TypeVariable::for_temp(1, BADADDR, "local");
    const auto related = TypeVariable::for_temp(2, BADADDR, "related");
    TypeConstraintSet constraints(context);
    constraints.add(TypeConstraint::make_equal(local, related));
    constraints.add(TypeConstraint::make_has_size(local, 3));
    constraints.add(TypeConstraint::make_one_of(related, {array3()}).soft(10));
    ::z3::optimize optimizer(context.ctx());
    optimizer.add(constraints.to_z3_hard(encoder));
    const auto soft = constraints.to_z3_soft(encoder, true);
    optimizer.add_soft(soft[0].first, soft[0].second);
    assert(optimizer.check() == ::z3::sat);
    assert(encoder.decode(constraints.get_z3_var(local, encoder), optimizer.get_model()) == array3());
}
} // namespace

int main() {
    check_inactive_weights_do_not_change_selected_objective();
    check_inactive_candidates_cannot_extend_hard_domain();
    check_inactive_predicates_use_no_generation_budget();
    check_positive_candidate_still_extends_hard_domain();
    check_hard_constraints_ignore_the_stored_weight();
    check_active_hard_aliases_preserve_candidate_propagation();
    std::cout << "6 inactive/active preference groups passed\n";
}
