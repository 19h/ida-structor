#include "structor/z3/model_value_evidence.hpp"
#include "structor/z3/instruction_semantics.hpp"
#include <cassert>
#include <iostream>
#include <string>

using namespace structor::z3;

namespace {
InferredType scalar(BaseType type) { return InferredType::make_base(type); }

std::vector<InferredType> compound_values() {
    auto record = InferredType::make_struct(0x1234567890ABCDEFULL);
    auto nested = InferredType::make_ptr(InferredType::make_ptr(record));
    std::vector<InferredType> parameters(19, nested);
    parameters[17] = InferredType::make_array(scalar(BaseType::UInt8), 512);
    auto callback = InferredType::make_func(nested, parameters);
    return {record, nested, callback, InferredType::make_ptr(callback),
        InferredType::make_array(InferredType::make_array(scalar(BaseType::UInt8), 256), 3),
        InferredType::make_sum({record, callback, nested})};
}

::z3::model solve(Z3Context& context, const ::z3::expr_vector& constraints) {
    auto solver = context.make_solver();
    solver.add(constraints);
    assert(solver.check() == ::z3::sat);
    return solver.get_model();
}

void check_witness(Z3Context& context, const ::z3::expr_vector& hard,
                   const ::z3::expr& variable, const ::z3::expr& selected,
                   const ModelValueEvidence& evidence) {
    assert(evidence.status == ModelValueStatus::AlternativeModelExists);
    assert(evidence.alternative);
    auto witness = context.make_solver();
    witness.add(hard);
    witness.add(variable == *evidence.alternative);
    witness.add(variable != selected);
    assert(witness.check() == ::z3::sat);
}

void check_unique_compound_values() {
    Z3Context context;
    TypeLatticeEncoder encoder(context);
    const auto variable = encoder.make_type_var("unique_compound");
    for (const auto& expected : compound_values()) {
        const auto value = encoder.encode(expected);
        ::z3::expr_vector hard(context.ctx());
        hard.push_back(variable == value);
        const auto model = solve(context, hard);
        assert(encoder.decode(variable, model) == expected);
        ModelValueEvidenceProbe proof(hard, model);
        assert(proof.inspect(variable, value).status == ModelValueStatus::DeterminedByHardConstraints);
        assert(proof.inspect(variable, variable).status == ModelValueStatus::InvalidModel);
        assert(proof.inspect(variable, encoder.encode_base(BaseType::Int32)).status == ModelValueStatus::InvalidModel);
        assert(proof.inspect(variable, value).status == ModelValueStatus::DeterminedByHardConstraints);
        assert(proof.queries_used() == 2);
    }
}

void check_compound_equality_chain() {
    Z3Context context;
    TypeLatticeEncoder encoder(context);
    const auto a = encoder.make_type_var("alias_a"), b = encoder.make_type_var("alias_b");
    const auto c = encoder.make_type_var("alias_c"), d = encoder.make_type_var("alias_d");
    const auto value = encoder.encode(compound_values()[2]);
    ::z3::expr_vector hard(context.ctx());
    hard.push_back(a == b);
    hard.push_back(c == d);
    hard.push_back(b == c);
    hard.push_back(d == value);
    const auto model = solve(context, hard);
    ModelValueEvidenceProbe proof(hard, model);
    for (const auto& variable : {a, b, c, d})
        assert(proof.inspect(variable, value).status == ModelValueStatus::DeterminedByHardConstraints);
    assert(proof.queries_used() == 4);
}

void check_soft_only_compound_selection() {
    Z3Context context;
    TypeLatticeEncoder encoder(context);
    const auto variable = encoder.make_type_var("soft_compound");
    for (const auto& expected : compound_values()) {
        const auto value = encoder.encode(expected);
        ::z3::expr_vector hard(context.ctx());
        auto optimizer = context.make_optimizer();
        optimizer.add_soft(variable == value, 10);
        assert(optimizer.check() == ::z3::sat);
        const auto model = optimizer.get_model();
        assert(encoder.decode(variable, model) == expected);
        ModelValueEvidenceProbe proof(hard, model);
        check_witness(context, hard, variable, value, proof.inspect(variable, value));
        check_witness(context, hard, variable, value, proof.inspect(variable, value));
        assert(proof.queries_used() == 2);
    }
}

void check_ambiguity_under_symbolic_bounds() {
    Z3Config config;
    config.max_symbolic_type_depth = 0;
    config.max_symbolic_type_list_length = 0;
    config.max_symbolic_type_expansions = 256;
    Z3Context context(config);
    TypeLatticeEncoder encoder(context);
    const auto variable = encoder.make_type_var("bounded_size8");
    const auto pointer = encoder.encode(compound_values()[1]);
    ::z3::expr_vector hard(context.ctx());
    hard.push_back(encoder.type_has_size(variable, 8));
    assert(encoder.bounded_symbolic_queries_used());
    auto optimizer = context.make_optimizer();
    optimizer.add(hard);
    optimizer.add_soft(variable == pointer, 10);
    assert(optimizer.check() == ::z3::sat);
    const auto model = optimizer.get_model();
    assert(::z3::eq(model.eval(variable, true), pointer));
    ModelValueEvidenceProbe proof(hard, model);
    check_witness(context, hard, variable, pointer, proof.inspect(variable, pointer));
    // The evidence query changes no codec-domain metadata. Boundedness remains
    // a caller-visible qualification even when a particular value is unique.
    assert(encoder.bounded_symbolic_queries_used());
    hard.push_back(variable == pointer);
    ModelValueEvidenceProbe qualified_unique(hard, model);
    assert(qualified_unique.inspect(variable, pointer).status == ModelValueStatus::DeterminedByHardConstraints);
    assert(encoder.bounded_symbolic_queries_used());
}

void check_explicit_compounds_remain_optional() {
    Z3Config config;
    config.max_symbolic_type_depth = 0;
    config.max_symbolic_type_list_length = 0;
    config.max_symbolic_type_expansions = 256;
    Z3Context context(config);
    TypeLatticeEncoder encoder(context);
    TypeConstraintSet constraints(context);
    const auto logical = TypeVariable::for_temp(17, 0x1234, "candidate");
    const auto first = InferredType::make_array(InferredType::make_array(scalar(BaseType::UInt8), 3), 2);
    const auto second = InferredType::make_array(scalar(BaseType::UInt8), 6);
    constraints.add(TypeConstraint::make_has_size(logical, 6));
    constraints.add(TypeConstraint::make_one_of(logical, {first}).soft(10));
    constraints.add(TypeConstraint::make_one_of(logical, {second}).soft(5));
    const auto hard = constraints.to_z3_hard(encoder);
    auto optimizer = context.make_optimizer();
    optimizer.add(hard);
    for (const auto& [expression, weight] : constraints.to_z3_soft(encoder, true))
        optimizer.add_soft(expression, weight);
    assert(optimizer.check() == ::z3::sat);
    const auto model = optimizer.get_model();
    const auto variable = constraints.get_z3_var(logical, encoder);
    const auto selected = model.eval(variable, true);
    assert(encoder.decode(variable, model) == first);
    assert(encoder.bounded_symbolic_queries_used() && encoder.explicit_candidate_queries_used());
    ModelValueEvidenceProbe proof(hard, model);
    const auto evidence = proof.inspect(variable, selected);
    check_witness(context, hard, variable, selected, evidence);
    assert(::z3::eq(*evidence.alternative, encoder.encode(second)));
}

void check_bounded_uniqueness_requires_qualification() {
    Z3Config config;
    config.max_symbolic_type_depth = 0;
    config.max_symbolic_type_list_length = 0;
    config.max_symbolic_type_expansions = 256;
    Z3Context context(config);
    TypeLatticeEncoder encoder(context);
    const auto variable = encoder.make_type_var("bounded_subtype");
    const auto selected = encoder.encode(InferredType::make_ptr(scalar(BaseType::Int32)));
    const auto omitted = encoder.encode(InferredType::make_ptr(scalar(BaseType::Int8)));
    ::z3::expr_vector hard(context.ctx());
    hard.push_back(encoder.subtype_of(variable, selected));
    hard.push_back(variable != encoder.encode_base(BaseType::Bottom));
    const auto model = solve(context, hard);
    assert(::z3::eq(model.eval(variable, true), selected));
    assert(encoder.bounded_symbolic_queries_used());
    ModelValueEvidenceProbe proof(hard, model);
    assert(proof.inspect(variable, selected).status == ModelValueStatus::DeterminedByHardConstraints);
    // Ptr(Int8) is a valid full-domain subtype, but depth zero cannot discover
    // its pointee relation. Therefore the preceding uniqueness result applies
    // only to the supplied bounded formulas, not the full source relation.
    assert(encoder.subtype_of(omitted, selected).simplify().is_true());
    assert((omitted != selected).simplify().is_true());
    auto excluded = context.make_solver();
    excluded.add(hard);
    excluded.add(variable == omitted);
    assert(excluded.check() == ::z3::unsat);
}

void check_invalid_models_and_contexts() {
    Z3Context context, foreign_context;
    TypeLatticeEncoder encoder(context), foreign(foreign_context);
    const auto variable = encoder.make_type_var("validation");
    const auto value = encoder.encode(compound_values()[2]);
    ::z3::expr_vector hard(context.ctx());
    hard.push_back(variable == value);
    const auto model = solve(context, hard);
    ModelValueEvidenceProbe proof(hard, model);
    assert(proof.inspect(foreign.make_type_var("foreign"), value).status == ModelValueStatus::InvalidModel);
    assert(proof.inspect(variable, foreign.encode(compound_values()[2])).status == ModelValueStatus::InvalidModel);
    assert(proof.inspect(variable, context.ctx().int_val(0)).status == ModelValueStatus::InvalidModel);
    assert(proof.queries_used() == 0);
    hard.push_back(variable == encoder.encode_base(BaseType::Int32));
    ModelValueEvidenceProbe inconsistent(hard, model);
    assert(inconsistent.inspect(variable, value).status == ModelValueStatus::InvalidModel);
    assert(inconsistent.queries_used() == 0);
    bool rejected_model_context = false;
    ::z3::expr_vector foreign_hard(foreign_context.ctx());
    try { ModelValueEvidenceProbe invalid(foreign_hard, model); }
    catch (const std::invalid_argument&) { rejected_model_context = true; }
    assert(rejected_model_context);
    bool rejected_nonboolean = false;
    ::z3::expr_vector nonboolean(context.ctx());
    nonboolean.push_back(variable);
    try { ModelValueEvidenceProbe invalid(nonboolean, model); }
    catch (const std::invalid_argument&) { rejected_nonboolean = true; }
    assert(rejected_nonboolean);
}

void check_budget_and_scope_restoration() {
    Z3Context context;
    TypeLatticeEncoder encoder(context);
    const auto x = encoder.make_type_var("scope_x"), y = encoder.make_type_var("scope_y");
    const auto first = encoder.encode(compound_values()[2]);
    const auto second = encoder.encode(compound_values()[4]);
    ::z3::expr_vector hard(context.ctx());
    hard.push_back(x == first);
    hard.push_back(y == first || y == second);
    const auto model = solve(context, hard);
    const auto selected_y = model.eval(y, true);
    ModelValueEvidenceProbe proof(hard, model, {4, 1000});
    assert(proof.inspect(x, first).status == ModelValueStatus::DeterminedByHardConstraints);
    check_witness(context, hard, y, selected_y, proof.inspect(y, selected_y));
    assert(proof.inspect(x, first).status == ModelValueStatus::DeterminedByHardConstraints);
    check_witness(context, hard, y, selected_y, proof.inspect(y, selected_y));
    assert(proof.inspect(x, first).status == ModelValueStatus::ResourceLimit);
    assert(proof.queries_used() == 4);
    ModelValueEvidenceProbe zero_queries(hard, model, {0, 1000});
    ModelValueEvidenceProbe zero_time(hard, model, {4, 0});
    assert(zero_queries.inspect(x, first).status == ModelValueStatus::ResourceLimit);
    assert(zero_time.inspect(x, first).status == ModelValueStatus::ResourceLimit);
    assert(zero_queries.queries_used() == 0 && zero_time.queries_used() == 0);
}
}

int main() {
    const std::pair<const char*, void(*)()> cases[] = {
        {"unique_compound", check_unique_compound_values},
        {"equality_chain", check_compound_equality_chain},
        {"soft_only_compound", check_soft_only_compound_selection},
        {"bounded_ambiguity", check_ambiguity_under_symbolic_bounds},
        {"explicit_candidates_optional", check_explicit_compounds_remain_optional},
        {"bounded_uniqueness_qualified", check_bounded_uniqueness_requires_qualification},
        {"invalid_context_sort_model", check_invalid_models_and_contexts},
        {"budgets_scope_restoration", check_budget_and_scope_restoration},
    };
    for (const auto& [name, test] : cases) { test(); std::cout << "[PASS] " << name << '\n'; }
}
