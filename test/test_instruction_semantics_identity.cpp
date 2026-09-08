#include "structor/z3/instruction_semantics.hpp"

#include <cassert>
#include <iostream>
#include <limits>
#include <string>
#include <unordered_set>

using namespace structor::z3;

namespace {

void require_independent_types(Z3Context& context, TypeLatticeEncoder& encoder,
                               const TypeVariable& integer,
                               const TypeVariable& floating) {
    TypeConstraintSet constraints(context);
    constraints.add(TypeConstraint::make_is_base(integer, BaseType::Int32));
    constraints.add(TypeConstraint::make_is_base(floating, BaseType::Float32));
    assert(constraints.variables().size() == 2);
    ::z3::solver solver(context.ctx());
    solver.add(constraints.to_z3_hard(encoder));
    assert(solver.check() == ::z3::sat);
    assert(!::z3::eq(constraints.get_z3_var(integer, encoder),
                    constraints.get_z3_var(floating, encoder)));
    solver.add(constraints.get_z3_var(integer, encoder) ==
               constraints.get_z3_var(floating, encoder));
    assert(solver.check() == ::z3::unsat);
}

void check_public_factory_and_diagnostic_compatibility() {
    Z3Context context;
    TypeLatticeEncoder encoder(context);
    // Existing public signatures and diagnostic IDs remain available. A new
    // factory invocation is a new variable, even when every label is reused.
    const auto integer = TypeVariable::for_temp(7, 0x100001234ULL, "shared");
    const auto floating = TypeVariable::for_temp(7, 0x100001234ULL, "shared");
    assert(integer.id == 7 && floating.id == 7);
    assert(integer != floating);
    require_independent_types(context, encoder, integer, floating);

    auto renamed_copy = integer;
    renamed_copy.name = "changed diagnostic label";
    renamed_copy.id = 999;
    assert(renamed_copy == integer);
    assert(TypeVariableHash{}(renamed_copy) == TypeVariableHash{}(integer));
    TypeConstraintSet constraints(context);
    assert(::z3::eq(constraints.get_z3_var(integer, encoder),
                    constraints.get_z3_var(renamed_copy, encoder)));
    constraints.add(TypeConstraint::make_is_base(integer, BaseType::Int32));
    constraints.add(TypeConstraint::make_is_base(renamed_copy, BaseType::Float32));
    assert(constraints.variables().size() == 1);
    ::z3::solver solver(context.ctx());
    solver.add(constraints.to_z3_hard(encoder));
    assert(solver.check() == ::z3::unsat);

    TypeVariable default_first, default_second;
    default_first.id = default_second.id = 7;
    assert(default_first != default_second);
    require_independent_types(context, encoder, default_first, default_second);
}

void check_production_extractor_keys() {
    Z3Context context;
    InstructionSemanticsExtractor extractor(context);
    auto& encoder = extractor.type_encoder();
    cfunc_t first_function, second_function;
    first_function.entry_ea = 0x100001234ULL;
    second_function.entry_ea = 0x200001234ULL;
    const auto first = extractor.get_var_type(&first_function, 2, 0);
    const auto second = extractor.get_var_type(&second_function, 2, 0);
    const auto version = extractor.get_var_type(&first_function, 2, 1);
    assert(first.func_ea == first_function.entry_ea);
    assert(second.func_ea == second_function.entry_ea);
    assert(version.ssa_version == 1);
    assert(first == extractor.get_var_type(&first_function, 2, 0));
    assert(version == extractor.get_var_type(&first_function, 2, 1));
    require_independent_types(context, encoder, first, second);
    require_independent_types(context, encoder, first, version);

    // These keys collide under the previous hash-only cache on libc++. Exact
    // key equality is also stress-tested with forced collisions in the
    // production interner's separate standalone test.
    const auto memory_first = extractor.get_mem_type(0x1000, 0, 4);
    const auto memory_second = extractor.get_mem_type(0x1008, 4, 4);
    const auto memory_width = extractor.get_mem_type(0x1000, 0, 8);
    assert(memory_first == extractor.get_mem_type(0x1000, 0, 4));
    assert(memory_width.mem_size == 8);
    require_independent_types(context, encoder, memory_first, memory_second);
    require_independent_types(context, encoder, memory_first, memory_width);

    std::string label = "shared";
    const auto temporary_first = extractor.get_temp_type(first_function.entry_ea, label.c_str());
    label = "mutated storage";
    const auto temporary_second = extractor.get_temp_type(second_function.entry_ea, "shared");
    assert(temporary_first == extractor.get_temp_type(first_function.entry_ea, "shared"));
    require_independent_types(context, encoder, temporary_first, temporary_second);

    InstructionSemanticsExtractor separate_extractor(context);
    const auto separate = separate_extractor.get_var_type(&first_function, 2, 0);
    assert(first.id == separate.id);
    require_independent_types(context, encoder, first, separate);
}

void check_shared_encoder_sorts_and_context_lifetime() {
    Z3Context context;
    {
        TypeLatticeEncoder first(context), second(context);
        assert(::z3::eq(first.base_type_sort(), second.base_type_sort()));
        assert(first.base_type_sort().sort_kind() == Z3_DATATYPE_SORT);
        assert(::z3::eq(first.type_sort(), second.type_sort()));
        assert(first.type_sort().is_datatype());
        TypeConstraintSet constraints(context);
        const auto variable = TypeVariable::for_temp(0, BADADDR, "same");
        assert(::z3::eq(constraints.get_z3_var(variable, first),
                        constraints.get_z3_var(variable, second)));
        ::z3::solver solver(context.ctx());
        solver.add(first.type_eq(constraints.get_z3_var(variable, first),
                                 second.encode(InferredType::make_base(BaseType::Int32))));
        assert(solver.check() == ::z3::sat);
    }
    {
        // The enum remains available after every earlier encoder has died.
        TypeLatticeEncoder recreated(context);
        assert(recreated.base_type_sort().sort_kind() == Z3_DATATYPE_SORT);
    }

    Z3Context destination;
    { TypeLatticeEncoder existing(destination); }
    destination = std::move(context);
    { TypeLatticeEncoder after_assignment(destination); }
    Z3Context moved(std::move(destination));
    { TypeLatticeEncoder after_move(moved); }
}

void check_full_production_extraction_and_node_identity() {
    Z3Context context;
    InstructionSemanticsExtractor extractor(context);
    auto& encoder = extractor.type_encoder();
    cfunc_t function;
    function.entry_ea = 0x100001234ULL;
    cblock_t block;
    block.resize(2);
    function.body.op = cit_block;
    function.body.cblock = &block;

    cexpr_t locals[2], casts[2], constants[2];
    for (int index = 0; index < 2; ++index) {
        block[index].op = cit_expr;
        auto& assignment = block[index].cexpr;
        assignment.op = cot_asg;
        assignment.x = &locals[index];
        assignment.y = &casts[index];
        locals[index].op = cot_var;
        locals[index].v.idx = index;
        casts[index].op = cot_cast;
        casts[index].ea = BADADDR;
        casts[index].x = &constants[index];
        casts[index].type.create_simple_type(index == 0 ? BTF_INT32 : BTF_FLOAT);
        constants[index].op = cot_num;
    }

    auto extracted = extractor.extract(&function);
    assert(extracted.hard_count() == 4);
    assert(extracted.soft_count() == 2);
    assert(extractor.stats().expressions_analyzed == 8);
    assert(extractor.stats().constraints_extracted == 6);
    assert(extractor.stats().hard_constraints == 4);
    assert(extractor.stats().soft_constraints == 2);
    ::z3::solver solver(context.ctx());
    solver.add(extracted.to_z3_hard(encoder));
    assert(solver.check() == ::z3::sat);

    qvector<TypeVariable> assignment_rhs, cast_targets;
    for (const auto& constraint : extracted.constraints()) {
        if (constraint.description == "assignment type equality") {
            assert(constraint.var2);
            assignment_rhs.push_back(*constraint.var2);
        } else if (constraint.description == "cast target type") {
            cast_targets.push_back(constraint.var1);
        }
    }
    assert(cast_targets.size() == 2 && assignment_rhs.size() == 2);
    assert(cast_targets[0].name == cast_targets[1].name);
    assert(cast_targets[0] != cast_targets[1]);
    assert(assignment_rhs[0] == cast_targets[0]);
    assert(assignment_rhs[1] == cast_targets[1]);

    const auto previous_local = extractor.get_var_type(&function, 0);
    auto repeated = extractor.extract(&function);
    assert(previous_local == extractor.get_var_type(&function, 0));
    for (const auto& constraint : repeated.constraints()) {
        if (constraint.description != "cast target type") continue;
        for (const auto& old_target : cast_targets) assert(constraint.var1 != old_target);
    }
}

void check_recycled_node_storage_between_expression_passes() {
    Z3Context context;
    InstructionSemanticsExtractor extractor(context);
    auto& encoder = extractor.type_encoder();
    cfunc_t function;
    function.entry_ea = 0x100001234ULL;
    cexpr_t cast, constant;
    cast.op = cot_cast;
    cast.x = &constant;
    cast.ea = BADADDR;
    cast.type.create_simple_type(BTF_INT32);
    const auto first = extractor.extract_expr(&cast, &function);
    cast.type.create_simple_type(BTF_FLOAT);
    const auto second = extractor.extract_expr(&cast, &function);
    assert(first.size() == 1 && second.size() == 1);
    assert(first[0].var1 != second[0].var1);
    require_independent_types(context, encoder, first[0].var1, second[0].var1);
    assert(extractor.extract_expr(&cast, nullptr).empty());
    assert(extractor.extract_expr(nullptr, &function).empty());
    assert(extractor.extract(nullptr).total_count() == 0);
}

void check_storage_width_validation_before_narrowing() {
    Z3Context context;
    InstructionSemanticsExtractor extractor(context);
    cfunc_t function;
    function.entry_ea = 0x100001234ULL;

    tinfo_t integer, void_type, empty_type, zero_width, oversized;
    integer.create_simple_type(BTF_INT32);
    void_type.create_simple_type(BTF_VOID);
    zero_width.create_array(integer, 0);
    tinfo_t wide_element;
    wide_element.create_simple_type(BTF_INT64);
    oversized.create_array(wide_element,
        static_cast<std::size_t>(std::numeric_limits<uint32_t>::max()) / 8 + 2);
    assert(oversized.get_size() > std::numeric_limits<uint32_t>::max());

    struct Case { tinfo_t type; std::optional<uint32_t> width; };
    for (const auto& test : std::vector<Case>{
             {integer, 4}, {void_type, std::nullopt}, {empty_type, std::nullopt},
             {zero_width, std::nullopt}, {oversized, std::nullopt}}) {
        for (const auto opcode : {cot_cast, cot_idx, cot_ptr}) {
            cexpr_t expression, operand, index;
            expression.op = opcode;
            expression.x = &operand;
            if (opcode == cot_idx) expression.y = &index;
            if (opcode == cot_cast) {
                expression.type = integer;
                operand.type = test.type;
            } else {
                expression.type = test.type;
            }
            const auto constraints = extractor.extract_expr(&expression, &function);
            std::size_t sizes = 0;
            for (const auto& constraint : constraints) {
                if (constraint.kind != TypeConstraint::Kind::HasSize) continue;
                ++sizes;
                assert(test.width.has_value());
                assert(constraint.size == test.width);
            }
            assert(sizes == (test.width.has_value() ? 1u : 0u));
        }
    }
}

void check_hard_evidence_specialization() {
    Z3Config config;
    config.max_symbolic_type_depth = 0;
    config.max_symbolic_type_list_length = 0;
    config.max_symbolic_type_expansions = 1;
    Z3Context context(config);
    TypeLatticeEncoder encoder(context);
    const auto integer = InferredType::make_base(BaseType::Int32);
    const auto nested = InferredType::make_array(InferredType::make_array(integer, 2), 3);
    const auto first = TypeVariable::for_temp(1, 0x1000, "exact");
    const auto alias = TypeVariable::for_temp(2, 0x1000, "alias");
    TypeConstraintSet exact(context);
    // Put the size constraint first to reject order-dependent specialization.
    exact.add(TypeConstraint::make_has_size(alias, 24));
    exact.add(TypeConstraint::make_equal(first, alias));
    exact.add(TypeConstraint::make_one_of(first, {nested}));
    auto solver = context.make_solver();
    solver.add(exact.to_z3_hard(encoder));
    assert(!encoder.bounded_symbolic_queries_used());
    assert(solver.check() == ::z3::sat);
    assert(encoder.decode(exact.get_z3_var(alias, encoder), solver.get_model()) == nested);
    exact.add(TypeConstraint::make_one_of(alias, {InferredType::make_array(integer, 2)}));
    solver.reset();
    solver.add(exact.to_z3_hard(encoder));
    assert(solver.check() == ::z3::unsat);
    assert(!encoder.bounded_symbolic_queries_used());

    TypeConstraintSet conflict(context);
    conflict.add(TypeConstraint::make_has_size(first, 4));
    conflict.add(TypeConstraint::make_is_base(first, BaseType::Int32));
    conflict.add(TypeConstraint::make_is_base(first, BaseType::Float32));
    solver.reset();
    solver.add(conflict.to_z3_hard(encoder));
    assert(solver.check() == ::z3::unsat);
    assert(!encoder.bounded_symbolic_queries_used());

    // Neither soft concrete hints nor multi-choice alternatives entail one
    // concrete equality. They must not bypass the symbolic work budget.
    for (const auto soft : {false, true}) {
        auto hint = TypeConstraint::make_one_of(first, soft
            ? std::vector<InferredType>{integer}
            : std::vector<InferredType>{integer, InferredType::make_base(BaseType::Float32)});
        if (soft) hint.soft(10);
        // Depth=0 permits only one size-builder step, so use zero budget
        // in a separate context to prove that no equality was assumed.
        Z3Config zero_config = config;
        zero_config.max_symbolic_type_expansions = 0;
        Z3Context zero_context(zero_config);
        TypeLatticeEncoder zero_encoder(zero_context);
        TypeConstraintSet zero_constraints(zero_context);
        zero_constraints.add(TypeConstraint::make_has_size(first, 4));
        zero_constraints.add(hint);
        bool exhausted = false;
        try {
            (void)zero_constraints.to_z3_hard(zero_encoder);
        } catch (const SymbolicTypeQueryLimit&) {
            exhausted = true;
        }
        assert(exhausted && zero_encoder.bounded_symbolic_queries_used());
    }
}

void check_soft_compound_candidates_outside_bounds() {
    const auto integer = InferredType::make_base(BaseType::Int32);
    const auto nested = InferredType::make_array(InferredType::make_array(integer, 2), 3);
    const auto pointer = InferredType::make_ptr(InferredType::make_ptr(nested));
    const auto function = InferredType::make_func(InferredType::make_ptr(nested),
        {InferredType::make_ptr(nested), InferredType::make_array(InferredType::make_ptr(integer), 4)});
    for (const auto& candidate : {nested, pointer, function}) {
        Z3Config config;
        config.max_symbolic_type_depth = 0;
        config.max_symbolic_type_list_length = 0;
        Z3Context context(config);
        TypeLatticeEncoder encoder(context);
        TypeConstraintSet constraints(context);
        const auto source = TypeVariable::for_temp(1, 0x1000, "soft source");
        const auto alias = TypeVariable::for_temp(2, 0x1000, "soft alias");
        constraints.add(TypeConstraint::make_has_size(alias, candidate.size(8)));
        if (candidate.is_pointer()) constraints.add(TypeConstraint::make_is_pointer(alias));
        constraints.add(TypeConstraint::make_equal(source, alias));
        constraints.add(TypeConstraint::make_one_of(source, {candidate}).soft(10));
        auto optimizer = context.make_optimizer();
        optimizer.add(constraints.to_z3_hard(encoder));
        for (const auto& [expression, weight] : constraints.to_z3_soft(encoder, true))
            optimizer.add_soft(expression, weight);
        assert(optimizer.check() == ::z3::sat);
        assert(encoder.decode(constraints.get_z3_var(alias, encoder), optimizer.get_model()) == candidate);
        assert(encoder.bounded_symbolic_queries_used());
        assert(encoder.explicit_candidate_queries_used());
        encoder.reset_symbolic_query_tracking();
        assert(!encoder.bounded_symbolic_queries_used() && !encoder.explicit_candidate_queries_used());
    }
    {
        Z3Config config;
        config.max_symbolic_type_depth = 0;
        config.max_symbolic_type_list_length = 0;
        Z3Context context(config);
        TypeLatticeEncoder encoder(context);
        TypeConstraintSet constraints(context);
        const auto a = TypeVariable::for_temp(1, 0x1000, "subtype source");
        const auto b = TypeVariable::for_temp(2, 0x1000, "subtype destination");
        const auto narrow = InferredType::make_ptr(InferredType::make_ptr(InferredType::make_base(BaseType::Int8)));
        const auto wide = InferredType::make_ptr(InferredType::make_ptr(integer));
        constraints.add(TypeConstraint::make_is_pointer(a));
        constraints.add(TypeConstraint::make_is_pointer(b));
        constraints.add(TypeConstraint::make_subtype(a, b));
        constraints.add(TypeConstraint::make_one_of(a, {narrow}).soft(10));
        constraints.add(TypeConstraint::make_one_of(b, {wide}).soft(10));
        auto optimizer = context.make_optimizer();
        optimizer.add(constraints.to_z3_hard(encoder));
        for (const auto& [expression, weight] : constraints.to_z3_soft(encoder, true))
            optimizer.add_soft(expression, weight);
        assert(optimizer.check() == ::z3::sat);
        assert(encoder.decode(constraints.get_z3_var(a, encoder), optimizer.get_model()) == narrow);
        assert(encoder.decode(constraints.get_z3_var(b, encoder), optimizer.get_model()) == wide);
        assert(encoder.bounded_symbolic_queries_used() && encoder.explicit_candidate_queries_used());
    }
    {
        Z3Context context;
        TypeLatticeEncoder encoder(context);
        TypeConstraintSet constraints(context);
        const auto variable = TypeVariable::for_temp(1, 0x1000, "conflicting preference");
        constraints.add(TypeConstraint::make_is_base(variable, BaseType::Int32));
        constraints.add(TypeConstraint::make_has_size(variable, 4));
        constraints.add(TypeConstraint::make_one_of(variable, {nested}).soft(10));
        auto optimizer = context.make_optimizer();
        optimizer.add(constraints.to_z3_hard(encoder));
        for (const auto& [expression, weight] : constraints.to_z3_soft(encoder, true))
            optimizer.add_soft(expression, weight);
        assert(optimizer.check() == ::z3::sat);
        assert(encoder.decode(constraints.get_z3_var(variable, encoder), optimizer.get_model()) == integer);
    }
}

} // namespace

int main(int argc, char** argv) {
    const std::string selected = argc == 2 ? argv[1] : "";
    bool ran = false;
    const auto run = [&](const char* name, auto check) {
        if (!selected.empty() && selected != name) return;
        check();
        ran = true;
        std::cout << "[PASS] " << name << '\n';
    };
    run("factory", check_public_factory_and_diagnostic_compatibility);
    run("keys", check_production_extractor_keys);
    run("sorts", check_shared_encoder_sorts_and_context_lifetime);
    run("full_extraction", check_full_production_extraction_and_node_identity);
    run("recycled_node", check_recycled_node_storage_between_expression_passes);
    run("storage_widths", check_storage_width_validation_before_narrowing);
    run("hard_evidence", check_hard_evidence_specialization);
    run("soft_compound_candidates", check_soft_compound_candidates_outside_bounds);
    assert(ran);
    std::cout << "Production instruction semantics identity checks passed\n";
}
