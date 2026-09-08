#include "structor/z3/constraint_source_evidence.hpp"
#include "structor/z3/alias_analysis.hpp"

#include <algorithm>
#include <cassert>
#include <iostream>

using namespace structor::z3;

namespace {
using Origin = TypeConstraintOrigin;
using Relation = ConstraintSourceRelation;
using Kind = TypeConstraint::Kind;

void check_explicit_origin_and_default() {
    const auto variable = TypeVariable::for_temp(1, BADADDR, "unknown_origin");
    auto constraint = TypeConstraint::make_is_integer(variable, 0x1234);
    assert(constraint.origin == Origin::Unspecified);
    constraint.soft(7).describe("parameter type from signature");
    assert(constraint.origin == Origin::Unspecified);
    auto& returned = constraint.sourced_from(Origin::InstructionUsage);
    assert(&returned == &constraint && constraint.origin == Origin::InstructionUsage);
    assert(constraint.is_soft && constraint.weight == 7 && constraint.source_ea == 0x1234);
    assert(constraint.kind == Kind::IsInteger);
}

void check_connected_sources_and_exact_identity() {
    Z3Context context;
    const auto local = TypeVariable::for_local(1, 0x100001234ULL, 0);
    const auto temporary = TypeVariable::for_temp(1, 0x100001234ULL, "copied");
    const auto memory = TypeVariable::for_memory(1, 0x200001234ULL, -8, 4);
    const auto unrelated = TypeVariable::for_local(1, 0x100001234ULL, 0);
    TypeConstraintSet constraints(context);
    constraints.add(TypeConstraint::make_equal(local, temporary, 0x100004000ULL)
        .sourced_from(Origin::InstructionUsage));
    constraints.add(TypeConstraint::make_one_of(temporary,
        {InferredType::make_base(BaseType::UInt32)}, 0x200004000ULL)
        .soft(20).sourced_from(Origin::FunctionSignature));
    constraints.add(TypeConstraint::make_equal(temporary, memory, BADADDR)
        .soft(5).sourced_from(Origin::AliasRelation));
    constraints.add(TypeConstraint::make_has_size(memory, 4, 0)
        .sourced_from(Origin::DecompilerType));
    constraints.add(TypeConstraint::make_is_signed(unrelated, 0x300004000ULL)
        .sourced_from(Origin::Heuristic));
    const ConstraintSourceIndex index(constraints);
    const auto evidence = index.for_variable(local);
    assert(evidence.records.size() == 4);
    assert((evidence.source_sites == std::vector<ea_t>{0, 0x100004000ULL, 0x200004000ULL}));
    assert(evidence.from_signature && evidence.from_decompiler && evidence.from_alias && evidence.from_usage);
    assert(std::count_if(evidence.records.begin(), evidence.records.end(), [](const auto& record) {
        return record.relation == Relation::Direct;
    }) == 1);
    const auto signature = std::find_if(evidence.records.begin(), evidence.records.end(), [](const auto& record) {
        return record.origin == Origin::FunctionSignature;
    });
    assert(signature != evidence.records.end() && signature->is_soft && signature->weight == 20 &&
           signature->relation == Relation::Related);
    const auto memory_sources = index.for_variable(memory);
    assert(std::count_if(memory_sources.records.begin(), memory_sources.records.end(), [](const auto& record) {
        return record.relation == Relation::Direct;
    }) == 2);
    assert(index.for_variable(unrelated).records.size() == 1);
    assert(index.for_variable(TypeVariable::for_local(1, local.func_ea, 0)).records.empty());
}

void check_deduplication_and_strength() {
    Z3Context context;
    const auto direct = TypeVariable::for_temp(1, BADADDR, "direct");
    const auto related = TypeVariable::for_temp(2, BADADDR, "related");
    TypeConstraintSet constraints(context);
    constraints.add(TypeConstraint::make_equal(direct, related).sourced_from(Origin::AliasRelation));
    const auto first = TypeConstraint::make_is_integer(direct, 0x1234).sourced_from(Origin::InstructionUsage);
    constraints.add(first);
    constraints.add(first);
    auto same_hard = first;
    same_hard.weight = 999; // Irrelevant when the constraint is hard.
    constraints.add(same_hard);
    constraints.add(TypeConstraint::make_is_integer(related, 0x1234).sourced_from(Origin::InstructionUsage));
    constraints.add(TypeConstraint::make_is_integer(direct, 0x1234).soft(7).sourced_from(Origin::InstructionUsage));
    constraints.add(TypeConstraint::make_is_integer(direct, 0x1234).soft(8).sourced_from(Origin::InstructionUsage));
    const auto evidence = ConstraintSourceIndex(constraints).for_variable(direct);
    assert(evidence.records.size() == 5);
    assert(evidence.source_sites == std::vector<ea_t>{0x1234});
    assert(std::count_if(evidence.records.begin(), evidence.records.end(), [](const auto& record) {
        return record.is_soft;
    }) == 2);
}

void check_cycles_and_inactive_soft_bridges() {
    Z3Context context;
    const auto first = TypeVariable::for_temp(1, BADADDR, "a");
    const auto second = TypeVariable::for_temp(2, BADADDR, "b");
    const auto third = TypeVariable::for_temp(3, BADADDR, "c");
    const auto other = TypeVariable::for_temp(4, BADADDR, "other");
    TypeConstraintSet constraints(context);
    constraints.add(TypeConstraint::make_equal(first, second).sourced_from(Origin::AliasRelation));
    constraints.add(TypeConstraint::make_equal(second, third).sourced_from(Origin::AliasRelation));
    constraints.add(TypeConstraint::make_equal(third, first).sourced_from(Origin::AliasRelation));
    constraints.add(TypeConstraint::make_equal(first, other).soft(0).sourced_from(Origin::FunctionSignature));
    constraints.add(TypeConstraint::make_equal(second, other).soft(-1).sourced_from(Origin::DecompilerType));
    constraints.add(TypeConstraint::make_is_integer(other, 0x1234).sourced_from(Origin::FunctionSignature));
    const auto evidence = ConstraintSourceIndex(constraints).for_variable(first);
    // The two direct equalities at unavailable sites share one source record;
    // the related equality is a separate relation record.
    assert(evidence.records.size() == 2 && evidence.source_sites.empty());
    assert(evidence.from_alias && !evidence.from_signature && !evidence.from_decompiler && !evidence.from_usage);
    auto invalid = first;
    invalid.identity = {};
    assert(ConstraintSourceIndex(constraints).for_variable(invalid).records.empty());
}

void check_descriptions_never_classify_origins() {
    Z3Context context;
    const auto variable = TypeVariable::for_temp(1, BADADDR, "description_control");
    TypeConstraintSet constraints(context);
    constraints.add(TypeConstraint::make_is_integer(variable, 0x1000)
        .describe("signature decompiler alias usage"));
    constraints.add(TypeConstraint::make_is_integer(variable, 0x2000)
        .sourced_from(Origin::FunctionSignature).describe("unrelated arbitrary label"));
    const auto evidence = ConstraintSourceIndex(constraints).for_variable(variable);
    assert(evidence.records.size() == 2 && evidence.from_signature);
    assert(!evidence.from_decompiler && !evidence.from_alias && !evidence.from_usage);
    assert(evidence.records[0].origin == Origin::Unspecified);
    assert(evidence.records[1].origin == Origin::FunctionSignature);
}

void check_actual_assignment_and_cast_origins() {
    Z3Context context;
    InstructionSemanticsExtractor extractor(context);
    cfunc_t function;
    function.entry_ea = 0x100004000ULL;
    cblock_t block;
    block.resize(1);
    function.body.op = cit_block;
    function.body.cblock = &block;
    block[0].op = cit_expr;
    auto& assignment = block[0].cexpr;
    cexpr_t local, cast, number;
    local.op = cot_var;
    local.v.idx = 0;
    cast.op = cot_cast;
    cast.x = &number;
    cast.ea = 0x100004004ULL;
    cast.type.create_simple_type(BTF_INT32);
    number.op = cot_num;
    assignment.op = cot_asg;
    assignment.x = &local;
    assignment.y = &cast;
    assignment.ea = 0x100004008ULL;
    const auto constraints = extractor.extract(&function);
    assert(constraints.total_count() == 3);
    for (const auto& constraint : constraints.constraints()) {
        assert(constraint.origin == (constraint.kind == Kind::Equal ? Origin::InstructionUsage : Origin::DecompilerType));
    }
    const auto evidence = ConstraintSourceIndex(constraints).for_variable(extractor.get_var_type(&function, 0));
    assert(evidence.from_usage && evidence.from_decompiler && !evidence.from_signature && !evidence.from_alias);
    assert(std::count_if(evidence.records.begin(), evidence.records.end(), [](const auto& record) {
        return record.origin == Origin::DecompilerType && record.relation == Relation::Related;
    }) == 2);
}

void check_actual_usage_and_heuristic_origins() {
    Z3Context context;
    InstructionSemanticsExtractor extractor(context);
    cfunc_t function;
    function.entry_ea = 0x100004000ULL;
    cexpr_t comparison, local, constant;
    local.op = cot_var;
    local.v.idx = 0;
    constant.op = cot_num;
    constant.set_numval(4);
    comparison.op = cot_slt;
    comparison.x = &local;
    comparison.y = &constant;
    comparison.ea = 0x100004004ULL;
    TypeConstraintSet constraints(context);
    constraints.add_all(extractor.extract_expr(&comparison, &function));
    assert(constraints.total_count() == 4);
    unsigned heuristics = 0;
    for (const auto& constraint : constraints.constraints()) {
        if (constraint.kind == Kind::IsInteger) {
            assert(constraint.origin == Origin::Heuristic && constraint.is_soft);
            ++heuristics;
        } else assert(constraint.origin == Origin::InstructionUsage);
    }
    assert(heuristics == 1);
    const auto evidence = ConstraintSourceIndex(constraints).for_variable(extractor.get_var_type(&function, 0));
    assert(evidence.from_usage && !evidence.from_decompiler && !evidence.from_signature && !evidence.from_alias);
}

void check_actual_memory_and_signature_origins() {
    Z3Context context;
    InstructionSemanticsExtractor extractor(context);
    cfunc_t function;
    function.entry_ea = 0x100004000ULL;
    cexpr_t object;
    object.op = cot_obj;
    object.obj_ea = 0x200001000ULL;
    object.type.create_simple_type(BTF_FLOAT);
    const auto memory = extractor.extract_expr(&object, &function);
    assert(memory.size() == 2);
    for (const auto& constraint : memory) assert(constraint.origin == Origin::DecompilerType);
    assert(memory[0].is_soft != memory[1].is_soft);

    cexpr_t call, callee;
    callee.op = cot_var;
    callee.v.idx = 0;
    func_type_data_t prototype;
    prototype.rettype.create_simple_type(BTF_INT32);
    prototype.resize(1);
    prototype[0].type.create_simple_type(BTF_FLOAT);
    callee.type.create_func(prototype);
    carglist_t arguments;
    arguments.resize(1);
    arguments[0].op = cot_var;
    arguments[0].v.idx = 1;
    call.op = cot_call;
    call.x = &callee;
    call.a = &arguments;
    call.ea = 0x100004010ULL;
    const auto signature = extractor.extract_expr(&call, &function);
    assert(signature.size() == 3);
    unsigned signature_count = 0;
    for (const auto& constraint : signature) {
        if (constraint.kind == Kind::OneOf) {
            assert(constraint.origin == Origin::FunctionSignature && constraint.is_soft);
            ++signature_count;
        } else assert(constraint.origin == Origin::InstructionUsage);
    }
    assert(signature_count == 2);
}
void check_actual_alias_producers() {
    Z3Context context;
    const auto first = TypeVariable::for_local(1, 0x100001000ULL, 0);
    const auto second = TypeVariable::for_local(2, 0x100001000ULL, 1);
    const auto third = TypeVariable::for_local(3, 0x100001000ULL, 2);
    SteensgaardAliasAnalyzer steensgaard(context);
    steensgaard.process_assignment(0, 1);
    const auto equalities = steensgaard.generate_type_constraints({{0, first}, {1, second}});
    assert(equalities.size() == 1 && equalities[0].kind == Kind::Equal);
    assert(equalities[0].origin == Origin::AliasRelation && !equalities[0].is_soft);

    cfunc_t function;
    function.entry_ea = first.func_ea;
    cblock_t block;
    block.resize(2);
    function.body.op = cit_block;
    function.body.cblock = &block;
    cexpr_t pointer[2], reference[2], pointee[2];
    for (int index = 0; index < 2; ++index) {
        pointer[index].op = cot_var;
        pointer[index].v.idx = 0;
        pointee[index].op = cot_var;
        pointee[index].v.idx = index + 1;
        reference[index].op = cot_ref;
        reference[index].x = &pointee[index];
        block[index].op = cit_expr;
        block[index].cexpr.op = cot_asg;
        block[index].cexpr.x = &pointer[index];
        block[index].cexpr.y = &reference[index];
    }
    AndersenAliasAnalyzer andersen(context);
    andersen.analyze(&function);
    // The analyzer allocates two reference-expression temporaries between the
    // three registered local locations: IDs 0, 2, and 4.
    const auto points_to = andersen.generate_type_constraints({{0, first}, {2, second}, {4, third}});
    assert(points_to.size() == 2);
    for (const auto& constraint : points_to) {
        assert(constraint.origin == Origin::AliasRelation);
        if (constraint.kind == Kind::Equal) assert(constraint.is_soft && constraint.weight == 5);
        else assert(constraint.kind == Kind::IsPointer && !constraint.is_soft);
    }
}
} // namespace

int main() {
    check_explicit_origin_and_default();
    check_connected_sources_and_exact_identity();
    check_deduplication_and_strength();
    check_cycles_and_inactive_soft_bridges();
    check_descriptions_never_classify_origins();
    check_actual_assignment_and_cast_origins();
    check_actual_usage_and_heuristic_origins();
    check_actual_memory_and_signature_origins();
    check_actual_alias_producers();
    std::cout << "9 structured source and production emission groups passed\n";
}
