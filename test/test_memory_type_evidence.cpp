#include "structor/z3/memory_type_evidence.hpp"

#include <algorithm>
#include <cassert>
#include <iostream>
#include <limits>
#include <vector>

using namespace structor::z3;

namespace {
InferredType integer32() { return InferredType::make_base(BaseType::UInt32); }
InferredType integer64() { return InferredType::make_base(BaseType::UInt64); }
InferredType floating32() { return InferredType::make_base(BaseType::Float32); }

MemoryTypeEvidenceResult solve(Z3Context& context, const TypeConstraintSet& constraints) {
    TypeLatticeEncoder encoder(context);
    ::z3::optimize optimizer(context.ctx());
    optimizer.add(constraints.to_z3_hard(encoder));
    for (const auto& [expression, weight] : constraints.to_z3_soft(encoder)) {
        optimizer.add_soft(expression, weight);
    }
    assert(optimizer.check() == ::z3::sat);
    return extract_memory_type_evidence(constraints, encoder, optimizer.get_model(),
                                        context.pointer_size());
}

void check_exact_keys_and_forced_collisions() {
    struct CollisionHash {
        std::size_t operator()(const MemoryLocationKey&) const noexcept { return 0; }
    };
    ExactMemoryLocationMap<InferredType, CollisionHash> types;
    const MemoryLocationKey first{0x100001234ULL, -8, 4};
    const MemoryLocationKey high{0x200001234ULL, -8, 4};
    const MemoryLocationKey wide{0x100001234ULL, -8, 8};
    types.emplace(first, integer32());
    types.emplace(high, floating32());
    types.emplace(wide, integer64());
    assert(types.size() == 3);
    assert(find_memory_type(types, first) == integer32());
    assert(find_memory_type(types, high) == floating32());
    assert(find_memory_type(types, wide) == integer64());
    assert(!find_memory_type(types, {first.base, first.offset, 2}));
    assert(!find_memory_type(types, {first.base, first.offset + 1, 4}));
    assert(!find_unambiguous_memory_type(types, first.base, first.offset));
    assert(find_unambiguous_memory_type(types, high.base, high.offset) == floating32());
    // These collided in the prior result map's base XOR (offset << 1) key.
    types.emplace(MemoryLocationKey{0x1000, 0, 4}, integer32());
    types.emplace(MemoryLocationKey{0x1008, 4, 4}, floating32());
    assert(find_memory_type(types, {0x1000, 0, 4}) == integer32());
    assert(find_memory_type(types, {0x1008, 4, 4}) == floating32());
}

void check_absolute_address_bounds() {
    constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
    assert(valid_memory_location({0x1000, -4, 4}, 8));
    assert(valid_memory_location({0x8000000000000020ULL,
        std::numeric_limits<std::int64_t>::min(), 4}, 8));
    assert(valid_memory_location({maximum - 1, 0, 1}, 8));
    assert(!valid_memory_location({maximum - 1, 0, 2}, 8));
    assert(!valid_memory_location({maximum, 0, 1}, 8));
    assert(!valid_memory_location({0, -1, 1}, 8));
    assert(!valid_memory_location({0x1000, 0, 0}, 8));
    assert(!valid_memory_location({0x1000, 0, 4}, 16));
    assert(valid_memory_location({0xffffffffULL, 0, 1}, 4));
    assert(!valid_memory_location({0xffffffffULL, 0, 2}, 4));
    assert(!valid_memory_location({0x100000000ULL, -1, 1}, 4));
}

void check_production_memory_variables_with_overlapping_widths() {
    Z3Context context;
    InstructionSemanticsExtractor extractor(context);
    const auto small = extractor.get_mem_type(0x100001234ULL, -8, 4);
    const auto wide = extractor.get_mem_type(0x100001234ULL, -8, 8);
    const auto high = extractor.get_mem_type(0x200001234ULL, -8, 4);
    TypeConstraintSet constraints(context);
    constraints.add(TypeConstraint::make_one_of(small, {integer32()}));
    constraints.add(TypeConstraint::make_one_of(wide, {integer64()}));
    constraints.add(TypeConstraint::make_one_of(high, {floating32()}));
    const auto result = solve(context, constraints);
    assert(result.types.size() == 3 && result.diagnostics.empty());
    assert(result.provenance.size() == result.types.size());
    for (const auto& [key, provenance] : result.provenance) {
        assert(provenance.kind == MemoryTypeEvidenceKind::HardConcreteConstraint);
    }
    assert(find_memory_type(result.types, {0x100001234ULL, -8, 4}) == integer32());
    assert(find_memory_type(result.types, {0x100001234ULL, -8, 8}) == integer64());
    assert(find_memory_type(result.types, {0x200001234ULL, -8, 4}) == floating32());
}

void check_no_concrete_type_from_size_or_registration_alone() {
    Z3Context context;
    InstructionSemanticsExtractor extractor(context);
    (void)extractor.get_mem_type(0x1000, 0, 4);
    TypeConstraintSet empty(context);
    assert(solve(context, empty).types.empty());
    const auto memory = extractor.get_mem_type(0x2000, 0, 4);
    TypeConstraintSet sizes(context);
    sizes.add(TypeConstraint::make_has_size(memory, 4));
    const auto result = solve(context, sizes);
    assert(result.types.empty() && result.diagnostics.size() == 1);
    assert(result.diagnostics[0].issue == MemoryInferenceIssue::InsufficientConcreteEvidence);
}

void check_conflicting_views_never_choose_a_last_writer() {
    Z3Context context;
    const auto memory = TypeVariable::for_memory(1, 0x1000, 0, 4);
    for (bool reverse : {false, true}) {
        TypeConstraintSet constraints(context);
        constraints.add(TypeConstraint::make_one_of(memory,
            {reverse ? floating32() : integer32()}).soft(10));
        constraints.add(TypeConstraint::make_one_of(memory,
            {reverse ? integer32() : floating32()}).soft(10));
        // Duplicating a view does not turn it into independent evidence.
        constraints.add(TypeConstraint::make_one_of(memory, {integer32()}).soft(10));
        const auto result = solve(context, constraints);
        assert(result.types.empty() && result.diagnostics.size() == 1);
        assert(result.diagnostics[0].issue == MemoryInferenceIssue::ConflictingConcreteViews);
        assert(result.diagnostics[0].concrete_views.size() == 2);
    }
    TypeConstraintSet separate_variables(context);
    const auto other = TypeVariable::for_memory(2, 0x1000, 0, 4);
    separate_variables.add(TypeConstraint::make_one_of(memory, {integer32()}));
    separate_variables.add(TypeConstraint::make_one_of(other, {floating32()}));
    assert(solve(context, separate_variables).types.empty());
}

void check_rejected_model_values_and_locations() {
    Z3Context context;
    const auto memory = TypeVariable::for_memory(1, 0x1000, 0, 4);
    TypeConstraintSet incompatible(context);
    incompatible.add(TypeConstraint::make_is_integer(memory));
    incompatible.add(TypeConstraint::make_one_of(memory, {floating32()}).soft(10));
    const auto mismatch = solve(context, incompatible);
    assert(mismatch.types.empty());
    assert(mismatch.diagnostics[0].issue == MemoryInferenceIssue::UnsupportedModelValue);

    TypeConstraintSet wrong_width(context);
    wrong_width.add(TypeConstraint::make_one_of(memory, {integer64()}));
    assert(solve(context, wrong_width).types.empty());

    TypeConstraintSet invalid(context);
    const auto invalid_memory = TypeVariable::for_memory(2, BADADDR, 0, 4);
    invalid.add(TypeConstraint::make_one_of(invalid_memory, {integer32()}));
    const auto bad = solve(context, invalid);
    assert(bad.types.empty() && bad.diagnostics.size() == 1);
    assert(bad.diagnostics[0].issue == MemoryInferenceIssue::InvalidLocation);

    auto changed_location = memory;
    changed_location.mem_offset = 4;
    TypeConstraintSet inconsistent(context);
    inconsistent.add(TypeConstraint::make_one_of(memory, {integer32()}));
    inconsistent.add(TypeConstraint::make_one_of(changed_location, {integer32()}));
    const auto changed = solve(context, inconsistent);
    assert(changed.types.empty() && changed.diagnostics.size() == 2);
    for (const auto& diagnostic : changed.diagnostics) {
        assert(diagnostic.issue == MemoryInferenceIssue::InconsistentVariableLocation);
    }
}

void check_duplicate_concrete_provenance() {
    Z3Context context;
    const auto memory = TypeVariable::for_memory(1, 0x1000, 0, 4);
    TypeConstraintSet constraints(context);
    auto first = TypeConstraint::make_one_of(memory, {integer32()}).soft(10);
    first.source_ea = 0x2000;
    auto second = first;
    second.source_ea = 0x3000;
    constraints.add(first);
    constraints.add(first);
    constraints.add(second);
    const auto result = solve(context, constraints);
    assert(result.types.size() == 1 && result.diagnostics.empty());
    const auto& evidence = result.provenance.at({0x1000, 0, 4});
    assert(evidence.kind == MemoryTypeEvidenceKind::SoftConcretePreference);
    assert((evidence.source_sites == std::vector<ea_t>{0x2000, 0x3000}));
}

struct AssignmentCarrier {
    cfunc_t function;
    cblock_t block;
    cexpr_t local;
    AssignmentCarrier(cexpr_t* value) {
        function.entry_ea = 0x100004000ULL;
        function.body.op = cit_block;
        function.body.cblock = &block;
        block.resize(1);
        block[0].op = cit_expr;
        block[0].cexpr.op = cot_asg;
        block[0].cexpr.x = &local;
        block[0].cexpr.y = value;
        local.op = cot_var;
        local.v.idx = 0;
    }
};

cexpr_t global_object(ea_t address, std::uint32_t kind) {
    cexpr_t expression;
    expression.op = cot_obj;
    expression.obj_ea = address;
    expression.type.create_simple_type(kind);
    return expression;
}

void check_actual_global_load_and_address_only_control() {
    Z3Context context;
    InstructionSemanticsExtractor extractor(context);
    auto object = global_object(0x200001000ULL, BTF_UINT32);
    AssignmentCarrier load(&object);
    const auto constraints = extractor.extract(&load.function);
    const auto result = solve(context, constraints);
    assert(result.types.size() == 1 && result.diagnostics.empty());
    assert(result.provenance.at({object.obj_ea, 0, 4}).kind ==
           MemoryTypeEvidenceKind::SoftConcretePreference);
    assert(find_memory_type(result.types, {object.obj_ea, 0, 4}) == integer32());
    unsigned concrete_views = 0;
    for (const auto& constraint : constraints.constraints()) {
        concrete_views += constraint.var1.is_memory() &&
                          constraint.kind == TypeConstraint::Kind::OneOf;
    }
    assert(concrete_views == 1);

    cexpr_t reference;
    reference.op = cot_ref;
    reference.x = &object;
    reference.type.create_ptr(object.type);
    AssignmentCarrier address_only(&reference);
    const auto reference_constraints = extractor.extract(&address_only.function);
    assert(solve(context, reference_constraints).types.empty());
    assert(extractor.stats().unresolved_memory_accesses == 0);
}

void check_bare_global_and_addressed_dereference() {
    Z3Context context;
    InstructionSemanticsExtractor extractor(context);
    auto object = global_object(0x200001000ULL, BTF_FLOAT);
    AssignmentCarrier bare(&object);
    bare.block[0].cexpr = object;
    const auto result = solve(context, extractor.extract(&bare.function));
    assert(find_memory_type(result.types, {object.obj_ea, 0, 4}) == floating32());

    auto partial = global_object(0x200001000ULL, BT_UNK_QWORD);
    bare.block[0].cexpr = partial;
    const auto unknown = solve(context, extractor.extract(&bare.function));
    assert(unknown.types.empty() && unknown.diagnostics.size() == 1);
    assert(unknown.diagnostics[0].issue == MemoryInferenceIssue::InsufficientConcreteEvidence);

    cexpr_t reference, dereference, address;
    reference.op = cot_ref;
    reference.x = &object;
    reference.type.create_ptr(object.type);
    dereference.op = cot_ptr;
    dereference.x = &reference;
    dereference.type = object.type;
    address.op = cot_ref;
    address.x = &dereference;
    address.type = reference.type;
    bare.block[0].cexpr = address;
    const auto address_only = solve(context, extractor.extract(&bare.function));
    assert(address_only.types.empty() && address_only.diagnostics.empty());
}

void check_constant_global_index_and_dynamic_control() {
    Z3Context context;
    InstructionSemanticsExtractor extractor(context);
    auto object = global_object(0x200001000ULL, BTF_UINT32);
    tinfo_t element = object.type;
    object.type.create_array(element, 4);
    cexpr_t index, access;
    index.op = cot_num;
    index.type.create_simple_type(BTF_INT32);
    index.set_numval(-1);
    access.op = cot_idx;
    access.x = &object;
    access.y = &index;
    access.type = element;
    AssignmentCarrier carrier(&access);
    const auto result = solve(context, extractor.extract(&carrier.function));
    assert(find_memory_type(result.types, {object.obj_ea, -4, 4}) == integer32());
    index.op = cot_var;
    index.v.idx = 1;
    assert(solve(context, extractor.extract(&carrier.function)).types.empty());
    assert(extractor.stats().unresolved_memory_accesses == 1);
}

void check_local_pointer_and_partial_global_remain_unresolved() {
    Z3Context context;
    InstructionSemanticsExtractor extractor(context);
    cexpr_t pointer, access;
    pointer.op = cot_var;
    pointer.v.idx = 1;
    tinfo_t integer;
    integer.create_simple_type(BTF_UINT32);
    pointer.type.create_ptr(integer);
    access.op = cot_ptr;
    access.x = &pointer;
    access.type = integer;
    AssignmentCarrier carrier(&access);
    assert(solve(context, extractor.extract(&carrier.function)).types.empty());
    assert(extractor.stats().unresolved_memory_accesses == 1);

    auto partial = global_object(0x200001000ULL, BT_UNK_QWORD);
    AssignmentCarrier partial_carrier(&partial);
    const auto result = solve(context, extractor.extract(&partial_carrier.function));
    assert(result.types.empty() && result.diagnostics.size() == 1);
    assert(result.diagnostics[0].issue == MemoryInferenceIssue::InsufficientConcreteEvidence);
}

void check_displaced_absolute_pointer_and_narrowing_control() {
    Z3Context context;
    InstructionSemanticsExtractor extractor(context);
    auto object = global_object(0x200001000ULL, BTF_UINT32);
    tinfo_t byte;
    byte.create_simple_type(BTF_UINT8);
    cexpr_t reference, cast, displacement, addition, load;
    reference.op = cot_ref;
    reference.x = &object;
    reference.type.create_ptr(object.type);
    cast.op = cot_cast;
    cast.x = &reference;
    cast.type.create_ptr(byte);
    displacement.op = cot_num;
    displacement.type.create_simple_type(BTF_INT32);
    displacement.set_numval(-4);
    addition.op = cot_add;
    addition.x = &cast;
    addition.y = &displacement;
    addition.type = cast.type;
    load.op = cot_ptr;
    load.x = &addition;
    load.type = byte;
    AssignmentCarrier carrier(&load);
    const auto result = solve(context, extractor.extract(&carrier.function));
    assert(find_memory_type(result.types, {object.obj_ea, -4, 1}) ==
           InferredType::make_base(BaseType::UInt8));

    cast.type.create_simple_type(BTF_UINT32);
    addition.type.create_simple_type(BTF_UINT64);
    const auto constraints = extractor.extract(&carrier.function);
    assert(std::none_of(constraints.variables().begin(), constraints.variables().end(),
        [](const TypeVariable& variable) { return variable.is_memory(); }));
    assert(extractor.stats().unresolved_memory_accesses == 1);
}
} // namespace

int main() {
    check_exact_keys_and_forced_collisions();
    check_absolute_address_bounds();
    check_production_memory_variables_with_overlapping_widths();
    check_no_concrete_type_from_size_or_registration_alone();
    check_conflicting_views_never_choose_a_last_writer();
    check_rejected_model_values_and_locations();
    check_duplicate_concrete_provenance();
    check_actual_global_load_and_address_only_control();
    check_bare_global_and_addressed_dereference();
    check_constant_global_index_and_dynamic_control();
    check_local_pointer_and_partial_global_remain_unresolved();
    check_displaced_absolute_pointer_and_narrowing_control();
    std::cout << "memory identity, concrete evidence, and production extraction checks passed\n";
}
