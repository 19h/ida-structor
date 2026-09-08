#include "structor/z3/instruction_semantics.hpp"
#include <algorithm>
#include <cassert>
#include <iostream>
#include <limits>

using namespace structor::z3;

namespace {
tinfo_t scalar(std::uint32_t value) {
    tinfo_t result;
    result.create_simple_type(value);
    return result;
}
void expect_rejected(const tinfo_t& source, TypeConversionIssue expected) {
    TypeConversionIssue actual = TypeConversionIssue::None;
    assert(InferredType::from_tinfo(source, &actual).is_unknown());
    assert(actual == expected);
}
void check_scalars_do_not_guess_from_width() {
    expect_rejected(scalar(BT_UNK_QWORD), TypeConversionIssue::PartialStorage);
    expect_rejected(scalar(BTF_ENUM_MOCK), TypeConversionIssue::Enumeration);
    expect_rejected(scalar(BTF_EXTFLOAT_MOCK), TypeConversionIssue::UnsupportedFloatingWidth);
    expect_rejected(scalar(BTF_BOOL4_MOCK), TypeConversionIssue::UnsupportedBooleanWidth);
    expect_rejected(scalar(BTF_BITFIELD_MOCK), TypeConversionIssue::Bitfield);
    assert(InferredType::from_tinfo(scalar(BTF_BOOL)) == InferredType::make_base(BaseType::Bool));
    for (const auto [source, expected] : {
            std::pair{BTF_INT32, BaseType::Int32}, std::pair{BTF_UINT64, BaseType::UInt64},
            std::pair{BTF_FLOAT, BaseType::Float32}, std::pair{BTF_DOUBLE, BaseType::Float64},
            std::pair{BTF_VOID, BaseType::Void}}) {
        TypeConversionIssue issue = TypeConversionIssue::DepthLimit;
        assert(InferredType::from_tinfo(scalar(source), &issue) == InferredType::make_base(expected));
        assert(issue == TypeConversionIssue::None);
    }
}
void check_unknown_children_never_become_exact_compounds() {
    tinfo_t pointer;
    pointer.create_ptr(scalar(BT_UNK_QWORD));
    expect_rejected(pointer, TypeConversionIssue::PartialStorage);
    tinfo_t array;
    array.create_array(pointer, 3);
    expect_rejected(array, TypeConversionIssue::PartialStorage);
    func_type_data_t details;
    details.rettype = scalar(BTF_INT32);
    funcarg_t parameter;
    parameter.type = array;
    details.push_back(parameter);
    tinfo_t function;
    function.create_func(details);
    expect_rejected(function, TypeConversionIssue::PartialStorage);
    pointer.create_ptr(function);
    expect_rejected(pointer, TypeConversionIssue::PartialStorage);
}
void check_fully_represented_compounds_remain_exact() {
    tinfo_t array;
    array.create_array(scalar(BTF_INT32), 3);
    const auto expected_array = InferredType::make_array(InferredType::make_base(BaseType::Int32), 3);
    assert(InferredType::from_tinfo(array) == expected_array);
    tinfo_t pointer;
    pointer.create_ptr(array);
    assert(InferredType::from_tinfo(pointer) == InferredType::make_ptr(expected_array));
    func_type_data_t details;
    details.rettype = scalar(BTF_DOUBLE);
    funcarg_t parameter;
    parameter.type = pointer;
    details.push_back(parameter);
    tinfo_t function;
    function.create_func(details);
    const auto expected_function = InferredType::make_func(InferredType::make_base(BaseType::Float64),
        {InferredType::make_ptr(expected_array)});
    assert(InferredType::from_tinfo(function) == expected_function);
    pointer.create_ptr(function);
    assert(InferredType::from_tinfo(pointer) == InferredType::make_ptr(expected_function));
}
void check_array_bounds_and_depth_are_explicit() {
    tinfo_t source;
    source.create_array(scalar(BTF_UINT8), 0);
    expect_rejected(source, TypeConversionIssue::UnsupportedArrayBounds);
    source.create_array(scalar(BTF_UINT8), std::numeric_limits<std::uint32_t>::max());
    const auto maximum = InferredType::from_tinfo(source);
    assert(maximum.is_array() && maximum.array_count() == std::numeric_limits<std::uint32_t>::max());
    // The portable shim has a wide count; the tested SDK already uses uint32.
    source.create_array(scalar(BTF_UINT8), std::uint64_t{1} << 32);
    expect_rejected(source, TypeConversionIssue::UnsupportedArrayBounds);
    array_type_data_t shifted;
    shifted.elem_type = scalar(BTF_INT32);
    shifted.nelems = 3;
    shifted.base = 1;
    source.create_array(shifted);
    expect_rejected(source, TypeConversionIssue::UnsupportedArrayBounds);
    source = scalar(BTF_INT32);
    for (unsigned depth = 0; depth < 64; ++depth) source.create_ptr(source);
    expect_rejected(source, TypeConversionIssue::DepthLimit);
}
qvector<TypeConstraint> dereference(InstructionSemanticsExtractor& extractor,
                                    cfunc_t& function, const tinfo_t& source) {
    cexpr_t local;
    local.op = cot_var;
    local.v.idx = 0;
    local.type.create_ptr(source);
    cexpr_t load;
    load.op = cot_ptr;
    load.x = &local;
    load.type = source;
    load.ea = 0x1010;
    return extractor.extract_expr(&load, &function);
}
void check_partial_dereference_keeps_use_and_width_without_scalar_claim() {
    Z3Context context;
    InstructionSemanticsExtractor extractor(context);
    cfunc_t function;
    function.entry_ea = 0x1000;
    const auto constraints = dereference(extractor, function, scalar(BT_UNK_QWORD));
    assert(std::count_if(constraints.begin(), constraints.end(), [](const auto& c) {
        return c.kind == TypeConstraint::Kind::IsPointer && !c.is_soft;
    }) == 1);
    assert(std::none_of(constraints.begin(), constraints.end(), [](const auto& c) {
        return c.kind == TypeConstraint::Kind::IsPointerTo || c.kind == TypeConstraint::Kind::OneOf;
    }));
    assert(std::count_if(constraints.begin(), constraints.end(), [](const auto& c) {
        return c.kind == TypeConstraint::Kind::HasSize && c.size == 8;
    }) == 1);
    const auto& observations = extractor.unsupported_type_observations();
    assert(observations.size() == 1);
    assert(observations[0].issue == TypeConversionIssue::PartialStorage);
    assert(observations[0].source_ea == 0x1010 && observations[0].byte_width == 8);
    assert(!observations[0].original_type_spelling.empty());
    // Both signed and unsigned same-width pointer views remain satisfiable.
    for (const auto base : {BaseType::Int64, BaseType::UInt64}) {
        TypeConstraintSet set(context);
        for (const auto& constraint : constraints) set.add(constraint);
        set.add(TypeConstraint::make_is_pointer_to(extractor.get_var_type(&function, 0),
            InferredType::make_base(base)));
        TypeLatticeEncoder encoder(context);
        ::z3::solver solver(context.ctx());
        solver.add(set.to_z3_hard(encoder));
        assert(solver.check() == ::z3::sat);
    }
}
void check_exact_dereference_preserves_type_and_clears_prior_diagnostics() {
    Z3Context context;
    InstructionSemanticsExtractor extractor(context);
    cfunc_t function;
    function.entry_ea = 0x1000;
    (void)dereference(extractor, function, scalar(BT_UNK_QWORD));
    const auto constraints = dereference(extractor, function, scalar(BTF_INT32));
    assert(extractor.unsupported_type_observations().empty());
    assert(std::count_if(constraints.begin(), constraints.end(), [](const auto& c) {
        return c.kind == TypeConstraint::Kind::IsPointerTo && !c.is_soft &&
            c.concrete_type == InferredType::make_ptr(InferredType::make_base(BaseType::Int32));
    }) == 1);
    TypeConstraintSet set(context);
    for (const auto& constraint : constraints) set.add(constraint);
    set.add(TypeConstraint::make_is_pointer_to(extractor.get_var_type(&function, 0),
        InferredType::make_base(BaseType::Float32)));
    TypeLatticeEncoder encoder(context);
    ::z3::solver solver(context.ctx());
    solver.add(set.to_z3_hard(encoder));
    assert(solver.check() == ::z3::unsat);
}
void check_address_and_loaded_or_cast_pointer_shape_are_distinct() {
    Z3Context context;
    InstructionSemanticsExtractor extractor(context);
    cfunc_t function;
    function.entry_ea = 0x1000;
    tinfo_t partial_pointer;
    partial_pointer.create_ptr(scalar(BT_UNK_QWORD));
    const auto constraints = dereference(extractor, function, partial_pointer);
    const auto address = extractor.get_var_type(&function, 0);
    std::vector<TypeVariableIdentity> pointers;
    for (const auto& constraint : constraints) {
        if (constraint.kind == TypeConstraint::Kind::IsPointer)
            pointers.push_back(constraint.var1.identity);
        assert(constraint.kind != TypeConstraint::Kind::IsPointerTo);
    }
    assert(pointers.size() == 2 && pointers[0] != pointers[1]);
    assert(std::find(pointers.begin(), pointers.end(), address.identity) != pointers.end());
    const auto integer_load = dereference(extractor, function, scalar(BTF_INT32));
    assert(std::count_if(integer_load.begin(), integer_load.end(), [](const auto& c) {
        return c.kind == TypeConstraint::Kind::IsPointer;
    }) == 1);
    cexpr_t local;
    local.op = cot_var;
    local.v.idx = 0;
    local.type = scalar(BTF_UINT64);
    cexpr_t cast;
    cast.op = cot_cast;
    cast.x = &local;
    cast.type = partial_pointer;
    cast.ea = 0x1050;
    const auto cast_constraints = extractor.extract_expr(&cast, &function);
    std::size_t cast_pointers = 0;
    for (const auto& constraint : cast_constraints) {
        assert(constraint.kind != TypeConstraint::Kind::OneOf);
        if (constraint.kind == TypeConstraint::Kind::IsPointer) {
            ++cast_pointers;
            assert(constraint.var1.identity != address.identity);
        }
    }
    assert(cast_pointers == 1);
    cast.type = scalar(BTF_INT32);
    const auto integer_cast = extractor.extract_expr(&cast, &function);
    assert(std::none_of(integer_cast.begin(), integer_cast.end(), [](const auto& c) {
        return c.kind == TypeConstraint::Kind::IsPointer;
    }));
}

void check_detached_source_metadata_survives_extractor_and_type_lifetime() {
    std::vector<TypeConversionObservation> saved;
    {
        Z3Context context;
        InstructionSemanticsExtractor extractor(context);
        auto enumeration = scalar(BTF_ENUM_MOCK);
        assert(!extractor.observe_type(enumeration, 0x1234));
        saved = extractor.unsupported_type_observations();
        enumeration.clear();
    }
    assert(saved.size() == 1 && saved[0].source_ea == 0x1234);
    assert(saved[0].issue == TypeConversionIssue::Enumeration && saved[0].byte_width == 4);
    assert(!saved[0].original_type_spelling.empty());
}
} // namespace
int main() {
    check_scalars_do_not_guess_from_width();
    check_unknown_children_never_become_exact_compounds();
    check_fully_represented_compounds_remain_exact();
    check_array_bounds_and_depth_are_explicit();
    check_partial_dereference_keeps_use_and_width_without_scalar_claim();
    check_exact_dereference_preserves_type_and_clears_prior_diagnostics();
    check_address_and_loaded_or_cast_pointer_shape_are_distinct();
    check_detached_source_metadata_survives_extractor_and_type_lifetime();
    std::cout << "8 represented-type conversion groups passed\n";
}
