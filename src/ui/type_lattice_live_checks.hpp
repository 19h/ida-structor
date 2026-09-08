#pragma once

#if defined(STRUCTOR_LIVE_TEST_HOOKS)

#include <structor/z3/type_lattice.hpp>
#include <limits>
#include <utility>
#include <vector>

namespace structor::detail {

// These checks use IDA's actual anonymous UDT construction and member types.
// No named type, local variable, or function prototype is changed.
inline std::vector<std::pair<const char*, bool>> run_live_type_lattice_checks() {
    using z3::BaseType;
    using z3::InferredType;
    const auto i32 = InferredType::make_base(BaseType::Int32);
    const auto f32 = InferredType::make_base(BaseType::Float32);
    const auto u16 = InferredType::make_base(BaseType::UInt16);
    const auto u8 = InferredType::make_base(BaseType::UInt8);
    std::vector<std::pair<const char*, bool>> checks;
    const auto check_union = [&](const char* name, const std::vector<InferredType>& views,
                                 asize_t expected_bytes) {
        const auto type = InferredType::make_sum(views).to_tinfo();
        udt_type_data_t members;
        bool valid = type.is_union() && type.get_size() == expected_bytes &&
            type.get_udt_details(&members) && members.size() == views.size();
        for (size_t i = 0; valid && i < views.size(); ++i) {
            const auto expected = views[i].to_tinfo();
            valid = members[i].offset == 0 && members[i].size == expected.get_size() * 8 &&
                members[i].type.equals_to(expected);
        }
        checks.emplace_back(name, valid);
    };
    check_union("integer_and_float_views", {i32, f32}, 4);
    check_union("packed_three_byte_extent", {InferredType::make_array(u8, 3), u16}, 3);
    check_union("distinct_pointer_views",
        {InferredType::make_ptr(i32), InferredType::make_ptr(f32)}, get_ptr_size());
    check_union("nested_union_views", {InferredType::make_sum({i32, f32}), u8}, 4);
    const auto function = InferredType::make_func(i32, {f32});
    check_union("function_pointer_view", {InferredType::make_ptr(function), u8}, get_ptr_size());
    checks.emplace_back("unknown_alternative_has_no_materialization",
        InferredType::make_sum({i32, InferredType::unknown()}).to_tinfo().empty());
    checks.emplace_back("bottom_alternative_has_no_materialization",
        InferredType::make_sum({i32, InferredType::bottom()}).to_tinfo().empty());
    checks.emplace_back("void_alternative_has_no_materialization",
        InferredType::make_sum({i32, InferredType::make_base(BaseType::Void)}).to_tinfo().empty());
    checks.emplace_back("bare_function_has_no_union_materialization",
        InferredType::make_sum({i32, function}).to_tinfo().empty());
    checks.emplace_back("empty_sum_has_no_materialization",
        InferredType::make_sum({}).to_tinfo().empty());
    const auto f64 = InferredType::make_base(BaseType::Float64);
    checks.emplace_back("array_size_boundary_bytes",
        InferredType::make_array(f64, 536870911).size(get_ptr_size()) == UINT32_C(4294967288) &&
        InferredType::make_array(f64, 536870912).size(get_ptr_size()) == 0 &&
        InferredType::make_array(f64, std::numeric_limits<uint32_t>::max()).size(get_ptr_size()) == 0);
    checks.emplace_back("unknown_union_extent_is_unknown",
        InferredType::make_sum({i32, InferredType::unknown()}).size(get_ptr_size()) == 0);
    return checks;
}

} // namespace structor::detail

#endif
