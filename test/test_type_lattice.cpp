/// @file test_type_lattice.cpp
/// @brief Unit tests for the type lattice system

#include <iostream>
#include <cassert>

// Include mock IDA types first (defines STRUCTOR_TESTING)
#include "mock_ida.hpp"

// Now include structor headers which will use mocked types
#include "structor/z3/type_lattice.hpp"
#include "structor/z3/context.hpp"

using namespace structor::z3;

// ============================================================================
// Test utilities
// ============================================================================

#define TEST(name) static void test_##name()
#define RUN_TEST(name) do { \
    std::cout << "Running " #name "..." << std::flush; \
    test_##name(); \
    std::cout << " PASSED" << std::endl; \
} while(0)

#define ASSERT_TRUE(cond) do { \
    if (!(cond)) { \
        std::cerr << "\nAssertion failed: " #cond << " at " << __FILE__ << ":" << __LINE__ << std::endl; \
        std::abort(); \
    } \
} while(0)

#define ASSERT_FALSE(cond) ASSERT_TRUE(!(cond))
#define ASSERT_EQ(a, b) ASSERT_TRUE((a) == (b))
#define ASSERT_NE(a, b) ASSERT_TRUE((a) != (b))

// ============================================================================
// BaseType tests
// ============================================================================

TEST(base_type_names) {
    ASSERT_EQ(std::string(base_type_name(BaseType::Unknown)), "unknown");
    ASSERT_EQ(std::string(base_type_name(BaseType::Int32)), "int32");
    ASSERT_EQ(std::string(base_type_name(BaseType::UInt64)), "uint64");
    ASSERT_EQ(std::string(base_type_name(BaseType::Float32)), "float32");
    ASSERT_EQ(std::string(base_type_name(BaseType::Void)), "void");
}

TEST(base_type_sizes) {
    ASSERT_EQ(base_type_size(BaseType::Int8, 8), 1u);
    ASSERT_EQ(base_type_size(BaseType::Int16, 8), 2u);
    ASSERT_EQ(base_type_size(BaseType::Int32, 8), 4u);
    ASSERT_EQ(base_type_size(BaseType::Int64, 8), 8u);
    ASSERT_EQ(base_type_size(BaseType::Float32, 8), 4u);
    ASSERT_EQ(base_type_size(BaseType::Float64, 8), 8u);
    ASSERT_EQ(base_type_size(BaseType::Bool, 8), 1u);
}

TEST(base_type_classification) {
    ASSERT_TRUE(is_signed_int(BaseType::Int8));
    ASSERT_TRUE(is_signed_int(BaseType::Int32));
    ASSERT_FALSE(is_signed_int(BaseType::UInt32));
    
    ASSERT_TRUE(is_unsigned_int(BaseType::UInt8));
    ASSERT_TRUE(is_unsigned_int(BaseType::UInt64));
    ASSERT_FALSE(is_unsigned_int(BaseType::Int64));
    
    ASSERT_TRUE(is_integer(BaseType::Int32));
    ASSERT_TRUE(is_integer(BaseType::UInt32));
    ASSERT_FALSE(is_integer(BaseType::Float32));
    
    ASSERT_TRUE(is_floating(BaseType::Float32));
    ASSERT_TRUE(is_floating(BaseType::Float64));
    ASSERT_FALSE(is_floating(BaseType::Int32));
}

TEST(base_type_from_size) {
    ASSERT_EQ(base_type_from_size(1, true), BaseType::Int8);
    ASSERT_EQ(base_type_from_size(2, true), BaseType::Int16);
    ASSERT_EQ(base_type_from_size(4, true), BaseType::Int32);
    ASSERT_EQ(base_type_from_size(8, true), BaseType::Int64);
    
    ASSERT_EQ(base_type_from_size(1, false), BaseType::UInt8);
    ASSERT_EQ(base_type_from_size(4, false), BaseType::UInt32);
    ASSERT_EQ(base_type_from_size(8, false), BaseType::UInt64);
    
    ASSERT_EQ(base_type_from_size(3, true), BaseType::Unknown);
}

// ============================================================================
// InferredType tests
// ============================================================================

TEST(inferred_type_base) {
    auto int32 = InferredType::make_base(BaseType::Int32);
    ASSERT_TRUE(int32.is_base());
    ASSERT_FALSE(int32.is_pointer());
    ASSERT_EQ(int32.base_type(), BaseType::Int32);
    ASSERT_EQ(int32.size(8), 4u);
}

TEST(inferred_type_unknown) {
    auto unknown = InferredType::unknown();
    ASSERT_TRUE(unknown.is_unknown());
    ASSERT_TRUE(unknown.is_base());
    ASSERT_EQ(unknown.base_type(), BaseType::Unknown);
}

TEST(inferred_type_bottom) {
    auto bottom = InferredType::bottom();
    ASSERT_TRUE(bottom.is_bottom());
    ASSERT_TRUE(bottom.is_base());
    ASSERT_EQ(bottom.base_type(), BaseType::Bottom);
}

TEST(inferred_type_pointer) {
    auto int32 = InferredType::make_base(BaseType::Int32);
    auto ptr = InferredType::make_ptr(int32);
    
    ASSERT_TRUE(ptr.is_pointer());
    ASSERT_FALSE(ptr.is_base());
    ASSERT_EQ(ptr.size(8), 8u);  // Pointer size
    
    const auto* pointee = ptr.pointee();
    ASSERT_TRUE(pointee != nullptr);
    ASSERT_EQ(pointee->base_type(), BaseType::Int32);
}

TEST(inferred_type_double_pointer) {
    auto int32 = InferredType::make_base(BaseType::Int32);
    auto ptr = InferredType::make_ptr(int32);
    auto ptr_ptr = InferredType::make_ptr(ptr);
    
    ASSERT_TRUE(ptr_ptr.is_pointer());
    const auto* first_level = ptr_ptr.pointee();
    ASSERT_TRUE(first_level != nullptr);
    ASSERT_TRUE(first_level->is_pointer());
    
    const auto* second_level = first_level->pointee();
    ASSERT_TRUE(second_level != nullptr);
    ASSERT_TRUE(second_level->is_base());
    ASSERT_EQ(second_level->base_type(), BaseType::Int32);
}

TEST(inferred_type_function) {
    auto ret = InferredType::make_base(BaseType::Int32);
    std::vector<InferredType> params = {
        InferredType::make_ptr(InferredType::make_base(BaseType::Void)),
        InferredType::make_base(BaseType::UInt64)
    };
    
    auto func = InferredType::make_func(ret, params);
    
    ASSERT_TRUE(func.is_function());
    ASSERT_FALSE(func.is_base());
    
    const auto* ret_type = func.return_type();
    ASSERT_TRUE(ret_type != nullptr);
    ASSERT_EQ(ret_type->base_type(), BaseType::Int32);
    
    ASSERT_EQ(func.param_types().size(), 2u);
}

TEST(inferred_type_array) {
    auto elem = InferredType::make_base(BaseType::Int32);
    auto arr = InferredType::make_array(elem, 10);
    
    ASSERT_TRUE(arr.is_array());
    ASSERT_EQ(arr.array_count(), 10u);
    ASSERT_EQ(arr.size(8), 40u);  // 10 * 4 bytes
    
    const auto* elem_type = arr.element_type();
    ASSERT_TRUE(elem_type != nullptr);
    ASSERT_EQ(elem_type->base_type(), BaseType::Int32);
}

TEST(inferred_type_struct) {
    auto s = InferredType::make_struct(0x12345);
    ASSERT_TRUE(s.is_struct());
    ASSERT_EQ(s.struct_tid(), 0x12345u);
}

TEST(inferred_type_sum) {
    std::vector<InferredType> alts = {
        InferredType::make_base(BaseType::Int32),
        InferredType::make_base(BaseType::Float32)
    };
    
    auto sum = InferredType::make_sum(alts);
    ASSERT_TRUE(sum.is_sum());
    ASSERT_EQ(sum.sum_alternatives().size(), 2u);
    ASSERT_EQ(sum.size(8), 4u);  // Max of int32 and float32
}

TEST(inferred_type_equality) {
    auto int32_a = InferredType::make_base(BaseType::Int32);
    auto int32_b = InferredType::make_base(BaseType::Int32);
    auto int64 = InferredType::make_base(BaseType::Int64);
    
    ASSERT_TRUE(int32_a == int32_b);
    ASSERT_FALSE(int32_a == int64);
    
    auto ptr_a = InferredType::make_ptr(int32_a);
    auto ptr_b = InferredType::make_ptr(int32_b);
    auto ptr_c = InferredType::make_ptr(int64);
    
    ASSERT_TRUE(ptr_a == ptr_b);
    ASSERT_FALSE(ptr_a == ptr_c);
}

TEST(inferred_type_to_string) {
    auto int32 = InferredType::make_base(BaseType::Int32);
    ASSERT_FALSE(int32.to_string().empty());
    
    auto ptr = InferredType::make_ptr(int32);
    qstring ptr_str = ptr.to_string();
    ASSERT_FALSE(ptr_str.empty());
    
    auto unknown = InferredType::unknown();
    ASSERT_FALSE(unknown.to_string().empty());
}

TEST(inferred_type_hash) {
    auto int32_a = InferredType::make_base(BaseType::Int32);
    auto int32_b = InferredType::make_base(BaseType::Int32);
    auto int64 = InferredType::make_base(BaseType::Int64);
    
    // Equal types should have equal hashes
    ASSERT_EQ(int32_a.hash(), int32_b.hash());
    
    // Different types should (likely) have different hashes
    ASSERT_NE(int32_a.hash(), int64.hash());
}

// ============================================================================
// TypeLattice tests
// ============================================================================

TEST(type_lattice_subtype_signed_int) {
    TypeLattice lattice(8);
    
    auto int8 = InferredType::make_base(BaseType::Int8);
    auto int16 = InferredType::make_base(BaseType::Int16);
    auto int32 = InferredType::make_base(BaseType::Int32);
    auto int64 = InferredType::make_base(BaseType::Int64);
    
    // Smaller integers are subtypes of larger ones
    ASSERT_TRUE(lattice.is_subtype(int8, int16));
    ASSERT_TRUE(lattice.is_subtype(int8, int32));
    ASSERT_TRUE(lattice.is_subtype(int16, int32));
    ASSERT_TRUE(lattice.is_subtype(int32, int64));
    
    // Not in reverse
    ASSERT_FALSE(lattice.is_subtype(int32, int8));
    ASSERT_FALSE(lattice.is_subtype(int64, int32));
    
    // Equal types are subtypes of each other
    ASSERT_TRUE(lattice.is_subtype(int32, int32));
}

TEST(type_lattice_subtype_unsigned_int) {
    TypeLattice lattice(8);
    
    auto uint8 = InferredType::make_base(BaseType::UInt8);
    auto uint32 = InferredType::make_base(BaseType::UInt32);
    auto uint64 = InferredType::make_base(BaseType::UInt64);
    
    ASSERT_TRUE(lattice.is_subtype(uint8, uint32));
    ASSERT_TRUE(lattice.is_subtype(uint32, uint64));
    ASSERT_FALSE(lattice.is_subtype(uint64, uint8));
}

TEST(type_lattice_subtype_unknown) {
    TypeLattice lattice(8);
    
    auto unknown = InferredType::unknown();
    auto int32 = InferredType::make_base(BaseType::Int32);
    auto ptr = InferredType::make_ptr(int32);
    
    // Everything is a subtype of unknown
    ASSERT_TRUE(lattice.is_subtype(int32, unknown));
    ASSERT_TRUE(lattice.is_subtype(ptr, unknown));
    
    // Unknown is not a subtype of anything except itself
    ASSERT_TRUE(lattice.is_subtype(unknown, unknown));
}

TEST(type_lattice_subtype_bottom) {
    TypeLattice lattice(8);
    
    auto bottom = InferredType::bottom();
    auto int32 = InferredType::make_base(BaseType::Int32);
    
    // Bottom is a subtype of everything
    ASSERT_TRUE(lattice.is_subtype(bottom, int32));
    ASSERT_TRUE(lattice.is_subtype(bottom, InferredType::unknown()));
}

TEST(type_lattice_lub) {
    TypeLattice lattice(8);
    
    auto int8 = InferredType::make_base(BaseType::Int8);
    auto int32 = InferredType::make_base(BaseType::Int32);
    auto int64 = InferredType::make_base(BaseType::Int64);
    
    // LUB of signed integers is the larger one
    auto lub_8_32 = lattice.lub(int8, int32);
    ASSERT_TRUE(lub_8_32.is_base());
    ASSERT_EQ(lub_8_32.base_type(), BaseType::Int32);
    
    auto lub_32_64 = lattice.lub(int32, int64);
    ASSERT_EQ(lub_32_64.base_type(), BaseType::Int64);
}

TEST(type_lattice_lub_mixed) {
    TypeLattice lattice(8);
    
    auto int32 = InferredType::make_base(BaseType::Int32);
    auto uint32 = InferredType::make_base(BaseType::UInt32);
    
    // Signed and unsigned observations remain separate interpretations;
    // choosing one signedness is not an upper bound under this subtype order.
    auto joined = lattice.lub(int32, uint32);
    ASSERT_TRUE(joined.is_sum());
    ASSERT_TRUE(lattice.is_subtype(int32, joined));
    ASSERT_TRUE(lattice.is_subtype(uint32, joined));
}

TEST(type_lattice_glb) {
    TypeLattice lattice(8);
    
    auto int8 = InferredType::make_base(BaseType::Int8);
    auto int32 = InferredType::make_base(BaseType::Int32);
    
    // GLB of signed integers is the smaller one
    auto glb = lattice.glb(int8, int32);
    ASSERT_TRUE(glb.is_base());
    ASSERT_EQ(glb.base_type(), BaseType::Int8);
}

TEST(type_lattice_compatible) {
    TypeLattice lattice(8);
    
    auto int8 = InferredType::make_base(BaseType::Int8);
    auto int32 = InferredType::make_base(BaseType::Int32);
    auto float32 = InferredType::make_base(BaseType::Float32);
    
    // Same-signed integers are compatible
    ASSERT_TRUE(lattice.are_compatible(int8, int32));
    
    // Integer and float are not compatible
    ASSERT_FALSE(lattice.are_compatible(int32, float32));
}

TEST(type_lattice_widen) {
    TypeLattice lattice(8);
    
    auto int8 = InferredType::make_base(BaseType::Int8);
    
    // Widen int8 to 4 bytes -> int32
    auto widened = lattice.widen_to_size(int8, 4);
    ASSERT_TRUE(widened.is_base());
    ASSERT_EQ(widened.base_type(), BaseType::Int32);
}

TEST(type_lattice_canonical) {
    TypeLattice lattice(8);
    
    // Canonical type for 4 bytes
    auto canonical4 = lattice.canonical_for_size(4);
    ASSERT_TRUE(canonical4.is_base());
    ASSERT_EQ(canonical4.size(8), 4u);
    
    // Canonical type for 8 bytes (pointer size) returns unknown
    // because it could be either pointer or integer - need more context
    auto canonical8 = lattice.canonical_for_size(8);
    ASSERT_TRUE(canonical8.is_unknown());
    
    // Non-pointer-sized 8-byte values on 4-byte pointer platforms get uint64
    TypeLattice lattice32(4);
    auto canonical8_32 = lattice32.canonical_for_size(8);
    ASSERT_TRUE(canonical8_32.is_base());
    ASSERT_EQ(canonical8_32.base_type(), BaseType::UInt64);
}

// Equal hashes must never substitute a different type at a lattice boundary.
TEST(type_lattice_function_hash_collision) {
    const auto scalar = InferredType::make_base(BaseType::Int32);
    std::vector<InferredType> args(9, scalar);
    const auto first = InferredType::make_func(scalar, args);
    args[8] = InferredType::make_base(BaseType::Float64);
    const auto second = InferredType::make_func(scalar, args);
    ASSERT_NE(first, second);
    // The current bounded hash deliberately samples only the first eight args.
    ASSERT_EQ(first.hash(), second.hash());
    TypeLattice lattice;
    ASSERT_EQ(lattice.lub(first, first), first);
    ASSERT_EQ(lattice.lub(second, second), second);
    ASSERT_EQ(lattice.glb(first, first), first);
    ASSERT_EQ(lattice.glb(second, second), second);
    ASSERT_EQ(lattice.lub(first, first), first);
    ASSERT_EQ(lattice.glb(second, second), second);
}

TEST(type_lattice_cache_mutable_arguments) {
    const auto scalar = InferredType::make_base(BaseType::Int32);
    std::vector<InferredType> args(9, scalar);
    auto first = InferredType::make_func(scalar, args);
    args[8] = InferredType::make_base(BaseType::Int8);
    const auto second = InferredType::make_func(scalar, args);
    TypeLattice cached, uncached;
    ASSERT_EQ(cached.lub(first, second), second);
    ASSERT_EQ(cached.glb(first, second), first);
    const auto original_hash = first.hash();
    *first.param_types()[8] = InferredType::make_base(BaseType::Float64);
    ASSERT_EQ(first.hash(), original_hash);
    // Shared children are mutable through the public API. Neither the cache
    // identity nor its result may silently change with an old caller object.
    ASSERT_EQ(cached.lub(first, second), uncached.lub(first, second));
    ASSERT_EQ(cached.glb(first, second), uncached.glb(first, second));
}

TEST(type_lattice_cache_result_isolation) {
    const auto scalar = InferredType::make_base(BaseType::Int32);
    const auto original = InferredType::make_func(scalar, {scalar});
    TypeLattice lattice;
    (void)lattice.lub(original, original);
    (void)lattice.glb(original, original);
    auto joined = lattice.lub(original, original);
    auto met = lattice.glb(original, original);
    *joined.param_types()[0] = InferredType::make_base(BaseType::Float32);
    *met.param_types()[0] = InferredType::make_base(BaseType::UInt64);
    const auto expected = InferredType::make_func(scalar, {scalar});
    ASSERT_EQ(original, expected);
    ASSERT_EQ(lattice.lub(expected, expected), expected);
    ASSERT_EQ(lattice.glb(expected, expected), expected);
}

TEST(inferred_type_snapshot) {
    auto pointee = std::make_shared<InferredType>(InferredType::make_base(BaseType::Int32));
    const auto pointer = InferredType::make_ptr(pointee);
    const auto compound = InferredType::make_sum({
        InferredType::make_array(pointer, 3),
        InferredType::make_func(pointer, {pointer})});
    const auto snapshot = compound.snapshot();
    ASSERT_EQ(compound, snapshot);
    *pointee = InferredType::make_base(BaseType::Float64);
    ASSERT_NE(compound, snapshot);
    ASSERT_EQ(snapshot.sum_alternatives()[0]->element_type()->pointee()->base_type(),
              BaseType::Int32);
    ASSERT_EQ(snapshot.sum_alternatives()[1]->return_type()->pointee()->base_type(),
              BaseType::Int32);
    ASSERT_EQ(snapshot.sum_alternatives()[1]->param_types()[0]->pointee()->base_type(),
              BaseType::Int32);
}

// ============================================================================
// TypeLatticeEncoder tests
// ============================================================================

TEST(type_encoder_cross_kind_hash_collision) {
    // Full-width structure identities can collide with scalar cache hashes.
    // This value is the inverse of the structure hash's pre-avalanche mix
    // for BaseType::Int32; equality still has to compare the complete type.
    const auto scalar = InferredType::make_base(BaseType::Int32);
    const auto structure = InferredType::make_struct(0xFD000001BA03ULL);
    ASSERT_NE(scalar, structure);
    ASSERT_EQ(scalar.hash(), structure.hash());
    Z3Context ctx;
    TypeLatticeEncoder encoder(ctx);
    const auto encoded_scalar = encoder.encode(scalar);
    const auto encoded_structure = encoder.encode(structure);
    ::z3::solver solver(ctx.ctx());
    solver.add(encoded_scalar == encoded_structure);
    ASSERT_TRUE(solver.check() == ::z3::unsat);
    solver.reset();
    solver.add(encoder.is_integer_type(encoded_structure));
    ASSERT_TRUE(solver.check() == ::z3::unsat);
}

TEST(type_encoder_basic) {
    Z3Context ctx;
    TypeLatticeEncoder encoder(ctx);
    
    // Create type variable
    auto tv = encoder.make_type_var("test_var");
    ASSERT_TRUE(tv.get_sort().is_datatype());
    
    // Encode base types
    auto int32 = InferredType::make_base(BaseType::Int32);
    auto encoded = encoder.encode(int32);
    ASSERT_TRUE(encoded.get_sort().is_datatype());
}

TEST(type_encoder_constraints) {
    Z3Context ctx;
    TypeLatticeEncoder encoder(ctx);
    
    auto tv1 = encoder.make_type_var("var1");
    auto tv2 = encoder.make_type_var("var2");
    
    // Type equality constraint
    auto eq = encoder.type_eq(tv1, tv2);
    ASSERT_TRUE(eq.is_bool());
    
    // Pointer check
    auto is_ptr = encoder.is_pointer_type(tv1);
    ASSERT_TRUE(is_ptr.is_bool());
    
    // Integer check
    auto is_int = encoder.is_integer_type(tv1);
    ASSERT_TRUE(is_int.is_bool());
}

// ============================================================================
// BitvectorTypeEncoder tests
// ============================================================================

TEST(bv_encoder_basic) {
    Z3Context ctx;
    BitvectorTypeEncoder encoder(ctx);
    
    auto tv = encoder.make_type_var("test_var");
    ASSERT_TRUE(tv.is_bv());
    ASSERT_EQ(tv.get_sort().bv_size(), BitvectorTypeEncoder::TYPE_BITS);
}

TEST(bv_encoder_encode_decode) {
    Z3Context ctx;
    BitvectorTypeEncoder encoder(ctx);
    
    auto int32 = InferredType::make_base(BaseType::Int32);
    auto encoded = encoder.encode(int32);
    ASSERT_TRUE(encoded.is_bv());
    
    // Create a model with the encoded value
    ::z3::solver solver(ctx.ctx());
    auto tv = encoder.make_type_var("test");
    solver.add(tv == encoded);
    
    ASSERT_TRUE(solver.check() == ::z3::sat);
    auto model = solver.get_model();
    
    auto decoded = encoder.decode(tv, model);
    ASSERT_TRUE(decoded.is_base());
    ASSERT_EQ(decoded.base_type(), BaseType::Int32);
}

TEST(bv_encoder_constraints) {
    Z3Context ctx;
    BitvectorTypeEncoder encoder(ctx);
    
    auto tv = encoder.make_type_var("test");
    
    // Test constraint generation
    auto is_ptr = encoder.is_pointer(tv);
    ASSERT_TRUE(is_ptr.is_bool());
    
    auto is_int = encoder.is_integer(tv);
    ASSERT_TRUE(is_int.is_bool());
    
    auto is_signed = encoder.is_signed(tv);
    ASSERT_TRUE(is_signed.is_bool());
    
    auto has_size_4 = encoder.has_size(tv, 4);
    ASSERT_TRUE(has_size_4.is_bool());
}

TEST(type_extent_checked) {
    const auto scalar = InferredType::make_base(BaseType::Float64);
    ASSERT_EQ(InferredType::make_array(scalar, 536870911).size(8), 4294967288u);
    ASSERT_EQ(InferredType::make_array(scalar, 536870912).size(8), 0u);
    ASSERT_EQ(InferredType::make_array(scalar, UINT32_MAX).size(8), 0u);
    const auto unknown_extent = InferredType::make_sum({scalar, InferredType::make_struct(12)});
    ASSERT_EQ(unknown_extent.size(8), 0u);
}

TEST(type_sum_materialization) {
    const auto integer = InferredType::make_base(BaseType::Int32);
    const auto floating = InferredType::make_base(BaseType::Float32);
    auto value = InferredType::make_sum({integer, floating}).to_tinfo();
    ASSERT_TRUE(value.is_union());
    udt_type_data_t members;
    ASSERT_TRUE(value.get_udt_details(&members));
    ASSERT_EQ(members.size(), 2u);
    ASSERT_EQ(value.get_size(), 4u);
    ASSERT_EQ(members[0].offset, 0u);
    ASSERT_EQ(members[1].offset, 0u);
    ASSERT_TRUE(members[0].type.equals_to(integer.to_tinfo()));
    ASSERT_TRUE(members[1].type.is_floating());
    const auto bytes = InferredType::make_array(InferredType::make_base(BaseType::UInt8), 3);
    const auto word = InferredType::make_base(BaseType::UInt16);
    auto packed = InferredType::make_sum({bytes, word}).to_tinfo();
    ASSERT_TRUE(packed.is_union());
    ASSERT_EQ(packed.get_size(), 3u);
    ASSERT_TRUE(InferredType::make_sum({integer, InferredType::unknown()}).to_tinfo().empty());
    ASSERT_TRUE(InferredType::make_sum({integer, InferredType::bottom()}).to_tinfo().empty());
    ASSERT_TRUE(InferredType::make_sum({integer, InferredType::make_base(BaseType::Void)}).to_tinfo().empty());
    ASSERT_TRUE(InferredType::make_sum({integer, InferredType::make_func(integer, {})}).to_tinfo().empty());
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "=== Type Lattice Tests ===" << std::endl;
    
    // BaseType tests
    RUN_TEST(base_type_names);
    RUN_TEST(base_type_sizes);
    RUN_TEST(base_type_classification);
    RUN_TEST(base_type_from_size);
    
    // InferredType tests
    RUN_TEST(inferred_type_base);
    RUN_TEST(inferred_type_unknown);
    RUN_TEST(inferred_type_bottom);
    RUN_TEST(inferred_type_pointer);
    RUN_TEST(inferred_type_double_pointer);
    RUN_TEST(inferred_type_function);
    RUN_TEST(inferred_type_array);
    RUN_TEST(inferred_type_struct);
    RUN_TEST(inferred_type_sum);
    RUN_TEST(inferred_type_equality);
    RUN_TEST(inferred_type_to_string);
    RUN_TEST(inferred_type_hash);
    
    // TypeLattice tests
    RUN_TEST(type_lattice_subtype_signed_int);
    RUN_TEST(type_lattice_subtype_unsigned_int);
    RUN_TEST(type_lattice_subtype_unknown);
    RUN_TEST(type_lattice_subtype_bottom);
    RUN_TEST(type_lattice_lub);
    RUN_TEST(type_lattice_lub_mixed);
    RUN_TEST(type_lattice_glb);
    RUN_TEST(type_lattice_compatible);
    RUN_TEST(type_lattice_widen);
    RUN_TEST(type_lattice_canonical);
    RUN_TEST(type_lattice_function_hash_collision);
    RUN_TEST(type_lattice_cache_mutable_arguments);
    RUN_TEST(type_lattice_cache_result_isolation);
    RUN_TEST(inferred_type_snapshot);
    
    // TypeLatticeEncoder tests
    RUN_TEST(type_encoder_cross_kind_hash_collision);
    RUN_TEST(type_encoder_basic);
    RUN_TEST(type_encoder_constraints);
    
    // BitvectorTypeEncoder tests
    RUN_TEST(bv_encoder_basic);
    RUN_TEST(bv_encoder_encode_decode);
    RUN_TEST(bv_encoder_constraints);
    RUN_TEST(type_extent_checked);
    RUN_TEST(type_sum_materialization);
    
    std::cout << "\n=== All tests passed! ===" << std::endl;
    return 0;
}
