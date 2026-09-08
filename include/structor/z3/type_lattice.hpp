#pragma once

#include <z3++.h>

#ifdef STRUCTOR_TESTING
// Use mock IDA types for testing - mock_ida.hpp is in test/ which is added
// to include path by test/CMakeLists.txt
#include "mock_ida.hpp"
#else
#include <pro.h>
#include <typeinf.hpp>
#endif

#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <memory>
#include <stdexcept>

namespace structor::z3 {

// Forward declarations
class Z3Context;

/// Base type identifiers in the type lattice
/// These represent concrete scalar types in the type system
enum class BaseType : unsigned {
    Unknown = 0,    // Top of integer lattice (unknown)
    Bottom,         // Bottom (contradiction)
    
    // Signed integers (ordered by width)
    Int8,
    Int16,
    Int32,
    Int64,
    
    // Unsigned integers (ordered by width)
    UInt8,
    UInt16,
    UInt32,
    UInt64,
    
    // Floating point
    Float32,
    Float64,
    
    // Special types
    Void,
    Bool,
    
    _Count
};

/// Get string name for a base type
[[nodiscard]] const char* base_type_name(BaseType type) noexcept;

/// Get the size of a base type in bytes
[[nodiscard]] uint32_t base_type_size(BaseType type, uint32_t ptr_size) noexcept;

/// Check if base type is a signed integer
[[nodiscard]] bool is_signed_int(BaseType type) noexcept;

/// Check if base type is an unsigned integer
[[nodiscard]] bool is_unsigned_int(BaseType type) noexcept;

/// Check if base type is any integer
[[nodiscard]] bool is_integer(BaseType type) noexcept;

/// Check if base type is floating point
[[nodiscard]] bool is_floating(BaseType type) noexcept;

/// Get base type from size and signedness
[[nodiscard]] BaseType base_type_from_size(uint32_t size, bool is_signed) noexcept;

/// Inferred type in the type lattice (supports recursive pointer types)
/// This represents types as: BaseType | Ptr(InferredType) | Func(args, ret) | Array(elem, count)
class InferredType {
public:
    enum class Kind {
        Base,       // Scalar base type
        Pointer,    // Pointer to another type
        Function,   // Function type (return type + param types)
        Array,      // Array type (element type + count)
        Struct,     // Structure type (tid-based)
        Sum         // Sum type for unions (multiple alternatives)
    };
    
    /// Create a base type
    static InferredType make_base(BaseType base);
    
    /// Create unknown type
    static InferredType unknown();
    
    /// Create bottom type (contradiction)
    static InferredType bottom();
    
    /// Create pointer type
    static InferredType make_ptr(InferredType pointee);
    
    /// Create pointer type from shared pointee
    static InferredType make_ptr(std::shared_ptr<InferredType> pointee);
    
    /// Create function pointer type
    static InferredType make_func(
        InferredType return_type,
        std::vector<InferredType> param_types
    );
    
    /// Create array type
    static InferredType make_array(InferredType element, uint32_t count);
    
    /// Create struct type by tid
    static InferredType make_struct(tid_t tid);
    
    /// Create sum type (union of alternatives)
    static InferredType make_sum(std::vector<InferredType> alternatives);
    
    // Type queries
    [[nodiscard]] Kind kind() const noexcept { return kind_; }
    [[nodiscard]] bool is_base() const noexcept { return kind_ == Kind::Base; }
    [[nodiscard]] bool is_pointer() const noexcept { return kind_ == Kind::Pointer; }
    [[nodiscard]] bool is_function() const noexcept { return kind_ == Kind::Function; }
    [[nodiscard]] bool is_array() const noexcept { return kind_ == Kind::Array; }
    [[nodiscard]] bool is_struct() const noexcept { return kind_ == Kind::Struct; }
    [[nodiscard]] bool is_sum() const noexcept { return kind_ == Kind::Sum; }
    
    [[nodiscard]] bool is_unknown() const noexcept { 
        return is_base() && base_type_ == BaseType::Unknown; 
    }
    [[nodiscard]] bool is_bottom() const noexcept { 
        return is_base() && base_type_ == BaseType::Bottom; 
    }
    
    // Accessors
    [[nodiscard]] BaseType base_type() const noexcept { return base_type_; }
    [[nodiscard]] const InferredType* pointee() const noexcept { 
        return pointee_ ? pointee_.get() : nullptr; 
    }
    [[nodiscard]] const InferredType* return_type() const noexcept { 
        return return_type_ ? return_type_.get() : nullptr; 
    }
    [[nodiscard]] const std::vector<std::shared_ptr<InferredType>>& param_types() const noexcept { 
        return param_types_; 
    }
    [[nodiscard]] const InferredType* element_type() const noexcept {
        return element_type_ ? element_type_.get() : nullptr;
    }
    [[nodiscard]] uint32_t array_count() const noexcept { return array_count_; }
    [[nodiscard]] tid_t struct_tid() const noexcept { return struct_tid_; }
    [[nodiscard]] const std::vector<std::shared_ptr<InferredType>>& sum_alternatives() const noexcept {
        return sum_alternatives_;
    }
    
    /// Get the size of this type in bytes
    [[nodiscard]] uint32_t size(uint32_t ptr_size) const noexcept;
    
    /// Convert to IDA tinfo_t
    [[nodiscard]] tinfo_t to_tinfo() const;
    
    /// Create from IDA tinfo_t
    static InferredType from_tinfo(const tinfo_t& type);
    
    /// Get human-readable string representation
    [[nodiscard]] qstring to_string() const;
    
    /// Equality comparison
    bool operator==(const InferredType& other) const;
    bool operator!=(const InferredType& other) const { return !(*this == other); }
    
    /// Hash support
    [[nodiscard]] std::size_t hash() const noexcept;

    /// Copy a finite, acyclic type tree without retaining mutable child aliases.
    /// Cache keys and cached results use snapshots to preserve value identity.
    [[nodiscard]] InferredType snapshot() const;

private:
    Kind kind_ = Kind::Base;
    BaseType base_type_ = BaseType::Unknown;
    std::shared_ptr<InferredType> pointee_;
    std::shared_ptr<InferredType> return_type_;
    std::vector<std::shared_ptr<InferredType>> param_types_;
    std::shared_ptr<InferredType> element_type_;
    uint32_t array_count_ = 0;
    tid_t struct_tid_ = BADADDR;
    std::vector<std::shared_ptr<InferredType>> sum_alternatives_;
};

/// Hash functor for InferredType
struct InferredTypeHash {
    std::size_t operator()(const InferredType& t) const noexcept {
        return t.hash();
    }
};

/// Type lattice operations
/// Implements subtyping with meet (greatest lower bound) and join (least upper bound)
class TypeLattice {
public:
    TypeLattice(uint32_t ptr_size = 8);
    
    /// Compute least upper bound (join) - most general common supertype
    /// Returns Unknown if no common supertype exists
    [[nodiscard]] InferredType lub(const InferredType& a, const InferredType& b) const;
    
    /// Compute greatest lower bound (meet) - most specific common subtype
    /// Returns Bottom if types are incompatible
    [[nodiscard]] InferredType glb(const InferredType& a, const InferredType& b) const;
    
    /// Check if a is a subtype of b (a <: b)
    [[nodiscard]] bool is_subtype(const InferredType& a, const InferredType& b) const;
    
    /// Check if types are compatible (can coexist at same location)
    [[nodiscard]] bool are_compatible(const InferredType& a, const InferredType& b) const;
    
    /// Widen type based on size (e.g., int8 -> int32 for 4-byte access)
    [[nodiscard]] InferredType widen_to_size(const InferredType& type, uint32_t target_size) const;
    
    /// Get canonical type for a given size (used when no type info available)
    [[nodiscard]] InferredType canonical_for_size(uint32_t size) const;
    
    /// Get pointer size
    [[nodiscard]] uint32_t ptr_size() const noexcept { return ptr_size_; }
    
    /// Clear the memoization caches
    void clear_cache() const noexcept { lub_cache_.clear(); glb_cache_.clear(); }
    
    /// Get cache statistics
    struct CacheStats {
        size_t lub_hits = 0;
        size_t lub_misses = 0;
        size_t glb_hits = 0;
        size_t glb_misses = 0;
    };
    [[nodiscard]] CacheStats cache_stats() const noexcept { return stats_; }

private:
    uint32_t ptr_size_;
    
    /// Check if signed integer a is subtype of signed integer b
    [[nodiscard]] bool signed_int_subtype(BaseType a, BaseType b) const noexcept;
    
    /// Check if unsigned integer a is subtype of unsigned integer b  
    [[nodiscard]] bool unsigned_int_subtype(BaseType a, BaseType b) const noexcept;
    
    [[nodiscard]] InferredType join_alternatives(std::vector<InferredType> alternatives) const;

    /// Internal LUB implementation without caching
    [[nodiscard]] InferredType lub_impl(const InferredType& a, const InferredType& b) const;
    
    /// Internal GLB implementation without caching
    [[nodiscard]] InferredType glb_impl(const InferredType& a, const InferredType& b) const;
    
    /// Cache keys own complete types; hashes only select lookup buckets.
    struct TypePairKey {
        InferredType type_a;
        InferredType type_b;

        bool operator==(const TypePairKey& other) const {
            return type_a == other.type_a && type_b == other.type_b;
        }
    };
    
    struct TypePairKeyHash {
        std::size_t operator()(const TypePairKey& k) const noexcept {
            // FNV-1a style mixing with golden ratio - better avalanche than XOR
            constexpr std::size_t kGoldenRatio = 0x9e3779b97f4a7c15ULL;
            std::size_t h = k.type_a.hash();
            h ^= k.type_b.hash() + kGoldenRatio + (h << 6) + (h >> 2);
            return h;
        }
    };
    
    /// Memoization caches for LUB and GLB
    mutable std::unordered_map<TypePairKey, InferredType, TypePairKeyHash> lub_cache_;
    mutable std::unordered_map<TypePairKey, InferredType, TypePairKeyHash> glb_cache_;
    mutable CacheStats stats_;
};

struct SymbolicTypeQueryBounds {
    unsigned max_depth;
    unsigned max_list_length;
    unsigned max_expansions;
};

/// The finite symbolic predicate builder exhausted its configured work budget.
class SymbolicTypeQueryLimit : public std::length_error {
public:
    using std::length_error::length_error;
};

/// Encodes InferredType to Z3 expressions
/// Uses a recursive datatype definition for pointer types
class TypeLatticeEncoder {
public:
    TypeLatticeEncoder(Z3Context& ctx);
    
    /// Get the Z3 sort representing types
    [[nodiscard]] ::z3::sort type_sort();
    
    /// Get the Z3 sort representing base types (flat enum)
    [[nodiscard]] ::z3::sort base_type_sort();
    
    /// Create a type variable with the given name
    [[nodiscard]] ::z3::expr make_type_var(const char* name);
    
    /// Create a type variable for a specific location
    [[nodiscard]] ::z3::expr make_type_var(ea_t func_ea, int var_idx, int version = 0);
    
    /// Create a type variable for a memory location
    [[nodiscard]] ::z3::expr make_mem_type_var(ea_t base, sval_t offset, uint32_t size);
    
    /// Encode a concrete InferredType as Z3 expression
    [[nodiscard]] ::z3::expr encode(const InferredType& type);
    
    /// Encode base type as Z3 expression
    [[nodiscard]] ::z3::expr encode_base(BaseType base);
    
    /// Build Z3 expression for ptr(pointee)
    [[nodiscard]] ::z3::expr encode_ptr(const ::z3::expr& pointee);
    
    /// Decode Z3 model value to InferredType
    [[nodiscard]] InferredType decode(const ::z3::expr& expr, const ::z3::model& model);
    
    /// Create constraint: type1 == type2
    [[nodiscard]] ::z3::expr type_eq(const ::z3::expr& t1, const ::z3::expr& t2);
    
    /// Create constraint: type is a pointer type
    [[nodiscard]] ::z3::expr is_pointer_type(const ::z3::expr& type);
    
    /// Create constraint: type is an integer type
    [[nodiscard]] ::z3::expr is_integer_type(const ::z3::expr& type);
    
    /// Create constraint: type is signed integer
    [[nodiscard]] ::z3::expr is_signed_type(const ::z3::expr& type);
    
    /// Create constraint: type is unsigned integer
    [[nodiscard]] ::z3::expr is_unsigned_type(const ::z3::expr& type);
    
    /// Create constraint: type is floating point
    [[nodiscard]] ::z3::expr is_floating_type(const ::z3::expr& type);
    
    /// Create constraint: type has size (in bytes)
    [[nodiscard]] ::z3::expr type_has_size(const ::z3::expr& type, uint32_t size);
    
    /// Create subtyping constraint: t1 <: t2
    [[nodiscard]] ::z3::expr subtype_of(const ::z3::expr& t1, const ::z3::expr& t2);
    
    /// Create compatibility constraint: types can coexist at same offset
    [[nodiscard]] ::z3::expr types_compatible(const ::z3::expr& t1, const ::z3::expr& t2);
    
    /// Get the type lattice
    [[nodiscard]] const TypeLattice& lattice() const noexcept { return lattice_; }

    /// Symbolic recursive predicates are complete only within these bounds.
    /// UNSAT after a bounded query means no model in that domain. Ground
    /// constructor queries, type equality, and pointer sizes remain exact.
    [[nodiscard]] SymbolicTypeQueryBounds symbolic_query_bounds() const noexcept;
    [[nodiscard]] bool bounded_symbolic_queries_used() const noexcept {
        return bounded_symbolic_queries_used_;
    }
    [[nodiscard]] bool explicit_candidate_queries_used() const noexcept {
        return explicit_candidate_queries_used_;
    }
    void reset_symbolic_query_tracking() noexcept {
        bounded_symbolic_queries_used_ = false;
        explicit_candidate_queries_used_ = false;
    }

private:
    Z3Context& ctx_;
    TypeLattice lattice_;
    
    // Z3 sorts
    std::optional<::z3::sort> type_sort_;         // Recursive lossless datatype
    std::optional<::z3::sort> base_type_sort_;    // Enumeration sort for base types
    
    // Base type enum constants
    std::vector<::z3::expr> base_type_consts_;
    
    // Cache for encoded types
    std::unordered_map<InferredType, ::z3::expr, InferredTypeHash> encode_cache_;
    bool bounded_symbolic_queries_used_ = false;
    bool explicit_candidate_queries_used_ = false;
    friend class TypeConstraintSet;

    struct QueryBudget {
        unsigned remaining;
        void consume();
    };
    
    void initialize_sorts();
    void initialize_base_sort();
    void initialize_type_datatype();
    void initialize_type_relations();
    [[nodiscard]] ::z3::expr encode_type(const InferredType& type);
    [[nodiscard]] ::z3::expr encode_list(
        const std::vector<std::shared_ptr<InferredType>>& types);
    [[nodiscard]] InferredType decode_type(const ::z3::expr& value);
    [[nodiscard]] std::vector<InferredType> decode_list(const ::z3::expr& value);
    [[nodiscard]] bool is_ground_type(const ::z3::expr& type) const;
    [[nodiscard]] int constructor_index(const ::z3::expr& type) const;
    [[nodiscard]] ::z3::expr project(const ::z3::expr& type,
                                   unsigned constructor, unsigned member) const;
    [[nodiscard]] ::z3::expr bounded_byte_size(const ::z3::expr& type,
                                              unsigned depth, QueryBudget& budget);
    [[nodiscard]] ::z3::expr bounded_sum_byte_size(const ::z3::expr& list,
                                                  unsigned depth, unsigned length,
                                                  QueryBudget& budget);
    [[nodiscard]] ::z3::expr bounded_subtype(const ::z3::expr& a, const ::z3::expr& b,
                                            unsigned depth, QueryBudget& budget);
    [[nodiscard]] ::z3::expr bounded_list_subtype(const ::z3::expr& a, const ::z3::expr& b,
                                                 unsigned depth, unsigned length,
                                                 QueryBudget& budget);
    [[nodiscard]] ::z3::expr bounded_sum_subtype(const ::z3::expr& list,
                                                const ::z3::expr& type, bool source,
                                                unsigned depth, unsigned length,
                                                QueryBudget& budget);
    [[nodiscard]] ::z3::expr bounded_compatible(const ::z3::expr& a, const ::z3::expr& b,
                                               unsigned depth, QueryBudget& budget);
    [[nodiscard]] ::z3::expr bounded_sum_compatible(const ::z3::expr& list,
                                                   const ::z3::expr& type,
                                                   unsigned depth, unsigned length,
                                                   QueryBudget& budget);
    [[nodiscard]] ::z3::expr bounded_same_list_length(const ::z3::expr& a,
                                                     const ::z3::expr& b,
                                                     unsigned length, QueryBudget& budget);
};

/// Bitvector-based type encoding for improved solver performance
/// Encodes types as fixed-size bitvectors instead of algebraic datatypes
/// Trade-off: faster solving but loses recursive type structure
class BitvectorTypeEncoder {
public:
    BitvectorTypeEncoder(Z3Context& ctx);
    
    // Encoding scheme:
    // Bits 0-5:   Base type tag (0-63)
    // Bits 6-13:  Size in bytes (0-255)  
    // Bit  14:    Is pointer flag
    // Bit  15:    Is signed flag
    // Bits 16-23: Pointer depth (0-255)
    // Bits 24-31: Reserved
    
    static constexpr unsigned TYPE_BITS = 32;
    
    /// Get the bitvector sort for types
    [[nodiscard]] ::z3::sort type_sort();
    
    /// Create a type variable
    [[nodiscard]] ::z3::expr make_type_var(const char* name);
    
    /// Encode InferredType as bitvector
    [[nodiscard]] ::z3::expr encode(const InferredType& type);
    
    /// Encode base type with known properties
    [[nodiscard]] ::z3::expr encode_known(
        BaseType base, 
        uint32_t size, 
        bool is_ptr = false, 
        unsigned ptr_depth = 0
    );
    
    /// Decode bitvector to InferredType
    [[nodiscard]] InferredType decode(const ::z3::expr& bv, const ::z3::model& model);
    
    /// Create constraint: type is pointer
    [[nodiscard]] ::z3::expr is_pointer(const ::z3::expr& type);
    
    /// Create constraint: type is integer
    [[nodiscard]] ::z3::expr is_integer(const ::z3::expr& type);
    
    /// Create constraint: type is signed
    [[nodiscard]] ::z3::expr is_signed(const ::z3::expr& type);
    
    /// Create constraint: type has size
    [[nodiscard]] ::z3::expr has_size(const ::z3::expr& type, uint32_t size);
    
    /// Extract size from type bitvector
    [[nodiscard]] ::z3::expr get_size(const ::z3::expr& type);
    
    /// Create compatibility constraint
    [[nodiscard]] ::z3::expr types_compatible(const ::z3::expr& t1, const ::z3::expr& t2);

private:
    Z3Context& ctx_;
    std::optional<::z3::sort> bv_sort_;
    
    void initialize();
    
    // Bit manipulation helpers
    [[nodiscard]] ::z3::expr extract_base_tag(const ::z3::expr& type);
    [[nodiscard]] ::z3::expr extract_size_bits(const ::z3::expr& type);
    [[nodiscard]] ::z3::expr extract_ptr_flag(const ::z3::expr& type);
    [[nodiscard]] ::z3::expr extract_signed_flag(const ::z3::expr& type);
    [[nodiscard]] ::z3::expr extract_ptr_depth(const ::z3::expr& type);
};

} // namespace structor::z3
