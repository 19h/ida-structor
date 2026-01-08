#pragma once

#include <z3++.h>
#include <pro.h>
#include <typeinf.hpp>
#include "structor/z3/context.hpp"
#include <optional>
#include <vector>
#include <unordered_map>

namespace structor::z3 {

/// Encoded type categories for Z3 reasoning
/// These are abstract categories, not full type representations
enum class TypeCategory : unsigned {
    Unknown = 0,
    Int8,
    Int16,
    Int32,
    Int64,
    UInt8,
    UInt16,
    UInt32,
    UInt64,
    Float32,
    Float64,
    Pointer,      // Generic pointer (size from config)
    FuncPtr,      // Function pointer (requires separate prototype tracking)
    Array,        // Array (element type tracked separately)
    Struct,       // Nested struct (tid tracked separately)
    Union,        // Union type (tid tracked separately)
    RawBytes,     // Fallback: uint8_t[] for irreconcilable regions
    Void,

    _Count  // For enumeration bounds
};

/// Get the name of a type category as a string
[[nodiscard]] const char* type_category_name(TypeCategory cat) noexcept;

/// Extended type info for complex types
struct ExtendedTypeInfo {
    TypeCategory category = TypeCategory::Unknown;

    // For Pointer/FuncPtr: pointed-to type (if known)
    std::optional<TypeCategory> pointee_category;

    // For Struct/Union: IDA type ID
    std::optional<tid_t> udt_tid;

    // For Array: element info
    std::optional<TypeCategory> element_category;
    std::optional<uint32_t> element_count;

    // For FuncPtr: prototype info (simplified)
    std::optional<uint32_t> func_arg_count;

    // Size in bytes
    uint32_t size = 0;

    // Check if this is a simple scalar type
    [[nodiscard]] bool is_scalar() const noexcept {
        return category >= TypeCategory::Int8 && category <= TypeCategory::Float64;
    }

    // Check if this is a pointer type
    [[nodiscard]] bool is_pointer() const noexcept {
        return category == TypeCategory::Pointer || category == TypeCategory::FuncPtr;
    }

    // Check if this is an aggregate type
    [[nodiscard]] bool is_aggregate() const noexcept {
        return category == TypeCategory::Array ||
               category == TypeCategory::Struct ||
               category == TypeCategory::Union;
    }
};

/// Confidence level for type hints (for soft constraint weighting)
enum class TypeConfidence : int {
    Low = 1,       // Inferred from context, may be wrong
    Medium = 5,    // Direct decompiler hint
    High = 10,     // Multiple consistent observations
    Absolute = 100 // User-specified or API-documented
};

/// Encode IDA types to Z3 and back
class TypeEncoder {
public:
    explicit TypeEncoder(Z3Context& ctx);

    /// Create the Z3 enumeration sort for types
    [[nodiscard]] ::z3::sort type_sort();

    /// Encode an IDA tinfo_t to Z3 type category expression
    [[nodiscard]] ::z3::expr encode(const tinfo_t& type);

    /// Encode with extended info extraction
    [[nodiscard]] std::pair<::z3::expr, ExtendedTypeInfo> encode_extended(const tinfo_t& type);

    /// Get Z3 expression for a specific category
    [[nodiscard]] ::z3::expr category_expr(TypeCategory cat);

    /// Decode Z3 model value back to IDA type
    /// Requires extended info for complex types
    [[nodiscard]] tinfo_t decode(
        TypeCategory category,
        uint32_t size,
        const ExtendedTypeInfo* extended = nullptr
    );

    /// Build type compatibility constraint (SOFT constraint)
    /// Returns (constraint_expr, is_hard)
    /// Two types are compatible if they can coexist at the same offset
    [[nodiscard]] std::pair<::z3::expr, bool> compatible(
        const ::z3::expr& t1,
        const ::z3::expr& t2
    );

    /// Build type-size consistency constraint
    [[nodiscard]] ::z3::expr size_matches_type(
        const ::z3::expr& type,
        const ::z3::expr& size
    );

    /// Get the natural size for a type category (architecture-aware)
    [[nodiscard]] uint32_t natural_size(TypeCategory cat) const;

    /// Get the natural alignment for a type category
    [[nodiscard]] uint32_t natural_alignment(TypeCategory cat) const;

    /// Extract TypeCategory from an IDA tinfo_t
    [[nodiscard]] TypeCategory categorize(const tinfo_t& type) const;

    /// Extract ExtendedTypeInfo from an IDA tinfo_t
    [[nodiscard]] ExtendedTypeInfo extract_extended_info(const tinfo_t& type) const;

    /// Check if a category represents a signed integer
    [[nodiscard]] static bool is_signed_int(TypeCategory cat) noexcept;

    /// Check if a category represents an unsigned integer
    [[nodiscard]] static bool is_unsigned_int(TypeCategory cat) noexcept;

    /// Check if a category represents an integer (signed or unsigned)
    [[nodiscard]] static bool is_integer(TypeCategory cat) noexcept;

    /// Check if a category represents a floating point type
    [[nodiscard]] static bool is_floating(TypeCategory cat) noexcept;

private:
    Z3Context& ctx_;
    std::optional<::z3::sort> type_sort_;
    std::vector<::z3::expr> category_exprs_;

    void initialize_type_sort();

    // Cache for decoded types
    mutable std::unordered_map<unsigned, tinfo_t> decode_cache_;
};

/// Type compatibility matrix
/// Returns true if types t1 and t2 can legally alias at the same memory location
[[nodiscard]] bool types_compatible(TypeCategory t1, TypeCategory t2);

/// Get the size of a type category for a given pointer size
[[nodiscard]] uint32_t type_category_size(TypeCategory cat, uint32_t pointer_size);

/// Get the alignment requirement for a type category
[[nodiscard]] uint32_t type_category_alignment(TypeCategory cat, uint32_t pointer_size);

/// Convert a SemanticType (from synth_types.hpp) to TypeCategory
[[nodiscard]] TypeCategory semantic_to_category(int semantic_type);

/// Convert TypeCategory back to SemanticType
[[nodiscard]] int category_to_semantic(TypeCategory cat);

} // namespace structor::z3
