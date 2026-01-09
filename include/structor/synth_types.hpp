#pragma once

// When testing, IDA types are provided by mock_ida.hpp
#ifndef STRUCTOR_TESTING
#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <xref.hpp>
#include <typeinf.hpp>
#include <hexrays.hpp>
#endif

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <variant>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <algorithm>
#include <format>
#include <span>

namespace structor {

// Forward declarations
class AccessCollector;
class LayoutSynthesizer;
class VTableDetector;
class TypePropagator;
class PseudocodeRewriter;
class StructurePersistence;

// ============================================================================
// Core Constants
// ============================================================================

inline constexpr const char* PLUGIN_NAME = "Structor";
inline constexpr const char* PLUGIN_VERSION = "1.0.0";
inline constexpr const char* PLUGIN_AUTHOR = "Structor Authors";
inline constexpr const char* ACTION_NAME = "synth:synthesize_structure";
inline constexpr const char* ACTION_LABEL = "Synthesize Structure";
inline constexpr const char* DEFAULT_HOTKEY = "Shift+S";

inline constexpr std::size_t MAX_STRUCT_SIZE = 0x100000;  // 1MB max structure size
inline constexpr std::size_t MAX_VTABLE_SLOTS = 512;
inline constexpr std::size_t MAX_FIELDS = 4096;

// ============================================================================
// Access Types and Patterns
// ============================================================================

/// Type of memory access observed
enum class AccessType : std::uint8_t {
    Unknown,
    Read,
    Write,
    ReadWrite,
    Call,           // Indirect call through pointer
    AddressTaken    // Address of field taken
};

/// Inferred semantic type of access
enum class SemanticType : std::uint8_t {
    Unknown,
    Integer,
    UnsignedInteger,
    Float,
    Double,
    Pointer,
    FunctionPointer,
    VTablePointer,
    Array,
    NestedStruct,
    Padding
};

/// Nested access information for multi-level structure recovery (adopted from Suture)
/// Represents a path through nested structures: obj->field->nested_field
/// Example: AccessInfo(0, AccessInfo(8, type)) means obj->vtable[1] (vtable at offset 0, slot at offset 8)
struct NestedAccessInfo {
    sval_t          offset;         // Offset at this level
    tinfo_t         type;           // Type at this level
    std::unique_ptr<NestedAccessInfo> nested;  // Next level of nesting (if any)

    NestedAccessInfo() : offset(0) {}
    NestedAccessInfo(sval_t off, const tinfo_t& t) : offset(off), type(t) {}
    NestedAccessInfo(sval_t off, NestedAccessInfo&& inner)
        : offset(off), nested(std::make_unique<NestedAccessInfo>(std::move(inner))) {}

    // Copy constructor
    NestedAccessInfo(const NestedAccessInfo& other)
        : offset(other.offset), type(other.type) {
        if (other.nested) {
            nested = std::make_unique<NestedAccessInfo>(*other.nested);
        }
    }

    // Move constructor
    NestedAccessInfo(NestedAccessInfo&& other) noexcept = default;

    // Assignment operators
    NestedAccessInfo& operator=(const NestedAccessInfo& other) {
        if (this != &other) {
            offset = other.offset;
            type = other.type;
            nested = other.nested ? std::make_unique<NestedAccessInfo>(*other.nested) : nullptr;
        }
        return *this;
    }
    NestedAccessInfo& operator=(NestedAccessInfo&& other) noexcept = default;

    /// Get the nesting depth (1 = single field, 2 = nested once, etc.)
    [[nodiscard]] int depth() const noexcept {
        return nested ? 1 + nested->depth() : 1;
    }

    /// Check if this access has nested levels
    [[nodiscard]] bool has_nested() const noexcept {
        return nested != nullptr;
    }

    /// Get the innermost (leaf) access info
    [[nodiscard]] const NestedAccessInfo& innermost() const noexcept {
        return nested ? nested->innermost() : *this;
    }

    /// Create a flat representation: returns all (offset, type) pairs from outer to inner
    [[nodiscard]] qvector<std::pair<sval_t, tinfo_t>> flatten() const {
        qvector<std::pair<sval_t, tinfo_t>> result;
        result.push_back({offset, type});
        if (nested) {
            auto inner = nested->flatten();
            for (const auto& p : inner) {
                result.push_back(p);
            }
        }
        return result;
    }
};

/// Represents a single observed access to a structure field
struct FieldAccess {
    ea_t            insn_ea;        // Instruction address where access occurs
    sval_t          offset;         // Offset from base pointer
    std::uint32_t   size;           // Size of access in bytes
    AccessType      access_type;    // Read/Write/Call
    SemanticType    semantic_type;  // Inferred type
    tinfo_t         inferred_type;  // Full type info if available
    qstring         context_expr;   // Expression context for debugging
    bool            is_vtable_access;
    sval_t          vtable_slot;    // If vtable access, which slot
    bool            is_zero_init;   // True if this is a zero-initialization write (e.g., memset to 0)

    // Nested access support (adopted from Suture)
    std::optional<NestedAccessInfo> nested_info;  // For multi-level accesses like obj->vtable[slot]

    FieldAccess()
        : insn_ea(BADADDR)
        , offset(0)
        , size(0)
        , access_type(AccessType::Unknown)
        , semantic_type(SemanticType::Unknown)
        , is_vtable_access(false)
        , vtable_slot(-1)
        , is_zero_init(false) {}

    bool operator<(const FieldAccess& other) const noexcept {
        if (offset != other.offset) return offset < other.offset;
        if (size != other.size) return size < other.size;
        return insn_ea < other.insn_ea;
    }

    bool overlaps(const FieldAccess& other) const noexcept {
        if (offset >= other.offset + static_cast<sval_t>(other.size)) return false;
        if (other.offset >= offset + static_cast<sval_t>(size)) return false;
        return true;
    }

    /// Check if this access represents nested structure access
    [[nodiscard]] bool is_nested_access() const noexcept {
        return nested_info.has_value() && nested_info->has_nested();
    }

    /// Get the nesting depth (1 = simple access, 2+ = nested)
    [[nodiscard]] int nesting_depth() const noexcept {
        return nested_info ? nested_info->depth() : 1;
    }

    /// Create nested access info for vtable patterns: obj->vtable[slot]
    void set_vtable_nested_access(sval_t vtable_offset, sval_t slot_offset, const tinfo_t& slot_type) {
        nested_info = NestedAccessInfo(vtable_offset, NestedAccessInfo(slot_offset, slot_type));
        is_vtable_access = true;
        vtable_slot = slot_offset / (inf_is_64bit() ? 8 : 4);
    }
};

/// Collection of accesses for analysis
struct AccessPattern {
    ea_t                    func_ea;        // Function being analyzed
    qstring                 var_name;       // Variable name
    int                     var_idx;        // Variable index in lvar array
    tinfo_t                 original_type;  // Original type before synthesis
    qvector<FieldAccess>    accesses;       // All observed accesses
    sval_t                  min_offset;     // Minimum observed offset
    sval_t                  max_offset;     // Maximum observed offset (exclusive)
    bool                    has_vtable;     // VTable pattern detected
    sval_t                  vtable_offset;  // Offset of vtable pointer (usually 0)

    AccessPattern()
        : func_ea(BADADDR)
        , var_idx(-1)
        , min_offset(0)
        , max_offset(0)
        , has_vtable(false)
        , vtable_offset(0) {}

    void add_access(FieldAccess&& access) {
        if (accesses.empty()) {
            min_offset = access.offset;
            max_offset = access.offset + access.size;
        } else {
            min_offset = std::min(min_offset, access.offset);
            max_offset = std::max(max_offset, access.offset + static_cast<sval_t>(access.size));
        }
        accesses.push_back(std::move(access));
    }

    void sort_by_offset() {
        std::sort(accesses.begin(), accesses.end());
    }

    [[nodiscard]] std::size_t access_count() const noexcept {
        return accesses.size();
    }
};

// ============================================================================
// Synthesized Structure Components
// ============================================================================

/// Confidence level for inferred types (used by Z3 synthesis)
enum class TypeConfidence : std::uint8_t {
    Low = 0,        // Single observation, could be coincidence
    Medium = 1,     // Multiple observations or strong heuristic
    High = 2,       // Very strong evidence (pattern match, explicit type)
    Certain = 3     // Type is definitively known (debug info, user override)
};

/// Get string representation of TypeConfidence
[[nodiscard]] inline const char* type_confidence_str(TypeConfidence conf) noexcept {
    switch (conf) {
        case TypeConfidence::Low:       return "low";
        case TypeConfidence::Medium:    return "medium";
        case TypeConfidence::High:      return "high";
        case TypeConfidence::Certain:   return "certain";
        default:                        return "unknown";
    }
}

/// A single field in a synthesized structure
struct SynthField {
    qstring         name;           // Field name (e.g., "field_10")
    sval_t          offset;         // Byte offset in structure
    std::uint32_t   size;           // Field size
    tinfo_t         type;           // Field type
    SemanticType    semantic;       // Semantic classification
    qstring         comment;        // Auto-generated comment
    bool            is_padding;     // True if this is alignment padding
    bool            is_union_candidate;  // True if overlapping accesses detected
    bool            is_array;       // True if this is an array field
    std::uint32_t   array_count;    // Number of array elements (1 if not array)
    TypeConfidence  confidence;     // How confident we are in the type
    qvector<FieldAccess> source_accesses;  // Accesses that contributed to this field

    SynthField()
        : offset(0)
        , size(0)
        , semantic(SemanticType::Unknown)
        , is_padding(false)
        , is_union_candidate(false)
        , is_array(false)
        , array_count(1)
        , confidence(TypeConfidence::Medium) {}

    static SynthField create_padding(sval_t off, std::uint32_t sz) {
        SynthField f;
        f.name.sprnt("__pad_%X", static_cast<unsigned>(off));
        f.offset = off;
        f.size = sz;
        f.semantic = SemanticType::Padding;
        f.is_padding = true;

        // Create array type for padding bytes
        tinfo_t byte_type;
        byte_type.create_simple_type(BT_INT8 | BTMT_CHAR);
        f.type.create_array(byte_type, sz);

        return f;
    }

    /// Create a raw bytes field for irreconcilable regions
    static SynthField create_raw_bytes(sval_t off, std::uint32_t sz) {
        SynthField f;
        f.name.sprnt("__raw_%X", static_cast<unsigned>(off));
        f.offset = off;
        f.size = sz;
        f.semantic = SemanticType::Unknown;
        f.is_padding = false;
        f.confidence = TypeConfidence::Low;

        // Create uint8_t array type
        tinfo_t byte_type;
        byte_type.create_simple_type(BT_INT8 | BTMT_USIGNED);
        f.type.create_array(byte_type, sz);

        return f;
    }

    /// Create an array field
    static SynthField create_array(sval_t off, const tinfo_t& elem_type, std::uint32_t count) {
        SynthField f;
        f.offset = off;
        f.is_array = true;
        f.array_count = count;

        // Calculate size
        size_t elem_size = elem_type.get_size();
        if (elem_size != BADSIZE) {
            f.size = static_cast<std::uint32_t>(elem_size * count);
        } else {
            f.size = count;  // Fallback
        }

        // Create array type
        f.type.create_array(elem_type, count);

        f.name.sprnt("arr_%X", static_cast<unsigned>(off));
        f.confidence = TypeConfidence::Medium;
        f.semantic = SemanticType::Array;

        return f;
    }
};

/// A slot in a synthesized vtable
struct VTableSlot {
    std::uint32_t   index;          // Slot index (0, 1, 2, ...)
    sval_t          offset;         // Byte offset in vtable
    tinfo_t         func_type;      // Function pointer type
    qstring         name;           // Slot name
    qvector<ea_t>   call_sites;     // Where this slot is called
    qstring         signature_hint; // Recovered signature hint

    VTableSlot()
        : index(0)
        , offset(0) {}
};

/// A synthesized vtable structure
struct SynthVTable {
    qstring                 name;           // VTable structure name
    tid_t                   tid;            // Type ID in IDB
    qvector<VTableSlot>     slots;          // Function pointer slots
    ea_t                    source_func;    // Function where vtable was detected
    sval_t                  parent_offset;  // Offset in parent struct (usually 0)

    SynthVTable()
        : tid(BADADDR)
        , source_func(BADADDR)
        , parent_offset(0) {}

    [[nodiscard]] std::size_t slot_count() const noexcept {
        return slots.size();
    }
};

/// A complete synthesized structure
struct SynthStruct {
    qstring                 name;           // Structure name
    tid_t                   tid;            // Type ID in IDB
    qvector<SynthField>     fields;         // All fields
    std::uint32_t           size;           // Total size
    std::uint32_t           alignment;      // Structure alignment
    ea_t                    source_func;    // Function where struct was synthesized
    qstring                 source_var;     // Variable name that was analyzed
    std::optional<SynthVTable> vtable;      // Associated vtable if any
    qvector<ea_t>           provenance;     // All functions contributing to this type

    SynthStruct()
        : tid(BADADDR)
        , size(0)
        , alignment(8)
        , source_func(BADADDR) {}

    [[nodiscard]] std::size_t field_count() const noexcept {
        return fields.size();
    }

    [[nodiscard]] bool has_vtable() const noexcept {
        return vtable.has_value();
    }

    void add_provenance(ea_t func_ea) {
        if (std::find(provenance.begin(), provenance.end(), func_ea) == provenance.end()) {
            provenance.push_back(func_ea);
        }
    }
};

// ============================================================================
// Synthesis Results
// ============================================================================

/// Error codes for synthesis operations
enum class SynthError : std::uint8_t {
    Success = 0,
    NoVariableSelected,
    InvalidVariable,
    NoAccessesFound,
    InsufficientAccesses,
    ConflictingAccesses,
    TypeCreationFailed,
    PropagationFailed,
    RewriteFailed,
    InternalError,
    // Z3-specific errors
    Z3Timeout,              // Z3 solver timed out
    Z3OutOfMemory,          // Z3 ran out of memory
    Z3Unsat,                // Z3 constraints are unsatisfiable
    Z3Disabled              // Z3 is disabled in configuration
};

/// Status of Z3 synthesis phase
enum class Z3SynthesisStatus : std::uint8_t {
    NotUsed = 0,            // Z3 was not used (disabled or skipped)
    Success,                // Z3 found a valid solution
    SuccessRelaxed,         // Solution found after relaxing constraints
    FallbackRawBytes,       // Fell back to raw bytes for some fields
    FallbackHeuristic,      // Fell back to heuristic synthesis
    Timeout,                // Z3 timed out
    OutOfMemory,            // Z3 ran out of memory
    Unsat,                  // Constraints unsatisfiable
    Error                   // Internal error
};

/// Z3-specific synthesis result information
struct Z3SynthesisInfo {
    Z3SynthesisStatus       status;                 // Z3 synthesis status
    std::uint32_t           solve_time_ms;          // Time spent in Z3 solver
    std::uint32_t           candidates_generated;   // Number of field candidates
    std::uint32_t           candidates_selected;    // Candidates in final solution
    std::uint32_t           constraints_hard;       // Hard constraints count
    std::uint32_t           constraints_soft;       // Soft constraints count
    std::uint32_t           constraints_relaxed;    // Constraints relaxed for solution
    std::uint32_t           arrays_detected;        // Arrays detected
    std::uint32_t           unions_created;         // Union types created
    std::uint32_t           cross_func_merged;      // Cross-function constraints merged
    qvector<qstring>        relaxed_reasons;        // Reasons for relaxed constraints
    qvector<qstring>        unsat_core;             // UNSAT core if applicable

    Z3SynthesisInfo()
        : status(Z3SynthesisStatus::NotUsed)
        , solve_time_ms(0)
        , candidates_generated(0)
        , candidates_selected(0)
        , constraints_hard(0)
        , constraints_soft(0)
        , constraints_relaxed(0)
        , arrays_detected(0)
        , unions_created(0)
        , cross_func_merged(0) {}

    [[nodiscard]] bool used_z3() const noexcept {
        return status != Z3SynthesisStatus::NotUsed;
    }

    [[nodiscard]] bool z3_succeeded() const noexcept {
        return status == Z3SynthesisStatus::Success ||
               status == Z3SynthesisStatus::SuccessRelaxed;
    }

    [[nodiscard]] bool used_fallback() const noexcept {
        return status == Z3SynthesisStatus::FallbackRawBytes ||
               status == Z3SynthesisStatus::FallbackHeuristic;
    }
};

/// Conflict information for user resolution
struct AccessConflict {
    sval_t          offset;
    qvector<FieldAccess> conflicting_accesses;
    qstring         description;

    AccessConflict() : offset(0) {}
};

/// Result of structure synthesis
struct SynthResult {
    SynthError              error;
    qstring                 error_message;
    tid_t                   struct_tid;         // Created structure type ID
    tid_t                   vtable_tid;         // Companion vtable TID (BADADDR if none)
    qvector<ea_t>           propagated_to;      // Functions receiving propagated types
    qvector<ea_t>           failed_sites;       // Locations where rewrite failed
    int                     fields_created;
    int                     vtable_slots;
    qvector<AccessConflict> conflicts;          // Conflicts for user review
    std::unique_ptr<SynthStruct> synthesized_struct;

    // Z3-specific result information
    Z3SynthesisInfo         z3_info;            // Z3 synthesis details

    SynthResult()
        : error(SynthError::Success)
        , struct_tid(BADADDR)
        , vtable_tid(BADADDR)
        , fields_created(0)
        , vtable_slots(0) {}

    [[nodiscard]] bool success() const noexcept {
        return error == SynthError::Success;
    }

    [[nodiscard]] bool has_conflicts() const noexcept {
        return !conflicts.empty();
    }

    [[nodiscard]] bool used_z3() const noexcept {
        return z3_info.used_z3();
    }

    [[nodiscard]] bool z3_succeeded() const noexcept {
        return z3_info.z3_succeeded();
    }

    static SynthResult make_error(SynthError err, const char* msg) {
        SynthResult r;
        r.error = err;
        r.error_message = msg;
        return r;
    }

    static SynthResult make_error(SynthError err, const qstring& msg) {
        SynthResult r;
        r.error = err;
        r.error_message = msg;
        return r;
    }
};

// ============================================================================
// Type Propagation
// ============================================================================

/// Direction of type propagation
enum class PropagationDirection : std::uint8_t {
    Forward,    // To callees and assignments
    Backward,   // To callers and sources
    Both
};

/// A site where type was propagated
struct PropagationSite {
    ea_t            func_ea;
    int             var_idx;
    qstring         var_name;
    tinfo_t         old_type;
    tinfo_t         new_type;
    PropagationDirection direction;
    bool            success;
    qstring         failure_reason;

    PropagationSite()
        : func_ea(BADADDR)
        , var_idx(-1)
        , direction(PropagationDirection::Forward)
        , success(false) {}
};

/// Result of type propagation
struct PropagationResult {
    qvector<PropagationSite> sites;
    int                      success_count;
    int                      failure_count;

    PropagationResult()
        : success_count(0)
        , failure_count(0) {}

    void add_success(PropagationSite&& site) {
        site.success = true;
        sites.push_back(std::move(site));
        ++success_count;
    }

    void add_failure(PropagationSite&& site) {
        site.success = false;
        sites.push_back(std::move(site));
        ++failure_count;
    }
};

// ============================================================================
// Pseudocode Rewrite
// ============================================================================

/// A single rewrite transformation
struct RewriteTransform {
    ea_t            insn_ea;
    qstring         original_expr;
    qstring         rewritten_expr;
    bool            success;
    qstring         failure_reason;

    RewriteTransform()
        : insn_ea(BADADDR)
        , success(false) {}
};

/// Result of pseudocode rewriting
struct RewriteResult {
    qvector<RewriteTransform> transforms;
    int                       success_count;
    int                       failure_count;
    bool                      refresh_required;

    RewriteResult()
        : success_count(0)
        , failure_count(0)
        , refresh_required(false) {}
};

// ============================================================================
// Utility Functions
// ============================================================================

/// Get string representation of SynthError
[[nodiscard]] inline const char* synth_error_str(SynthError err) noexcept {
    switch (err) {
        case SynthError::Success:               return "Success";
        case SynthError::NoVariableSelected:    return "No variable selected";
        case SynthError::InvalidVariable:       return "Invalid variable";
        case SynthError::NoAccessesFound:       return "No dereferences found for variable";
        case SynthError::InsufficientAccesses:  return "Insufficient accesses for synthesis";
        case SynthError::ConflictingAccesses:   return "Conflicting access patterns detected";
        case SynthError::TypeCreationFailed:    return "Failed to create type";
        case SynthError::PropagationFailed:     return "Type propagation failed";
        case SynthError::RewriteFailed:         return "Pseudocode rewrite failed";
        case SynthError::InternalError:         return "Internal error";
        case SynthError::Z3Timeout:             return "Z3 solver timed out";
        case SynthError::Z3OutOfMemory:         return "Z3 ran out of memory";
        case SynthError::Z3Unsat:               return "Z3 constraints unsatisfiable";
        case SynthError::Z3Disabled:            return "Z3 synthesis is disabled";
        default:                                return "Unknown error";
    }
}

/// Get string representation of Z3SynthesisStatus
[[nodiscard]] inline const char* z3_status_str(Z3SynthesisStatus status) noexcept {
    switch (status) {
        case Z3SynthesisStatus::NotUsed:            return "not_used";
        case Z3SynthesisStatus::Success:            return "success";
        case Z3SynthesisStatus::SuccessRelaxed:     return "success_relaxed";
        case Z3SynthesisStatus::FallbackRawBytes:   return "fallback_raw_bytes";
        case Z3SynthesisStatus::FallbackHeuristic:  return "fallback_heuristic";
        case Z3SynthesisStatus::Timeout:            return "timeout";
        case Z3SynthesisStatus::OutOfMemory:        return "out_of_memory";
        case Z3SynthesisStatus::Unsat:              return "unsat";
        case Z3SynthesisStatus::Error:              return "error";
        default:                                    return "unknown";
    }
}

/// Get string representation of AccessType
[[nodiscard]] inline const char* access_type_str(AccessType type) noexcept {
    switch (type) {
        case AccessType::Read:          return "read";
        case AccessType::Write:         return "write";
        case AccessType::ReadWrite:     return "read/write";
        case AccessType::Call:          return "call";
        case AccessType::AddressTaken:  return "address-taken";
        default:                        return "unknown";
    }
}

/// Get string representation of SemanticType
[[nodiscard]] inline const char* semantic_type_str(SemanticType type) noexcept {
    switch (type) {
        case SemanticType::Integer:         return "int";
        case SemanticType::UnsignedInteger: return "uint";
        case SemanticType::Float:           return "float";
        case SemanticType::Double:          return "double";
        case SemanticType::Pointer:         return "ptr";
        case SemanticType::FunctionPointer: return "funcptr";
        case SemanticType::VTablePointer:   return "vtbl";
        case SemanticType::Array:           return "array";
        case SemanticType::NestedStruct:    return "struct";
        case SemanticType::Padding:         return "padding";
        default:                            return "unknown";
    }
}

/// Compute alignment for a given size
[[nodiscard]] inline std::uint32_t compute_alignment(std::uint32_t size) noexcept {
    if (size >= 8) return 8;
    if (size >= 4) return 4;
    if (size >= 2) return 2;
    return 1;
}

/// Align offset to boundary
[[nodiscard]] inline sval_t align_offset(sval_t offset, std::uint32_t alignment) noexcept {
    if (alignment == 0) alignment = 1;
    return (offset + alignment - 1) & ~(alignment - 1);
}

/// Check if a type is a pointer type
[[nodiscard]] inline bool is_pointer_type(const tinfo_t& type) {
    return type.is_ptr() || type.is_funcptr();
}

/// Get pointer size for current database
[[nodiscard]] inline std::uint32_t get_ptr_size() noexcept {
    return static_cast<std::uint32_t>(inf_is_64bit() ? 8 : 4);
}

// ============================================================================
// Type Resolution Utilities (adopted from Suture)
// ============================================================================

/// Semantic type priority scoring (adopted from Suture's rule weight concept)
/// Higher score = more specific/informative semantic classification
[[nodiscard]] inline int semantic_priority(SemanticType s) noexcept {
    switch (s) {
        case SemanticType::VTablePointer:   return 100;  // Most specific - vtable pattern
        case SemanticType::FunctionPointer: return 90;   // Specific - function pointer
        case SemanticType::NestedStruct:    return 85;   // Specific - nested structure
        case SemanticType::Pointer:         return 80;   // Specific - pointer type
        case SemanticType::Double:          return 70;   // Specific - 64-bit float
        case SemanticType::Float:           return 65;   // Specific - 32-bit float
        case SemanticType::Array:           return 60;   // Semi-specific
        case SemanticType::UnsignedInteger: return 50;   // Less specific
        case SemanticType::Integer:         return 40;   // Generic
        case SemanticType::Padding:         return 10;   // Internal use
        default:                            return 0;    // Unknown
    }
}

/// Type priority scoring for conflict resolution (adopted from Suture)
/// Higher score = more specific/preferred type
[[nodiscard]] inline int type_priority_score(const tinfo_t& type) noexcept {
    if (type.empty()) return 0;

    // Function pointers are highest priority (most specific)
    if (type.is_funcptr()) return 100;

    // Check for pointer to function pointer (vtable-like)
    if (type.is_ptr()) {
        tinfo_t pointed = type.get_pointed_object();
        if (!pointed.empty()) {
            if (pointed.is_funcptr()) return 95;  // void (**)(...)
            if (pointed.is_ptr()) {
                tinfo_t inner = pointed.get_pointed_object();
                if (!inner.empty() && inner.is_funcptr()) return 90;  // vtable pointer
            }
        }
        return 80;  // Generic pointer
    }

    // Floating point types
    if (type.is_floating()) return 70;

    // Sized integer types
    size_t size = type.get_size();
    if (size == 8) return 65;
    if (size == 4) return 60;
    if (size == 2) return 55;
    if (size == 1) return 50;

    return 40;  // Unknown/other
}

/// Strip pointer wrapper to get underlying type (adopted from Suture)
[[nodiscard]] inline tinfo_t strip_ptr(const tinfo_t& type) {
    if (type.is_ptr()) {
        return type.get_pointed_object();
    }
    return type;
}

/// Resolve type conflict between two candidates (adopted from Suture)
/// Returns the preferred type based on specificity rules
[[nodiscard]] inline tinfo_t resolve_type_conflict(const tinfo_t& a, const tinfo_t& b) {
    if (a.empty()) return b;
    if (b.empty()) return a;

    // Use priority scoring
    int score_a = type_priority_score(a);
    int score_b = type_priority_score(b);

    if (score_a != score_b) {
        return score_a > score_b ? a : b;
    }

    // Same priority - prefer larger size
    size_t size_a = a.get_size();
    size_t size_b = b.get_size();

    if (size_a != BADSIZE && size_b != BADSIZE && size_a != size_b) {
        return size_a > size_b ? a : b;
    }

    // If one is funcptr and other is generic ptr, prefer funcptr
    tinfo_t stripped_a = strip_ptr(a);
    tinfo_t stripped_b = strip_ptr(b);

    if (stripped_a.is_funcptr() && !stripped_b.is_funcptr()) {
        return a;
    }
    if (stripped_b.is_funcptr() && !stripped_a.is_funcptr()) {
        return b;
    }

    // Default: keep first
    return a;
}

/// Generate unique structure name
[[nodiscard]] inline qstring generate_struct_name(ea_t func_ea, int index = 0) {
    qstring name;
    name.sprnt("synth_struct_%llX_%d", static_cast<unsigned long long>(func_ea), index);
    return name;
}

/// Generate unique vtable name
[[nodiscard]] inline qstring generate_vtable_name(ea_t func_ea, int index = 0) {
    qstring name;
    name.sprnt("synth_vtbl_%llX_%d", static_cast<unsigned long long>(func_ea), index);
    return name;
}

/// Generate field name from offset
[[nodiscard]] inline qstring generate_field_name(sval_t offset, SemanticType semantic = SemanticType::Unknown) {
    qstring name;
    const char* prefix = "field";

    switch (semantic) {
        case SemanticType::VTablePointer:   prefix = "vtbl"; break;
        case SemanticType::FunctionPointer: prefix = "func"; break;
        case SemanticType::Pointer:         prefix = "ptr"; break;
        default: break;
    }

    name.sprnt("%s_%X", prefix, static_cast<unsigned>(offset));
    return name;
}

} // namespace structor
