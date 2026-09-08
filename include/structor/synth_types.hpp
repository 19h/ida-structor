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
#include <span>
#include <stdexcept>
#include <limits>

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
inline constexpr const char* PLUGIN_VERSION = "2.2.0";
inline constexpr const char* PLUGIN_AUTHOR = "Structor Authors";
inline constexpr const char* ACTION_NAME = "synth:synthesize_structure";
inline constexpr const char* ACTION_LABEL = "Synthesize Structure";
inline constexpr const char* MATCH_ACTION_NAME = "synth:match_existing_structure";
inline constexpr const char* MATCH_ACTION_LABEL = "Match Existing Structure...";
inline constexpr const char* DEFAULT_HOTKEY = "Shift+S";
inline constexpr const char* DEFAULT_MATCH_HOTKEY = "Ctrl+Shift+S";

inline constexpr std::size_t MAX_STRUCT_SIZE = 0x100000;  // 1MB max structure size
inline constexpr std::size_t MAX_VTABLE_SLOTS = 512;
inline constexpr std::size_t MAX_FIELDS = 4096;

/// A virtual dispatch slot is addressable only at a non-negative,
/// pointer-width-aligned byte offset. Reject all other offsets rather than
/// silently truncating them into a slot index.
[[nodiscard]] inline bool is_valid_vtable_slot_offset(sval_t offset) noexcept {
    const sval_t pointer_size = inf_is_64bit() ? 8 : 4;
    return offset >= 0 &&
           (offset % pointer_size) == 0 &&
           static_cast<std::uint64_t>(offset / pointer_size) < MAX_VTABLE_SLOTS;
}

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

/// Compute the exclusive end of a byte interval without signed overflow.
/// `size == 0` is a valid empty interval.  Invalid intervals are represented
/// explicitly instead of invoking undefined behavior in range predicates.
[[nodiscard]] inline constexpr std::optional<sval_t> checked_interval_end(
    sval_t offset,
    std::uint32_t size) noexcept
{
    if (offset > std::numeric_limits<sval_t>::max() -
                     static_cast<sval_t>(size)) {
        return std::nullopt;
    }
    return offset + static_cast<sval_t>(size);
}

/// Return the mathematical distance between two ordered signed offsets.  The
/// unsigned subtraction is intentional: for end >= begin it is the exact
/// two's-complement distance over the full signed domain, including
/// [SVAL_MIN, SVAL_MAX].
[[nodiscard]] inline constexpr std::optional<std::uint64_t>
checked_interval_span(sval_t begin, sval_t end) noexcept
{
    if (end < begin) {
        return std::nullopt;
    }
    return static_cast<std::uint64_t>(end) -
           static_cast<std::uint64_t>(begin);
}

[[nodiscard]] inline constexpr bool checked_intervals_overlap(
    sval_t lhs_offset,
    std::uint32_t lhs_size,
    sval_t rhs_offset,
    std::uint32_t rhs_size) noexcept
{
    if (lhs_size == 0 || rhs_size == 0) {
        return false;
    }
    const auto lhs_end = checked_interval_end(lhs_offset, lhs_size);
    const auto rhs_end = checked_interval_end(rhs_offset, rhs_size);
    return lhs_end.has_value() && rhs_end.has_value() &&
           lhs_offset < *rhs_end && rhs_offset < *lhs_end;
}

[[nodiscard]] inline constexpr bool checked_interval_contains(
    sval_t outer_offset,
    std::uint32_t outer_size,
    sval_t inner_offset,
    std::uint32_t inner_size) noexcept
{
    const auto outer_end = checked_interval_end(outer_offset, outer_size);
    const auto inner_end = checked_interval_end(inner_offset, inner_size);
    return outer_end.has_value() && inner_end.has_value() &&
           outer_offset <= inner_offset && *outer_end >= *inner_end;
}

[[nodiscard]] inline constexpr std::optional<std::uint32_t>
checked_u32_product(std::uint32_t lhs, std::uint32_t rhs) noexcept
{
    if (lhs != 0 && rhs > std::numeric_limits<std::uint32_t>::max() / lhs) {
        return std::nullopt;
    }
    return lhs * rhs;
}

/// How a generated name should be interpreted by the naming pipeline
enum class GeneratedNameKind : std::uint8_t {
    Unknown,
    RootStruct,
    Field,
    ArrayField,
    ArrayElementType,
    SubStructField,
    UnionField,
    UnionAlternative,
    Bitfield,
    Padding,
    RawBytes,
    VTable,
    VTableSlot,
    ShiftedView,
    TailView,
};

/// Where a name came from. Higher-priority origins can replace lower-priority ones.
enum class NameOrigin : std::uint8_t {
    Unknown,
    GeneratedFallback,
    HeuristicRole,
    AccessContext,
    OriginalType,
    PropagatedDonor,
    ReusedType,
    UserProvided,
};

/// Confidence in a generated/adopted name.
enum class NameConfidence : std::uint8_t {
    Low,
    Medium,
    High,
    Certain,
};

struct NameMetadata {
    GeneratedNameKind kind = GeneratedNameKind::Unknown;
    NameOrigin origin = NameOrigin::Unknown;
    NameConfidence confidence = NameConfidence::Low;
    bool locked = false;

    [[nodiscard]] bool is_generated() const noexcept {
        return origin == NameOrigin::GeneratedFallback ||
               origin == NameOrigin::HeuristicRole;
    }

    [[nodiscard]] bool is_semantic() const noexcept {
        return origin == NameOrigin::AccessContext ||
               origin == NameOrigin::OriginalType ||
               origin == NameOrigin::PropagatedDonor ||
               origin == NameOrigin::ReusedType ||
               origin == NameOrigin::UserProvided;
    }
};

/// Bitfield access information
struct BitfieldInfo {
    std::uint16_t bit_offset = 0;
    std::uint16_t bit_size = 0;

    BitfieldInfo() = default;
    BitfieldInfo(std::uint16_t off, std::uint16_t sz)
        : bit_offset(off)
        , bit_size(sz) {}

    bool operator==(const BitfieldInfo& other) const noexcept {
        return bit_offset == other.bit_offset && bit_size == other.bit_size;
    }
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
    ea_t            source_func_ea; // Function where access occurs
    sval_t          offset;         // Offset from base pointer
    std::uint32_t   size;           // Size of access in bytes
    AccessType      access_type;    // Read/Write/Call
    SemanticType    semantic_type;  // Inferred type
    tinfo_t         inferred_type;  // Full type info if available
    qstring         context_expr;   // Expression context for debugging
    bool            is_vtable_access;
    sval_t          vtable_slot;    // If vtable access, which slot
    bool            is_zero_init;   // True if this is a zero-initialization write (e.g., memset to 0)
    bool            is_call_argument; // Value from this region flowed into a call argument.

    // Bitfield observations for this access (if any)
    qvector<BitfieldInfo> bitfields;

    // Semantic constant comparisons observed for this access (e.g. field == 1)
    qvector<std::uint64_t> observed_constants;

    // Array stride hint derived from index expressions (if any)
    std::optional<std::uint32_t> array_stride_hint;

    // Extra deref levels before reaching base var (e.g., *param = 1)
    std::optional<std::uint8_t> base_indirection;

    // Nested access support (adopted from Suture)
    std::optional<NestedAccessInfo> nested_info;  // For multi-level accesses like obj->vtable[slot]

    FieldAccess()
        : insn_ea(BADADDR)
        , source_func_ea(BADADDR)
        , offset(0)
        , size(0)
        , access_type(AccessType::Unknown)
        , semantic_type(SemanticType::Unknown)
        , is_vtable_access(false)
        , vtable_slot(-1)
        , is_zero_init(false)
        , is_call_argument(false) {}

    bool operator<(const FieldAccess& other) const noexcept {
        if (offset != other.offset) return offset < other.offset;
        if (size != other.size) return size < other.size;
        return insn_ea < other.insn_ea;
    }

    bool overlaps(const FieldAccess& other) const noexcept {
        return checked_intervals_overlap(
            offset, size, other.offset, other.size);
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
    [[nodiscard]] bool set_vtable_nested_access(
        sval_t vtable_offset,
        sval_t slot_offset,
        const tinfo_t& slot_type)
    {
        if (!is_valid_vtable_slot_offset(slot_offset)) {
            nested_info.reset();
            is_vtable_access = false;
            vtable_slot = -1;
            return false;
        }
        nested_info = NestedAccessInfo(vtable_offset, NestedAccessInfo(slot_offset, slot_type));
        is_vtable_access = true;
        vtable_slot = slot_offset / (inf_is_64bit() ? 8 : 4);
        return true;
    }

    void add_bitfield(const BitfieldInfo& info) {
        for (const auto& existing : bitfields) {
            if (existing == info) {
                return;
            }
        }
        bitfields.push_back(info);
    }

    void add_observed_constant(std::uint64_t value) {
        for (auto existing : observed_constants) {
            if (existing == value) {
                return;
            }
        }
        observed_constants.push_back(value);
    }
};

/// True when equal-range observations can be combined without destroying a
/// materially different storage interpretation (for example integer vs float
/// or pointer vs integer).
[[nodiscard]] bool field_access_evidence_compatible(
    const FieldAccess& lhs, const FieldAccess& rhs);

/// Merge metadata from a compatible equal-range observation.
void merge_field_access_evidence(FieldAccess& dst, const FieldAccess& src);

/// Canonical ordering for evidence retained as distinct alternatives.
[[nodiscard]] bool canonical_field_access_less(
    const FieldAccess& lhs, const FieldAccess& rhs);

/// Causes that can remove reaching-definition information during collection.
/// These describe observed analysis limitations, not proof of completeness.
enum class FlowPrecisionLoss : std::uint8_t {
    StateBudget,
    StepBudget,
    UnknownJumpEntry,
    UnknownExceptionEntry,
    OpaqueAssembly,
};

[[nodiscard]] inline const char* flow_precision_loss_str(FlowPrecisionLoss reason) noexcept {
    switch (reason) {
        case FlowPrecisionLoss::StateBudget: return "state_budget";
        case FlowPrecisionLoss::StepBudget: return "step_budget";
        case FlowPrecisionLoss::UnknownJumpEntry: return "unknown_jump_entry";
        case FlowPrecisionLoss::UnknownExceptionEntry: return "unknown_exception_entry";
        case FlowPrecisionLoss::OpaqueAssembly: return "opaque_assembly";
    }
    return "unknown";
}

struct FlowPrecisionEvent {
    FlowPrecisionLoss reason = FlowPrecisionLoss::StateBudget;
    // Preorder ordinal in the collected ctree. It is independent of pointer
    // addresses, print_func(), and repeated loop exploration. Zero means absent.
    std::uint64_t node_ordinal = 0;
    ea_t ea = BADADDR;
    int label = -1;
    std::uint64_t occurrences = 0;
    std::uint64_t max_states_before = 0;
};

struct FlowAnalysisInfo {
    bool started = false;
    bool invalid_limits = false;
    std::uint32_t max_states = 16;
    std::uint64_t max_steps = 65536;
    // Counts include provisional loop exploration. The step budget triggers
    // widening; collection continues and executed_steps can exceed max_steps.
    std::uint64_t executed_steps = 0;
    std::uint64_t peak_candidate_states = 0;
    std::uint64_t widening_operations = 0;
    qvector<FlowPrecisionEvent> precision_events;

    [[nodiscard]] bool has_loss(FlowPrecisionLoss reason) const noexcept {
        return std::any_of(precision_events.begin(), precision_events.end(),
            [reason](const FlowPrecisionEvent& event) { return event.reason == reason; });
    }
    [[nodiscard]] bool budget_exhausted() const noexcept {
        return has_loss(FlowPrecisionLoss::StateBudget) || has_loss(FlowPrecisionLoss::StepBudget);
    }
    [[nodiscard]] bool precision_lost() const noexcept { return !precision_events.empty(); }
};

/// Context-independent collection diagnostics retained by synthesis results.
struct FlowAnalysisDiagnostic {
    ea_t func_ea = BADADDR;
    int var_idx = -1;
    FlowAnalysisInfo analysis;
};

/// Collection of accesses for analysis
struct AccessPattern {
    ea_t                    func_ea;        // Function being analyzed
    qstring                 var_name;       // Variable name
    int                     var_idx;        // Variable index in lvar array
    tinfo_t                 original_type;  // Original type before synthesis
    qvector<FieldAccess>    accesses;       // All observed accesses
    FlowAnalysisInfo        flow_analysis;  // Collection precision and configured budgets
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
        const auto access_end = checked_interval_end(access.offset, access.size);
        if (accesses.empty()) {
            min_offset = access.offset;
            max_offset = access_end.value_or(
                std::numeric_limits<sval_t>::max());
        } else {
            min_offset = std::min(min_offset, access.offset);
            max_offset = std::max(
                max_offset,
                access_end.value_or(std::numeric_limits<sval_t>::max()));
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

/// Stable percentage representation used by the public 0..100 confidence
/// threshold.  Direct evidence is never discarded by this score; it controls
/// only optional aggregate/covering/padding candidates.
[[nodiscard]] inline constexpr std::uint8_t type_confidence_percent(
    TypeConfidence confidence) noexcept {
    switch (confidence) {
        case TypeConfidence::Low:     return 25;
        case TypeConfidence::Medium:  return 50;
        case TypeConfidence::High:    return 75;
        case TypeConfidence::Certain: return 100;
        default:                      return 0;
    }
}

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
    struct UnionMember {
        qstring name;
        NameMetadata naming;
        sval_t offset = 0;
        std::uint32_t size = 0;
        tinfo_t type;
        qstring comment;
    };

    qstring         name;           // Field name (e.g., "field_10")
    NameMetadata    naming;         // Name provenance and strength
    sval_t          offset;         // Byte offset in structure
    std::uint32_t   size;           // Field size
    tinfo_t         type;           // Field type
    SemanticType    semantic;       // Semantic classification
    qstring         comment;        // Auto-generated comment
    bool            is_padding;     // True if this is alignment padding
    bool            is_union_candidate;  // True if overlapping accesses detected
    bool            is_array;       // True if this is an array field
    std::uint32_t   array_count;    // Number of array elements (1 if not array)
    bool            is_bitfield;    // True if this is a bitfield member
    std::uint16_t   bit_offset;     // Bit offset within the storage unit
    std::uint16_t   bit_size;       // Bit size of the bitfield
    TypeConfidence  confidence;     // How confident we are in the type
    qvector<FieldAccess> source_accesses;  // Accesses that contributed to this field
    qvector<UnionMember> union_members;    // Alternatives when this field is a union

    SynthField()
        : naming{GeneratedNameKind::Field, NameOrigin::Unknown, NameConfidence::Low, false}
        , offset(0)
        , size(0)
        , semantic(SemanticType::Unknown)
        , is_padding(false)
        , is_union_candidate(false)
        , is_array(false)
        , array_count(1)
        , is_bitfield(false)
        , bit_offset(0)
        , bit_size(0)
        , confidence(TypeConfidence::Medium) {}

    static SynthField create_padding(sval_t off, std::uint32_t sz) {
        SynthField f;
        f.name.sprnt("__pad_%X", static_cast<unsigned>(off));
        f.naming.kind = GeneratedNameKind::Padding;
        f.naming.origin = NameOrigin::GeneratedFallback;
        f.naming.confidence = NameConfidence::High;
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
        f.naming.kind = GeneratedNameKind::RawBytes;
        f.naming.origin = NameOrigin::GeneratedFallback;
        f.naming.confidence = NameConfidence::Medium;
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
        f.naming.kind = GeneratedNameKind::ArrayField;
        f.naming.origin = NameOrigin::GeneratedFallback;
        f.naming.confidence = NameConfidence::Medium;
        f.is_array = true;
        f.array_count = count;

        // Calculate size
        size_t elem_size = elem_type.get_size();
        if (elem_size != BADSIZE &&
            elem_size <= std::numeric_limits<std::uint32_t>::max()) {
            f.size = checked_u32_product(
                static_cast<std::uint32_t>(elem_size), count).value_or(0);
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

    /// Create a bitfield member
    static SynthField create_bitfield(sval_t off, std::uint32_t storage_size,
                                      std::uint16_t bit_off, std::uint16_t bit_sz) {
        SynthField f;
        f.offset = off;
        f.naming.kind = GeneratedNameKind::Bitfield;
        f.naming.origin = NameOrigin::GeneratedFallback;
        f.naming.confidence = NameConfidence::Medium;
        f.size = storage_size;
        f.is_bitfield = true;
        f.bit_offset = bit_off;
        f.bit_size = bit_sz;
        f.semantic = SemanticType::UnsignedInteger;
        f.confidence = TypeConfidence::Medium;
        f.name.sprnt("bf_%X_%u", static_cast<unsigned>(off), static_cast<unsigned>(bit_off));
        return f;
    }
};

/// A slot in a synthesized vtable
struct VTableSlot {
    std::uint32_t   index;          // Slot index (0, 1, 2, ...)
    sval_t          offset;         // Byte offset in vtable
    tinfo_t         func_type;      // Function pointer type
    qstring         name;           // Slot name
    NameMetadata    naming;         // Slot name provenance
    qvector<ea_t>   call_sites;     // Where this slot is called
    qstring         signature_hint; // Recovered signature hint

    VTableSlot()
        : index(0)
        , offset(0)
        , naming{GeneratedNameKind::VTableSlot, NameOrigin::Unknown, NameConfidence::Low, false} {}
};

/// A synthesized vtable structure
struct SynthVTable {
    qstring                 name;           // VTable structure name
    NameMetadata            naming;         // Type name provenance
    tid_t                   tid;            // Type ID in IDB
    qvector<VTableSlot>     slots;          // Function pointer slots
    ea_t                    source_func;    // Function where vtable was detected
    sval_t                  parent_offset;  // Offset in parent struct (usually 0)

    SynthVTable()
        : naming{GeneratedNameKind::VTable, NameOrigin::Unknown, NameConfidence::Low, false}
        , tid(BADADDR)
        , source_func(BADADDR)
        , parent_offset(0) {}

    [[nodiscard]] std::size_t slot_count() const noexcept {
        return slots.size();
    }
};

/// A complete synthesized structure
struct SynthStruct {
    qstring                 name;           // Structure name
    NameMetadata            naming;         // Type name provenance
    tid_t                   tid;            // Type ID in IDB
    qvector<SynthField>     fields;         // All fields
    std::uint32_t           size;           // Total size
    std::uint32_t           alignment;      // Effective structure alignment in bytes
    std::optional<std::uint32_t> packing;   // Explicit packing cap in bytes; nullopt = ABI default
    ea_t                    source_func;    // Function where struct was synthesized
    qstring                 source_var;     // Variable name that was analyzed
    std::optional<SynthVTable> vtable;      // Associated vtable if any
    qvector<ea_t>           provenance;     // All functions contributing to this type

    SynthStruct()
        : naming{GeneratedNameKind::RootStruct, NameOrigin::Unknown, NameConfidence::Low, false}
        , tid(BADADDR)
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

/// Information about a detected sub-structure embedded in a parent struct
struct SubStructInfo {
    SynthStruct     structure;
    sval_t          parent_offset = 0;
    int             source_var_idx = -1;
    std::optional<lvar_locator_t> source_locator;
    qstring         field_name;
    NameMetadata    field_naming;
    qvector<SubStructInfo> children;
};

enum class ResourceLimitKind : std::uint8_t {
    Accesses,
    Candidates,
    Fields,
    ArrayElements,
    StructureSize,
    ConstraintPairs,
    UnionAlternatives,
    SolverTimeout,
    SolverMemory,
};

[[nodiscard]] inline constexpr const char* resource_limit_kind_str(
    ResourceLimitKind kind) noexcept
{
    switch (kind) {
        case ResourceLimitKind::Accesses:          return "accesses";
        case ResourceLimitKind::Candidates:        return "candidates";
        case ResourceLimitKind::Fields:            return "fields";
        case ResourceLimitKind::ArrayElements:     return "array_elements";
        case ResourceLimitKind::StructureSize:     return "structure_size";
        case ResourceLimitKind::ConstraintPairs:   return "constraint_pairs";
        case ResourceLimitKind::UnionAlternatives: return "union_alternatives";
        case ResourceLimitKind::SolverTimeout:     return "solver_timeout";
        case ResourceLimitKind::SolverMemory:      return "solver_memory";
        default:                                   return "unknown";
    }
}

struct ResourceLimitViolation {
    ResourceLimitKind kind = ResourceLimitKind::Candidates;
    std::uint64_t configured_limit = 0;
    std::uint64_t observed_value = 0;
    qstring phase;
};

class ResourceLimitException final : public std::runtime_error {
public:
    ResourceLimitException(ResourceLimitKind kind,
                           std::uint64_t configured_limit,
                           std::uint64_t observed_value,
                           const char* phase,
                           const std::string& message)
        : std::runtime_error(message)
        , violation{kind, configured_limit, observed_value, qstring(phase)} {}

    ResourceLimitViolation violation;
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
    ResourceLimitExceeded,
    InternalError,
    // Z3-specific errors
    Z3Timeout,              // Z3 solver timed out
    Z3OutOfMemory,          // Z3 ran out of memory
    Z3Unsat,                // Z3 constraints are unsatisfiable
    Z3Disabled,             // Z3 is disabled in configuration
    ExperimentalFeatureDisabled // Explicitly quarantined adjunct is disabled
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
    ResourceLimit,          // Host-side synthesis limit exceeded
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
    std::optional<ResourceLimitViolation> resource_limit;

    qvector<FlowAnalysisDiagnostic> flow_diagnostics;
    bool arrays_suppressed_by_flow_budget = false;

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
    // Index in the post-application decompilation generation. A durable
    // application whose locator can no longer be resolved reports -1.
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
    bool                     incomplete;
    qstring                  error_message;

    PropagationResult()
        : success_count(0)
        , failure_count(0)
        , incomplete(false) {}

    [[nodiscard]] bool can_record_site() const noexcept {
        return sites.size() < MAX_FIELDS;
    }

    void mark_incomplete(const char* reason) noexcept {
        incomplete = true;
        try {
            if (error_message.empty() && reason != nullptr) {
                error_message = reason;
            }
        } catch (...) {
        }
    }

    void add_success(PropagationSite&& site) {
        if (!can_record_site()) {
            mark_incomplete("propagation site limit exceeded");
            return;
        }
        site.success = true;
        sites.push_back(std::move(site));
        ++success_count;
    }

    void add_failure(PropagationSite&& site) {
        if (!can_record_site()) {
            mark_incomplete("propagation site limit exceeded");
            return;
        }
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
        case SynthError::ResourceLimitExceeded: return "Synthesis resource limit exceeded";
        case SynthError::InternalError:         return "Internal error";
        case SynthError::Z3Timeout:             return "Z3 solver timed out";
        case SynthError::Z3OutOfMemory:         return "Z3 ran out of memory";
        case SynthError::Z3Unsat:               return "Z3 constraints unsatisfiable";
        case SynthError::Z3Disabled:            return "Z3 synthesis is disabled";
        case SynthError::ExperimentalFeatureDisabled:
            return "Experimental feature is disabled";
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
        case Z3SynthesisStatus::ResourceLimit:      return "resource_limit";
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

/// Validate an ABI alignment before it is stored in SynthOptions::alignment or
/// embedded in integer-valued solver constraints. The configured value must be
/// positive, a power of two, and representable by the public int field.
[[nodiscard]] inline constexpr bool is_valid_abi_alignment(
    std::int64_t alignment) noexcept
{
    if (alignment <= 0 ||
        alignment > static_cast<std::int64_t>(std::numeric_limits<int>::max())) {
        return false;
    }
    const auto value = static_cast<std::uint64_t>(alignment);
    return (value & (value - 1)) == 0;
}

/// Checked arithmetic in IDA's signed address-offset domain. The
/// implementation avoids non-portable wider integer types and is therefore
/// shared by MSVC, Clang, and GCC builds.
[[nodiscard]] inline constexpr std::optional<sval_t> checked_sval_add(
    sval_t lhs, sval_t rhs) noexcept {
    constexpr sval_t kMin = std::numeric_limits<sval_t>::min();
    constexpr sval_t kMax = std::numeric_limits<sval_t>::max();
    if ((rhs > 0 && lhs > kMax - rhs) ||
        (rhs < 0 && lhs < kMin - rhs)) {
        return std::nullopt;
    }
    return static_cast<sval_t>(lhs + rhs);
}

[[nodiscard]] inline constexpr std::optional<sval_t> checked_sval_sub(
    sval_t lhs, sval_t rhs) noexcept {
    constexpr sval_t kMin = std::numeric_limits<sval_t>::min();
    constexpr sval_t kMax = std::numeric_limits<sval_t>::max();
    if ((rhs > 0 && lhs < kMin + rhs) ||
        (rhs < 0 && lhs > kMax + rhs)) {
        return std::nullopt;
    }
    return static_cast<sval_t>(lhs - rhs);
}

[[nodiscard]] inline constexpr std::optional<sval_t> checked_sval_mul(
    sval_t lhs, sval_t rhs) noexcept {
    using U = std::make_unsigned_t<sval_t>;
    constexpr U kPositiveLimit =
        static_cast<U>(std::numeric_limits<sval_t>::max());
    constexpr U kNegativeLimit = kPositiveLimit + U{1};
    const bool negative = (lhs < 0) != (rhs < 0);
    const U lhs_bits = static_cast<U>(lhs);
    const U rhs_bits = static_cast<U>(rhs);
    const U lhs_magnitude = lhs < 0 ? U{0} - lhs_bits : lhs_bits;
    const U rhs_magnitude = rhs < 0 ? U{0} - rhs_bits : rhs_bits;
    const U limit = negative ? kNegativeLimit : kPositiveLimit;
    if (lhs_magnitude != 0 && rhs_magnitude > limit / lhs_magnitude) {
        return std::nullopt;
    }
    const U magnitude = lhs_magnitude * rhs_magnitude;
    if (!negative) {
        return static_cast<sval_t>(magnitude);
    }
    if (magnitude == kNegativeLimit) {
        return std::numeric_limits<sval_t>::min();
    }
    return static_cast<sval_t>(-static_cast<sval_t>(magnitude));
}

[[nodiscard]] inline constexpr std::optional<sval_t> checked_sval_from_u64(
    std::uint64_t value) noexcept {
    if (value > static_cast<std::uint64_t>(
            std::numeric_limits<sval_t>::max())) {
        return std::nullopt;
    }
    return static_cast<sval_t>(value);
}

/// Align offset to boundary
[[nodiscard]] inline sval_t align_offset(sval_t offset, std::uint32_t alignment) noexcept {
    if (alignment == 0 || (alignment & (alignment - 1)) != 0) {
        return std::numeric_limits<sval_t>::max();
    }
    const sval_t adjustment = static_cast<sval_t>(alignment - 1);
    if (offset > std::numeric_limits<sval_t>::max() - adjustment) {
        return std::numeric_limits<sval_t>::max();
    }
    return (offset + adjustment) & ~adjustment;
}

/// One selected storage location whose natural alignment constrains the
/// maximum physically representable structure packing cap.
struct PackingAlignmentRequirement {
    sval_t offset = 0;
    std::uint32_t natural_alignment = 1;
};

[[nodiscard]] inline bool is_valid_packing_value(std::uint32_t value) noexcept {
    return value != 0 && (value & (value - 1)) == 0;
}

/// Select the largest configured packing cap for which every selected field
/// is aligned to min(natural_alignment, packing). Invalid/non-power-of-two
/// options are ignored. Complexity: O(k log k + k*n) time and O(k) space.
[[nodiscard]] inline std::optional<std::uint32_t> canonical_packing_cap(
    std::span<const PackingAlignmentRequirement> requirements,
    std::span<const std::uint32_t> packing_options,
    std::uint32_t maximum_cap) {
    if (maximum_cap == 0) {
        return std::nullopt;
    }

    std::vector<std::uint32_t> options;
    options.reserve(packing_options.size());
    for (std::uint32_t value : packing_options) {
        if (is_valid_packing_value(value) && value <= maximum_cap) {
            options.push_back(value);
        }
    }
    std::sort(options.begin(), options.end(), std::greater<std::uint32_t>());
    options.erase(std::unique(options.begin(), options.end()), options.end());

    for (std::uint32_t packing : options) {
        const bool valid = std::all_of(
            requirements.begin(), requirements.end(),
            [packing](const PackingAlignmentRequirement& requirement) {
                const std::uint32_t natural =
                    std::max<std::uint32_t>(1, requirement.natural_alignment);
                const std::uint32_t effective = std::min(natural, packing);
                return requirement.offset % static_cast<sval_t>(effective) == 0;
            });
        if (valid) {
            return packing;
        }
    }
    return std::nullopt;
}

[[nodiscard]] inline std::uint32_t effective_alignment_for_packing(
    std::span<const PackingAlignmentRequirement> requirements,
    std::uint32_t packing) noexcept {
    packing = std::max<std::uint32_t>(1, packing);
    std::uint32_t result = 1;
    for (const auto& requirement : requirements) {
        result = std::max(
            result,
            std::min(std::max<std::uint32_t>(1, requirement.natural_alignment),
                     packing));
    }
    return result;
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
[[nodiscard]] inline int type_priority_score(const tinfo_t& type) {
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

namespace detail {

enum class EvidenceTypeClass : std::uint8_t {
    Unknown,
    Integer,
    Floating,
    Pointer,
    Aggregate,
};

[[nodiscard]] inline EvidenceTypeClass evidence_type_class(
    const FieldAccess& access) {
    if (!access.inferred_type.empty()) {
        if (access.inferred_type.is_ptr() || access.inferred_type.is_funcptr() ||
            access.inferred_type.is_func()) {
            return EvidenceTypeClass::Pointer;
        }
        if (access.inferred_type.is_floating()) {
            return EvidenceTypeClass::Floating;
        }
        if (access.inferred_type.is_struct() || access.inferred_type.is_union() ||
            access.inferred_type.is_array()) {
            return EvidenceTypeClass::Aggregate;
        }
        const size_t size = access.inferred_type.get_size();
        if (size != BADSIZE && size > 0) {
            return EvidenceTypeClass::Integer;
        }
    }

    switch (access.semantic_type) {
        case SemanticType::Integer:
        case SemanticType::UnsignedInteger:
            return EvidenceTypeClass::Integer;
        case SemanticType::Float:
        case SemanticType::Double:
            return EvidenceTypeClass::Floating;
        case SemanticType::Pointer:
        case SemanticType::FunctionPointer:
        case SemanticType::VTablePointer:
            return EvidenceTypeClass::Pointer;
        case SemanticType::Array:
        case SemanticType::NestedStruct:
            return EvidenceTypeClass::Aggregate;
        default:
            return EvidenceTypeClass::Unknown;
    }
}

} // namespace detail

inline bool field_access_evidence_compatible(
    const FieldAccess& lhs, const FieldAccess& rhs) {
    const auto lhs_class = detail::evidence_type_class(lhs);
    const auto rhs_class = detail::evidence_type_class(rhs);
    return lhs_class == detail::EvidenceTypeClass::Unknown ||
           rhs_class == detail::EvidenceTypeClass::Unknown ||
           lhs_class == rhs_class;
}

inline void merge_field_access_evidence(
    FieldAccess& dst, const FieldAccess& src) {
    const bool dst_reads = dst.access_type == AccessType::Read ||
                           dst.access_type == AccessType::ReadWrite;
    const bool dst_writes = dst.access_type == AccessType::Write ||
                            dst.access_type == AccessType::ReadWrite;
    const bool src_reads = src.access_type == AccessType::Read ||
                           src.access_type == AccessType::ReadWrite;
    const bool src_writes = src.access_type == AccessType::Write ||
                            src.access_type == AccessType::ReadWrite;
    if ((dst_reads || src_reads) && (dst_writes || src_writes)) {
        dst.access_type = AccessType::ReadWrite;
    } else if (dst.access_type == AccessType::Unknown) {
        dst.access_type = src.access_type;
    }

    if (semantic_priority(src.semantic_type) >
        semantic_priority(dst.semantic_type)) {
        dst.semantic_type = src.semantic_type;
    }
    if (!src.inferred_type.empty()) {
        dst.inferred_type = resolve_type_conflict(
            dst.inferred_type, src.inferred_type);
    }
    if (src.is_vtable_access) {
        dst.is_vtable_access = true;
        dst.vtable_slot = src.vtable_slot;
    }
    if (src.nested_info && !dst.nested_info) {
        dst.nested_info = src.nested_info;
    }
    for (const auto& bitfield : src.bitfields) {
        dst.add_bitfield(bitfield);
    }
    for (std::uint64_t value : src.observed_constants) {
        dst.add_observed_constant(value);
    }
    dst.is_zero_init = dst.is_zero_init || src.is_zero_init;
    dst.is_call_argument = dst.is_call_argument || src.is_call_argument;

    if (src.array_stride_hint.has_value()) {
        if (!dst.array_stride_hint.has_value()) {
            dst.array_stride_hint = src.array_stride_hint;
        } else if (*dst.array_stride_hint != *src.array_stride_hint) {
            dst.array_stride_hint.reset();
        }
    }
    if (src.base_indirection.has_value()) {
        if (!dst.base_indirection.has_value()) {
            dst.base_indirection = src.base_indirection;
        } else if (*dst.base_indirection != *src.base_indirection) {
            dst.base_indirection.reset();
        }
    }
}

inline bool canonical_field_access_less(
    const FieldAccess& lhs, const FieldAccess& rhs) {
    if (lhs.offset != rhs.offset) return lhs.offset < rhs.offset;
    if (lhs.size != rhs.size) return lhs.size < rhs.size;
    const auto lhs_class = detail::evidence_type_class(lhs);
    const auto rhs_class = detail::evidence_type_class(rhs);
    if (lhs_class != rhs_class) return lhs_class < rhs_class;
    if (lhs.semantic_type != rhs.semantic_type) {
        return lhs.semantic_type < rhs.semantic_type;
    }
    if (lhs.source_func_ea != rhs.source_func_ea) {
        return lhs.source_func_ea < rhs.source_func_ea;
    }
    return lhs.insn_ea < rhs.insn_ea;
}

/// Generate unique structure name
[[nodiscard]] qstring generate_struct_name(ea_t func_ea, int index = 0);

/// Generate unique vtable name
[[nodiscard]] qstring generate_vtable_name(ea_t func_ea, int index = 0);

/// Generate field name from offset
[[nodiscard]] qstring generate_field_name(sval_t offset,
                                          SemanticType semantic = SemanticType::Unknown,
                                          std::uint32_t size = 0);

} // namespace structor
