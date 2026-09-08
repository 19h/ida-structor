#pragma once

#include "structor/z3/instruction_semantics.hpp"

#include <cstdint>
#include <limits>
#include <optional>
#include <unordered_map>
#include <vector>

namespace structor::z3 {

/// Absolute data origin plus a signed byte displacement and access width.
/// Function entry addresses do not stand for pointer-relative object origins.
using MemoryLocationKey = MemoryTypeVariableKey;

struct MemoryLocationKeyHash {
    std::size_t operator()(const MemoryLocationKey& key) const noexcept {
        return std::hash<std::uint64_t>{}(key.base) ^
               (std::hash<std::int64_t>{}(key.offset) << 1) ^
               (std::hash<std::uint32_t>{}(key.size) << 2);
    }
};

/// Complete key equality determines identity, including when hashes collide.
template<class Value, class Hash = MemoryLocationKeyHash>
using ExactMemoryLocationMap = std::unordered_map<MemoryLocationKey, Value, Hash>;
using InferredMemoryTypes = ExactMemoryLocationMap<InferredType>;

/// Validate an absolute byte interval without pointer wrap or signed overflow.
/// BADADDR is reserved; pointer_size is the analyzed target's width in bytes.
[[nodiscard]] inline bool valid_memory_location(
    const MemoryLocationKey& key, std::uint32_t pointer_size) noexcept
{
    if (key.size == 0 || (pointer_size != 4 && pointer_size != 8)) return false;
    const std::uint64_t maximum = pointer_size == 4
        ? std::numeric_limits<std::uint32_t>::max()
        : std::numeric_limits<std::uint64_t>::max() - 1;
    if (key.base > maximum) return false;
    std::uint64_t address = key.base;
    if (key.offset < 0) {
        const auto magnitude = std::uint64_t{0} - static_cast<std::uint64_t>(key.offset);
        if (magnitude > address) return false;
        address -= magnitude;
    } else {
        const auto displacement = static_cast<std::uint64_t>(key.offset);
        if (displacement > maximum - address) return false;
        address += displacement;
    }
    return static_cast<std::uint64_t>(key.size - 1) <= maximum - address;
}

template<class Hash>
[[nodiscard]] inline std::optional<InferredType> find_memory_type(
    const ExactMemoryLocationMap<InferredType, Hash>& types,
    const MemoryLocationKey& location)
{
    const auto found = types.find(location);
    return found == types.end() ? std::nullopt
        : std::optional<InferredType>(found->second.snapshot());
}

/// Compatibility lookup has no width information. Multiple widths are
/// ambiguous even when their represented types happen to compare equal.
template<class Hash>
[[nodiscard]] inline std::optional<InferredType> find_unambiguous_memory_type(
    const ExactMemoryLocationMap<InferredType, Hash>& types,
    std::uint64_t base, std::int64_t offset)
{
    const InferredType* match = nullptr;
    for (const auto& [location, type] : types) {
        if (location.base != base || location.offset != offset) continue;
        if (match != nullptr) return std::nullopt;
        match = &type;
    }
    return match ? std::optional<InferredType>(match->snapshot()) : std::nullopt;
}

enum class MemoryInferenceIssue {
    InvalidLocation,
    InconsistentVariableLocation,
    InsufficientConcreteEvidence,
    ConflictingConcreteViews,
    UnsupportedModelValue,
};

struct MemoryInferenceDiagnostic {
    std::optional<MemoryLocationKey> location;
    MemoryInferenceIssue issue = MemoryInferenceIssue::InsufficientConcreteEvidence;
    // Distinct concrete views, not independent observations or confidence.
    std::vector<InferredType> concrete_views;
};

enum class MemoryTypeEvidenceKind {
    HardConcreteConstraint,
    SoftConcretePreference,
};

struct MemoryTypeProvenance {
    MemoryTypeEvidenceKind kind = MemoryTypeEvidenceKind::SoftConcretePreference;
    // Distinct recorded constraint sites, without an independence assumption.
    std::vector<ea_t> source_sites;
};

struct MemoryTypeEvidenceResult {
    InferredMemoryTypes types;
    ExactMemoryLocationMap<MemoryTypeProvenance> provenance;
    std::vector<MemoryInferenceDiagnostic> diagnostics;
};

/// Publish only exact memory variables having one concrete view supported by
/// their actual constraints and matched by the model. Size/category-only facts
/// never justify an arbitrary concrete model choice. Conflicts are omitted.
[[nodiscard]] MemoryTypeEvidenceResult extract_memory_type_evidence(
    const TypeConstraintSet& constraints, TypeLatticeEncoder& encoder,
    const ::z3::model& model, std::uint32_t pointer_size);

} // namespace structor::z3
