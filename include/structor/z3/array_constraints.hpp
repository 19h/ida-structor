#pragma once

#include <z3++.h>
#include <optional>
#include "structor/synth_types.hpp"
#include "structor/z3/context.hpp"
#include "structor/z3/type_encoding.hpp"

namespace structor::z3 {

/// Represents a detected array pattern
struct ArrayCandidate {
    sval_t base_offset;           // Starting offset of array
    uint32_t stride;              // Bytes between elements (== sizeof(element))
    uint32_t element_count;       // Number of elements
    tinfo_t element_type;         // Type of each element
    qvector<sval_t> member_offsets;  // Original offsets covered by this array

    // For stride > access_size cases: synthetic element struct
    bool needs_element_struct = false;
    uint32_t inner_access_offset = 0;  // Offset of accessed subfield within element
    uint32_t inner_access_size = 0;    // Size of the inner access

    // Confidence in the detection
    TypeConfidence confidence = TypeConfidence::Medium;

    ArrayCandidate()
        : base_offset(0)
        , stride(0)
        , element_count(0) {}

    /// C array semantics check: stride must equal element size
    [[nodiscard]] bool is_valid_c_array() const noexcept {
        if (element_type.empty()) return false;
        return stride == element_type.get_size();
    }

    /// Calculate total array size in bytes
    [[nodiscard]] uint32_t total_size() const noexcept {
        return stride * element_count;
    }

    /// Check if an offset falls within this array
    [[nodiscard]] bool contains_offset(sval_t offset) const noexcept {
        return offset >= base_offset &&
               offset < base_offset + static_cast<sval_t>(total_size());
    }

    /// Get the element index for an offset
    [[nodiscard]] std::optional<uint32_t> get_element_index(sval_t offset) const noexcept {
        if (!contains_offset(offset)) return std::nullopt;
        sval_t relative = offset - base_offset;
        if (relative % stride != static_cast<sval_t>(inner_access_offset)) {
            return std::nullopt;  // Not at the expected inner offset
        }
        return static_cast<uint32_t>(relative / stride);
    }

    /// Generate description string
    [[nodiscard]] qstring description() const {
        qstring desc;
        desc.sprnt("Array[%u] at 0x%llX, stride=%u",
                  element_count,
                  static_cast<unsigned long long>(base_offset),
                  stride);
        if (needs_element_struct) {
            desc.cat_sprnt(" (element struct, inner@0x%X)", inner_access_offset);
        }
        return desc;
    }
};

/// Configuration for array detection
struct ArrayDetectionConfig {
    int min_elements = 3;                    // Minimum elements to form an array
    int max_gap_ratio = 2;                   // Max allowed gap as multiple of stride
    bool require_consistent_types = true;    // All elements must have same type
    bool detect_arrays_of_structs = true;    // When stride > access_size, create element struct
    bool use_symbolic_indices = true;        // Use Z3 for affine index detection
    uint32_t max_stride = 4096;              // Maximum allowed stride
    uint32_t max_elements = 10000;           // Maximum array elements to consider
};

/// Builds Z3 constraints for array pattern detection
class ArrayConstraintBuilder {
public:
    ArrayConstraintBuilder(Z3Context& ctx, const ArrayDetectionConfig& config = {});

    /// Analyze accesses and detect array patterns
    /// Returns all detected array candidates, sorted by base offset
    [[nodiscard]] qvector<ArrayCandidate> detect_arrays(
        const qvector<FieldAccess>& accesses
    );

    /// Build Z3 constraint for affine index detection
    /// Solves: offset[i] = base + index[i] * stride + inner_offset
    /// where index[i] are unknown integers
    [[nodiscard]] std::optional<ArrayCandidate> detect_symbolic_array(
        const qvector<const FieldAccess*>& accesses
    );

    /// Handle stride > access_size: create element struct type
    [[nodiscard]] tinfo_t create_element_struct_type(
        uint32_t stride,
        uint32_t inner_offset,
        const tinfo_t& inner_type
    );

    /// Use Z3 to find optimal stride when simple AP detection fails
    [[nodiscard]] std::optional<ArrayCandidate> solve_stride_z3(
        const qvector<const FieldAccess*>& accesses
    );

    /// Get statistics about last detection
    struct DetectionStats {
        int arrays_found = 0;
        int elements_covered = 0;
        int symbolic_detections = 0;
        int struct_element_arrays = 0;
    };
    [[nodiscard]] const DetectionStats& stats() const noexcept { return stats_; }

private:
    Z3Context& ctx_;
    ArrayDetectionConfig config_;
    DetectionStats stats_;

    /// Pre-filter: group accesses by size (potential array elements)
    [[nodiscard]] std::unordered_map<uint32_t, qvector<const FieldAccess*>>
    group_by_size(const qvector<FieldAccess>& accesses);

    /// Fast path: check if offsets form perfect arithmetic progression
    [[nodiscard]] std::optional<std::pair<sval_t, uint32_t>>  // (base, stride)
    find_arithmetic_progression(const qvector<sval_t>& offsets);

    /// Verify type consistency for potential array elements
    [[nodiscard]] bool verify_type_consistency(
        const qvector<const FieldAccess*>& accesses
    );

    /// Merge compatible array candidates (overlapping ranges)
    void merge_overlapping_arrays(qvector<ArrayCandidate>& candidates);

    /// Create array candidate from detected parameters
    [[nodiscard]] ArrayCandidate create_candidate(
        sval_t base,
        uint32_t stride,
        uint32_t count,
        const qvector<const FieldAccess*>& accesses
    );

    /// Calculate GCD of all offset differences (for stride detection)
    [[nodiscard]] uint32_t calculate_gcd_stride(const qvector<sval_t>& offsets) const;

    /// Check if accesses could form struct-of-arrays pattern
    [[nodiscard]] bool check_struct_element_pattern(
        const qvector<const FieldAccess*>& accesses,
        uint32_t stride,
        uint32_t& inner_offset
    );
};

/// Quick check: can these offsets possibly form an array?
[[nodiscard]] inline bool could_be_array(
    const qvector<sval_t>& offsets,
    uint32_t element_size,
    int min_elements = 3)
{
    if (static_cast<int>(offsets.size()) < min_elements) {
        return false;
    }

    // Check if offsets could form arithmetic progression with stride >= element_size
    if (offsets.size() < 2) return false;

    // Sort offsets
    qvector<sval_t> sorted = offsets;
    std::sort(sorted.begin(), sorted.end());

    // Check first difference as potential stride
    sval_t potential_stride = sorted[1] - sorted[0];
    if (potential_stride <= 0 || potential_stride < static_cast<sval_t>(element_size)) {
        return false;
    }

    // Quick check: all differences should be multiples of potential stride
    for (size_t i = 1; i < sorted.size(); ++i) {
        sval_t diff = sorted[i] - sorted[0];
        if (diff % potential_stride != 0) {
            return false;
        }
    }

    return true;
}

/// Find the GCD of two integers
[[nodiscard]] inline uint32_t gcd(uint32_t a, uint32_t b) {
    while (b != 0) {
        uint32_t t = b;
        b = a % b;
        a = t;
    }
    return a;
}

/// Calculate the GCD of a vector of values
[[nodiscard]] inline uint32_t gcd_vector(const qvector<uint32_t>& values) {
    if (values.empty()) return 0;
    uint32_t result = values[0];
    for (size_t i = 1; i < values.size(); ++i) {
        result = gcd(result, values[i]);
        if (result == 1) break;
    }
    return result;
}

} // namespace structor::z3
