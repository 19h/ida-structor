#pragma once

#include <z3++.h>
#include "structor/synth_types.hpp"
#include "structor/cross_function_analyzer.hpp"
#include "structor/z3/context.hpp"
#include "structor/z3/type_encoding.hpp"
#include <optional>
#include <unordered_set>

namespace structor::z3 {

/// A candidate field that may or may not appear in the final struct
struct FieldCandidate {
    int id;                          // Unique identifier
    sval_t offset;                   // Fixed offset (from access observation)
    uint32_t size;                   // Size in bytes
    TypeCategory type_category;      // Inferred type category
    ExtendedTypeInfo extended_type;  // Extended type info

    // Source tracking
    qvector<int> source_access_indices;
    ea_t primary_func_ea = BADADDR;
    TypeConfidence confidence = TypeConfidence::Medium;

    // Candidate classification
    enum class Kind {
        DirectAccess,    // Directly observed access
        CoveringField,   // Larger field that covers multiple accesses
        ArrayElement,    // Part of a detected array
        ArrayField,      // The entire array as a single field
        PaddingField,    // Inferred padding
        UnionAlternative // One alternative in a union
    };
    Kind kind = Kind::DirectAccess;

    // For array candidates
    std::optional<uint32_t> array_element_count;
    std::optional<uint32_t> array_stride;

    // For union candidates
    std::optional<int> union_group_id;

    FieldCandidate()
        : id(-1)
        , offset(0)
        , size(0)
        , type_category(TypeCategory::Unknown) {}

    /// Check if this candidate overlaps with another
    [[nodiscard]] bool overlaps(const FieldCandidate& other) const noexcept {
        if (offset >= other.offset + static_cast<sval_t>(other.size)) return false;
        if (other.offset >= offset + static_cast<sval_t>(size)) return false;
        return true;
    }

    /// Check if this candidate contains another
    [[nodiscard]] bool contains(const FieldCandidate& other) const noexcept {
        return offset <= other.offset &&
               offset + static_cast<sval_t>(size) >= other.offset + static_cast<sval_t>(other.size);
    }

    /// Check if this is an array candidate
    [[nodiscard]] bool is_array() const noexcept {
        return kind == Kind::ArrayElement || kind == Kind::ArrayField;
    }

    /// Get end offset (exclusive)
    [[nodiscard]] sval_t end_offset() const noexcept {
        return offset + static_cast<sval_t>(size);
    }

    /// Get alignment requirement
    [[nodiscard]] uint32_t alignment() const noexcept {
        if (size >= 8) return 8;
        if (size >= 4) return 4;
        if (size >= 2) return 2;
        return 1;
    }
};

/// Configuration for candidate generation
struct CandidateGenerationConfig {
    bool generate_covering_candidates = true;  // Larger fields covering multiple accesses
    bool generate_array_candidates = true;     // Array field candidates
    bool generate_padding_candidates = true;   // Padding between fields
    uint32_t max_covering_size = 64;           // Max size for covering candidates
    uint32_t min_array_elements = 3;           // Minimum elements for array detection
    bool merge_adjacent_same_type = true;      // Merge adjacent same-type fields
};

/// Result of candidate overlap analysis
struct OverlapAnalysis {
    qvector<std::pair<int, int>> overlapping_pairs;  // (candidate_id, candidate_id)
    qvector<qvector<int>> overlap_groups;            // Groups of mutually overlapping candidates

    [[nodiscard]] bool has_overlaps() const noexcept {
        return !overlapping_pairs.empty();
    }
};

/// Generates the universe of candidate fields from access patterns
class FieldCandidateGenerator {
public:
    FieldCandidateGenerator(
        Z3Context& ctx,
        const CandidateGenerationConfig& config = {}
    );

    /// Generate all candidates from a unified access pattern
    [[nodiscard]] qvector<FieldCandidate> generate(
        const UnifiedAccessPattern& pattern
    );

    /// Analyze overlaps between candidates
    [[nodiscard]] OverlapAnalysis analyze_overlaps(
        const qvector<FieldCandidate>& candidates
    ) const;

    /// Get type encoder for external use
    [[nodiscard]] TypeEncoder& type_encoder() noexcept { return type_encoder_; }

private:
    Z3Context& ctx_;
    CandidateGenerationConfig config_;
    TypeEncoder type_encoder_;
    int next_id_ = 0;

    /// Generate one candidate per unique (offset, size) pair
    void generate_direct_candidates(
        const UnifiedAccessPattern& pattern,
        qvector<FieldCandidate>& candidates
    );

    /// Generate larger covering candidates
    void generate_covering_candidates(
        const UnifiedAccessPattern& pattern,
        qvector<FieldCandidate>& candidates
    );

    /// Generate array candidates (uses stride detection)
    void generate_array_candidates(
        const UnifiedAccessPattern& pattern,
        qvector<FieldCandidate>& candidates
    );

    /// Generate padding candidates between non-overlapping fields
    void generate_padding_candidates(
        const qvector<FieldCandidate>& existing_candidates,
        sval_t struct_end,
        qvector<FieldCandidate>& candidates
    );

    /// Assign unique IDs and sort by offset
    void finalize_candidates(qvector<FieldCandidate>& candidates);

    /// Infer type category from a FieldAccess
    [[nodiscard]] TypeCategory infer_category(const FieldAccess& access) const;

    /// Create candidate from FieldAccess
    [[nodiscard]] FieldCandidate create_from_access(
        const FieldAccess& access,
        int access_index
    );

    /// Find candidates that could be array elements
    [[nodiscard]] qvector<qvector<int>> find_array_patterns(
        const qvector<FieldCandidate>& candidates
    ) const;

    /// Check if candidates form valid arithmetic progression
    [[nodiscard]] bool is_arithmetic_progression(
        const qvector<sval_t>& offsets,
        uint32_t expected_stride
    ) const;
};

/// Builder for creating field candidates from scratch
class FieldCandidateBuilder {
public:
    FieldCandidateBuilder& at_offset(sval_t off) {
        candidate_.offset = off;
        return *this;
    }

    FieldCandidateBuilder& with_size(uint32_t sz) {
        candidate_.size = sz;
        return *this;
    }

    FieldCandidateBuilder& with_type(TypeCategory cat) {
        candidate_.type_category = cat;
        return *this;
    }

    FieldCandidateBuilder& with_extended_type(const ExtendedTypeInfo& ext) {
        candidate_.extended_type = ext;
        return *this;
    }

    FieldCandidateBuilder& from_function(ea_t func_ea) {
        candidate_.primary_func_ea = func_ea;
        return *this;
    }

    FieldCandidateBuilder& with_confidence(TypeConfidence conf) {
        candidate_.confidence = conf;
        return *this;
    }

    FieldCandidateBuilder& as_kind(FieldCandidate::Kind k) {
        candidate_.kind = k;
        return *this;
    }

    FieldCandidateBuilder& as_array(uint32_t element_count, uint32_t stride) {
        candidate_.kind = FieldCandidate::Kind::ArrayField;
        candidate_.array_element_count = element_count;
        candidate_.array_stride = stride;
        return *this;
    }

    FieldCandidateBuilder& add_source_access(int idx) {
        candidate_.source_access_indices.push_back(idx);
        return *this;
    }

    FieldCandidateBuilder& in_union_group(int group_id) {
        candidate_.union_group_id = group_id;
        return *this;
    }

    [[nodiscard]] FieldCandidate build() const { return candidate_; }

private:
    FieldCandidate candidate_;
};

/// Statistics about generated candidates
struct CandidateStats {
    int total_candidates = 0;
    int direct_access_candidates = 0;
    int covering_candidates = 0;
    int array_candidates = 0;
    int padding_candidates = 0;
    int union_alternatives = 0;

    int overlap_groups = 0;
    int max_overlap_group_size = 0;

    [[nodiscard]] qstring summary() const {
        qstring result;
        result.sprnt("Candidate Statistics:\n");
        result.cat_sprnt("  Total: %d\n", total_candidates);
        result.cat_sprnt("  Direct access: %d\n", direct_access_candidates);
        result.cat_sprnt("  Covering: %d\n", covering_candidates);
        result.cat_sprnt("  Array: %d\n", array_candidates);
        result.cat_sprnt("  Padding: %d\n", padding_candidates);
        result.cat_sprnt("  Union alternatives: %d\n", union_alternatives);
        if (overlap_groups > 0) {
            result.cat_sprnt("  Overlap groups: %d (max size: %d)\n",
                            overlap_groups, max_overlap_group_size);
        }
        return result;
    }
};

/// Compute statistics for a set of candidates
[[nodiscard]] inline CandidateStats compute_stats(
    const qvector<FieldCandidate>& candidates,
    const OverlapAnalysis& overlaps)
{
    CandidateStats stats;
    stats.total_candidates = static_cast<int>(candidates.size());
    stats.overlap_groups = static_cast<int>(overlaps.overlap_groups.size());

    for (const auto& candidate : candidates) {
        switch (candidate.kind) {
            case FieldCandidate::Kind::DirectAccess:
                ++stats.direct_access_candidates;
                break;
            case FieldCandidate::Kind::CoveringField:
                ++stats.covering_candidates;
                break;
            case FieldCandidate::Kind::ArrayElement:
            case FieldCandidate::Kind::ArrayField:
                ++stats.array_candidates;
                break;
            case FieldCandidate::Kind::PaddingField:
                ++stats.padding_candidates;
                break;
            case FieldCandidate::Kind::UnionAlternative:
                ++stats.union_alternatives;
                break;
        }
    }

    for (const auto& group : overlaps.overlap_groups) {
        stats.max_overlap_group_size = std::max(
            stats.max_overlap_group_size,
            static_cast<int>(group.size())
        );
    }

    return stats;
}

} // namespace structor::z3
