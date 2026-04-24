#pragma once

#include "synth_types.hpp"
#include "naming.hpp"

namespace structor {

/// A non-padding field extracted from an existing IDA struct/local type.
struct ExistingTypeField {
    qstring name;
    sval_t offset = 0;
    std::uint32_t size = 0;
    tinfo_t type;
    qstring type_decl;
    bool is_padding = false;
};

/// Ranked overlap between a provisional synthesized struct and an existing type.
struct TypeOverlapCandidate {
    tid_t tid = BADADDR;
    qstring name;
    std::uint32_t size = 0;
    double score = 0.0;

    std::uint32_t synth_field_count = 0;
    std::uint32_t existing_field_count = 0;
    std::uint32_t matched_synth_fields = 0;
    std::uint32_t matched_existing_fields = 0;
    std::uint32_t exact_offset_matches = 0;
    std::uint32_t type_matches = 0;

    qstring summary;
    qvector<ExistingTypeField> fields;
};

/// Result of overlaying one existing type onto a synthesized structure.
struct TypeMergeResult {
    bool success = false;
    qstring message;
    std::uint32_t fields_added = 0;
    std::uint32_t fields_renamed = 0;
    std::uint32_t fields_retyped = 0;
    std::uint32_t fields_skipped = 0;
};

/// Finds sparse offset overlap with existing structs and merges selected names/types.
class ExistingTypeMatcher {
public:
    [[nodiscard]] qvector<TypeOverlapCandidate> find_matches(
        const SynthStruct& synth_struct,
        std::size_t max_results = 64,
        double min_score = 0.05) const;

    [[nodiscard]] TypeMergeResult merge_existing_type(
        SynthStruct& synth_struct,
        const TypeOverlapCandidate& candidate) const;

    [[nodiscard]] static bool ranges_overlap(
        sval_t a_offset,
        std::uint32_t a_size,
        sval_t b_offset,
        std::uint32_t b_size) noexcept;

    [[nodiscard]] static bool is_padding_name(const qstring& name) noexcept;
    [[nodiscard]] static bool is_effective_padding(const SynthField& field) noexcept;
    [[nodiscard]] static SemanticType semantic_from_type(const tinfo_t& type) noexcept;
    [[nodiscard]] static bool types_compatible(const tinfo_t& a, const tinfo_t& b) noexcept;
    [[nodiscard]] static bool field_name_can_be_reused(const SynthField& field) noexcept;
};

} // namespace structor
