#include "structor/z3/field_candidates.hpp"
#include <algorithm>
#include <unordered_map>

#ifndef STRUCTOR_TESTING
#include <pro.h>
#include <kernwin.hpp>
#endif

namespace structor::z3 {

namespace {
    // Helper for conditional logging
    inline void z3_log(const char* fmt, ...) {
#ifndef STRUCTOR_TESTING
        va_list va;
        va_start(va, fmt);
        vmsg(fmt, va);
        va_end(va);
#endif
    }
}

// ============================================================================
// FieldCandidateGenerator Implementation
// ============================================================================

FieldCandidateGenerator::FieldCandidateGenerator(
    Z3Context& ctx,
    const CandidateGenerationConfig& config)
    : ctx_(ctx)
    , config_(config) {}

qvector<FieldCandidate> FieldCandidateGenerator::generate(
    const UnifiedAccessPattern& pattern)
{
    qvector<FieldCandidate> candidates;
    next_id_ = 0;

    z3_log("[Structor/Z3] Generating field candidates from %zu accesses\n", pattern.all_accesses.size());

    if (pattern.all_accesses.empty()) {
        return candidates;
    }

    // Step 1: Generate direct access candidates
    generate_direct_candidates(pattern, candidates);
    size_t direct_count = candidates.size();
    z3_log("[Structor/Z3]   Direct access candidates: %zu\n", direct_count);

    // Step 2: Generate covering candidates (larger fields that cover multiple accesses)
    if (config_.generate_covering_candidates) {
        generate_covering_candidates(pattern, candidates);
        z3_log("[Structor/Z3]   Covering candidates: %zu\n", candidates.size() - direct_count);
    }

    size_t before_array = candidates.size();
    // Step 3: Generate array candidates
    if (config_.generate_array_candidates) {
        generate_array_candidates(pattern, candidates);
        z3_log("[Structor/Z3]   Array candidates: %zu\n", candidates.size() - before_array);
    }

    size_t before_padding = candidates.size();
    // Step 4: Generate padding candidates
    if (config_.generate_padding_candidates) {
        generate_padding_candidates(candidates, pattern.global_max_offset, candidates);
        z3_log("[Structor/Z3]   Padding candidates: %zu\n", candidates.size() - before_padding);
    }

    // Finalize: assign IDs and sort
    finalize_candidates(candidates);

    z3_log("[Structor/Z3]   Total candidates generated: %zu\n", candidates.size());
    
    // Log candidate summary by offset
    if (!candidates.empty()) {
        z3_log("[Structor/Z3]   Candidate summary:\n");
        for (const auto& cand : candidates) {
            const char* kind_str = "unknown";
            switch (cand.kind) {
                case FieldCandidate::Kind::DirectAccess: kind_str = "direct"; break;
                case FieldCandidate::Kind::CoveringField: kind_str = "covering"; break;
                case FieldCandidate::Kind::ArrayElement: kind_str = "array_elem"; break;
                case FieldCandidate::Kind::ArrayField: kind_str = "array"; break;
                case FieldCandidate::Kind::PaddingField: kind_str = "padding"; break;
                case FieldCandidate::Kind::UnionAlternative: kind_str = "union_alt"; break;
            }
            z3_log("[Structor/Z3]     [%d] offset=0x%llX size=%u type=%s kind=%s\n",
                   cand.id, static_cast<unsigned long long>(cand.offset), cand.size,
                   type_category_name(cand.type_category), kind_str);
        }
    }

    return candidates;
}

void FieldCandidateGenerator::generate_direct_candidates(
    const UnifiedAccessPattern& pattern,
    qvector<FieldCandidate>& candidates)
{
    // Track unique (offset, size) pairs to avoid duplicates
    std::unordered_set<uint64_t> seen;

    for (size_t i = 0; i < pattern.all_accesses.size(); ++i) {
        const auto& access = pattern.all_accesses[i];

        // Create key from (offset, size)
        uint64_t key = (static_cast<uint64_t>(access.offset) << 32) |
                       static_cast<uint64_t>(access.size);

        if (seen.insert(key).second) {
            // New unique access
            FieldCandidate candidate = create_from_access(access, static_cast<int>(i));
            candidates.push_back(std::move(candidate));
        } else {
            // Existing candidate - add this access as additional source
            for (auto& existing : candidates) {
                if (existing.offset == access.offset && existing.size == access.size) {
                    existing.source_access_indices.push_back(static_cast<int>(i));

                    // Upgrade type if more specific
                    TypeCategory new_cat = infer_category(access);
                    if (static_cast<int>(new_cat) > static_cast<int>(existing.type_category)) {
                        existing.type_category = new_cat;
                    }
                    break;
                }
            }
        }
    }
}

void FieldCandidateGenerator::generate_covering_candidates(
    const UnifiedAccessPattern& pattern,
    qvector<FieldCandidate>& candidates)
{
    if (candidates.empty()) return;

    // Sort candidates by offset for analysis
    qvector<FieldCandidate> sorted_candidates = candidates;
    std::sort(sorted_candidates.begin(), sorted_candidates.end(),
        [](const FieldCandidate& a, const FieldCandidate& b) {
            return a.offset < b.offset;
        });

    // Find groups of adjacent small fields that could be covered by a larger field
    qvector<FieldCandidate> covering;

    size_t i = 0;
    while (i < sorted_candidates.size()) {
        // Look for sequence of small fields
        size_t j = i + 1;
        sval_t group_start = sorted_candidates[i].offset;
        sval_t group_end = sorted_candidates[i].end_offset();

        // Extend group while fields are adjacent or slightly gapped
        while (j < sorted_candidates.size()) {
            const auto& next = sorted_candidates[j];
            sval_t gap = next.offset - group_end;

            // Allow small gaps (padding)
            if (gap < 0 || gap > 4) break;

            group_end = next.end_offset();
            ++j;
        }

        // If we found multiple fields, create covering candidate
        if (j > i + 1) {
            uint32_t covering_size = static_cast<uint32_t>(group_end - group_start);

            if (covering_size <= config_.max_covering_size) {
                FieldCandidate cover;
                cover.offset = group_start;
                cover.size = covering_size;
                cover.kind = FieldCandidate::Kind::CoveringField;
                cover.type_category = TypeCategory::RawBytes;
                cover.confidence = TypeConfidence::Low;

                // Track which candidates this covers
                for (size_t k = i; k < j; ++k) {
                    for (int idx : sorted_candidates[k].source_access_indices) {
                        cover.source_access_indices.push_back(idx);
                    }
                }

                covering.push_back(std::move(cover));
            }
        }

        i = j;
    }

    // Add covering candidates
    for (auto& c : covering) {
        candidates.push_back(std::move(c));
    }
}

void FieldCandidateGenerator::generate_array_candidates(
    const UnifiedAccessPattern& pattern,
    qvector<FieldCandidate>& candidates)
{
    // Find potential array patterns among existing candidates
    auto array_groups = find_array_patterns(candidates);

    for (const auto& group : array_groups) {
        if (group.size() < config_.min_array_elements) continue;

        // Extract offsets and check for arithmetic progression
        qvector<sval_t> offsets;
        uint32_t element_size = 0;

        for (int idx : group) {
            offsets.push_back(candidates[idx].offset);
            if (element_size == 0) {
                element_size = candidates[idx].size;
            }
        }

        std::sort(offsets.begin(), offsets.end());

        // Calculate stride
        if (offsets.size() < 2) continue;

        sval_t stride = offsets[1] - offsets[0];
        if (stride <= 0 || stride > 1024) continue;

        // Verify it's a valid arithmetic progression
        if (!is_arithmetic_progression(offsets, static_cast<uint32_t>(stride))) {
            continue;
        }

        // Create array field candidate
        FieldCandidate array_candidate;
        array_candidate.offset = offsets.front();
        array_candidate.size = static_cast<uint32_t>(stride * offsets.size());
        array_candidate.kind = FieldCandidate::Kind::ArrayField;
        array_candidate.type_category = candidates[group[0]].type_category;
        array_candidate.array_element_count = static_cast<uint32_t>(offsets.size());
        array_candidate.array_stride = static_cast<uint32_t>(stride);
        array_candidate.confidence = TypeConfidence::Medium;

        // Copy source accesses
        for (int idx : group) {
            for (int src_idx : candidates[idx].source_access_indices) {
                array_candidate.source_access_indices.push_back(src_idx);
            }
        }

        // Mark original candidates as array elements
        for (int idx : group) {
            candidates[idx].kind = FieldCandidate::Kind::ArrayElement;
        }

        candidates.push_back(std::move(array_candidate));
    }
}

void FieldCandidateGenerator::generate_padding_candidates(
    const qvector<FieldCandidate>& existing_candidates,
    sval_t struct_end,
    qvector<FieldCandidate>& candidates)
{
    if (existing_candidates.empty()) return;

    // Get non-overlapping coverage ranges
    qvector<std::pair<sval_t, sval_t>> ranges;  // (start, end)

    for (const auto& c : existing_candidates) {
        if (c.kind == FieldCandidate::Kind::ArrayElement) {
            continue;  // Skip array elements (covered by ArrayField)
        }
        ranges.push_back({c.offset, c.end_offset()});
    }

    if (ranges.empty()) return;

    // Sort by start offset
    std::sort(ranges.begin(), ranges.end());

    // Merge overlapping ranges
    qvector<std::pair<sval_t, sval_t>> merged;
    merged.push_back(ranges[0]);

    for (size_t i = 1; i < ranges.size(); ++i) {
        if (ranges[i].first <= merged.back().second) {
            merged.back().second = std::max(merged.back().second, ranges[i].second);
        } else {
            merged.push_back(ranges[i]);
        }
    }

    // Find gaps
    sval_t current_pos = 0;

    for (const auto& [start, end] : merged) {
        if (start > current_pos) {
            // Gap found - create padding
            FieldCandidate padding;
            padding.offset = current_pos;
            padding.size = static_cast<uint32_t>(start - current_pos);
            padding.kind = FieldCandidate::Kind::PaddingField;
            padding.type_category = TypeCategory::RawBytes;
            padding.confidence = TypeConfidence::Low;

            candidates.push_back(std::move(padding));
        }
        current_pos = std::max(current_pos, end);
    }

    // Final padding to struct end
    if (struct_end > current_pos) {
        FieldCandidate padding;
        padding.offset = current_pos;
        padding.size = static_cast<uint32_t>(struct_end - current_pos);
        padding.kind = FieldCandidate::Kind::PaddingField;
        padding.type_category = TypeCategory::RawBytes;
        padding.confidence = TypeConfidence::Low;

        candidates.push_back(std::move(padding));
    }
}

void FieldCandidateGenerator::finalize_candidates(qvector<FieldCandidate>& candidates) {
    // Sort by offset, then by size (smaller first)
    std::sort(candidates.begin(), candidates.end(),
        [](const FieldCandidate& a, const FieldCandidate& b) {
            if (a.offset != b.offset) return a.offset < b.offset;
            return a.size < b.size;
        });

    // Assign IDs
    for (size_t i = 0; i < candidates.size(); ++i) {
        candidates[i].id = static_cast<int>(i);
    }
}

TypeCategory FieldCandidateGenerator::infer_category(const FieldAccess& access) const {
    // First check semantic type
    switch (access.semantic_type) {
        case SemanticType::Pointer:
            return TypeCategory::Pointer;
        case SemanticType::FunctionPointer:
        case SemanticType::VTablePointer:
            return TypeCategory::FuncPtr;
        case SemanticType::Float:
            return TypeCategory::Float32;
        case SemanticType::Double:
            return TypeCategory::Float64;
        default:
            break;
    }

    // Then check inferred type
    if (!access.inferred_type.empty()) {
        return ctx_.type_encoder().categorize(access.inferred_type);
    }

    // Fall back to size-based inference
    switch (access.size) {
        case 1:
            return TypeCategory::UInt8;
        case 2:
            return TypeCategory::UInt16;
        case 4:
            return TypeCategory::UInt32;
        case 8:
            // Could be uint64 or pointer
            if (get_ptr_size() == 8) {
                return TypeCategory::Pointer;  // Conservative assumption
            }
            return TypeCategory::UInt64;
        default:
            return TypeCategory::RawBytes;
    }
}

FieldCandidate FieldCandidateGenerator::create_from_access(
    const FieldAccess& access,
    int access_index)
{
    FieldCandidate candidate;
    candidate.offset = access.offset;
    candidate.size = access.size;
    candidate.kind = FieldCandidate::Kind::DirectAccess;
    candidate.type_category = infer_category(access);
    candidate.source_access_indices.push_back(access_index);

    // Extract extended type info if available
    if (!access.inferred_type.empty()) {
        candidate.extended_type = ctx_.type_encoder().extract_extended_info(access.inferred_type);
    } else {
        candidate.extended_type.category = candidate.type_category;
        candidate.extended_type.size = access.size;
    }

    // Set confidence based on access type
    if (access.semantic_type != SemanticType::Unknown) {
        candidate.confidence = TypeConfidence::Medium;
    } else {
        candidate.confidence = TypeConfidence::Low;
    }

    return candidate;
}

qvector<qvector<int>> FieldCandidateGenerator::find_array_patterns(
    const qvector<FieldCandidate>& candidates) const
{
    qvector<qvector<int>> result;

    // Group candidates by size and type
    std::unordered_map<uint64_t, qvector<int>> size_type_groups;

    for (size_t i = 0; i < candidates.size(); ++i) {
        const auto& c = candidates[i];

        // Skip non-direct-access candidates
        if (c.kind != FieldCandidate::Kind::DirectAccess) continue;

        // Key: (size, type_category)
        uint64_t key = (static_cast<uint64_t>(c.size) << 32) |
                       static_cast<uint64_t>(c.type_category);
        size_type_groups[key].push_back(static_cast<int>(i));
    }

    // For each group, check if offsets form arithmetic progression
    for (const auto& [key, indices] : size_type_groups) {
        if (indices.size() < config_.min_array_elements) continue;

        // Extract offsets
        qvector<std::pair<sval_t, int>> offset_idx;
        for (int idx : indices) {
            offset_idx.push_back({candidates[idx].offset, idx});
        }

        // Sort by offset
        std::sort(offset_idx.begin(), offset_idx.end());

        // Find longest arithmetic progression subsequence
        uint32_t size = static_cast<uint32_t>(key >> 32);
        qvector<int> current_group;

        for (size_t i = 0; i < offset_idx.size(); ++i) {
            if (current_group.empty()) {
                current_group.push_back(offset_idx[i].second);
                continue;
            }

            // Check if this extends current progression
            sval_t expected_offset = candidates[current_group.back()].offset + size;
            if (offset_idx[i].first == expected_offset) {
                current_group.push_back(offset_idx[i].second);
            } else {
                // Break in progression
                if (current_group.size() >= config_.min_array_elements) {
                    result.push_back(current_group);
                }
                current_group.clear();
                current_group.push_back(offset_idx[i].second);
            }
        }

        // Don't forget the last group
        if (current_group.size() >= config_.min_array_elements) {
            result.push_back(current_group);
        }
    }

    return result;
}

bool FieldCandidateGenerator::is_arithmetic_progression(
    const qvector<sval_t>& offsets,
    uint32_t expected_stride) const
{
    if (offsets.size() < 2) return true;

    for (size_t i = 1; i < offsets.size(); ++i) {
        sval_t actual_stride = offsets[i] - offsets[i - 1];
        if (actual_stride != static_cast<sval_t>(expected_stride)) {
            return false;
        }
    }

    return true;
}

// ============================================================================
// OverlapAnalysis Implementation
// ============================================================================

OverlapAnalysis FieldCandidateGenerator::analyze_overlaps(
    const qvector<FieldCandidate>& candidates) const
{
    OverlapAnalysis result;

    // Find all overlapping pairs
    for (size_t i = 0; i < candidates.size(); ++i) {
        for (size_t j = i + 1; j < candidates.size(); ++j) {
            if (candidates[i].overlaps(candidates[j])) {
                result.overlapping_pairs.push_back({
                    candidates[i].id,
                    candidates[j].id
                });
            }
        }
    }

    if (result.overlapping_pairs.empty()) {
        return result;
    }

    // Build overlap groups using union-find
    std::unordered_map<int, int> parent;

    auto find = [&parent](int x) -> int {
        if (parent.find(x) == parent.end()) {
            parent[x] = x;
        }
        while (parent[x] != x) {
            parent[x] = parent[parent[x]];  // Path compression
            x = parent[x];
        }
        return x;
    };

    auto unite = [&parent, &find](int x, int y) {
        int px = find(x);
        int py = find(y);
        if (px != py) {
            parent[px] = py;
        }
    };

    // Unite overlapping candidates
    for (const auto& [id1, id2] : result.overlapping_pairs) {
        unite(id1, id2);
    }

    // Collect groups
    std::unordered_map<int, qvector<int>> groups;
    for (const auto& [id, _] : parent) {
        groups[find(id)].push_back(id);
    }

    for (auto& [root, members] : groups) {
        if (members.size() > 1) {
            std::sort(members.begin(), members.end());
            result.overlap_groups.push_back(std::move(members));
        }
    }

    return result;
}

} // namespace structor::z3
