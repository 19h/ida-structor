#include "structor/z3/array_constraints.hpp"
#include <algorithm>
#include <numeric>

namespace structor::z3 {

// ============================================================================
// ArrayConstraintBuilder Implementation
// ============================================================================

ArrayConstraintBuilder::ArrayConstraintBuilder(
    Z3Context& ctx,
    const ArrayDetectionConfig& config)
    : ctx_(ctx)
    , config_(config)
    , type_encoder_(ctx) {}

qvector<ArrayCandidate> ArrayConstraintBuilder::detect_arrays(
    const qvector<FieldAccess>& accesses)
{
    qvector<ArrayCandidate> candidates;
    stats_ = DetectionStats();

    if (accesses.size() < static_cast<size_t>(config_.min_elements)) {
        return candidates;
    }

    // Group accesses by size
    auto size_groups = group_by_size(accesses);

    // Process each size group
    for (auto& [size, group] : size_groups) {
        if (static_cast<int>(group.size()) < config_.min_elements) {
            continue;
        }

        // Extract and sort offsets
        qvector<sval_t> offsets;
        for (const auto* access : group) {
            offsets.push_back(access->offset);
        }
        std::sort(offsets.begin(), offsets.end());

        // Remove duplicates
        offsets.erase(std::unique(offsets.begin(), offsets.end()), offsets.end());

        if (static_cast<int>(offsets.size()) < config_.min_elements) {
            continue;
        }

        // Try simple arithmetic progression detection first
        auto ap_result = find_arithmetic_progression(offsets);

        if (ap_result.has_value()) {
            auto [base, stride] = *ap_result;

            // Verify type consistency if required
            if (config_.require_consistent_types && !verify_type_consistency(group)) {
                continue;
            }

            // Create candidate
            ArrayCandidate candidate = create_candidate(
                base, stride, static_cast<uint32_t>(offsets.size()), group);

            candidates.push_back(std::move(candidate));
            stats_.arrays_found++;
            stats_.elements_covered += static_cast<int>(offsets.size());
        }
        // Try symbolic detection if simple AP failed
        else if (config_.use_symbolic_indices) {
            auto symbolic_result = detect_symbolic_array(group);
            if (symbolic_result.has_value()) {
                candidates.push_back(std::move(*symbolic_result));
                stats_.arrays_found++;
                stats_.symbolic_detections++;
            }
        }
    }

    // Merge overlapping arrays
    merge_overlapping_arrays(candidates);

    // Sort by base offset
    std::sort(candidates.begin(), candidates.end(),
        [](const ArrayCandidate& a, const ArrayCandidate& b) {
            return a.base_offset < b.base_offset;
        });

    return candidates;
}

std::unordered_map<uint32_t, qvector<const FieldAccess*>>
ArrayConstraintBuilder::group_by_size(const qvector<FieldAccess>& accesses) {
    std::unordered_map<uint32_t, qvector<const FieldAccess*>> groups;

    for (const auto& access : accesses) {
        groups[access.size].push_back(&access);
    }

    return groups;
}

std::optional<std::pair<sval_t, uint32_t>>
ArrayConstraintBuilder::find_arithmetic_progression(const qvector<sval_t>& offsets) {
    if (offsets.size() < 2) return std::nullopt;

    // Calculate stride as GCD of all differences
    qvector<uint32_t> diffs;
    for (size_t i = 1; i < offsets.size(); ++i) {
        sval_t diff = offsets[i] - offsets[i - 1];
        if (diff <= 0) return std::nullopt;  // Must be strictly increasing
        diffs.push_back(static_cast<uint32_t>(diff));
    }

    uint32_t stride = gcd_vector(diffs);
    if (stride == 0 || stride > config_.max_stride) {
        return std::nullopt;
    }

    // Verify all offsets fit the pattern: offset[i] = base + i * stride
    sval_t base = offsets[0];

    for (const auto& offset : offsets) {
        sval_t relative = offset - base;
        if (relative % stride != 0) {
            return std::nullopt;  // Doesn't fit the pattern
        }
    }

    // Check for gaps (missing elements)
    size_t expected_count = static_cast<size_t>((offsets.back() - offsets.front()) / stride) + 1;
    if (expected_count > config_.max_elements) {
        return std::nullopt;
    }

    // Allow some gaps based on config
    double coverage_ratio = static_cast<double>(offsets.size()) / expected_count;
    if (coverage_ratio < 1.0 / config_.max_gap_ratio) {
        return std::nullopt;  // Too sparse
    }

    return std::make_pair(base, stride);
}

bool ArrayConstraintBuilder::verify_type_consistency(
    const qvector<const FieldAccess*>& accesses)
{
    if (accesses.empty()) return true;

    // Check that all accesses have compatible types
    SemanticType first_semantic = accesses[0]->semantic_type;
    uint32_t first_size = accesses[0]->size;

    for (const auto* access : accesses) {
        if (access->size != first_size) {
            return false;
        }

        // Allow some flexibility in semantic type
        if (access->semantic_type != first_semantic) {
            // Both unknown is OK
            if (first_semantic == SemanticType::Unknown ||
                access->semantic_type == SemanticType::Unknown) {
                continue;
            }

            // Integer/UnsignedInteger compatibility
            if ((first_semantic == SemanticType::Integer ||
                 first_semantic == SemanticType::UnsignedInteger) &&
                (access->semantic_type == SemanticType::Integer ||
                 access->semantic_type == SemanticType::UnsignedInteger)) {
                continue;
            }

            return false;
        }
    }

    return true;
}

void ArrayConstraintBuilder::merge_overlapping_arrays(qvector<ArrayCandidate>& candidates) {
    if (candidates.size() <= 1) return;

    // Sort by base offset
    std::sort(candidates.begin(), candidates.end(),
        [](const ArrayCandidate& a, const ArrayCandidate& b) {
            return a.base_offset < b.base_offset;
        });

    qvector<ArrayCandidate> merged;
    merged.push_back(candidates[0]);

    for (size_t i = 1; i < candidates.size(); ++i) {
        ArrayCandidate& last = merged.back();
        const ArrayCandidate& curr = candidates[i];

        // Check for overlap
        sval_t last_end = last.base_offset + last.total_size();

        if (curr.base_offset < last_end && curr.stride == last.stride) {
            // Merge: extend the last array
            sval_t new_end = std::max(last_end,
                curr.base_offset + static_cast<sval_t>(curr.total_size()));
            uint32_t new_count = static_cast<uint32_t>(
                (new_end - last.base_offset) / last.stride);
            last.element_count = new_count;

            // Merge member offsets
            for (sval_t off : curr.member_offsets) {
                bool found = false;
                for (sval_t existing : last.member_offsets) {
                    if (existing == off) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    last.member_offsets.push_back(off);
                }
            }
        } else {
            // No overlap, keep separate
            merged.push_back(curr);
        }
    }

    candidates = std::move(merged);
}

ArrayCandidate ArrayConstraintBuilder::create_candidate(
    sval_t base,
    uint32_t stride,
    uint32_t count,
    const qvector<const FieldAccess*>& accesses)
{
    ArrayCandidate candidate;
    candidate.base_offset = base;
    candidate.stride = stride;
    candidate.element_count = count;

    // Collect member offsets
    for (const auto* access : accesses) {
        candidate.member_offsets.push_back(access->offset);
    }

    // Get element type from first access
    if (!accesses.empty()) {
        const FieldAccess* first = accesses[0];
        candidate.element_type = first->inferred_type;

        // Check if stride > access_size (struct element pattern)
        if (stride > first->size) {
            candidate.needs_element_struct = true;
            candidate.inner_access_offset = static_cast<uint32_t>(
                (first->offset - base) % stride);
            candidate.inner_access_size = first->size;
            stats_.struct_element_arrays++;

            // Create synthetic element type
            if (config_.detect_arrays_of_structs) {
                candidate.element_type = create_element_struct_type(
                    stride,
                    candidate.inner_access_offset,
                    first->inferred_type
                );
            }
        }
    }

    // Determine confidence
    if (count >= 5 && !candidate.needs_element_struct) {
        candidate.confidence = TypeConfidence::High;
    } else if (count >= 3) {
        candidate.confidence = TypeConfidence::Medium;
    } else {
        candidate.confidence = TypeConfidence::Low;
    }

    return candidate;
}

std::optional<ArrayCandidate> ArrayConstraintBuilder::detect_symbolic_array(
    const qvector<const FieldAccess*>& accesses)
{
    if (accesses.size() < static_cast<size_t>(config_.min_elements)) {
        return std::nullopt;
    }

    // Use Z3 to solve for: offset[i] = base + index[i] * stride
    // Variables: base (Int), stride (Int)
    // For each access, we want: (access.offset - base) % stride == inner_offset

    return solve_stride_z3(accesses);
}

std::optional<ArrayCandidate> ArrayConstraintBuilder::solve_stride_z3(
    const qvector<const FieldAccess*>& accesses)
{
    if (accesses.empty()) return std::nullopt;

    // Extract offsets
    qvector<sval_t> offsets;
    for (const auto* access : accesses) {
        offsets.push_back(access->offset);
    }
    std::sort(offsets.begin(), offsets.end());

    // Calculate GCD stride
    uint32_t stride = calculate_gcd_stride(offsets);
    if (stride == 0 || stride > config_.max_stride) {
        return std::nullopt;
    }

    // Try to detect if accesses are at consistent inner offset
    uint32_t inner_offset = 0;
    if (!check_struct_element_pattern(accesses, stride, inner_offset)) {
        // Fall back to stride = access size
        stride = accesses[0]->size;
        inner_offset = 0;
    }

    sval_t base = offsets[0] - inner_offset;
    sval_t last = offsets.back();
    uint32_t count = static_cast<uint32_t>((last - base) / stride) + 1;

    if (count > config_.max_elements || count < static_cast<uint32_t>(config_.min_elements)) {
        return std::nullopt;
    }

    return create_candidate(base, stride, count, accesses);
}

uint32_t ArrayConstraintBuilder::calculate_gcd_stride(const qvector<sval_t>& offsets) const {
    if (offsets.size() < 2) return 0;

    qvector<uint32_t> diffs;
    for (size_t i = 1; i < offsets.size(); ++i) {
        sval_t diff = offsets[i] - offsets[i - 1];
        if (diff > 0) {
            diffs.push_back(static_cast<uint32_t>(diff));
        }
    }

    if (diffs.empty()) return 0;
    return gcd_vector(diffs);
}

bool ArrayConstraintBuilder::check_struct_element_pattern(
    const qvector<const FieldAccess*>& accesses,
    uint32_t stride,
    uint32_t& inner_offset)
{
    if (accesses.empty() || stride == 0) return false;

    // Calculate inner offset from first access
    sval_t min_offset = accesses[0]->offset;
    for (const auto* access : accesses) {
        min_offset = std::min(min_offset, access->offset);
    }

    uint32_t first_inner = static_cast<uint32_t>(accesses[0]->offset - min_offset) % stride;

    // Check all accesses have the same inner offset
    for (const auto* access : accesses) {
        uint32_t this_inner = static_cast<uint32_t>(access->offset - min_offset) % stride;
        if (this_inner != first_inner) {
            return false;
        }
    }

    inner_offset = first_inner;
    return true;
}

tinfo_t ArrayConstraintBuilder::create_element_struct_type(
    uint32_t stride,
    uint32_t inner_offset,
    const tinfo_t& inner_type)
{
    // Create synthetic element struct:
    //   struct __element_N {
    //       char __pad_0[inner_offset];  // if inner_offset > 0
    //       <inner_type> accessed_field;
    //       char __pad_1[stride - inner_offset - inner_type.size()];
    //   };

    uint32_t inner_size = inner_type.empty() ? 4 : static_cast<uint32_t>(inner_type.get_size());
    uint32_t trailing_pad = stride - inner_offset - inner_size;

    // Generate unique name
    qstring name;
    name.sprnt("__array_elem_%u_%u", stride, inner_offset);

    // Create struct type
    tinfo_t struct_type;
    udt_type_data_t udt;

    // Leading padding
    if (inner_offset > 0) {
        udm_t pad_field;
        pad_field.name = "__pad_0";
        pad_field.offset = 0;
        pad_field.size = inner_offset * 8;  // bits

        tinfo_t byte_type;
        byte_type.create_simple_type(BT_INT8 | BTMT_CHAR);
        tinfo_t pad_array;
        pad_array.create_array(byte_type, inner_offset);
        pad_field.type = pad_array;

        udt.push_back(pad_field);
    }

    // Accessed field
    udm_t accessed_field;
    accessed_field.name = "value";
    accessed_field.offset = inner_offset * 8;
    accessed_field.size = inner_size * 8;
    accessed_field.type = inner_type.empty() ?
        tinfo_t() : inner_type;

    if (accessed_field.type.empty()) {
        // Default to uint32_t
        accessed_field.type.create_simple_type(BT_INT32 | BTMT_UNSIGNED);
    }

    udt.push_back(accessed_field);

    // Trailing padding
    if (trailing_pad > 0) {
        udm_t trail_field;
        trail_field.name = "__pad_1";
        trail_field.offset = (inner_offset + inner_size) * 8;
        trail_field.size = trailing_pad * 8;

        tinfo_t byte_type;
        byte_type.create_simple_type(BT_INT8 | BTMT_CHAR);
        tinfo_t pad_array;
        pad_array.create_array(byte_type, trailing_pad);
        trail_field.type = pad_array;

        udt.push_back(trail_field);
    }

    // Finalize struct
    udt.total_size = stride;
    udt.pack = 1;  // Packed

    struct_type.create_udt(udt, BTF_STRUCT);

    return struct_type;
}

} // namespace structor::z3
