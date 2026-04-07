#include "structor/z3/array_constraints.hpp"
#include <algorithm>
#include <numeric>
#include <unordered_set>

namespace structor::z3 {

namespace {

double coverage_ratio(const qvector<sval_t>& offsets, sval_t base, uint32_t stride) {
    if (offsets.empty() || stride == 0) {
        return 0.0;
    }

    const std::size_t expected =
        static_cast<std::size_t>((offsets.back() - base) / static_cast<sval_t>(stride)) + 1;
    if (expected == 0) {
        return 0.0;
    }

    return static_cast<double>(offsets.size()) / static_cast<double>(expected);
}

bool has_excessive_gap(const qvector<sval_t>& offsets, uint32_t stride, int max_gap_ratio) {
    if (offsets.size() < 2 || stride == 0) {
        return false;
    }

    const sval_t max_gap = static_cast<sval_t>(std::max(1, max_gap_ratio)) * stride;
    for (size_t i = 1; i < offsets.size(); ++i) {
        if (offsets[i] - offsets[i - 1] > max_gap) {
            return true;
        }
    }

    return false;
}

bool categories_compatible_for_array(TypeCategory a, TypeCategory b) {
    if (a == b) {
        return true;
    }

    if (TypeEncoder::is_integer(a) && TypeEncoder::is_integer(b)) {
        return true;
    }

    return false;
}

bool is_weak_single_field_struct_array(const ArrayCandidate& candidate,
                                       const qvector<const FieldAccess*>& accesses) {
    if (!candidate.needs_element_struct || candidate.element_count >= 4 || accesses.empty()) {
        return false;
    }

    std::unordered_set<uint32_t> inner_offsets;
    for (const auto* access : accesses) {
        if (access->offset < candidate.base_offset) {
            continue;
        }
        const sval_t rel = access->offset - candidate.base_offset;
        inner_offsets.insert(static_cast<uint32_t>(rel % candidate.stride));
    }

    return inner_offsets.size() <= 1 && accesses.size() == candidate.element_count;
}

} // namespace

// ============================================================================
// ArrayConstraintBuilder Implementation
// ============================================================================

ArrayConstraintBuilder::ArrayConstraintBuilder(
    Z3Context& ctx,
    const ArrayDetectionConfig& config)
    : ctx_(ctx)
    , config_(config) {}

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

        // Honor stride hints from index expressions when available
        auto stride_hint = extract_stride_hint(group);
        if (stride_hint.has_value()) {
            auto hinted_result = find_progression_with_stride(offsets, group, *stride_hint);
            if (hinted_result.has_value()) {
                auto [base, stride] = *hinted_result;

                // Verify type consistency if required
                if (config_.require_consistent_types && !verify_type_consistency(group)) {
                    continue;
                }

                uint32_t count = static_cast<uint32_t>((offsets.back() - base) / stride) + 1;
                ArrayCandidate candidate = create_candidate(base, stride, count, group);

                if (is_weak_single_field_struct_array(candidate, group)) {
                    continue;
                }

                candidates.push_back(std::move(candidate));
                stats_.arrays_found++;
                stats_.elements_covered += static_cast<int>(offsets.size());
                continue;
            }
        }

        auto append_exact_stride_runs = [&](uint32_t stride) {
            if (stride == 0 || stride > config_.max_stride || offsets.size() < 2) {
                return;
            }

            size_t run_start = 0;
            while (run_start + 1 < offsets.size()) {
                size_t run_end = run_start + 1;
                while (run_end < offsets.size() &&
                       offsets[run_end] - offsets[run_end - 1] == static_cast<sval_t>(stride)) {
                    ++run_end;
                }

                const size_t run_len = run_end - run_start;
                if (static_cast<int>(run_len) >= config_.min_elements) {
                    qvector<const FieldAccess*> run_group;
                    std::unordered_set<sval_t> run_offsets;
                    for (size_t i = run_start; i < run_end; ++i) {
                        run_offsets.insert(offsets[i]);
                    }

                    for (const auto* access : group) {
                        if (run_offsets.count(access->offset) > 0) {
                            run_group.push_back(access);
                        }
                    }

                    if (!config_.require_consistent_types || verify_type_consistency(run_group)) {
                        ArrayCandidate candidate = create_candidate(
                            offsets[run_start],
                            stride,
                            static_cast<uint32_t>(run_len),
                            run_group);
                        if (is_weak_single_field_struct_array(candidate, run_group)) {
                            run_start = run_end;
                            continue;
                        }
                        candidates.push_back(std::move(candidate));
                        stats_.arrays_found++;
                        stats_.elements_covered += static_cast<int>(run_len);
                    }
                }

                run_start = run_end;
            }
        };

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

            if (is_weak_single_field_struct_array(candidate, group)) {
                continue;
            }

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
            } else {
                append_exact_stride_runs(size);
            }
        } else {
            append_exact_stride_runs(size);
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

    if (has_excessive_gap(offsets, stride, config_.max_gap_ratio)) {
        return std::nullopt;
    }

    // Allow some gaps based on config
    double ratio = static_cast<double>(offsets.size()) / expected_count;
    if (ratio < 1.0 / config_.max_gap_ratio) {
        return std::nullopt;  // Too sparse
    }

    return std::make_pair(base, stride);
}

std::optional<uint32_t> ArrayConstraintBuilder::extract_stride_hint(
    const qvector<const FieldAccess*>& accesses) const
{
    std::optional<uint32_t> hint;

    for (const auto* access : accesses) {
        if (!access || !access->array_stride_hint.has_value()) {
            continue;
        }

        uint32_t value = *access->array_stride_hint;
        if (value == 0 || value > config_.max_stride) {
            continue;
        }

        if (!hint.has_value()) {
            hint = value;
        } else if (*hint != value) {
            return std::nullopt;
        }
    }

    return hint;
}

std::optional<std::pair<sval_t, uint32_t>> ArrayConstraintBuilder::find_progression_with_stride(
    const qvector<sval_t>& offsets,
    const qvector<const FieldAccess*>& accesses,
    uint32_t stride_hint) const
{
    if (stride_hint == 0 || stride_hint > config_.max_stride) {
        return std::nullopt;
    }
    if (offsets.size() < 2) {
        return std::nullopt;
    }

    uint32_t inner_offset = 0;
    if (!check_struct_element_pattern(accesses, stride_hint, inner_offset)) {
        sval_t base = offsets.front();
        for (const auto& offset : offsets) {
            if ((offset - base) % static_cast<sval_t>(stride_hint) != 0) {
                return std::nullopt;
            }
        }
        inner_offset = 0;
    }

    sval_t base = offsets.front() - static_cast<sval_t>(inner_offset);
    for (const auto& offset : offsets) {
        if ((offset - base) % static_cast<sval_t>(stride_hint) != 0) {
            return std::nullopt;
        }
    }

    size_t expected_count = static_cast<size_t>((offsets.back() - base) / stride_hint) + 1;
    if (expected_count == 0 || expected_count > config_.max_elements) {
        return std::nullopt;
    }

    if (has_excessive_gap(offsets, stride_hint, config_.max_gap_ratio)) {
        return std::nullopt;
    }

    double ratio = static_cast<double>(offsets.size()) / expected_count;
    if (ratio < 1.0 / config_.max_gap_ratio) {
        return std::nullopt;
    }

    return std::make_pair(base, stride_hint);
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

        if (!accesses[0]->inferred_type.empty() && !access->inferred_type.empty()) {
            TypeCategory first_cat = ctx_.type_encoder().categorize(accesses[0]->inferred_type);
            TypeCategory this_cat = ctx_.type_encoder().categorize(access->inferred_type);
            if (!categories_compatible_for_array(first_cat, this_cat)) {
                return false;
            }
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
    merged.reserve(candidates.size());  // Reserve to avoid reallocations
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

            // Merge member offsets using hash-based deduplication
            // Build hash set of existing offsets for O(1) lookup
            std::unordered_set<sval_t> existing_offsets(
                last.member_offsets.begin(), 
                last.member_offsets.end()
            );
            
            // Add new offsets that don't exist
            for (sval_t off : curr.member_offsets) {
                if (existing_offsets.insert(off).second) {
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

    auto stride_hint = extract_stride_hint(accesses);
    if (stride_hint.has_value()) {
        auto hinted = find_progression_with_stride(offsets, accesses, *stride_hint);
        if (hinted.has_value()) {
            auto [base, stride] = *hinted;
            uint32_t count = static_cast<uint32_t>((offsets.back() - base) / stride) + 1;
            if (count >= static_cast<uint32_t>(config_.min_elements) &&
                count <= config_.max_elements) {
                ArrayCandidate candidate = create_candidate(base, stride, count, accesses);
                if (!is_weak_single_field_struct_array(candidate, accesses)) {
                    return candidate;
                }
            }
        }
    }

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

    if (has_excessive_gap(offsets, stride, config_.max_gap_ratio)) {
        return std::nullopt;
    }

    if (coverage_ratio(offsets, base, stride) < 1.0 / config_.max_gap_ratio) {
        return std::nullopt;
    }

    ArrayCandidate candidate = create_candidate(base, stride, count, accesses);
    if (is_weak_single_field_struct_array(candidate, accesses)) {
        return std::nullopt;
    }

    return candidate;
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
    uint32_t& inner_offset) const
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
