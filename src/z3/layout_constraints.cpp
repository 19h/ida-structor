#include "structor/z3/layout_constraints.hpp"
#include <algorithm>
#include <chrono>
#include <unordered_set>

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

    inline int clamp_weight(int value, int min_val, int max_val) {
        return std::max(min_val, std::min(max_val, value));
    }

    inline int access_weight(const FieldCandidate& cand, int base_weight) {
        if (base_weight <= 0) return 0;
        int count = static_cast<int>(cand.source_access_indices.size());
        int multiplier = clamp_weight(count, 1, 10);
        return base_weight * multiplier;
    }

    inline int padding_weight(uint32_t size, int base_weight) {
        if (base_weight <= 0) return 0;
        int multiplier = clamp_weight(static_cast<int>((size + 3) / 4), 1, 10);
        return base_weight * multiplier;
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

SynthField field_from_candidate(
    const FieldCandidate& candidate,
    TypeEncoder& type_encoder)
{
    SynthField field;
    field.offset = candidate.offset;
    field.size = candidate.size;
    field.name = generate_field_name(candidate.offset,
        semantic_to_category(static_cast<int>(candidate.type_category)) == TypeCategory::Pointer
            ? SemanticType::Pointer
            : (semantic_to_category(static_cast<int>(candidate.type_category)) == TypeCategory::FuncPtr
                ? SemanticType::FunctionPointer
                : SemanticType::Unknown));

    // Decode type
    field.type = type_encoder.decode(
        candidate.type_category,
        candidate.size,
        &candidate.extended_type
    );

    // Set semantic type
    if (TypeEncoder::is_integer(candidate.type_category)) {
        field.semantic = TypeEncoder::is_signed_int(candidate.type_category)
            ? SemanticType::Integer : SemanticType::UnsignedInteger;
    } else if (TypeEncoder::is_floating(candidate.type_category)) {
        field.semantic = candidate.size == 4 ? SemanticType::Float : SemanticType::Double;
    } else if (candidate.type_category == TypeCategory::Pointer) {
        field.semantic = SemanticType::Pointer;
    } else if (candidate.type_category == TypeCategory::FuncPtr) {
        field.semantic = SemanticType::FunctionPointer;
    } else if (candidate.type_category == TypeCategory::Array) {
        field.semantic = SemanticType::Array;
    }

    // Handle arrays
    if (candidate.is_array() && candidate.array_element_count.has_value()) {
        tinfo_t array_type;
        array_type.create_array(field.type, *candidate.array_element_count);
        field.type = array_type;
        field.size = candidate.array_stride.value_or(candidate.size) * *candidate.array_element_count;
    }

    return field;
}

bool candidates_compatible_for_union(
    const FieldCandidate& a,
    const FieldCandidate& b)
{
    // Must have the same offset
    if (a.offset != b.offset) return false;

    // Size should be the same or one contains the other
    if (a.size != b.size && !a.contains(b) && !b.contains(a)) {
        return false;
    }

    return true;
}

// ============================================================================
// LayoutConstraintBuilder Implementation
// ============================================================================

LayoutConstraintBuilder::LayoutConstraintBuilder(
    Z3Context& ctx,
    const LayoutConstraintConfig& config)
    : ctx_(ctx)
    , config_(config)
    , array_builder_(ctx)
    , constraint_tracker_(ctx.ctx())
    , solver_(ctx.make_solver()) {}

void LayoutConstraintBuilder::build_constraints(
    const UnifiedAccessPattern& pattern,
    const qvector<FieldCandidate>& candidates)
{
    auto start_time = std::chrono::steady_clock::now();

    z3_log("[Structor/Z3] Building constraints for %zu accesses, %zu field candidates\n",
           pattern.all_accesses.size(), candidates.size());

    pattern_ = &pattern;
    candidates_ = candidates;

    // Reset state
    field_vars_.clear();
    arrays_.clear();
    union_resolutions_.clear();
    solver_.reset();
    constraint_tracker_.clear();

    // Detect arrays first
    arrays_ = array_builder_.detect_arrays(pattern.all_accesses);
    if (!arrays_.empty()) {
        z3_log("[Structor/Z3] Detected %zu potential arrays\n", arrays_.size());
    }

    // Create field variables
    create_field_variables();

    // Add constraints in order of importance
    add_coverage_constraints();      // HARD
    add_size_bound_constraints();    // HARD

    add_non_overlap_constraints();   // SOFT (union option)
    add_alignment_constraints();     // SOFT
    add_type_constraints();          // SOFT
    add_type_preference_constraints(); // SOFT (prefer typed over raw_bytes)
    add_array_constraints();         // SOFT

    // Add optimization objectives
    add_optimization_objectives();

    auto end_time = std::chrono::steady_clock::now();
    statistics_.constraint_build_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time);
    statistics_.total_constraints = static_cast<unsigned>(constraint_tracker_.total_constraints());
    statistics_.hard_constraints = static_cast<unsigned>(constraint_tracker_.hard_constraint_count());
    statistics_.soft_constraints = static_cast<unsigned>(constraint_tracker_.soft_constraint_count());

    z3_log("[Structor/Z3] Built %u constraints (%u hard, %u soft) in %lldms\n",
           statistics_.total_constraints,
           statistics_.hard_constraints,
           statistics_.soft_constraints,
           static_cast<long long>(statistics_.constraint_build_time.count()));
}

void LayoutConstraintBuilder::create_field_variables() {
    auto& ctx = ctx_.ctx();

    z3_log("[Structor/Z3] Creating field variables for %zu candidates\n", candidates_.size());

    // Create packing variable if needed
    if (config_.model_packing && !config_.packing_options.empty()) {
        packing_var_ = ctx.int_const("__packing");

        // Constrain packing to valid options (hard constraint, not tracked)
        ::z3::expr_vector options(ctx);
        for (uint32_t p : config_.packing_options) {
            options.push_back(*packing_var_ == static_cast<int>(p));
        }

        ConstraintProvenance prov;
        prov.description = "Packing value constraint";
        prov.is_soft = false;
        prov.kind = ConstraintProvenance::Kind::Other;
        constraint_tracker_.add_hard(solver_, ::z3::mk_or(options), prov);
        z3_log("[Structor/Z3]   Added packing constraint with %zu options\n", config_.packing_options.size());
    }

    // Create variables for each candidate
    for (size_t i = 0; i < candidates_.size(); ++i) {
        const auto& cand = candidates_[i];

        FieldVariables fv(ctx);
        fv.candidate_id = static_cast<int>(i);

        // Create named variables for this candidate
        qstring prefix;
        prefix.sprnt("f%zu_", i);

        fv.selected = ctx.bool_const((prefix + "sel").c_str());
        fv.offset = ctx.int_val(static_cast<int>(cand.offset));  // Fixed
        fv.size = ctx.int_val(static_cast<int>(cand.size));      // Fixed
        fv.type = ctx.int_val(static_cast<int>(cand.type_category));  // Fixed
        fv.is_array = ctx.bool_val(cand.is_array());
        fv.array_count = ctx.int_val(cand.array_element_count.value_or(1));
        fv.is_union_member = ctx.bool_const((prefix + "union").c_str());
        fv.union_group = ctx.int_const((prefix + "ugrp").c_str());

        // Constraint: if not union member, union_group is -1 (hard, tracked)
        {
            ConstraintProvenance prov;
            prov.description.sprnt("Union group default for field %zu", i);
            prov.is_soft = false;
            prov.kind = ConstraintProvenance::Kind::Other;
            constraint_tracker_.add_hard(solver_, 
                ::z3::implies(!fv.is_union_member, fv.union_group == -1), prov);
        }

        // Constraint: union group in valid range (hard, tracked)
        {
            ConstraintProvenance prov;
            prov.description.sprnt("Union group bounds for field %zu", i);
            prov.is_soft = false;
            prov.kind = ConstraintProvenance::Kind::Other;
            constraint_tracker_.add_hard(solver_, fv.union_group >= -1, prov);
            constraint_tracker_.add_hard(solver_, 
                fv.union_group < config_.max_union_alternatives, prov);
        }

        // Soft constraint: prefer NOT being a union member
        // This prevents Z3 from arbitrarily marking fields as unions
        {
            int weight = access_weight(cand, config_.weight_prefer_non_union);
            if (weight > 0) {
                ConstraintProvenance prov;
                prov.description.sprnt("Prefer non-union for field %zu", i);
                prov.is_soft = true;
                prov.kind = ConstraintProvenance::Kind::Other;
                prov.weight = weight;
                constraint_tracker_.add_soft(solver_, !fv.is_union_member, prov, weight);
            }
        }

        // Soft constraint: penalize selecting padding fields
        if (cand.kind == FieldCandidate::Kind::PaddingField) {
            int weight = padding_weight(cand.size, config_.weight_minimize_padding);
            if (weight > 0) {
                ConstraintProvenance prov;
                prov.description.sprnt("Penalize padding at 0x%llX", static_cast<unsigned long long>(cand.offset));
                prov.is_soft = true;
                prov.kind = ConstraintProvenance::Kind::Other;
                prov.weight = weight;
                constraint_tracker_.add_soft(solver_, !fv.selected, prov, weight);
            }
        }

        field_vars_.push_back(fv);
    }
}

void LayoutConstraintBuilder::add_coverage_constraints() {
    auto& ctx = ctx_.ctx();

    z3_log("[Structor/Z3] Adding coverage constraints for %zu accesses\n", pattern_->all_accesses.size());
    int uncovered_count = 0;

    for (size_t i = 0; i < pattern_->all_accesses.size(); ++i) {
        const auto& access = pattern_->all_accesses[i];

        // Build: OR of all candidates that cover this access
        ::z3::expr_vector covering(ctx);

        for (const auto& fv : field_vars_) {
            const auto& cand = candidates_[fv.candidate_id];

            if (candidate_covers_access(cand, access)) {
                covering.push_back(fv.selected);
            }
        }

        if (covering.empty()) {
            // No candidate covers this access - this is a problem
            // Add a false constraint to force UNSAT with useful core
            ConstraintProvenance prov;
            prov.insn_ea = access.insn_ea;
            prov.access_idx = static_cast<int>(i);
            prov.description.sprnt("Access at 0x%llX (offset 0x%llX size %u) has no covering field",
                static_cast<unsigned long long>(access.insn_ea),
                static_cast<unsigned long long>(access.offset),
                access.size);
            prov.is_soft = false;
            prov.kind = ConstraintProvenance::Kind::Coverage;
            prov.weight = config_.weight_coverage;

            z3_log("[Structor/Z3]   WARNING: Access %zu at offset 0x%llX size %u has NO covering candidates!\n",
                   i, static_cast<unsigned long long>(access.offset), access.size);
            constraint_tracker_.add_hard(solver_, ctx.bool_val(false), prov);
            ++uncovered_count;
            continue;
        }

        // At least one covering field must be selected
        ::z3::expr coverage = ::z3::mk_or(covering);

        ConstraintProvenance prov;
        prov.insn_ea = access.insn_ea;
        prov.access_idx = static_cast<int>(i);
        prov.description.sprnt("Access at offset 0x%llX size %u must be covered",
            static_cast<unsigned long long>(access.offset), access.size);
        prov.is_soft = false;
        prov.kind = ConstraintProvenance::Kind::Coverage;
        prov.weight = config_.weight_coverage;

        constraint_tracker_.add_hard(solver_, coverage, prov);
        ++statistics_.coverage_constraints;
    }
    
    z3_log("[Structor/Z3]   Added %u coverage constraints (%d uncovered accesses)\n", 
           statistics_.coverage_constraints, uncovered_count);
}

void LayoutConstraintBuilder::add_non_overlap_constraints() {
    auto& ctx = ctx_.ctx();

    z3_log("[Structor/Z3] Adding non-overlap constraints (allow_unions=%s)\n", 
           config_.allow_unions ? "true" : "false");
    int overlap_count = 0;
    int non_overlap_union_constraints = 0;

    for (size_t i = 0; i < field_vars_.size(); ++i) {
        for (size_t j = i + 1; j < field_vars_.size(); ++j) {
            const auto& fv1 = field_vars_[i];
            const auto& fv2 = field_vars_[j];
            const auto& c1 = candidates_[fv1.candidate_id];
            const auto& c2 = candidates_[fv2.candidate_id];

            // Check if candidates could overlap
            bool could_overlap = c1.overlaps(c2);

            if (!could_overlap) {
                // Non-overlapping fields cannot be in the same union group
                // This prevents Z3 from putting all fields in one union
                if (config_.allow_unions) {
                    ::z3::expr different_groups = 
                        !fv1.is_union_member || !fv2.is_union_member ||
                        (fv1.union_group != fv2.union_group);
                    
                    // Add as hard constraint (not tracked, always true)
                    solver_.add(::z3::implies(fv1.selected && fv2.selected, different_groups));
                    ++non_overlap_union_constraints;
                }
                continue;
            }
            ++overlap_count;

            if (config_.allow_unions) {
                // Either non-overlapping OR both are union members in same group
                ::z3::expr non_overlap =
                    (fv1.offset + ctx.int_val(static_cast<int>(c1.size)) <= fv2.offset) ||
                    (fv2.offset + ctx.int_val(static_cast<int>(c2.size)) <= fv1.offset);

                ::z3::expr same_union =
                    fv1.is_union_member && fv2.is_union_member &&
                    (fv1.union_group == fv2.union_group) &&
                    (fv1.union_group >= 0);

                ::z3::expr constraint = ::z3::implies(
                    fv1.selected && fv2.selected,
                    non_overlap || same_union
                );

                ConstraintProvenance prov;
                prov.description.sprnt("Non-overlap or union at 0x%llX",
                    static_cast<unsigned long long>(c1.offset));
                prov.is_soft = true;
                prov.kind = ConstraintProvenance::Kind::NonOverlap;
                prov.weight = config_.weight_minimize_fields;

                constraint_tracker_.add_soft(solver_, constraint, prov, config_.weight_minimize_fields);
            } else {
                // Hard non-overlap
                ::z3::expr non_overlap =
                    (fv1.offset + ctx.int_val(static_cast<int>(c1.size)) <= fv2.offset) ||
                    (fv2.offset + ctx.int_val(static_cast<int>(c2.size)) <= fv1.offset);

                ::z3::expr constraint = ::z3::implies(
                    fv1.selected && fv2.selected,
                    non_overlap
                );

                ConstraintProvenance prov;
                prov.description.sprnt("Non-overlap at 0x%llX",
                    static_cast<unsigned long long>(c1.offset));
                prov.is_soft = false;
                prov.kind = ConstraintProvenance::Kind::NonOverlap;

                constraint_tracker_.add_hard(solver_, constraint, prov);
            }
        }
    }
    
    z3_log("[Structor/Z3]   Added %d non-overlap constraints for overlapping candidate pairs\n", overlap_count);
    if (non_overlap_union_constraints > 0) {
        z3_log("[Structor/Z3]   Added %d constraints preventing non-overlapping fields from sharing union groups\n", 
               non_overlap_union_constraints);
    }
}

void LayoutConstraintBuilder::add_alignment_constraints() {
    auto& ctx = ctx_.ctx();

    z3_log("[Structor/Z3] Adding alignment constraints\n");
    int misaligned_count = 0;

    for (const auto& fv : field_vars_) {
        const auto& cand = candidates_[fv.candidate_id];
        uint32_t natural_align = ctx_.type_encoder().natural_alignment(cand.type_category);

        // Effective alignment = min(natural_align, packing)
        ::z3::expr effective_align = config_.model_packing && packing_var_
            ? ::z3::ite(ctx.int_val(static_cast<int>(natural_align)) < *packing_var_,
                        ctx.int_val(static_cast<int>(natural_align)),
                        *packing_var_)
            : ctx.int_val(static_cast<int>(natural_align));

        // Soft constraint: offset % effective_align == 0
        // Since offset is fixed, we can check this statically
        bool is_aligned = (cand.offset % natural_align) == 0;

        if (!is_aligned) {
            // Only add constraint if misaligned
            ::z3::expr constraint = ::z3::implies(fv.selected, ctx.bool_val(is_aligned));

            ConstraintProvenance prov;
            prov.description.sprnt("Alignment of field at 0x%llX (need %u, candidate %d)",
                static_cast<unsigned long long>(cand.offset), natural_align, fv.candidate_id);
            prov.is_soft = true;
            prov.kind = ConstraintProvenance::Kind::Alignment;
            prov.weight = config_.weight_alignment;

            constraint_tracker_.add_soft(solver_, constraint, prov, config_.weight_alignment);
            ++statistics_.alignment_constraints;
            ++misaligned_count;
        }
    }
    
    z3_log("[Structor/Z3]   Added %d alignment constraints for misaligned candidates\n", misaligned_count);
}

void LayoutConstraintBuilder::add_type_constraints() {
    // Add soft constraints for type consistency between overlapping candidates
    // that might end up in the same union

    z3_log("[Structor/Z3] Adding type consistency constraints\n");
    int type_constraint_count = 0;

    for (size_t i = 0; i < field_vars_.size(); ++i) {
        for (size_t j = i + 1; j < field_vars_.size(); ++j) {
            const auto& c1 = candidates_[field_vars_[i].candidate_id];
            const auto& c2 = candidates_[field_vars_[j].candidate_id];

            // Only for overlapping candidates at same offset
            if (c1.offset != c2.offset) continue;

            // Check type compatibility
            bool compatible = types_compatible(c1.type_category, c2.type_category);
            ++type_constraint_count;

            if (!compatible) {
                ConstraintProvenance prov;
                prov.description.sprnt("Type consistency at 0x%llX: %s vs %s",
                    static_cast<unsigned long long>(c1.offset),
                    type_category_name(c1.type_category),
                    type_category_name(c2.type_category));
                const auto& weight_source = (c1.source_access_indices.size() >= c2.source_access_indices.size())
                    ? c1 : c2;
                int weight = access_weight(weight_source, config_.weight_type_consistency);

                prov.is_soft = true;
                prov.kind = ConstraintProvenance::Kind::TypeMatch;
                prov.weight = weight;

                // Prefer not selecting both incompatible types
                ::z3::expr constraint = !(field_vars_[i].selected && field_vars_[j].selected);

                constraint_tracker_.add_soft(solver_, constraint, prov, weight);
                ++statistics_.type_constraints;
            }
        }
    }
    
    z3_log("[Structor/Z3]   Added %u type consistency constraints (checked %d pairs)\n", 
           statistics_.type_constraints, type_constraint_count);
}

void LayoutConstraintBuilder::add_type_preference_constraints() {
    // Add soft constraints preferring typed fields over raw_bytes/unknown
    // When two overlapping candidates exist, prefer the one with a more specific type
    
    int preference_count = 0;
    
    for (size_t i = 0; i < field_vars_.size(); ++i) {
        for (size_t j = i + 1; j < field_vars_.size(); ++j) {
            const auto& c1 = candidates_[field_vars_[i].candidate_id];
            const auto& c2 = candidates_[field_vars_[j].candidate_id];
            
            // Only for overlapping candidates
            if (!c1.overlaps(c2)) continue;
            
            // Determine which one is more specifically typed
            bool c1_is_raw = (c1.type_category == TypeCategory::RawBytes || 
                              c1.type_category == TypeCategory::Unknown);
            bool c2_is_raw = (c2.type_category == TypeCategory::RawBytes || 
                              c2.type_category == TypeCategory::Unknown);
            
            if (c1_is_raw && !c2_is_raw) {
                // Prefer c2 (typed) over c1 (raw)
                ConstraintProvenance prov;
                prov.description.sprnt("Prefer typed field at 0x%llX over raw at 0x%llX",
                    static_cast<unsigned long long>(c2.offset),
                    static_cast<unsigned long long>(c1.offset));
                int weight = access_weight(c2, 1);
                prov.is_soft = true;
                prov.kind = ConstraintProvenance::Kind::TypeMatch;
                prov.weight = weight;
                
                // Prefer the typed candidate by penalizing selecting raw when typed exists
                constraint_tracker_.add_soft(solver_, !field_vars_[i].selected, prov, weight);
                ++preference_count;
            }
            else if (c2_is_raw && !c1_is_raw) {
                // Prefer c1 (typed) over c2 (raw)
                ConstraintProvenance prov;
                prov.description.sprnt("Prefer typed field at 0x%llX over raw at 0x%llX",
                    static_cast<unsigned long long>(c1.offset),
                    static_cast<unsigned long long>(c2.offset));
                int weight = access_weight(c1, 1);
                prov.is_soft = true;
                prov.kind = ConstraintProvenance::Kind::TypeMatch;
                prov.weight = weight;
                
                constraint_tracker_.add_soft(solver_, !field_vars_[j].selected, prov, weight);
                ++preference_count;
            }
        }
    }
    
    if (preference_count > 0) {
        z3_log("[Structor/Z3]   Added %d type preference constraints (prefer typed over raw)\n", 
               preference_count);
    }
}

void LayoutConstraintBuilder::add_size_bound_constraints() {
    // Add hard constraint for max struct size
    // The struct size is max(field.offset + field.size) for all selected fields

    // Since offsets/sizes are fixed, we can just check the bounds
    sval_t max_end = 0;
    for (const auto& cand : candidates_) {
        sval_t end = cand.offset + cand.size;
        max_end = std::max(max_end, end);
    }

    if (max_end > static_cast<sval_t>(config_.max_struct_size)) {
        ConstraintProvenance prov;
        prov.description.sprnt("Struct size limit exceeded (max=%u)",
            config_.max_struct_size);
        prov.is_soft = false;
        prov.kind = ConstraintProvenance::Kind::SizeMatch;

        // This would make the whole thing UNSAT - issue a warning instead
        // For now, just log and continue
    }
}

void LayoutConstraintBuilder::add_array_constraints() {
    // For each detected array, prefer selecting the array field over individual elements
    for (const auto& array : arrays_) {
        // Find the array field candidate (if any)
        int array_field_idx = -1;
        qvector<int> element_indices;

        for (size_t i = 0; i < candidates_.size(); ++i) {
            const auto& cand = candidates_[i];

            if (cand.kind == FieldCandidate::Kind::ArrayField &&
                cand.offset == array.base_offset &&
                cand.array_element_count == array.element_count) {
                array_field_idx = static_cast<int>(i);
            }
            else if (array.contains_offset(cand.offset) &&
                     cand.kind == FieldCandidate::Kind::ArrayElement) {
                element_indices.push_back(static_cast<int>(i));
            }
        }

        if (array_field_idx >= 0 && !element_indices.empty()) {
            // Soft constraint: if array field selected, don't select individual elements
            ::z3::expr array_selected = field_vars_[array_field_idx].selected;

            for (int elem_idx : element_indices) {
                ::z3::expr constraint = ::z3::implies(
                    array_selected,
                    !field_vars_[elem_idx].selected
                );

                ConstraintProvenance prov;
                prov.description.sprnt("Prefer array over elements at 0x%llX",
                    static_cast<unsigned long long>(array.base_offset));
                prov.is_soft = true;
                prov.kind = ConstraintProvenance::Kind::ArrayDetection;
                prov.weight = config_.weight_prefer_arrays;

                constraint_tracker_.add_soft(solver_, constraint, prov,
                    config_.weight_prefer_arrays);
            }
        }
    }
}

void LayoutConstraintBuilder::add_optimization_objectives() {
    // Minimize total number of selected fields (soft)
    auto& ctx = ctx_.ctx();

    ::z3::expr_vector selected(ctx);
    for (const auto& fv : field_vars_) {
        selected.push_back(::z3::ite(fv.selected, ctx.int_val(1), ctx.int_val(0)));
    }

    if (!selected.empty()) {
        // We can't directly add optimization objectives to a regular solver
        // This would need z3::optimize, but we're using solver for tracking
        // Instead, we add soft constraints that penalize selecting too many fields
    }
}

Z3Result LayoutConstraintBuilder::solve() {
    auto start_time = std::chrono::steady_clock::now();

    z3_log("[Structor/Z3] Solving constraints...\n");
    z3_log("[Structor/Z3] Solver assertions: %u\n", solver_.assertions().size());

    // Build assumptions from all tracking literals
    // All constraints are guarded by implications: tracking_lit => constraint
    // By assuming all tracking_lits are true, we activate all constraints
    ::z3::expr_vector assumptions = constraint_tracker_.get_all_literals();
    z3_log("[Structor/Z3] Assumptions (tracking literals): %u\n", assumptions.size());

    // First attempt: solve with all constraints assumed active
    auto result = solver_.check(assumptions);

    auto end_time = std::chrono::steady_clock::now();
    auto solve_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time);

    statistics_.solve_time = solve_time;
    ++statistics_.solve_iterations;

    if (result == ::z3::sat) {
        z3_log("[Structor/Z3] SAT - solution found in %lldms\n",
               static_cast<long long>(solve_time.count()));

        ::z3::model model = solver_.get_model();

        // Extract packing if modeled
        if (packing_var_) {
            inferred_packing_ = static_cast<uint32_t>(get_int_value(model, *packing_var_));
            z3_log("[Structor/Z3] Inferred packing: %u\n", *inferred_packing_);
        }

        // Detect union groups
        detect_union_groups(model);
        if (!union_resolutions_.empty()) {
            z3_log("[Structor/Z3] Detected %zu union groups\n", union_resolutions_.size());
        }

        return Z3Result::make_sat(std::move(model), solve_time);
    }
    else if (result == ::z3::unsat) {
        z3_log("[Structor/Z3] UNSAT - attempting relaxation...\n");
        // Try relaxation
        return solve_with_relaxation();
    }
    else {
        // Get the actual reason for unknown
        std::string reason = Z3Context::get_unknown_reason(solver_);
        z3_log("[Structor/Z3] UNKNOWN result after %lldms: %s\n",
               static_cast<long long>(solve_time.count()), reason.c_str());
        
        qstring reason_msg;
        reason_msg.sprnt("solver returned unknown: %s", reason.c_str());
        return Z3Result::make_unknown(reason_msg.c_str(), solve_time);
    }
}

Z3Result LayoutConstraintBuilder::solve_with_relaxation() {
    auto start_time = std::chrono::steady_clock::now();
    qvector<ConstraintProvenance> dropped_constraints;

    // Build the set of active assumptions (tracking literals)
    // Start with all tracking literals active
    std::unordered_set<std::string> active_assumptions;
    ::z3::expr_vector all_literals = constraint_tracker_.get_all_literals();
    for (unsigned i = 0; i < all_literals.size(); ++i) {
        active_assumptions.insert(all_literals[i].to_string());
    }

    constexpr int MAX_RELAXATION_ITERATIONS = 10;

    z3_log("[Structor/Z3] Starting constraint relaxation (max %d iterations)\n",
           MAX_RELAXATION_ITERATIONS);
    z3_log("[Structor/Z3] Initial assumptions: %zu\n", active_assumptions.size());

    for (int iteration = 0; iteration < MAX_RELAXATION_ITERATIONS; ++iteration) {
        // Get UNSAT core from the last check (which used assumptions)
        auto core = solver_.unsat_core();
        auto core_provenances = constraint_tracker_.analyze_unsat_core(core);

        z3_log("[Structor/Z3] Iteration %d: UNSAT core has %u constraints (%zu analyzed)\n",
               iteration + 1, core.size(), core_provenances.size());

        // Log all constraints in the core
        z3_log("[Structor/Z3]   Core contents:\n");
        for (const auto& prov : core_provenances) {
            z3_log("[Structor/Z3]     [%s w=%d] %s (lit=%s)\n",
                   prov.is_soft ? "SOFT" : "HARD",
                   prov.weight,
                   prov.description.c_str(),
                   prov.tracking_literal ? prov.tracking_literal->to_string().c_str() : "none");
        }

        // Find soft constraints in the core (prioritize by weight - lower weight = relax first)
        qvector<ConstraintProvenance> relaxable;
        for (const auto& prov : core_provenances) {
            if (prov.is_soft && prov.tracking_literal) {
                // Only include if it's still in our active assumptions
                std::string lit_str = prov.tracking_literal->to_string();
                if (active_assumptions.count(lit_str)) {
                    relaxable.push_back(prov);
                }
            }
        }

        if (relaxable.empty()) {
            // All core constraints are hard - truly unsatisfiable
            z3_log("[Structor/Z3] Relaxation failed - all core constraints are hard\n");
            auto end_time = std::chrono::steady_clock::now();
            auto solve_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                end_time - start_time);
            return Z3Result::make_unsat(std::move(core_provenances), solve_time);
        }

        // Sort by weight (ascending) - relax lowest weight constraints first
        std::sort(relaxable.begin(), relaxable.end(),
            [](const ConstraintProvenance& a, const ConstraintProvenance& b) {
                return a.weight < b.weight;
            });

        // Relax the lowest-weight soft constraint by removing from assumptions
        const auto& to_relax = relaxable[0];
        dropped_constraints.push_back(to_relax);

        z3_log("[Structor/Z3] Relaxing constraint (weight=%d): %s\n",
               to_relax.weight, to_relax.description.c_str());
        z3_log("[Structor/Z3]   Tracking literal: %s\n",
               to_relax.tracking_literal->to_string().c_str());

        // Remove this tracking literal from active assumptions
        active_assumptions.erase(to_relax.tracking_literal->to_string());

        ++statistics_.relaxations_performed;

        // Build new assumptions vector
        ::z3::expr_vector current_assumptions(ctx_.ctx());
        for (unsigned i = 0; i < all_literals.size(); ++i) {
            if (active_assumptions.count(all_literals[i].to_string())) {
                current_assumptions.push_back(all_literals[i]);
            }
        }

        z3_log("[Structor/Z3]   Remaining assumptions: %u\n", current_assumptions.size());

        // Re-solve with reduced assumptions
        auto result = solver_.check(current_assumptions);

        if (result == ::z3::sat) {
            z3_log("[Structor/Z3] Relaxation succeeded after dropping %zu constraints\n",
                   dropped_constraints.size());

            ::z3::model model = solver_.get_model();

            // Extract packing if modeled
            if (packing_var_) {
                inferred_packing_ = static_cast<uint32_t>(get_int_value(model, *packing_var_));
            }

            // Detect union groups
            detect_union_groups(model);

            auto end_time = std::chrono::steady_clock::now();
            auto solve_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                end_time - start_time);

            // Return SAT with dropped constraints info
            Z3Result sat_result = Z3Result::make_sat(std::move(model), solve_time);
            sat_result.dropped_constraints = std::move(dropped_constraints);
            return sat_result;
        }
        // If still UNSAT, continue relaxing
    }

    // Reached max iterations without satisfiability
    auto end_time = std::chrono::steady_clock::now();
    auto solve_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time);

    // Return UNSAT with all dropped constraints for diagnostics
    Z3Result unsat_result = Z3Result::make_unsat(
        constraint_tracker_.analyze_unsat_core(solver_.unsat_core()), solve_time);
    unsat_result.dropped_constraints = std::move(dropped_constraints);
    return unsat_result;
}

qvector<ConstraintProvenance> LayoutConstraintBuilder::extract_mus() {
    // Extract minimal unsatisfiable subset
    auto core = solver_.unsat_core();
    return constraint_tracker_.analyze_unsat_core(core);
}

SynthStruct LayoutConstraintBuilder::extract_struct(const ::z3::model& model) {
    auto start_time = std::chrono::steady_clock::now();

    z3_log("[Structor/Z3] Extracting structure from Z3 model...\n");

    SynthStruct result;

    // Collect selected fields
    qvector<std::pair<int, FieldCandidate>> selected_fields;

    for (const auto& fv : field_vars_) {
        if (get_bool_value(model, fv.selected)) {
            selected_fields.push_back({fv.candidate_id, candidates_[fv.candidate_id]});
        }
    }

    z3_log("[Structor/Z3]   Model selected %zu of %zu candidates\n", 
           selected_fields.size(), field_vars_.size());

    // Sort by offset
    std::sort(selected_fields.begin(), selected_fields.end(),
        [](const auto& a, const auto& b) {
            return a.second.offset < b.second.offset;
        });
    
    // Log selected fields
    for (const auto& [cand_id, cand] : selected_fields) {
        z3_log("[Structor/Z3]   Selected: candidate %d at offset 0x%llX size %u type %s\n",
               cand_id, static_cast<unsigned long long>(cand.offset), cand.size,
               type_category_name(cand.type_category));
    }

    // Build fields, handling unions
    std::unordered_set<int> processed_union_groups;

    z3_log("[Structor/Z3]   Processing selected candidates for union detection:\n");
    for (const auto& [cand_id, candidate] : selected_fields) {
        const auto& fv = field_vars_[cand_id];

        // Check if part of a union
        bool is_union = get_bool_value(model, fv.is_union_member);
        int union_group = static_cast<int>(get_int_value(model, fv.union_group));

        z3_log("[Structor/Z3]     Candidate %d (offset=0x%llX, size=%u): is_union=%s, union_group=%d\n",
               cand_id, static_cast<unsigned long long>(candidate.offset), candidate.size,
               is_union ? "true" : "false", union_group);

        if (is_union && union_group >= 0) {
            // Check if we've already processed this union group
            if (processed_union_groups.count(union_group)) {
                z3_log("[Structor/Z3]       -> Skipping (union group %d already processed)\n", union_group);
                continue;
            }
            processed_union_groups.insert(union_group);

            // Find all members of this union group
            qvector<int> union_members;
            for (size_t i = 0; i < field_vars_.size(); ++i) {
                const auto& other_fv = field_vars_[i];
                if (get_bool_value(model, other_fv.selected) &&
                    get_bool_value(model, other_fv.is_union_member) &&
                    get_int_value(model, other_fv.union_group) == union_group) {
                    union_members.push_back(static_cast<int>(i));
                }
            }

            z3_log("[Structor/Z3]       -> Creating union with %zu members\n", union_members.size());
            for (int member_idx : union_members) {
                const auto& member_cand = candidates_[field_vars_[member_idx].candidate_id];
                z3_log("[Structor/Z3]         Union member: idx=%d, offset=0x%llX, size=%u\n",
                       member_idx, static_cast<unsigned long long>(member_cand.offset), member_cand.size);
            }

            // Create union field
            SynthField union_field = create_union_field(union_members, model);
            z3_log("[Structor/Z3]       -> Created union field: name='%s', offset=0x%llX, size=%u\n",
                   union_field.name.c_str(), static_cast<unsigned long long>(union_field.offset), union_field.size);
            result.fields.push_back(std::move(union_field));
        } else {
            // Regular field
            z3_log("[Structor/Z3]       -> Adding as regular field\n");
            SynthField field = field_from_candidate(candidate, ctx_.type_encoder());
            z3_log("[Structor/Z3]       -> Created field: name='%s', offset=0x%llX, size=%u\n",
                   field.name.c_str(), static_cast<unsigned long long>(field.offset), field.size);
            result.fields.push_back(std::move(field));
        }
    }

    // Set struct properties
    if (!result.fields.empty()) {
        result.size = static_cast<uint32_t>(
            result.fields.back().offset + result.fields.back().size);
    }

    result.alignment = config_.default_alignment;
    if (inferred_packing_) {
        result.alignment = std::min(result.alignment, *inferred_packing_);
    }

    auto end_time = std::chrono::steady_clock::now();
    statistics_.extraction_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time);

    // Fill gaps between fields with padding
    if (config_.fill_gaps_with_padding && !result.fields.empty()) {
        qvector<SynthField> fields_with_padding;
        sval_t current_end = 0;

        for (const auto& field : result.fields) {
            // Check for gap before this field
            if (field.offset > current_end) {
                uint32_t gap_size = static_cast<uint32_t>(field.offset - current_end);
                z3_log("[Structor/Z3] Filling gap at 0x%llX (size %u) with padding\n",
                       static_cast<unsigned long long>(current_end), gap_size);
                fields_with_padding.push_back(SynthField::create_padding(current_end, gap_size));
            }
            fields_with_padding.push_back(field);
            current_end = field.offset + static_cast<sval_t>(field.size);
        }

        result.fields = std::move(fields_with_padding);
        
        // Recalculate size
        if (!result.fields.empty()) {
            result.size = static_cast<uint32_t>(
                result.fields.back().offset + result.fields.back().size);
        }
    }

    z3_log("[Structor/Z3] Extracted structure: %zu fields, %u bytes, alignment %u\n",
           result.fields.size(), result.size, result.alignment);
    
    // Dump all fields for debugging
    z3_log("[Structor/Z3] Final field list:\n");
    for (size_t i = 0; i < result.fields.size(); ++i) {
        const auto& f = result.fields[i];
        z3_log("[Structor/Z3]   [%zu] name='%s', offset=0x%llX, size=%u, is_union=%s%s\n",
               i, f.name.c_str(), static_cast<unsigned long long>(f.offset),
               f.size, f.is_union_candidate ? "yes" : "no",
               f.is_padding ? " [padding]" : "");
    }

    return result;
}

void LayoutConstraintBuilder::detect_union_groups(const ::z3::model& model) {
    union_resolutions_.clear();

    std::unordered_map<int, qvector<int>> groups;

    for (size_t i = 0; i < field_vars_.size(); ++i) {
        const auto& fv = field_vars_[i];

        if (get_bool_value(model, fv.selected) &&
            get_bool_value(model, fv.is_union_member)) {
            int group = static_cast<int>(get_int_value(model, fv.union_group));
            if (group >= 0) {
                groups[group].push_back(static_cast<int>(i));
            }
        }
    }

    for (const auto& [group_id, members] : groups) {
        if (members.size() <= 1) continue;

        UnionResolution resolution;
        resolution.union_id = group_id;
        resolution.member_candidate_ids = members;

        // Calculate union offset and size
        sval_t min_offset = SVAL_MAX;
        sval_t max_end = 0;

        for (int idx : members) {
            const auto& cand = candidates_[field_vars_[idx].candidate_id];
            min_offset = std::min(min_offset, cand.offset);
            max_end = std::max(max_end, cand.offset + static_cast<sval_t>(cand.size));
        }

        resolution.offset = min_offset;
        resolution.size = static_cast<uint32_t>(max_end - min_offset);

        // Create alternative fields
        for (int idx : members) {
            const auto& cand = candidates_[field_vars_[idx].candidate_id];
            resolution.alternatives.push_back(field_from_candidate(cand, ctx_.type_encoder()));
        }

        union_resolutions_.push_back(std::move(resolution));
    }
}

SynthField LayoutConstraintBuilder::create_union_field(
    const qvector<int>& overlapping_ids,
    const ::z3::model& model)
{
    SynthField union_field;
    union_field.is_union_candidate = true;

    // Calculate union bounds
    sval_t min_offset = SVAL_MAX;
    sval_t max_end = 0;

    z3_log("[Structor/Z3] create_union_field: %zu overlapping candidates\n", overlapping_ids.size());
    for (int idx : overlapping_ids) {
        const auto& cand = candidates_[field_vars_[idx].candidate_id];
        z3_log("[Structor/Z3]   Member idx=%d, cand_id=%d, offset=0x%llX, size=%u\n",
               idx, field_vars_[idx].candidate_id,
               static_cast<unsigned long long>(cand.offset), cand.size);
        min_offset = std::min(min_offset, cand.offset);
        max_end = std::max(max_end, cand.offset + static_cast<sval_t>(cand.size));
    }

    // Validate: if no valid members, use offset 0
    if (min_offset == SVAL_MAX || min_offset < 0) {
        z3_log("[Structor/Z3] WARNING: Invalid min_offset=0x%llX, using 0\n",
               static_cast<unsigned long long>(min_offset));
        min_offset = 0;
    }
    if (max_end <= min_offset) {
        z3_log("[Structor/Z3] WARNING: Invalid max_end=0x%llX (< min_offset), using min+8\n",
               static_cast<unsigned long long>(max_end));
        max_end = min_offset + 8;
    }

    union_field.offset = min_offset;
    union_field.size = static_cast<uint32_t>(max_end - min_offset);
    union_field.name.sprnt("union_%llX", static_cast<unsigned long long>(min_offset));
    z3_log("[Structor/Z3] Created union: offset=0x%llX, size=%u, name='%s'\n",
           static_cast<unsigned long long>(union_field.offset), union_field.size,
           union_field.name.c_str());
    union_field.semantic = SemanticType::Unknown;

    // Create union type
    // For now, use the largest member's type
    const FieldCandidate* largest = nullptr;
    for (int idx : overlapping_ids) {
        const auto& cand = candidates_[field_vars_[idx].candidate_id];
        if (!largest || cand.size > largest->size) {
            largest = &cand;
        }
    }

    if (largest) {
        union_field.type = ctx_.type_encoder().decode(
            largest->type_category,
            largest->size,
            &largest->extended_type
        );
    }

    return union_field;
}

SynthField LayoutConstraintBuilder::create_raw_bytes_field(
    sval_t offset,
    uint32_t size)
{
    return SynthField::create_padding(offset, size);
}

bool LayoutConstraintBuilder::get_bool_value(
    const ::z3::model& model,
    const ::z3::expr& e) const
{
    try {
        ::z3::expr val = model.eval(e, true);
        return val.is_true();
    } catch (...) {
        return false;
    }
}

int64_t LayoutConstraintBuilder::get_int_value(
    const ::z3::model& model,
    const ::z3::expr& e) const
{
    try {
        ::z3::expr val = model.eval(e, true);
        if (val.is_numeral()) {
            return val.get_numeral_int64();
        }
    } catch (...) {
    }
    return 0;
}

bool LayoutConstraintBuilder::candidate_covers_access(
    const FieldCandidate& candidate,
    const FieldAccess& access) const
{
    // Candidate covers access if:
    //   cand.offset <= access.offset AND
    //   cand.offset + cand.size >= access.offset + access.size
    return candidate.offset <= access.offset &&
           candidate.offset + static_cast<sval_t>(candidate.size) >=
           access.offset + static_cast<sval_t>(access.size);
}

} // namespace structor::z3
