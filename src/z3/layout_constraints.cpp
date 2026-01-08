#include "structor/z3/layout_constraints.hpp"
#include <algorithm>
#include <chrono>

namespace structor::z3 {

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
    , type_encoder_(ctx)
    , array_builder_(ctx)
    , constraint_tracker_(ctx.ctx())
    , solver_(ctx.ctx()) {}

void LayoutConstraintBuilder::build_constraints(
    const UnifiedAccessPattern& pattern,
    const qvector<FieldCandidate>& candidates)
{
    auto start_time = std::chrono::steady_clock::now();

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

    // Create field variables
    create_field_variables();

    // Add constraints in order of importance
    add_coverage_constraints();      // HARD
    add_size_bound_constraints();    // HARD

    add_non_overlap_constraints();   // SOFT (union option)
    add_alignment_constraints();     // SOFT
    add_type_constraints();          // SOFT
    add_array_constraints();         // SOFT

    // Add optimization objectives
    add_optimization_objectives();

    auto end_time = std::chrono::steady_clock::now();
    statistics_.constraint_build_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time);
    statistics_.total_constraints = static_cast<unsigned>(constraint_tracker_.total_constraints());
    statistics_.hard_constraints = static_cast<unsigned>(constraint_tracker_.hard_constraint_count());
    statistics_.soft_constraints = static_cast<unsigned>(constraint_tracker_.soft_constraint_count());
}

void LayoutConstraintBuilder::create_field_variables() {
    auto& ctx = ctx_.ctx();

    // Create packing variable if needed
    if (config_.model_packing && !config_.packing_options.empty()) {
        packing_var_ = ctx.int_const("__packing");

        // Constrain packing to valid options
        ::z3::expr_vector options(ctx);
        for (uint32_t p : config_.packing_options) {
            options.push_back(*packing_var_ == static_cast<int>(p));
        }
        solver_.add(::z3::mk_or(options));
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

        // Constraint: if not union member, union_group is -1
        solver_.add(::z3::implies(!fv.is_union_member, fv.union_group == -1));

        // Constraint: union group in valid range
        solver_.add(fv.union_group >= -1);
        solver_.add(fv.union_group < config_.max_union_alternatives);

        field_vars_.push_back(fv);
    }
}

void LayoutConstraintBuilder::add_coverage_constraints() {
    auto& ctx = ctx_.ctx();

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

            constraint_tracker_.add_hard(solver_, ctx.bool_val(false), prov);
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
}

void LayoutConstraintBuilder::add_non_overlap_constraints() {
    auto& ctx = ctx_.ctx();

    for (size_t i = 0; i < field_vars_.size(); ++i) {
        for (size_t j = i + 1; j < field_vars_.size(); ++j) {
            const auto& fv1 = field_vars_[i];
            const auto& fv2 = field_vars_[j];
            const auto& c1 = candidates_[fv1.candidate_id];
            const auto& c2 = candidates_[fv2.candidate_id];

            // Check if candidates could overlap
            bool could_overlap = c1.overlaps(c2);

            if (!could_overlap) continue;

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
}

void LayoutConstraintBuilder::add_alignment_constraints() {
    auto& ctx = ctx_.ctx();

    for (const auto& fv : field_vars_) {
        const auto& cand = candidates_[fv.candidate_id];
        uint32_t natural_align = type_encoder_.natural_alignment(cand.type_category);

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
            prov.description.sprnt("Alignment of field at 0x%llX (need %u)",
                static_cast<unsigned long long>(cand.offset), natural_align);
            prov.is_soft = true;
            prov.kind = ConstraintProvenance::Kind::Alignment;
            prov.weight = config_.weight_alignment;

            constraint_tracker_.add_soft(solver_, constraint, prov, config_.weight_alignment);
            ++statistics_.alignment_constraints;
        }
    }
}

void LayoutConstraintBuilder::add_type_constraints() {
    // Add soft constraints for type consistency between overlapping candidates
    // that might end up in the same union

    for (size_t i = 0; i < field_vars_.size(); ++i) {
        for (size_t j = i + 1; j < field_vars_.size(); ++j) {
            const auto& c1 = candidates_[field_vars_[i].candidate_id];
            const auto& c2 = candidates_[field_vars_[j].candidate_id];

            // Only for overlapping candidates at same offset
            if (c1.offset != c2.offset) continue;

            // Check type compatibility
            bool compatible = types_compatible(c1.type_category, c2.type_category);

            if (!compatible) {
                ConstraintProvenance prov;
                prov.description.sprnt("Type consistency at 0x%llX: %s vs %s",
                    static_cast<unsigned long long>(c1.offset),
                    type_category_name(c1.type_category),
                    type_category_name(c2.type_category));
                prov.is_soft = true;
                prov.kind = ConstraintProvenance::Kind::TypeMatch;
                prov.weight = config_.weight_type_consistency;

                // Prefer not selecting both incompatible types
                auto& ctx = ctx_.ctx();
                ::z3::expr constraint = !(field_vars_[i].selected && field_vars_[j].selected);

                constraint_tracker_.add_soft(solver_, constraint, prov,
                    config_.weight_type_consistency);
                ++statistics_.type_constraints;
            }
        }
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
    auto& ctx = ctx_.ctx();

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

    // First attempt: solve with all constraints
    auto result = solver_.check();

    auto end_time = std::chrono::steady_clock::now();
    auto solve_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time);

    statistics_.solve_time = solve_time;
    ++statistics_.solve_iterations;

    if (result == ::z3::sat) {
        ::z3::model model = solver_.get_model();

        // Extract packing if modeled
        if (packing_var_) {
            inferred_packing_ = static_cast<uint32_t>(get_int_value(model, *packing_var_));
        }

        // Detect union groups
        detect_union_groups(model);

        return Z3Result::make_sat(std::move(model), solve_time);
    }
    else if (result == ::z3::unsat) {
        // Try relaxation
        return solve_with_relaxation();
    }
    else {
        return Z3Result::make_unknown("solver returned unknown", solve_time);
    }
}

Z3Result LayoutConstraintBuilder::solve_with_relaxation() {
    auto start_time = std::chrono::steady_clock::now();
    qvector<ConstraintProvenance> dropped_constraints;

    constexpr int MAX_RELAXATION_ITERATIONS = 10;

    for (int iteration = 0; iteration < MAX_RELAXATION_ITERATIONS; ++iteration) {
        // Get UNSAT core
        auto core = solver_.unsat_core();
        auto core_provenances = constraint_tracker_.analyze_unsat_core(core);

        // Find soft constraints in the core (prioritize by weight - lower weight = relax first)
        qvector<ConstraintProvenance> relaxable;
        for (const auto& prov : core_provenances) {
            if (prov.is_soft) {
                relaxable.push_back(prov);
            }
        }

        if (relaxable.empty()) {
            // All core constraints are hard - truly unsatisfiable
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

        // Relax the lowest-weight soft constraint
        const auto& to_relax = relaxable[0];
        dropped_constraints.push_back(to_relax);

        // Add negation of the tracking literal to disable this constraint
        // The constraint is: tracking_lit => actual_constraint
        // To disable: add !tracking_lit (the constraint becomes vacuously true)
        if (to_relax.tracking_literal) {
            solver_.add(!(*to_relax.tracking_literal));
        }

        ++statistics_.relaxations_performed;

        // Re-solve
        auto result = solver_.check();

        if (result == ::z3::sat) {
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

    SynthStruct result;

    // Collect selected fields
    qvector<std::pair<int, FieldCandidate>> selected_fields;

    for (const auto& fv : field_vars_) {
        if (get_bool_value(model, fv.selected)) {
            selected_fields.push_back({fv.candidate_id, candidates_[fv.candidate_id]});
        }
    }

    // Sort by offset
    std::sort(selected_fields.begin(), selected_fields.end(),
        [](const auto& a, const auto& b) {
            return a.second.offset < b.second.offset;
        });

    // Build fields, handling unions
    std::unordered_set<int> processed_union_groups;

    for (const auto& [cand_id, candidate] : selected_fields) {
        const auto& fv = field_vars_[cand_id];

        // Check if part of a union
        bool is_union = get_bool_value(model, fv.is_union_member);
        int union_group = static_cast<int>(get_int_value(model, fv.union_group));

        if (is_union && union_group >= 0) {
            // Check if we've already processed this union group
            if (processed_union_groups.count(union_group)) {
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

            // Create union field
            SynthField union_field = create_union_field(union_members, model);
            result.fields.push_back(std::move(union_field));
        } else {
            // Regular field
            SynthField field = field_from_candidate(candidate, type_encoder_);
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
            resolution.alternatives.push_back(field_from_candidate(cand, type_encoder_));
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

    for (int idx : overlapping_ids) {
        const auto& cand = candidates_[field_vars_[idx].candidate_id];
        min_offset = std::min(min_offset, cand.offset);
        max_end = std::max(max_end, cand.offset + static_cast<sval_t>(cand.size));
    }

    union_field.offset = min_offset;
    union_field.size = static_cast<uint32_t>(max_end - min_offset);
    union_field.name.sprnt("union_%llX", static_cast<unsigned long long>(min_offset));
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
        union_field.type = type_encoder_.decode(
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
