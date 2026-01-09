#pragma once

#include <z3++.h>
#include "structor/synth_types.hpp"
#include "structor/cross_function_analyzer.hpp"
#include "structor/z3/context.hpp"
#include "structor/z3/type_encoding.hpp"
#include "structor/z3/array_constraints.hpp"
#include "structor/z3/field_candidates.hpp"
#include "structor/z3/constraint_tracker.hpp"
#include "structor/z3/result.hpp"
#include <optional>

namespace structor::z3 {

/// Z3 variables representing a candidate field
struct FieldVariables {
    int candidate_id;              // Links to FieldCandidate
    ::z3::expr selected;           // Bool: is this candidate selected?
    ::z3::expr offset;             // Int: byte offset (fixed from candidate)
    ::z3::expr size;               // Int: field size (fixed from candidate)
    ::z3::expr type;               // TypeSort: field type category
    ::z3::expr is_array;           // Bool: is this an array field?
    ::z3::expr array_count;        // Int: number of elements (1 if not array)
    ::z3::expr is_union_member;    // Bool: is this part of a union?
    ::z3::expr union_group;        // Int: which union group (if any)

    FieldVariables(::z3::context& ctx)
        : candidate_id(-1)
        , selected(ctx.bool_val(false))
        , offset(ctx.int_val(0))
        , size(ctx.int_val(0))
        , type(ctx.int_val(0))
        , is_array(ctx.bool_val(false))
        , array_count(ctx.int_val(1))
        , is_union_member(ctx.bool_val(false))
        , union_group(ctx.int_val(-1)) {}
};

/// Configuration for layout constraint building
struct LayoutConstraintConfig {
    // Packing/alignment (modeled as soft constraint with variable p)
    uint32_t default_alignment = 8;
    bool model_packing = true;           // Infer packing parameter
    qvector<uint32_t> packing_options;   // Possible packing values

    // Union handling
    bool allow_unions = true;
    bool create_actual_unions = true;
    int max_union_alternatives = 8;

    // Optimization weights (for Max-SMT)
    int weight_coverage = 100;           // Hard: every access must be covered
    int weight_type_consistency = 10;    // Soft: prefer consistent types
    int weight_alignment = 5;            // Soft: prefer aligned fields
    int weight_minimize_fields = 2;      // Soft: prefer fewer fields
    int weight_minimize_padding = 1;     // Soft: prefer compact layout
    int weight_prefer_arrays = 3;        // Soft: prefer array detection

    // Limits
    uint32_t max_struct_size = 0x10000;

    // Post-processing
    bool fill_gaps_with_padding = true;  // Fill gaps between fields with padding

    LayoutConstraintConfig() {
        packing_options.push_back(1);
        packing_options.push_back(2);
        packing_options.push_back(4);
        packing_options.push_back(8);
        packing_options.push_back(16);
    }
};

/// Union resolution information
struct UnionResolution {
    int union_id;
    sval_t offset;
    uint32_t size;
    qvector<int> member_candidate_ids;
    qvector<SynthField> alternatives;
};

/// Builds and solves Z3 constraints for struct layout synthesis
class LayoutConstraintBuilder {
public:
    LayoutConstraintBuilder(
        Z3Context& ctx,
        const LayoutConstraintConfig& config = {}
    );

    /// Build all constraints from unified access pattern
    void build_constraints(
        const UnifiedAccessPattern& pattern,
        const qvector<FieldCandidate>& candidates
    );

    /// Solve with Max-SMT: maximize satisfied soft constraints
    /// On UNSAT of hard constraints: extract core, relax, re-solve
    [[nodiscard]] Z3Result solve();

    /// Extract synthesized struct from SAT model
    [[nodiscard]] SynthStruct extract_struct(const ::z3::model& model);

    /// Get detected arrays (available after build_constraints)
    [[nodiscard]] const qvector<ArrayCandidate>& detected_arrays() const noexcept {
        return arrays_;
    }

    /// Get field variables (for inspection)
    [[nodiscard]] const qvector<FieldVariables>& field_variables() const noexcept {
        return field_vars_;
    }

    /// Get inferred packing value (after solve)
    [[nodiscard]] std::optional<uint32_t> inferred_packing() const noexcept {
        return inferred_packing_;
    }

    /// Get union resolutions (after solve)
    [[nodiscard]] const qvector<UnionResolution>& union_resolutions() const noexcept {
        return union_resolutions_;
    }

    /// Get statistics
    [[nodiscard]] const Z3Statistics& statistics() const noexcept {
        return statistics_;
    }

    /// Get constraint tracker for debugging
    [[nodiscard]] const ConstraintTracker& tracker() const noexcept {
        return constraint_tracker_;
    }

private:
    Z3Context& ctx_;
    LayoutConstraintConfig config_;
    ArrayConstraintBuilder array_builder_;
    ConstraintTracker constraint_tracker_;

    ::z3::solver solver_;
    qvector<FieldVariables> field_vars_;
    qvector<ArrayCandidate> arrays_;
    qvector<FieldCandidate> candidates_;

    // Packing parameter variable (if modeling packing)
    std::optional<::z3::expr> packing_var_;

    // The pattern being analyzed
    const UnifiedAccessPattern* pattern_ = nullptr;

    // Results
    std::optional<uint32_t> inferred_packing_;
    qvector<UnionResolution> union_resolutions_;
    Z3Statistics statistics_;

    /// Create Z3 variables for each candidate
    void create_field_variables();

    /// Add HARD constraints (coverage is non-negotiable)
    void add_coverage_constraints();       // Every access covered by selected field

    /// Add SOFT constraints (can be relaxed if needed)
    void add_non_overlap_constraints();    // Fields don't overlap (or form union)
    void add_alignment_constraints();      // Alignment as soft with packing var
    void add_type_constraints();           // Type consistency
    void add_type_preference_constraints(); // Prefer typed fields over raw_bytes
    void add_size_bound_constraints();     // Size limits
    void add_array_constraints();          // Array-specific constraints

    /// Add optimization objectives
    void add_optimization_objectives();

    /// Relaxation loop for UNSAT cases
    [[nodiscard]] Z3Result solve_with_relaxation();

    /// Extract minimal unsatisfiable subset (MUS)
    [[nodiscard]] qvector<ConstraintProvenance> extract_mus();

    /// Create union type when fields must overlap
    [[nodiscard]] SynthField create_union_field(
        const qvector<int>& overlapping_ids,
        const ::z3::model& model
    );

    /// Create fallback raw bytes field for irreconcilable regions
    [[nodiscard]] SynthField create_raw_bytes_field(
        sval_t offset,
        uint32_t size
    );

    /// Detect which candidates should form unions
    void detect_union_groups(const ::z3::model& model);

    /// Helper: get concrete bool value from model
    [[nodiscard]] bool get_bool_value(const ::z3::model& model, const ::z3::expr& e) const;

    /// Helper: get concrete int value from model
    [[nodiscard]] int64_t get_int_value(const ::z3::model& model, const ::z3::expr& e) const;

    /// Helper: check if candidate covers an access
    [[nodiscard]] bool candidate_covers_access(
        const FieldCandidate& candidate,
        const FieldAccess& access
    ) const;
};

/// Create a SynthField from a FieldCandidate and model
[[nodiscard]] SynthField field_from_candidate(
    const FieldCandidate& candidate,
    TypeEncoder& type_encoder
);

/// Check if two candidates are compatible for the same union
[[nodiscard]] bool candidates_compatible_for_union(
    const FieldCandidate& a,
    const FieldCandidate& b
);

} // namespace structor::z3
