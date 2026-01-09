#pragma once

#include <z3++.h>
#include <pro.h>
#include <unordered_map>
#include <vector>
#include <string>
#include <optional>

namespace structor::z3 {

/// Provenance information for a constraint
struct ConstraintProvenance {
    ea_t func_ea = BADADDR;           // Function where observation occurred
    ea_t insn_ea = BADADDR;           // Instruction address
    int access_idx = -1;              // Index in access pattern
    qstring description;              // Human-readable description
    bool is_soft = false;             // Soft constraint (can be dropped)
    int weight = 1;                   // Weight for Max-SMT (higher = more important)
    std::optional<::z3::expr> tracking_literal;  // The tracking literal for relaxation

    /// Kind of constraint for categorization
    enum class Kind {
        Coverage,       // Access must be covered by a field
        NonOverlap,     // Fields must not overlap (or be in union)
        Alignment,      // Field alignment requirement
        TypeMatch,      // Type consistency between observations
        SizeMatch,      // Size consistency
        ArrayDetection, // Array pattern detection
        Other
    };
    Kind kind = Kind::Other;

    /// Create from basic info
    static ConstraintProvenance make(
        ea_t func_ea,
        const char* desc,
        bool soft = false,
        int weight = 1,
        Kind kind = Kind::Other)
    {
        ConstraintProvenance p;
        p.func_ea = func_ea;
        p.description = desc;
        p.is_soft = soft;
        p.weight = weight;
        p.kind = kind;
        return p;
    }

    /// Create for an access
    static ConstraintProvenance for_access(
        ea_t func_ea,
        ea_t insn_ea,
        int access_idx,
        const char* desc,
        Kind kind = Kind::Coverage)
    {
        ConstraintProvenance p;
        p.func_ea = func_ea;
        p.insn_ea = insn_ea;
        p.access_idx = access_idx;
        p.description = desc;
        p.is_soft = false;
        p.weight = 100;  // Coverage is important
        p.kind = kind;
        return p;
    }
};

/// Tracks constraints for UNSAT core analysis
class ConstraintTracker {
public:
    explicit ConstraintTracker(::z3::context& ctx);

    /// Add a constraint with tracking literal for UNSAT core
    /// Returns the tracking literal
    [[nodiscard]] ::z3::expr add_tracked(
        ::z3::solver& solver,
        const ::z3::expr& constraint,
        const ConstraintProvenance& provenance
    );

    /// Add a hard constraint (always required)
    void add_hard(
        ::z3::solver& solver,
        const ::z3::expr& constraint,
        const ConstraintProvenance& provenance
    );

    /// Add a soft constraint (can be dropped if needed)
    void add_soft(
        ::z3::solver& solver,
        const ::z3::expr& constraint,
        const ConstraintProvenance& provenance,
        int weight = 1
    );

    /// Add constraint to optimizer (for Max-SMT)
    void add_to_optimizer(
        ::z3::optimize& opt,
        const ::z3::expr& constraint,
        const ConstraintProvenance& provenance
    );

    /// Add soft constraint to optimizer with weight
    void add_soft_to_optimizer(
        ::z3::optimize& opt,
        const ::z3::expr& constraint,
        const ConstraintProvenance& provenance,
        unsigned weight = 1
    );

    /// Extract provenance from UNSAT core
    [[nodiscard]] qvector<ConstraintProvenance> analyze_unsat_core(
        const ::z3::expr_vector& core
    ) const;

    /// Get all soft constraint tracking literals (for Max-SMT)
    [[nodiscard]] ::z3::expr_vector get_soft_literals() const;

    /// Get all hard constraint tracking literals
    [[nodiscard]] ::z3::expr_vector get_hard_literals() const;

    /// Get all tracking literals (hard + soft) for use as assumptions
    [[nodiscard]] ::z3::expr_vector get_all_literals() const;

    /// Get provenance for a tracking literal
    [[nodiscard]] const ConstraintProvenance* get_provenance(
        const ::z3::expr& tracking_lit
    ) const;

    /// Get provenance by ID
    [[nodiscard]] const ConstraintProvenance* get_provenance_by_id(unsigned id) const;

    /// Get all constraints of a specific kind
    [[nodiscard]] qvector<ConstraintProvenance> get_by_kind(
        ConstraintProvenance::Kind kind
    ) const;

    /// Get total number of constraints
    [[nodiscard]] size_t total_constraints() const noexcept {
        return provenance_map_.size();
    }

    /// Get number of hard constraints
    [[nodiscard]] size_t hard_constraint_count() const noexcept {
        return hard_constraint_ids_.size();
    }

    /// Get number of soft constraints
    [[nodiscard]] size_t soft_constraint_count() const noexcept {
        return soft_constraint_ids_.size();
    }

    /// Clear all tracking state
    void clear();

    /// Generate a diagnostic report of tracked constraints
    [[nodiscard]] qstring generate_report() const;

private:
    ::z3::context& ctx_;
    unsigned next_id_ = 0;

    // Map tracking literal ID -> provenance
    std::unordered_map<unsigned, ConstraintProvenance> provenance_map_;

    // Map tracking literal expression string -> ID (for lookup from UNSAT core)
    std::unordered_map<std::string, unsigned> expr_to_id_;

    // Separate lists for hard vs soft
    std::vector<unsigned> hard_constraint_ids_;
    std::vector<unsigned> soft_constraint_ids_;

    // Store tracking expressions for retrieval
    std::vector<::z3::expr> tracking_exprs_;

    /// Generate unique tracking literal name
    [[nodiscard]] std::string make_tracking_name(unsigned id) const;

    /// Create tracking literal for constraint
    [[nodiscard]] ::z3::expr make_tracking_literal(unsigned id);
};

/// Helper for building constraint descriptions
class ConstraintDescriptionBuilder {
public:
    ConstraintDescriptionBuilder() = default;

    ConstraintDescriptionBuilder& at_offset(sval_t offset) {
        desc_.cat_sprnt("at offset 0x%llX", static_cast<unsigned long long>(offset));
        return *this;
    }

    ConstraintDescriptionBuilder& with_size(uint32_t size) {
        if (!desc_.empty()) desc_.append(", ");
        desc_.cat_sprnt("size %u", size);
        return *this;
    }

    ConstraintDescriptionBuilder& for_field(int field_idx) {
        if (!desc_.empty()) desc_.append(", ");
        desc_.cat_sprnt("field %d", field_idx);
        return *this;
    }

    ConstraintDescriptionBuilder& text(const char* txt) {
        if (!desc_.empty()) desc_.append(": ");
        desc_.append(txt);
        return *this;
    }

    [[nodiscard]] qstring build() const { return desc_; }

private:
    qstring desc_;
};

} // namespace structor::z3
