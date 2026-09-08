#pragma once

#include "structor/z3/instruction_semantics.hpp"

#include <cstdint>
#include <unordered_map>
#include <vector>

namespace structor::z3 {

/// Direct means the constraint mentions the queried variable. Related means
/// it is reached through other effective constraints; neither is a causal proof.
enum class ConstraintSourceRelation : std::uint8_t { Direct, Related };

/// A source-site/category record, not a count of independent observations.
/// Different concrete values at the same site/category can share one record.
struct ConstraintSourceEvidence {
    TypeConstraintOrigin origin = TypeConstraintOrigin::Unspecified;
    TypeConstraint::Kind kind = TypeConstraint::Kind::Equal;
    ea_t source_ea = BADADDR;
    bool is_soft = false;
    int weight = 0; // Meaningful only for soft constraints; hard records use zero.
    ConstraintSourceRelation relation = ConstraintSourceRelation::Direct;

    bool operator==(const ConstraintSourceEvidence&) const = default;
};

struct VariableSourceEvidence {
    std::vector<ConstraintSourceEvidence> records;
    std::vector<ea_t> source_sites; // Sorted, distinct; unavailable BADADDR omitted.
    bool from_signature = false;
    bool from_decompiler = false;
    bool from_alias = false;
    bool from_usage = false;
};

/// Index over the current immutable constraint set. It must outlive this index.
/// Both hard and positive-weight soft relations connect variables. Connectivity
/// describes available metadata; it does not establish a selected model cause.
/// Nonpositive soft constraints are ignored, matching the solver converter.
class ConstraintSourceIndex {
public:
    explicit ConstraintSourceIndex(const TypeConstraintSet& constraints);
    [[nodiscard]] VariableSourceEvidence for_variable(const TypeVariable& variable) const;

private:
    std::vector<const TypeConstraint*> constraints_;
    std::unordered_map<TypeVariableIdentity, std::vector<std::size_t>,
                       TypeVariableIdentityHash> incident_;
};

} // namespace structor::z3
