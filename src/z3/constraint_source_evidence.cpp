#include "structor/z3/constraint_source_evidence.hpp"

#include <algorithm>
#include <tuple>
#include <unordered_set>

namespace structor::z3 {
namespace {
auto record_key(const ConstraintSourceEvidence& record) {
    return std::tuple(record.source_ea, record.origin, record.kind,
                      record.is_soft, record.weight, record.relation);
}
} // namespace

ConstraintSourceIndex::ConstraintSourceIndex(const TypeConstraintSet& constraints) {
    for (const auto& constraint : constraints.constraints()) {
        if (constraint.is_soft && constraint.weight <= 0) continue;
        const auto index = constraints_.size();
        constraints_.push_back(&constraint);
        if (constraint.var1.identity.valid()) incident_[constraint.var1.identity].push_back(index);
        if (constraint.var2 && constraint.var2->identity.valid() &&
            constraint.var2->identity != constraint.var1.identity) {
            incident_[constraint.var2->identity].push_back(index);
        }
    }
}

VariableSourceEvidence ConstraintSourceIndex::for_variable(const TypeVariable& variable) const {
    VariableSourceEvidence result;
    if (!variable.identity.valid()) return result;
    std::vector<TypeVariableIdentity> pending{variable.identity};
    std::unordered_set<TypeVariableIdentity, TypeVariableIdentityHash> seen_variables;
    seen_variables.insert(variable.identity);
    std::unordered_set<std::size_t> seen_constraints;
    for (std::size_t cursor = 0; cursor < pending.size(); ++cursor) {
        const auto found = incident_.find(pending[cursor]);
        if (found == incident_.end()) continue;
        for (const auto index : found->second) {
            if (!seen_constraints.insert(index).second) continue;
            const auto& constraint = *constraints_[index];
            const bool direct = constraint.var1.identity == variable.identity ||
                (constraint.var2 && constraint.var2->identity == variable.identity);
            result.records.push_back({constraint.origin, constraint.kind, constraint.source_ea,
                constraint.is_soft, constraint.is_soft ? constraint.weight : 0,
                direct ? ConstraintSourceRelation::Direct : ConstraintSourceRelation::Related});
            const auto enqueue = [&](const TypeVariable& connected) {
                if (connected.identity.valid() && seen_variables.insert(connected.identity).second)
                    pending.push_back(connected.identity);
            };
            enqueue(constraint.var1);
            if (constraint.var2) enqueue(*constraint.var2);
        }
    }
    std::sort(result.records.begin(), result.records.end(), [](const auto& lhs, const auto& rhs) {
        return record_key(lhs) < record_key(rhs);
    });
    result.records.erase(std::unique(result.records.begin(), result.records.end()), result.records.end());
    for (const auto& record : result.records) {
        if (record.source_ea != BADADDR) result.source_sites.push_back(record.source_ea);
        result.from_signature |= record.origin == TypeConstraintOrigin::FunctionSignature;
        result.from_decompiler |= record.origin == TypeConstraintOrigin::DecompilerType;
        result.from_alias |= record.origin == TypeConstraintOrigin::AliasRelation;
        result.from_usage |= record.origin == TypeConstraintOrigin::InstructionUsage;
    }
    // Records are already sorted by address, but multiple source categories
    // at one address remain distinct records while sharing one legacy site.
    result.source_sites.erase(std::unique(result.source_sites.begin(), result.source_sites.end()),
                              result.source_sites.end());
    return result;
}

} // namespace structor::z3
