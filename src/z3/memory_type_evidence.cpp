#include "structor/z3/memory_type_evidence.hpp"

#include <algorithm>
#include <unordered_set>

namespace structor::z3 {
namespace {
struct LocationEvidence {
    std::vector<TypeVariable> variables;
    std::vector<InferredType> views;
    bool inconsistent = false;
    bool ambiguous = false;
    bool hard_concrete = false;
    std::vector<ea_t> source_sites;
};

std::optional<MemoryLocationKey> location_of(const TypeVariable& variable) {
    if (!variable.is_memory() || variable.is_local() ||
        !variable.mem_offset || !variable.mem_size) return std::nullopt;
    return MemoryLocationKey{*variable.mem_base, *variable.mem_offset, *variable.mem_size};
}

void add_distinct(std::vector<InferredType>& views, const InferredType& type) {
    if (std::none_of(views.begin(), views.end(),
                    [&](const InferredType& known) { return known == type; })) {
        views.push_back(type.snapshot());
    }
}
} // namespace

MemoryTypeEvidenceResult extract_memory_type_evidence(
    const TypeConstraintSet& constraints, TypeLatticeEncoder& encoder,
    const ::z3::model& model, std::uint32_t pointer_size)
{
    MemoryTypeEvidenceResult result;
    ExactMemoryLocationMap<LocationEvidence> locations;
    std::unordered_map<TypeVariableIdentity, MemoryLocationKey,
                       TypeVariableIdentityHash> identities;
    std::unordered_set<TypeVariableIdentity, TypeVariableIdentityHash> invalid_identities;
    const auto observe = [&](const TypeVariable& variable) {
        if (!variable.is_memory()) return;
        const auto key = location_of(variable);
        if (!key || !valid_memory_location(*key, pointer_size) || !variable.identity.valid()) {
            if (invalid_identities.insert(variable.identity).second) {
                result.diagnostics.push_back({key, MemoryInferenceIssue::InvalidLocation, {}});
            }
            return;
        }
        auto& evidence = locations[*key];
        const auto [found, inserted] = identities.emplace(variable.identity, *key);
        if (!inserted && found->second != *key) {
            evidence.inconsistent = true;
            locations[found->second].inconsistent = true;
            invalid_identities.insert(variable.identity);
        }
        if (std::none_of(evidence.variables.begin(), evidence.variables.end(),
                [&](const TypeVariable& known) { return known == variable; })) {
            evidence.variables.push_back(variable);
        }
    };
    for (const auto& constraint : constraints.constraints()) {
        observe(constraint.var1);
        if (constraint.var2) observe(*constraint.var2);
    }

    for (const auto& constraint : constraints.constraints()) {
        const auto key = location_of(constraint.var1);
        if (!key || !locations.contains(*key) ||
            (constraint.is_soft && constraint.weight <= 0)) continue;
        auto& evidence = locations.at(*key);
        const auto record = [&](const InferredType& type) {
            if (type.is_unknown()) return;
            add_distinct(evidence.views, type);
            evidence.hard_concrete |= !constraint.is_soft;
            if (constraint.source_ea != BADADDR &&
                std::find(evidence.source_sites.begin(), evidence.source_sites.end(),
                          constraint.source_ea) == evidence.source_sites.end()) {
                evidence.source_sites.push_back(constraint.source_ea);
            }
        };
        switch (constraint.kind) {
            case TypeConstraint::Kind::IsBase:
                if (constraint.concrete_type && constraint.concrete_type->is_base()) {
                    record(*constraint.concrete_type);
                }
                break;
            case TypeConstraint::Kind::IsPointerTo:
                if (constraint.concrete_type && constraint.concrete_type->is_pointer()) {
                    record(*constraint.concrete_type);
                }
                break;
            case TypeConstraint::Kind::OneOf: {
                std::vector<InferredType> alternatives;
                for (const auto& type : constraint.alternatives) {
                    add_distinct(alternatives, type);
                    record(type);
                }
                evidence.ambiguous |= alternatives.size() > 1;
                break;
            }
            default:
                break;
        }
    }

    for (const auto& [location, evidence] : locations) {
        auto issue = MemoryInferenceIssue::UnsupportedModelValue;
        bool supported = false;
        const bool invalid = evidence.inconsistent || std::any_of(
            evidence.variables.begin(), evidence.variables.end(),
            [&](const TypeVariable& variable) { return invalid_identities.contains(variable.identity); });
        if (invalid) {
            issue = MemoryInferenceIssue::InconsistentVariableLocation;
        } else if (evidence.views.empty()) {
            issue = MemoryInferenceIssue::InsufficientConcreteEvidence;
        } else if (evidence.ambiguous || evidence.views.size() != 1) {
            issue = MemoryInferenceIssue::ConflictingConcreteViews;
        } else {
            const auto& view = evidence.views.front();
            supported = !view.is_unknown() && view.size(pointer_size) == location.size;
            for (const auto& variable : evidence.variables) {
                if (!supported) break;
                const auto expression = constraints.get_z3_var(variable, encoder);
                supported = encoder.decode(expression, model) == view;
            }
            if (supported) {
                result.types.emplace(location, view.snapshot());
                auto sites = evidence.source_sites;
                std::sort(sites.begin(), sites.end());
                result.provenance.emplace(location, MemoryTypeProvenance{
                    evidence.hard_concrete ? MemoryTypeEvidenceKind::HardConcreteConstraint
                                           : MemoryTypeEvidenceKind::SoftConcretePreference,
                    std::move(sites)});
            }
        }
        if (!supported) {
            result.diagnostics.push_back({location, issue, evidence.views});
        }
    }
    return result;
}

} // namespace structor::z3
