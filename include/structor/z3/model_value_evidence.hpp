#pragma once

#include <z3++.h>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace structor::z3 {

enum class ModelValueStatus : std::uint8_t {
    DeterminedByHardConstraints,
    AlternativeModelExists,
    ResourceLimit,
    SolverUnknown,
    InvalidModel,
};

struct ModelValueEvidence {
    ModelValueStatus status = ModelValueStatus::InvalidModel;
    // A witness value, not a second preferred interpretation. The expression
    // borrows the same Z3 context as this probe and must not outlive it.
    std::optional<::z3::expr> alternative;
    std::string reason;
};

struct ModelEvidenceBudget {
    std::uint32_t max_queries = 512;
    std::uint32_t timeout_ms = 1000;
};

// Checks uniqueness relative to the supplied hard formulas. Soft objectives
// deliberately do not become hard facts. If the formulas describe a bounded
// domain, the caller must preserve that domain qualification in its result.
class ModelValueEvidenceProbe {
public:
    ModelValueEvidenceProbe(const ::z3::expr_vector& hard_constraints,
                            const ::z3::model& selected_model,
                            ModelEvidenceBudget budget = {});

    [[nodiscard]] ModelValueEvidence inspect(const ::z3::expr& variable,
                                              const ::z3::expr& selected_value);
    [[nodiscard]] std::uint32_t queries_used() const noexcept { return queries_used_; }

private:
    ::z3::solver solver_;
    ::z3::model selected_model_;
    ModelEvidenceBudget budget_;
    std::chrono::steady_clock::time_point deadline_;
    std::uint32_t queries_used_ = 0;
    bool model_satisfies_hard_constraints_ = true;
};

} // namespace structor::z3
