#pragma once

#include <z3++.h>
#include <pro.h>
#include <optional>
#include <chrono>
#include "structor/z3/constraint_tracker.hpp"

namespace structor::z3 {

/// Result of Z3 solving attempt
struct Z3Result {
    enum class Status {
        Sat,           // Solution found
        SatRelaxed,    // Solution found after relaxing some constraints
        Unsat,         // No solution exists even after relaxation
        Unknown,       // Timeout or resource limit
        Error          // Z3 internal error
    };

    Status status = Status::Unknown;
    std::optional<::z3::model> model;

    // Constraints that were dropped to achieve SAT (for SatRelaxed)
    qvector<ConstraintProvenance> dropped_constraints;

    // Minimal unsatisfiable core (for Unsat)
    qvector<ConstraintProvenance> unsat_core;

    qstring error_message;
    std::chrono::milliseconds solve_time{0};

    // Statistics
    unsigned iterations = 0;          // Number of solve attempts
    unsigned constraints_relaxed = 0; // Number of relaxed constraints

    [[nodiscard]] bool is_sat() const noexcept {
        return status == Status::Sat || status == Status::SatRelaxed;
    }

    [[nodiscard]] bool is_unsat() const noexcept {
        return status == Status::Unsat;
    }

    [[nodiscard]] bool is_unknown() const noexcept {
        return status == Status::Unknown;
    }

    [[nodiscard]] bool is_error() const noexcept {
        return status == Status::Error;
    }

    [[nodiscard]] bool should_fallback() const noexcept {
        return status == Status::Unknown || status == Status::Error || status == Status::Unsat;
    }

    [[nodiscard]] bool has_dropped_constraints() const noexcept {
        return !dropped_constraints.empty();
    }

    [[nodiscard]] bool has_model() const noexcept {
        return model.has_value();
    }

    /// Get a string description of the status
    [[nodiscard]] const char* status_string() const noexcept {
        switch (status) {
            case Status::Sat:        return "SAT";
            case Status::SatRelaxed: return "SAT (relaxed)";
            case Status::Unsat:      return "UNSAT";
            case Status::Unknown:    return "UNKNOWN";
            case Status::Error:      return "ERROR";
            default:                 return "INVALID";
        }
    }

    /// Generate a diagnostic summary
    [[nodiscard]] qstring summary() const {
        qstring result;
        result.sprnt("Z3 Result: %s\n", status_string());
        result.cat_sprnt("Solve time: %lldms\n",
                        static_cast<long long>(solve_time.count()));
        result.cat_sprnt("Iterations: %u\n", iterations);

        if (has_dropped_constraints()) {
            result.cat_sprnt("Dropped constraints: %zu\n", dropped_constraints.size());
            for (const auto& dc : dropped_constraints) {
                result.cat_sprnt("  - %s\n", dc.description.c_str());
            }
        }

        if (!unsat_core.empty()) {
            result.cat_sprnt("UNSAT core (%zu constraints):\n", unsat_core.size());
            for (const auto& uc : unsat_core) {
                result.cat_sprnt("  - %s\n", uc.description.c_str());
            }
        }

        if (!error_message.empty()) {
            result.cat_sprnt("Error: %s\n", error_message.c_str());
        }

        return result;
    }

    /// Factory methods
    static Z3Result make_sat(::z3::model&& m, std::chrono::milliseconds time) {
        Z3Result r;
        r.status = Status::Sat;
        r.model = std::move(m);
        r.solve_time = time;
        return r;
    }

    static Z3Result make_sat_relaxed(
        ::z3::model&& m,
        qvector<ConstraintProvenance>&& dropped,
        std::chrono::milliseconds time)
    {
        Z3Result r;
        r.status = Status::SatRelaxed;
        r.model = std::move(m);
        r.dropped_constraints = std::move(dropped);
        r.solve_time = time;
        return r;
    }

    static Z3Result make_unsat(
        qvector<ConstraintProvenance>&& core,
        std::chrono::milliseconds time)
    {
        Z3Result r;
        r.status = Status::Unsat;
        r.unsat_core = std::move(core);
        r.solve_time = time;
        return r;
    }

    static Z3Result make_unknown(const char* reason, std::chrono::milliseconds time) {
        Z3Result r;
        r.status = Status::Unknown;
        r.error_message = reason;
        r.solve_time = time;
        return r;
    }

    static Z3Result make_error(const char* msg) {
        Z3Result r;
        r.status = Status::Error;
        r.error_message = msg;
        return r;
    }
};

/// Helper to extract values from Z3 model
class ModelExtractor {
public:
    explicit ModelExtractor(const ::z3::model& model) : model_(model) {}

    /// Get integer value from model
    [[nodiscard]] std::optional<int64_t> get_int(const ::z3::expr& e) const {
        try {
            ::z3::expr val = model_.eval(e, true);
            if (val.is_numeral()) {
                return val.get_numeral_int64();
            }
        } catch (...) {
        }
        return std::nullopt;
    }

    /// Get unsigned integer value from model
    [[nodiscard]] std::optional<uint64_t> get_uint(const ::z3::expr& e) const {
        try {
            ::z3::expr val = model_.eval(e, true);
            if (val.is_numeral()) {
                return val.get_numeral_uint64();
            }
        } catch (...) {
        }
        return std::nullopt;
    }

    /// Get boolean value from model
    [[nodiscard]] std::optional<bool> get_bool(const ::z3::expr& e) const {
        try {
            ::z3::expr val = model_.eval(e, true);
            if (val.is_true()) return true;
            if (val.is_false()) return false;
        } catch (...) {
        }
        return std::nullopt;
    }

    /// Get integer value with default
    [[nodiscard]] int64_t get_int_or(const ::z3::expr& e, int64_t default_val) const {
        return get_int(e).value_or(default_val);
    }

    /// Get boolean value with default
    [[nodiscard]] bool get_bool_or(const ::z3::expr& e, bool default_val) const {
        return get_bool(e).value_or(default_val);
    }

    /// Get the underlying model
    [[nodiscard]] const ::z3::model& model() const noexcept { return model_; }

private:
    const ::z3::model& model_;
};

/// Statistics about a Z3 solving session
struct Z3Statistics {
    unsigned total_constraints = 0;
    unsigned hard_constraints = 0;
    unsigned soft_constraints = 0;
    unsigned coverage_constraints = 0;
    unsigned alignment_constraints = 0;
    unsigned type_constraints = 0;

    std::chrono::milliseconds constraint_build_time{0};
    std::chrono::milliseconds solve_time{0};
    std::chrono::milliseconds extraction_time{0};

    unsigned solve_iterations = 0;
    unsigned relaxations_performed = 0;

    [[nodiscard]] qstring summary() const {
        qstring result;
        result.sprnt("Z3 Statistics:\n");
        result.cat_sprnt("  Constraints: %u total (%u hard, %u soft)\n",
                        total_constraints, hard_constraints, soft_constraints);
        result.cat_sprnt("  Coverage: %u, Alignment: %u, Type: %u\n",
                        coverage_constraints, alignment_constraints, type_constraints);
        result.cat_sprnt("  Build time: %lldms\n",
                        static_cast<long long>(constraint_build_time.count()));
        result.cat_sprnt("  Solve time: %lldms (%u iterations)\n",
                        static_cast<long long>(solve_time.count()), solve_iterations);
        result.cat_sprnt("  Extraction time: %lldms\n",
                        static_cast<long long>(extraction_time.count()));
        if (relaxations_performed > 0) {
            result.cat_sprnt("  Relaxations: %u\n", relaxations_performed);
        }
        return result;
    }
};

} // namespace structor::z3
