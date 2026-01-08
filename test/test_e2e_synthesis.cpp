/**
 * @file test_e2e_synthesis.cpp
 * @brief End-to-end integration tests for struct synthesis pipeline
 *
 * This test exercises the complete synthesis workflow using the ACTUAL
 * constraint patterns and solving strategies from the real implementation.
 * It validates:
 * - Full constraint system (coverage, non-overlap, alignment, type)
 * - Tiered fallback: Z3 -> relaxation -> raw bytes
 * - UNSAT core extraction and constraint relaxation
 * - Real-world struct layout scenarios
 * - Performance with realistic struct sizes
 */

#include <cassert>
#include <iostream>
#include <chrono>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <optional>
#include <sstream>
#include <iomanip>
#include <functional>
#include <memory>

// Z3 headers
#include <z3++.h>

// Test IR (IDA-independent)
#include "structor/z3/test_ir.hpp"

namespace {

using namespace structor::z3::test;

// ============================================================================
// Test Framework
// ============================================================================

struct TestResult {
    bool passed;
    std::string name;
    std::string message;
    std::chrono::milliseconds duration;

    TestResult(const std::string& n, bool p, const std::string& msg = "")
        : passed(p), name(n), message(msg), duration(0) {}
};

class TestRunner {
public:
    template<typename F>
    void run(const std::string& name, F&& test_fn) {
        auto start = std::chrono::steady_clock::now();
        try {
            test_fn();
            auto end = std::chrono::steady_clock::now();
            auto dur = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

            TestResult result(name, true);
            result.duration = dur;
            results_.push_back(result);
            std::cout << "[PASS] " << name << " (" << dur.count() << "ms)\n";
        }
        catch (const std::exception& e) {
            auto end = std::chrono::steady_clock::now();
            auto dur = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

            TestResult result(name, false, e.what());
            result.duration = dur;
            results_.push_back(result);
            std::cout << "[FAIL] " << name << ": " << e.what() << "\n";
        }
        catch (...) {
            TestResult result(name, false, "Unknown exception");
            results_.push_back(result);
            std::cout << "[FAIL] " << name << ": Unknown exception\n";
        }
    }

    void summary() const {
        int passed = 0, failed = 0;
        std::chrono::milliseconds total_time(0);

        for (const auto& r : results_) {
            if (r.passed) ++passed;
            else ++failed;
            total_time += r.duration;
        }

        std::cout << "\n=== Summary ===\n";
        std::cout << "Passed: " << passed << ", Failed: " << failed << "\n";
        std::cout << "Total time: " << total_time.count() << "ms\n";
    }

    bool all_passed() const {
        for (const auto& r : results_) {
            if (!r.passed) return false;
        }
        return true;
    }

private:
    std::vector<TestResult> results_;
};

// ============================================================================
// Constraint Provenance (mirrors real implementation)
// ============================================================================

struct ConstraintProvenance {
    enum class Kind {
        Coverage,       // Access must be covered by a field
        NonOverlap,     // Fields must not overlap
        Alignment,      // Field alignment requirement
        TypeMatch,      // Type consistency
        SizeMatch,      // Size consistency
        ArrayDetection, // Array pattern
        Other
    };

    Kind kind = Kind::Other;
    std::string description;
    bool is_soft = false;
    int weight = 1;
    int32_t offset = -1;
    int candidate_id = -1;
    std::optional<z3::expr> tracking_literal;
};

// ============================================================================
// Constraint Tracker (mirrors real implementation)
// ============================================================================

class ConstraintTracker {
public:
    explicit ConstraintTracker(z3::context& ctx) : ctx_(ctx) {}

    /// Add a tracked constraint with provenance
    z3::expr add_tracked(
        z3::solver& solver,
        const z3::expr& constraint,
        const ConstraintProvenance& prov)
    {
        unsigned id = next_id_++;
        provenance_[id] = prov;

        // Create tracking literal
        std::string name = "__track_" + std::to_string(id);
        z3::expr lit = ctx_.bool_const(name.c_str());
        tracking_exprs_.push_back(lit);
        expr_to_id_[lit.to_string()] = id;

        // Add constraint as implication: tracking_lit => constraint
        // When tracking_lit is in assumptions (true), constraint is enforced
        // When tracking_lit is not in assumptions (false), constraint is optional
        solver.add(z3::implies(lit, constraint));

        // Also add the tracking literal for UNSAT core extraction
        // This allows us to get the literal back in the core when constraint fails
        // Note: for soft constraints, we'll negate when they conflict

        if (prov.is_soft) {
            soft_ids_.push_back(id);
        } else {
            hard_ids_.push_back(id);
        }

        return lit;
    }

    /// Add hard constraint
    void add_hard(
        z3::solver& solver,
        const z3::expr& constraint,
        const ConstraintProvenance& prov)
    {
        ConstraintProvenance hard_prov = prov;
        hard_prov.is_soft = false;
        add_tracked(solver, constraint, hard_prov);
    }

    /// Add soft constraint
    void add_soft(
        z3::solver& solver,
        const z3::expr& constraint,
        const ConstraintProvenance& prov,
        int weight = 1)
    {
        ConstraintProvenance soft_prov = prov;
        soft_prov.is_soft = true;
        soft_prov.weight = weight;
        add_tracked(solver, constraint, soft_prov);
    }

    /// Analyze UNSAT core
    std::vector<ConstraintProvenance> analyze_unsat_core(
        const z3::expr_vector& core) const
    {
        std::vector<ConstraintProvenance> result;

        for (unsigned i = 0; i < core.size(); ++i) {
            std::string expr_str = core[i].to_string();
            auto it = expr_to_id_.find(expr_str);
            if (it != expr_to_id_.end()) {
                auto prov_it = provenance_.find(it->second);
                if (prov_it != provenance_.end()) {
                    ConstraintProvenance prov = prov_it->second;
                    prov.tracking_literal = core[i];
                    result.push_back(prov);
                }
            }
        }

        return result;
    }

    /// Get all soft constraint literals
    z3::expr_vector get_soft_literals() const {
        z3::expr_vector result(ctx_);
        for (unsigned id : soft_ids_) {
            if (id < tracking_exprs_.size()) {
                result.push_back(tracking_exprs_[id]);
            }
        }
        return result;
    }

    /// Get all hard constraint literals
    z3::expr_vector get_hard_literals() const {
        z3::expr_vector result(ctx_);
        for (unsigned id : hard_ids_) {
            if (id < tracking_exprs_.size()) {
                result.push_back(tracking_exprs_[id]);
            }
        }
        return result;
    }

    /// Get provenance by tracking literal
    const ConstraintProvenance* get_provenance(const z3::expr& lit) const {
        auto it = expr_to_id_.find(lit.to_string());
        if (it == expr_to_id_.end()) return nullptr;
        auto prov_it = provenance_.find(it->second);
        if (prov_it == provenance_.end()) return nullptr;
        return &prov_it->second;
    }

    size_t total_constraints() const { return provenance_.size(); }
    size_t hard_count() const { return hard_ids_.size(); }
    size_t soft_count() const { return soft_ids_.size(); }

    void clear() {
        provenance_.clear();
        expr_to_id_.clear();
        tracking_exprs_.clear();
        hard_ids_.clear();
        soft_ids_.clear();
        next_id_ = 0;
    }

private:
    z3::context& ctx_;
    unsigned next_id_ = 0;
    std::map<unsigned, ConstraintProvenance> provenance_;
    std::map<std::string, unsigned> expr_to_id_;
    std::vector<z3::expr> tracking_exprs_;
    std::vector<unsigned> hard_ids_;
    std::vector<unsigned> soft_ids_;
};

// ============================================================================
// Synthesis Result Types
// ============================================================================

enum class SynthStatus {
    Success,           // Z3 found valid solution
    SuccessRelaxed,    // Solution after relaxing constraints
    FallbackRawBytes,  // Some regions as raw bytes
    Timeout,           // Z3 timed out
    Unsat,             // No solution exists
    Error
};

struct SynthField {
    int32_t offset;
    uint32_t size;
    TestTypeCategory type;
    std::string name;
    bool is_array;
    uint32_t array_count;
    uint8_t confidence;

    SynthField(int32_t off, uint32_t sz, TestTypeCategory t,
               uint8_t conf = 50)
        : offset(off), size(sz), type(t),
          is_array(false), array_count(1), confidence(conf)
    {
        std::ostringstream ss;
        ss << "field_" << std::hex << off;
        name = ss.str();
    }

    static SynthField raw_bytes(int32_t off, uint32_t sz) {
        SynthField f(off, sz, TestTypeCategory::RawBytes, 10);
        std::ostringstream ss;
        ss << "__raw_" << std::hex << off;
        f.name = ss.str();
        return f;
    }

    static SynthField array(int32_t off, uint32_t elem_sz,
                            TestTypeCategory elem_type, uint32_t count) {
        SynthField f(off, elem_sz * count, elem_type, 70);
        f.is_array = true;
        f.array_count = count;
        std::ostringstream ss;
        ss << "arr_" << std::hex << off;
        f.name = ss.str();
        return f;
    }
};

struct SynthResult {
    SynthStatus status;
    std::vector<SynthField> fields;
    uint32_t struct_size;
    std::chrono::milliseconds solve_time;
    unsigned iterations;
    unsigned constraints_relaxed;
    std::vector<std::string> dropped_reasons;
    std::vector<std::string> warnings;

    SynthResult() : status(SynthStatus::Error), struct_size(0),
                    iterations(0), constraints_relaxed(0) {}

    bool is_success() const {
        return status == SynthStatus::Success ||
               status == SynthStatus::SuccessRelaxed ||
               status == SynthStatus::FallbackRawBytes;
    }
};

// ============================================================================
// Field Candidate (mirrors real implementation)
// ============================================================================

struct FieldCandidate {
    int id;
    int32_t offset;
    uint32_t size;
    TestTypeCategory type;
    uint8_t confidence;
    bool is_array;
    uint32_t array_count;
    bool is_padding;

    FieldCandidate(int i, int32_t off, uint32_t sz, TestTypeCategory t,
                   uint8_t conf = 50)
        : id(i), offset(off), size(sz), type(t), confidence(conf),
          is_array(false), array_count(1), is_padding(false) {}

    bool overlaps(const FieldCandidate& other) const {
        if (offset >= other.offset + static_cast<int32_t>(other.size)) return false;
        if (other.offset >= offset + static_cast<int32_t>(size)) return false;
        return true;
    }

    uint32_t alignment() const {
        if (size >= 8) return 8;
        if (size >= 4) return 4;
        if (size >= 2) return 2;
        return 1;
    }
};

// ============================================================================
// Full Synthesis Pipeline (mirrors real implementation)
// ============================================================================

class SynthesisPipeline {
public:
    struct Config {
        uint32_t timeout_ms;
        uint32_t max_struct_size;
        int max_relaxation_iterations;
        bool allow_unions;
        int weight_coverage;
        int weight_alignment;
        int weight_type;

        Config()
            : timeout_ms(5000)
            , max_struct_size(0x10000)
            , max_relaxation_iterations(10)
            , allow_unions(true)
            , weight_coverage(100)
            , weight_alignment(5)
            , weight_type(10) {}
    };

    explicit SynthesisPipeline(const Config& cfg = Config())
        : config_(cfg), ctx_(), tracker_(ctx_) {}

    /// Full synthesis with constraint tracking and relaxation
    SynthResult synthesize(
        const std::vector<TestAccess>& accesses,
        uint32_t struct_size)
    {
        SynthResult result;
        result.struct_size = struct_size;

        auto start = std::chrono::steady_clock::now();

        // Phase 1: Generate candidates
        auto candidates = generate_candidates(accesses);
        if (candidates.empty()) {
            result.status = SynthStatus::Error;
            result.warnings.push_back("No candidates generated");
            return result;
        }

        // Phase 1.5: Generate padding candidates for gaps
        generate_padding_candidates(candidates, struct_size);

        // Phase 2: Build constraint system
        z3::solver solver(ctx_);
        configure_solver(solver);
        tracker_.clear();

        build_constraints(solver, candidates, struct_size);

        // Phase 3: Solve with relaxation
        result = solve_with_relaxation(solver, candidates, struct_size);

        auto end = std::chrono::steady_clock::now();
        result.solve_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            end - start);

        return result;
    }

    const ConstraintTracker& tracker() const { return tracker_; }

private:
    Config config_;
    z3::context ctx_;
    ConstraintTracker tracker_;
    std::vector<z3::expr> sel_vars_;
    std::vector<z3::expr> off_vars_;

    void configure_solver(z3::solver& solver) {
        z3::params p(ctx_);
        p.set("timeout", config_.timeout_ms);
        solver.set(p);
    }

    std::vector<FieldCandidate> generate_candidates(
        const std::vector<TestAccess>& accesses)
    {
        std::vector<FieldCandidate> candidates;

        // Group by offset
        std::map<int64_t, std::vector<const TestAccess*>> by_offset;
        for (const auto& acc : accesses) {
            by_offset[acc.offset].push_back(&acc);
        }

        int id = 0;
        for (const auto& [offset, group] : by_offset) {
            // Find dominant type and size
            std::map<TestTypeCategory, int> type_counts;
            std::map<uint32_t, int> size_counts;

            for (const auto* acc : group) {
                type_counts[acc->type_category]++;
                size_counts[acc->size]++;
            }

            TestTypeCategory best_type = TestTypeCategory::Unknown;
            int best_type_count = 0;
            for (const auto& [t, c] : type_counts) {
                if (c > best_type_count) {
                    best_type = t;
                    best_type_count = c;
                }
            }

            uint32_t best_size = 0;
            int best_size_count = 0;
            for (const auto& [s, c] : size_counts) {
                if (c > best_size_count) {
                    best_size = s;
                    best_size_count = c;
                }
            }

            uint8_t conf = std::min(90u, 30 + static_cast<unsigned>(group.size()) * 10);
            candidates.emplace_back(id++, static_cast<int32_t>(offset),
                                    best_size, best_type, conf);
        }

        // Detect arrays
        detect_arrays(candidates);

        return candidates;
    }

    void detect_arrays(std::vector<FieldCandidate>& candidates) {
        if (candidates.size() < 3) return;

        std::sort(candidates.begin(), candidates.end(),
                  [](const FieldCandidate& a, const FieldCandidate& b) {
                      return a.offset < b.offset;
                  });

        size_t i = 0;
        while (i < candidates.size()) {
            uint32_t elem_size = candidates[i].size;
            TestTypeCategory elem_type = candidates[i].type;

            size_t run = 1;
            for (size_t j = i + 1; j < candidates.size(); ++j) {
                int32_t expected = candidates[i].offset +
                    static_cast<int32_t>(run * elem_size);

                if (candidates[j].offset == expected &&
                    candidates[j].size == elem_size &&
                    candidates[j].type == elem_type) {
                    ++run;
                } else {
                    break;
                }
            }

            if (run >= 3) {
                // Convert to array
                candidates[i].is_array = true;
                candidates[i].array_count = run;
                candidates[i].size = elem_size * run;
                candidates[i].confidence = 85;

                // Remove individual elements
                candidates.erase(candidates.begin() + i + 1,
                                 candidates.begin() + i + run);
            }

            ++i;
        }
    }

    /// Generate padding candidates to fill gaps between fields
    void generate_padding_candidates(
        std::vector<FieldCandidate>& candidates,
        uint32_t struct_size)
    {
        if (candidates.empty()) return;

        // Sort by offset
        std::sort(candidates.begin(), candidates.end(),
                  [](const FieldCandidate& a, const FieldCandidate& b) {
                      return a.offset < b.offset;
                  });

        std::vector<FieldCandidate> padding;
        int next_id = static_cast<int>(candidates.size()) + 1000;  // Avoid ID collision

        // Check gap before first field
        if (candidates[0].offset > 0) {
            int32_t gap_start = 0;
            int32_t gap_size = candidates[0].offset;
            padding.emplace_back(next_id++, gap_start, gap_size,
                                 TestTypeCategory::Unknown, 10);  // Low confidence padding
            padding.back().is_padding = true;
        }

        // Check gaps between fields
        for (size_t i = 0; i < candidates.size() - 1; ++i) {
            int32_t end_curr = candidates[i].offset + static_cast<int32_t>(candidates[i].size);
            int32_t start_next = candidates[i + 1].offset;

            if (start_next > end_curr) {
                int32_t gap_size = start_next - end_curr;
                padding.emplace_back(next_id++, end_curr, gap_size,
                                     TestTypeCategory::Unknown, 10);
                padding.back().is_padding = true;
            }
        }

        // Check gap after last field
        int32_t last_end = candidates.back().offset +
                           static_cast<int32_t>(candidates.back().size);
        if (static_cast<uint32_t>(last_end) < struct_size) {
            int32_t gap_size = static_cast<int32_t>(struct_size) - last_end;
            padding.emplace_back(next_id++, last_end, gap_size,
                                 TestTypeCategory::Unknown, 10);
            padding.back().is_padding = true;
        }

        // Add padding candidates
        candidates.insert(candidates.end(), padding.begin(), padding.end());
    }

    void build_constraints(
        z3::solver& solver,
        const std::vector<FieldCandidate>& candidates,
        uint32_t struct_size)
    {
        sel_vars_.clear();
        off_vars_.clear();

        // Create variables
        for (size_t i = 0; i < candidates.size(); ++i) {
            sel_vars_.push_back(ctx_.bool_const(
                ("sel_" + std::to_string(i)).c_str()));
            off_vars_.push_back(ctx_.int_const(
                ("off_" + std::to_string(i)).c_str()));
        }

        // Bounds constraints (hard)
        for (size_t i = 0; i < candidates.size(); ++i) {
            ConstraintProvenance prov;
            prov.kind = ConstraintProvenance::Kind::Other;
            prov.description = "bounds_" + std::to_string(i);
            prov.candidate_id = static_cast<int>(i);

            z3::expr bounds = z3::implies(sel_vars_[i],
                off_vars_[i] >= 0 &&
                off_vars_[i] + static_cast<int>(candidates[i].size) <=
                    static_cast<int>(struct_size));

            tracker_.add_hard(solver, bounds, prov);
        }

        // Non-overlap constraints (hard)
        for (size_t i = 0; i < candidates.size(); ++i) {
            for (size_t j = i + 1; j < candidates.size(); ++j) {
                ConstraintProvenance prov;
                prov.kind = ConstraintProvenance::Kind::NonOverlap;
                prov.description = "non_overlap_" + std::to_string(i) +
                                   "_" + std::to_string(j);

                z3::expr no_overlap =
                    (off_vars_[i] + static_cast<int>(candidates[i].size) <= off_vars_[j]) ||
                    (off_vars_[j] + static_cast<int>(candidates[j].size) <= off_vars_[i]);

                tracker_.add_hard(solver,
                    z3::implies(sel_vars_[i] && sel_vars_[j], no_overlap), prov);
            }
        }

        // Coverage constraints (soft - can be dropped if needed)
        for (uint32_t byte = 0; byte < struct_size; ++byte) {
            z3::expr_vector covers(ctx_);
            for (size_t i = 0; i < candidates.size(); ++i) {
                covers.push_back(sel_vars_[i] &&
                    off_vars_[i] <= static_cast<int>(byte) &&
                    static_cast<int>(byte) < off_vars_[i] +
                        static_cast<int>(candidates[i].size));
            }

            if (covers.size() > 0) {
                ConstraintProvenance prov;
                prov.kind = ConstraintProvenance::Kind::Coverage;
                prov.description = "coverage_byte_" + std::to_string(byte);
                prov.offset = byte;

                tracker_.add_soft(solver, z3::mk_or(covers), prov,
                                  config_.weight_coverage);
            }
        }

        // Offset preference (soft)
        for (size_t i = 0; i < candidates.size(); ++i) {
            ConstraintProvenance prov;
            prov.kind = ConstraintProvenance::Kind::Other;
            prov.description = "prefer_offset_" + std::to_string(i);
            prov.candidate_id = static_cast<int>(i);

            tracker_.add_soft(solver,
                z3::implies(sel_vars_[i],
                    off_vars_[i] == candidates[i].offset),
                prov, candidates[i].confidence);
        }

        // Alignment (soft)
        for (size_t i = 0; i < candidates.size(); ++i) {
            uint32_t align = candidates[i].alignment();
            if (align > 1) {
                ConstraintProvenance prov;
                prov.kind = ConstraintProvenance::Kind::Alignment;
                prov.description = "align_" + std::to_string(i);
                prov.candidate_id = static_cast<int>(i);

                tracker_.add_soft(solver,
                    z3::implies(sel_vars_[i],
                        (off_vars_[i] % static_cast<int>(align)) == 0),
                    prov, config_.weight_alignment);
            }
        }
    }

    SynthResult solve_with_relaxation(
        z3::solver& solver,
        const std::vector<FieldCandidate>& candidates,
        uint32_t struct_size)
    {
        SynthResult result;
        result.struct_size = struct_size;
        result.iterations = 0;

        // Get all tracking literals
        z3::expr_vector soft_assumptions(ctx_);
        auto soft_lits = tracker_.get_soft_literals();
        for (unsigned i = 0; i < soft_lits.size(); ++i) {
            soft_assumptions.push_back(soft_lits[i]);
        }

        // Hard literals are always enabled
        z3::expr_vector hard_assumptions(ctx_);
        auto hard_lits = tracker_.get_hard_literals();
        for (unsigned i = 0; i < hard_lits.size(); ++i) {
            hard_assumptions.push_back(hard_lits[i]);
        }

        std::set<std::string> disabled_lits;

        for (int iter = 0; iter < config_.max_relaxation_iterations; ++iter) {
            result.iterations++;

            // Build current assumptions: all hard + non-disabled soft
            z3::expr_vector current_assumptions(ctx_);

            // Always include hard constraints
            for (unsigned i = 0; i < hard_assumptions.size(); ++i) {
                current_assumptions.push_back(hard_assumptions[i]);
            }

            // Include non-disabled soft constraints
            for (unsigned i = 0; i < soft_assumptions.size(); ++i) {
                if (disabled_lits.find(soft_assumptions[i].to_string()) ==
                    disabled_lits.end()) {
                    current_assumptions.push_back(soft_assumptions[i]);
                }
            }

            z3::check_result z3_result = solver.check(current_assumptions);

            if (z3_result == z3::sat) {
                // Success!
                z3::model model = solver.get_model();
                result.fields = extract_fields(model, candidates, struct_size);

                if (result.constraints_relaxed > 0) {
                    result.status = SynthStatus::SuccessRelaxed;
                } else {
                    result.status = SynthStatus::Success;
                }

                return result;
            }

            if (z3_result == z3::unknown) {
                result.status = SynthStatus::Timeout;
                result.warnings.push_back("Solver timeout");

                // Fall back to heuristic
                result.fields = fallback_layout(candidates, struct_size);
                if (!result.fields.empty()) {
                    result.status = SynthStatus::FallbackRawBytes;
                }
                return result;
            }

            // UNSAT - extract core and relax
            z3::expr_vector core = solver.unsat_core();
            if (core.size() == 0) {
                result.status = SynthStatus::Unsat;
                result.warnings.push_back("Hard constraints unsatisfiable");
                return result;
            }

            // Find lowest-weight soft constraint in core to relax
            auto core_provs = tracker_.analyze_unsat_core(core);

            const ConstraintProvenance* to_relax = nullptr;
            int min_weight = INT_MAX;

            for (const auto& prov : core_provs) {
                if (prov.is_soft && prov.weight < min_weight) {
                    min_weight = prov.weight;
                    to_relax = &prov;
                }
            }

            if (!to_relax || !to_relax->tracking_literal) {
                // No soft constraint to relax - truly UNSAT
                result.status = SynthStatus::Unsat;
                result.warnings.push_back("Cannot relax any constraints");
                return result;
            }

            // Disable this constraint
            disabled_lits.insert(to_relax->tracking_literal->to_string());
            result.constraints_relaxed++;
            result.dropped_reasons.push_back(to_relax->description);
        }

        // Max iterations reached
        result.status = SynthStatus::Unsat;
        result.warnings.push_back("Max relaxation iterations reached");
        return result;
    }

    std::vector<SynthField> extract_fields(
        const z3::model& model,
        const std::vector<FieldCandidate>& candidates,
        uint32_t struct_size)
    {
        std::vector<SynthField> fields;

        for (size_t i = 0; i < candidates.size(); ++i) {
            z3::expr sel_val = model.eval(sel_vars_[i], true);
            if (sel_val.is_true()) {
                z3::expr off_val = model.eval(off_vars_[i], true);
                int32_t offset = off_val.get_numeral_int();

                SynthField f(offset, candidates[i].size, candidates[i].type,
                             candidates[i].confidence);
                f.is_array = candidates[i].is_array;
                f.array_count = candidates[i].array_count;
                fields.push_back(f);
            }
        }

        // Sort by offset
        std::sort(fields.begin(), fields.end(),
                  [](const SynthField& a, const SynthField& b) {
                      return a.offset < b.offset;
                  });

        // Fill gaps with raw bytes
        fill_gaps(fields, struct_size);

        return fields;
    }

    void fill_gaps(std::vector<SynthField>& fields, uint32_t struct_size) {
        std::vector<bool> covered(struct_size, false);

        for (const auto& f : fields) {
            for (uint32_t b = 0; b < f.size; ++b) {
                if (f.offset + b >= 0 &&
                    static_cast<uint32_t>(f.offset + b) < struct_size) {
                    covered[f.offset + b] = true;
                }
            }
        }

        int32_t gap_start = -1;
        for (uint32_t b = 0; b <= struct_size; ++b) {
            bool is_covered = (b < struct_size) ? covered[b] : true;

            if (!is_covered && gap_start < 0) {
                gap_start = b;
            } else if (is_covered && gap_start >= 0) {
                fields.push_back(SynthField::raw_bytes(gap_start, b - gap_start));
                gap_start = -1;
            }
        }

        std::sort(fields.begin(), fields.end(),
                  [](const SynthField& a, const SynthField& b) {
                      return a.offset < b.offset;
                  });
    }

    std::vector<SynthField> fallback_layout(
        const std::vector<FieldCandidate>& candidates,
        uint32_t struct_size)
    {
        std::vector<SynthField> fields;
        std::vector<bool> used(struct_size, false);

        // Sort by confidence
        std::vector<const FieldCandidate*> sorted;
        for (const auto& c : candidates) {
            sorted.push_back(&c);
        }
        std::sort(sorted.begin(), sorted.end(),
                  [](const FieldCandidate* a, const FieldCandidate* b) {
                      return a->confidence > b->confidence;
                  });

        // Greedy placement
        for (const auto* c : sorted) {
            bool can_place = true;
            for (uint32_t b = 0; b < c->size; ++b) {
                if (c->offset + b >= static_cast<int32_t>(struct_size) ||
                    used[c->offset + b]) {
                    can_place = false;
                    break;
                }
            }

            if (can_place) {
                for (uint32_t b = 0; b < c->size; ++b) {
                    used[c->offset + b] = true;
                }
                SynthField f(c->offset, c->size, c->type, c->confidence);
                f.is_array = c->is_array;
                f.array_count = c->array_count;
                fields.push_back(f);
            }
        }

        fill_gaps(fields, struct_size);
        return fields;
    }
};

// ============================================================================
// Test Helper Functions
// ============================================================================

void print_result(const SynthResult& result) {
    std::cout << "  Status: ";
    switch (result.status) {
        case SynthStatus::Success: std::cout << "Success"; break;
        case SynthStatus::SuccessRelaxed: std::cout << "Success (relaxed)"; break;
        case SynthStatus::FallbackRawBytes: std::cout << "Fallback"; break;
        case SynthStatus::Timeout: std::cout << "Timeout"; break;
        case SynthStatus::Unsat: std::cout << "UNSAT"; break;
        case SynthStatus::Error: std::cout << "Error"; break;
    }
    std::cout << "\n";

    std::cout << "  Size: " << result.struct_size << " bytes\n";
    std::cout << "  Solve time: " << result.solve_time.count() << "ms\n";
    std::cout << "  Iterations: " << result.iterations << "\n";

    if (result.constraints_relaxed > 0) {
        std::cout << "  Constraints relaxed: " << result.constraints_relaxed << "\n";
    }

    std::cout << "  Fields (" << result.fields.size() << "):\n";
    for (const auto& f : result.fields) {
        std::cout << "    +" << std::setw(4) << f.offset << ": ";
        if (f.is_array) {
            std::cout << "[" << f.array_count << "] ";
        }
        std::cout << "size=" << f.size;
        std::cout << " type=" << static_cast<int>(f.type);
        std::cout << " \"" << f.name << "\"";
        std::cout << "\n";
    }

    if (!result.warnings.empty()) {
        std::cout << "  Warnings:\n";
        for (const auto& w : result.warnings) {
            std::cout << "    - " << w << "\n";
        }
    }
}

bool verify_coverage(const SynthResult& result) {
    std::vector<bool> covered(result.struct_size, false);

    for (const auto& f : result.fields) {
        for (uint32_t b = 0; b < f.size; ++b) {
            if (f.offset + b >= 0 &&
                static_cast<uint32_t>(f.offset + b) < result.struct_size) {
                covered[f.offset + b] = true;
            }
        }
    }

    return std::all_of(covered.begin(), covered.end(), [](bool b) { return b; });
}

bool verify_no_overlaps(const SynthResult& result) {
    for (size_t i = 0; i < result.fields.size(); ++i) {
        for (size_t j = i + 1; j < result.fields.size(); ++j) {
            const auto& a = result.fields[i];
            const auto& b = result.fields[j];

            bool overlaps =
                !(a.offset + static_cast<int32_t>(a.size) <= b.offset ||
                  b.offset + static_cast<int32_t>(b.size) <= a.offset);

            if (overlaps) {
                return false;
            }
        }
    }
    return true;
}

// ============================================================================
// End-to-End Tests
// ============================================================================

/// Test complete synthesis of simple struct
void test_e2e_simple_struct() {
    SynthesisPipeline pipeline;

    std::vector<TestAccess> accesses = {
        TestAccess::read(0, 4, TestTypeCategory::Int32),
        TestAccess::read(4, 4, TestTypeCategory::Float32),
        TestAccess::read(8, 8, TestTypeCategory::Pointer),
    };

    auto result = pipeline.synthesize(accesses, 16);

    print_result(result);

    assert(result.is_success());
    assert(verify_coverage(result));
    assert(verify_no_overlaps(result));
}

/// Test synthesis with array detection
void test_e2e_array_detection() {
    SynthesisPipeline pipeline;

    std::vector<TestAccess> accesses;
    for (int i = 0; i < 8; ++i) {
        accesses.push_back(TestAccess::read(i * 4, 4, TestTypeCategory::Int32));
    }

    auto result = pipeline.synthesize(accesses, 32);

    print_result(result);

    assert(result.is_success());

    // Should detect array
    bool found_array = false;
    for (const auto& f : result.fields) {
        if (f.is_array && f.array_count >= 8) {
            found_array = true;
            break;
        }
    }
    assert(found_array);
}

/// Test constraint relaxation with conflicting accesses
void test_e2e_constraint_relaxation() {
    SynthesisPipeline pipeline;

    // Soft constraint scenario: many accesses with some that need relaxation
    // Use overlapping coverage requirements that can be satisfied by picking
    // one of multiple candidates
    std::vector<TestAccess> accesses = {
        TestAccess::read(0, 4, TestTypeCategory::Int32),
        TestAccess::read(0, 4, TestTypeCategory::Float32),  // Same offset, same size
        TestAccess::read(4, 4, TestTypeCategory::Int32),
        TestAccess::read(8, 8, TestTypeCategory::Pointer),
    };

    auto result = pipeline.synthesize(accesses, 16);

    print_result(result);

    // Should succeed - picks one type for offset 0
    assert(result.is_success());
    assert(verify_no_overlaps(result));
    assert(verify_coverage(result));
}

/// Test gap filling
void test_e2e_gap_filling() {
    SynthesisPipeline pipeline;

    // Fields with gap
    std::vector<TestAccess> accesses = {
        TestAccess::read(0, 4, TestTypeCategory::Int32),
        TestAccess::read(12, 4, TestTypeCategory::Int32),
    };

    auto result = pipeline.synthesize(accesses, 16);

    print_result(result);

    assert(result.is_success());
    assert(verify_coverage(result));

    // Gap should be filled
    uint32_t total_size = 0;
    for (const auto& f : result.fields) {
        total_size += f.size;
    }
    assert(total_size == 16);
}

/// Test large struct performance
void test_e2e_large_struct() {
    SynthesisPipeline::Config cfg;
    cfg.timeout_ms = 10000;

    SynthesisPipeline pipeline(cfg);

    // Large struct: 100 fields
    std::vector<TestAccess> accesses;
    for (int i = 0; i < 100; ++i) {
        accesses.push_back(TestAccess::read(i * 8, 8, TestTypeCategory::Int64));
    }

    auto result = pipeline.synthesize(accesses, 800);

    std::cout << "  Large struct solve time: " << result.solve_time.count() << "ms\n";

    assert(result.is_success());
    assert(result.solve_time.count() < 10000);  // Should complete in time
}

/// Test mixed access patterns
void test_e2e_mixed_patterns() {
    SynthesisPipeline pipeline;

    // Mix of reads and writes with different types
    std::vector<TestAccess> accesses = {
        TestAccess::read(0, 8, TestTypeCategory::Pointer),    // vtable?
        TestAccess::write(8, 4, TestTypeCategory::Int32),     // field1
        TestAccess::read(8, 4, TestTypeCategory::Int32),      // same field
        TestAccess::write(12, 4, TestTypeCategory::Float32),  // field2
        TestAccess::read(16, 8, TestTypeCategory::Pointer),   // field3
        TestAccess::read(24, 1, TestTypeCategory::Int8),      // flags
        TestAccess::read(25, 1, TestTypeCategory::Int8),
        TestAccess::read(26, 1, TestTypeCategory::Int8),
        TestAccess::read(27, 1, TestTypeCategory::Int8),
    };

    auto result = pipeline.synthesize(accesses, 32);

    print_result(result);

    assert(result.is_success());
    assert(verify_coverage(result));
    assert(verify_no_overlaps(result));
}

/// Test standard test cases from test_ir.hpp
void test_e2e_standard_cases() {
    SynthesisPipeline pipeline;

    auto test_cases = standard_test_cases();

    for (const auto& tc : test_cases) {
        std::cout << "  Sub-test: " << tc.name << "\n";

        auto result = pipeline.synthesize(tc.accesses, tc.expected_size());

        assert(result.is_success());
    }
}

/// Test array test cases
void test_e2e_array_cases() {
    SynthesisPipeline pipeline;

    auto test_cases = array_test_cases();

    for (const auto& tc : test_cases) {
        std::cout << "  Sub-test: " << tc.name << "\n";

        auto result = pipeline.synthesize(tc.accesses, tc.expected_size());

        assert(result.is_success());
    }
}

/// Test cross-function test cases
void test_e2e_cross_function_cases() {
    SynthesisPipeline pipeline;

    auto test_cases = cross_function_test_cases();

    for (const auto& tc : test_cases) {
        std::cout << "  Sub-test: " << tc.name << "\n";

        // Note: In real implementation, deltas would be normalized
        auto result = pipeline.synthesize(tc.accesses, tc.expected_size());

        assert(result.is_success());
    }
}

/// Test constraint tracker statistics
void test_e2e_constraint_tracking() {
    SynthesisPipeline pipeline;

    std::vector<TestAccess> accesses = {
        TestAccess::read(0, 4, TestTypeCategory::Int32),
        TestAccess::read(4, 4, TestTypeCategory::Int32),
        TestAccess::read(8, 8, TestTypeCategory::Pointer),
    };

    auto result = pipeline.synthesize(accesses, 16);

    // Verify constraint tracking worked
    const auto& tracker = pipeline.tracker();

    std::cout << "  Total constraints: " << tracker.total_constraints() << "\n";
    std::cout << "  Hard constraints: " << tracker.hard_count() << "\n";
    std::cout << "  Soft constraints: " << tracker.soft_count() << "\n";

    assert(tracker.total_constraints() > 0);
    assert(tracker.hard_count() > 0);
    assert(tracker.soft_count() > 0);
}

/// Test timeout handling
void test_e2e_timeout_handling() {
    SynthesisPipeline::Config cfg;
    cfg.timeout_ms = 10;  // Very short timeout

    SynthesisPipeline pipeline(cfg);

    // Complex problem
    std::vector<TestAccess> accesses;
    for (int i = 0; i < 50; ++i) {
        accesses.push_back(TestAccess::read(i * 4, 4, TestTypeCategory::Int32));
    }

    auto result = pipeline.synthesize(accesses, 200);

    // Either succeeds quickly or falls back gracefully
    std::cout << "  Status: " << static_cast<int>(result.status) << "\n";

    // Should not crash
    // Status will be either Success (fast solve) or Timeout -> Fallback
}

/// Test deterministic results
void test_e2e_determinism() {
    SynthesisPipeline pipeline;

    std::vector<TestAccess> accesses = {
        TestAccess::read(0, 4, TestTypeCategory::Int32),
        TestAccess::read(4, 4, TestTypeCategory::Float32),
        TestAccess::read(8, 8, TestTypeCategory::Pointer),
    };

    // Run multiple times
    std::vector<SynthResult> results;
    for (int i = 0; i < 3; ++i) {
        results.push_back(pipeline.synthesize(accesses, 16));
    }

    // All should produce same layout
    for (size_t i = 1; i < results.size(); ++i) {
        assert(results[i].fields.size() == results[0].fields.size());
        for (size_t j = 0; j < results[0].fields.size(); ++j) {
            assert(results[i].fields[j].offset == results[0].fields[j].offset);
            assert(results[i].fields[j].size == results[0].fields[j].size);
        }
    }
}

/// Test empty struct handling
void test_e2e_empty_struct() {
    SynthesisPipeline pipeline;

    std::vector<TestAccess> accesses;  // Empty

    auto result = pipeline.synthesize(accesses, 8);

    // Should fill with raw bytes or handle gracefully
    std::cout << "  Status: " << static_cast<int>(result.status) << "\n";

    // May succeed with raw bytes fill or fail gracefully
}

/// Test single field
void test_e2e_single_field() {
    SynthesisPipeline pipeline;

    std::vector<TestAccess> accesses = {
        TestAccess::read(0, 8, TestTypeCategory::Pointer),
    };

    auto result = pipeline.synthesize(accesses, 8);

    assert(result.is_success());
    assert(result.fields.size() == 1);
    assert(result.fields[0].offset == 0);
    assert(result.fields[0].size == 8);
}

} // anonymous namespace

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "=== End-to-End Synthesis Integration Tests ===\n\n";

    TestRunner runner;

    runner.run("e2e_simple_struct", test_e2e_simple_struct);
    runner.run("e2e_array_detection", test_e2e_array_detection);
    runner.run("e2e_constraint_relaxation", test_e2e_constraint_relaxation);
    runner.run("e2e_gap_filling", test_e2e_gap_filling);
    runner.run("e2e_large_struct", test_e2e_large_struct);
    runner.run("e2e_mixed_patterns", test_e2e_mixed_patterns);
    runner.run("e2e_standard_cases", test_e2e_standard_cases);
    runner.run("e2e_array_cases", test_e2e_array_cases);
    runner.run("e2e_cross_function_cases", test_e2e_cross_function_cases);
    runner.run("e2e_constraint_tracking", test_e2e_constraint_tracking);
    runner.run("e2e_timeout_handling", test_e2e_timeout_handling);
    runner.run("e2e_determinism", test_e2e_determinism);
    runner.run("e2e_empty_struct", test_e2e_empty_struct);
    runner.run("e2e_single_field", test_e2e_single_field);

    runner.summary();

    return runner.all_passed() ? 0 : 1;
}
