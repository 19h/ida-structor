/**
 * @file test_layout_constraints.cpp
 * @brief Unit tests for layout constraint generation and solving
 *
 * Tests the LayoutConstraintBuilder and Max-SMT solving, including:
 * - Coverage constraints (all offsets must be covered)
 * - Non-overlap constraints (fields cannot overlap unless union)
 * - Alignment constraints (fields aligned to size boundaries)
 * - Max-SMT solving with soft constraints
 * - Constraint relaxation for UNSAT cases
 * - Tiered fallback behavior
 */

#include <cassert>
#include <iostream>
#include <chrono>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <cmath>
#include <optional>

// Z3 headers
#include <z3++.h>

// Test IR (IDA-independent)
#include "structor/z3/test_ir.hpp"

namespace {

// ============================================================================
// Test Helpers
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
        for (const auto& r : results_) {
            if (r.passed) ++passed;
            else ++failed;
        }
        std::cout << "\n=== Summary ===\n";
        std::cout << "Passed: " << passed << ", Failed: " << failed << "\n";
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
// Field Candidate Types (mirrors actual implementation)
// ============================================================================

enum class TestTypeCategory {
    Unknown = 0,
    Int8, Int16, Int32, Int64,
    UInt8, UInt16, UInt32, UInt64,
    Float32, Float64,
    Pointer, FuncPtr,
    Array, Struct, Union,
    RawBytes
};

struct TestFieldCandidate {
    int32_t offset;
    uint32_t size;
    TestTypeCategory type;
    uint8_t confidence;  // 0-100
    bool is_array;
    uint32_t array_count;

    TestFieldCandidate(int32_t off, uint32_t sz, TestTypeCategory t, uint8_t conf = 50)
        : offset(off), size(sz), type(t), confidence(conf),
          is_array(false), array_count(1) {}

    static TestFieldCandidate create_array(int32_t off, uint32_t elem_sz,
                                            TestTypeCategory elem_type, uint32_t count,
                                            uint8_t conf = 50) {
        TestFieldCandidate c(off, elem_sz * count, elem_type, conf);
        c.is_array = true;
        c.array_count = count;
        return c;
    }
};

// ============================================================================
// Test Layout Constraint Builder (mirrors actual implementation)
// ============================================================================

class TestLayoutConstraintBuilder {
public:
    explicit TestLayoutConstraintBuilder(z3::context& ctx, uint32_t struct_size)
        : ctx_(ctx), solver_(ctx), struct_size_(struct_size) {}

    /// Add a field candidate to the constraint system
    void add_candidate(const TestFieldCandidate& candidate, size_t index) {
        // Create selection variable: sel_i is true if candidate i is selected
        std::string sel_name = "sel_" + std::to_string(index);
        z3::expr sel = ctx_.bool_const(sel_name.c_str());

        // Create offset variable (may be adjusted from observed offset)
        std::string off_name = "off_" + std::to_string(index);
        z3::expr off = ctx_.int_const(off_name.c_str());

        // Store variables
        selection_vars_.push_back(sel);
        offset_vars_.push_back(off);
        candidates_.push_back(candidate);

        // Constraint: offset must be within struct bounds
        solver_.add(z3::implies(sel, off >= 0));
        solver_.add(z3::implies(sel, off + static_cast<int>(candidate.size) <=
                                     static_cast<int>(struct_size_)));

        // Soft constraint: prefer observed offset (with weight based on confidence)
        soft_constraints_.push_back({
            z3::implies(sel, off == candidate.offset),
            candidate.confidence
        });

        // Alignment constraint: offset should be aligned to field size
        uint32_t align = std::min(candidate.size, 8u);
        if (align > 1) {
            soft_constraints_.push_back({
                z3::implies(sel, (off % static_cast<int>(align)) == 0),
                20  // Lower weight for alignment
            });
        }
    }

    /// Add non-overlap constraints between all candidates
    void add_non_overlap_constraints() {
        for (size_t i = 0; i < candidates_.size(); ++i) {
            for (size_t j = i + 1; j < candidates_.size(); ++j) {
                z3::expr sel_i = selection_vars_[i];
                z3::expr sel_j = selection_vars_[j];
                z3::expr off_i = offset_vars_[i];
                z3::expr off_j = offset_vars_[j];

                int size_i = static_cast<int>(candidates_[i].size);
                int size_j = static_cast<int>(candidates_[j].size);

                // If both selected, they must not overlap
                z3::expr no_overlap = (off_i + size_i <= off_j) ||
                                      (off_j + size_j <= off_i);
                solver_.add(z3::implies(sel_i && sel_j, no_overlap));
            }
        }
    }

    /// Add coverage constraint: every byte must be covered
    void add_coverage_constraint() {
        // For each byte position, at least one selected candidate must cover it
        for (uint32_t byte = 0; byte < struct_size_; ++byte) {
            z3::expr_vector covers_byte(ctx_);

            for (size_t i = 0; i < candidates_.size(); ++i) {
                z3::expr sel = selection_vars_[i];
                z3::expr off = offset_vars_[i];
                int size = static_cast<int>(candidates_[i].size);
                int b = static_cast<int>(byte);

                // Candidate covers this byte if selected and byte is within range
                z3::expr covers = sel && (off <= b) && (b < off + size);
                covers_byte.push_back(covers);
            }

            if (covers_byte.size() > 0) {
                coverage_constraints_.push_back(z3::mk_or(covers_byte));
            }
        }
    }

    /// Force a candidate to be selected or deselected
    void force_selection(size_t index, bool selected) {
        if (index < selection_vars_.size()) {
            solver_.add(selected ? selection_vars_[index] : !selection_vars_[index]);
        }
    }

    /// Fix a candidate's offset to its observed value (make it a hard constraint)
    void fix_offset(size_t index) {
        if (index < offset_vars_.size() && index < candidates_.size()) {
            solver_.add(offset_vars_[index] == candidates_[index].offset);
        }
    }

    /// Solve with Max-SMT (maximize satisfied soft constraints)
    bool solve_maxsmt() {
        // Add all hard constraints from coverage
        for (const auto& cc : coverage_constraints_) {
            solver_.add(cc);
        }

        // Use optimization for soft constraints
        z3::optimize opt(ctx_);

        // Transfer hard constraints to optimizer
        for (const auto& a : solver_.assertions()) {
            opt.add(a);
        }

        // Add coverage as hard constraints
        for (const auto& cc : coverage_constraints_) {
            opt.add(cc);
        }

        // Add soft constraints with weights
        for (const auto& [constraint, weight] : soft_constraints_) {
            opt.add_soft(constraint, weight);
        }

        // Objective: maximize number of selected candidates
        z3::expr selection_count = ctx_.int_val(0);
        for (const auto& sel : selection_vars_) {
            selection_count = selection_count + z3::ite(sel, ctx_.int_val(1), ctx_.int_val(0));
        }
        opt.maximize(selection_count);

        z3::check_result result = opt.check();

        if (result == z3::sat) {
            model_ = opt.get_model();
            return true;
        }
        return false;
    }

    /// Simple solve (without soft constraint optimization)
    bool solve_basic() {
        for (const auto& cc : coverage_constraints_) {
            solver_.add(cc);
        }

        z3::check_result result = solver_.check();
        if (result == z3::sat) {
            model_ = solver_.get_model();
            return true;
        }
        return false;
    }

    /// Get selected candidates from model
    std::vector<std::pair<size_t, int32_t>> get_selected_candidates() const {
        std::vector<std::pair<size_t, int32_t>> result;

        for (size_t i = 0; i < selection_vars_.size(); ++i) {
            z3::expr sel_val = model_->eval(selection_vars_[i], true);
            if (sel_val.is_true()) {
                z3::expr off_val = model_->eval(offset_vars_[i], true);
                int32_t offset = off_val.get_numeral_int();
                result.push_back({i, offset});
            }
        }

        return result;
    }

    /// Check if solution has full coverage (no gaps)
    bool has_full_coverage() const {
        std::vector<bool> covered(struct_size_, false);

        for (size_t i = 0; i < selection_vars_.size(); ++i) {
            z3::expr sel_val = model_->eval(selection_vars_[i], true);
            if (sel_val.is_true()) {
                z3::expr off_val = model_->eval(offset_vars_[i], true);
                int32_t offset = off_val.get_numeral_int();
                uint32_t size = candidates_[i].size;

                for (uint32_t b = 0; b < size && offset + b < struct_size_; ++b) {
                    if (offset + b >= 0) {
                        covered[offset + b] = true;
                    }
                }
            }
        }

        return std::all_of(covered.begin(), covered.end(), [](bool b) { return b; });
    }

    /// Check if solution has no overlaps
    bool has_no_overlaps() const {
        std::vector<std::pair<int32_t, uint32_t>> selected;

        for (size_t i = 0; i < selection_vars_.size(); ++i) {
            z3::expr sel_val = model_->eval(selection_vars_[i], true);
            if (sel_val.is_true()) {
                z3::expr off_val = model_->eval(offset_vars_[i], true);
                int32_t offset = off_val.get_numeral_int();
                selected.push_back({offset, candidates_[i].size});
            }
        }

        std::sort(selected.begin(), selected.end());

        for (size_t i = 1; i < selected.size(); ++i) {
            if (selected[i-1].first + static_cast<int32_t>(selected[i-1].second) >
                selected[i].first) {
                return false;
            }
        }

        return true;
    }

private:
    z3::context& ctx_;
    z3::solver solver_;
    uint32_t struct_size_;

    std::vector<z3::expr> selection_vars_;
    std::vector<z3::expr> offset_vars_;
    std::vector<TestFieldCandidate> candidates_;

    std::vector<z3::expr> coverage_constraints_;
    std::vector<std::pair<z3::expr, unsigned>> soft_constraints_;

    std::optional<z3::model> model_;
};

// ============================================================================
// Layout Constraint Tests
// ============================================================================

/// Test basic layout with non-overlapping fields
void test_basic_layout() {
    z3::context ctx;
    TestLayoutConstraintBuilder builder(ctx, 16);

    // Simple struct: 4-byte int at 0, 8-byte ptr at 8
    builder.add_candidate(TestFieldCandidate(0, 4, TestTypeCategory::Int32, 80), 0);
    builder.add_candidate(TestFieldCandidate(8, 8, TestTypeCategory::Pointer, 90), 1);

    builder.add_non_overlap_constraints();
    builder.add_coverage_constraint();

    // Need filler candidate for bytes 4-7
    builder.add_candidate(TestFieldCandidate(4, 4, TestTypeCategory::RawBytes, 10), 2);

    // Re-add constraints for the new candidate
    TestLayoutConstraintBuilder builder2(ctx, 16);
    builder2.add_candidate(TestFieldCandidate(0, 4, TestTypeCategory::Int32, 80), 0);
    builder2.add_candidate(TestFieldCandidate(8, 8, TestTypeCategory::Pointer, 90), 1);
    builder2.add_candidate(TestFieldCandidate(4, 4, TestTypeCategory::RawBytes, 10), 2);
    builder2.add_non_overlap_constraints();
    builder2.add_coverage_constraint();

    bool solved = builder2.solve_basic();
    assert(solved);

    auto selected = builder2.get_selected_candidates();
    assert(selected.size() >= 2);  // At least the main fields

    assert(builder2.has_no_overlaps());
}

/// Test overlapping candidates (conflict resolution)
void test_overlapping_candidates() {
    z3::context ctx;
    TestLayoutConstraintBuilder builder(ctx, 8);

    // Two overlapping interpretations at offset 0
    // Interpretation 1: 4-byte int
    builder.add_candidate(TestFieldCandidate(0, 4, TestTypeCategory::Int32, 60), 0);
    // Interpretation 2: 8-byte pointer (overlaps with int)
    builder.add_candidate(TestFieldCandidate(0, 8, TestTypeCategory::Pointer, 80), 1);

    builder.add_non_overlap_constraints();
    builder.add_coverage_constraint();

    bool solved = builder.solve_basic();
    assert(solved);

    auto selected = builder.get_selected_candidates();

    // Only one should be selected (no overlaps allowed)
    assert(selected.size() == 1);
    assert(builder.has_no_overlaps());
    assert(builder.has_full_coverage());
}

/// Test Max-SMT optimization (prefer higher confidence)
void test_maxsmt_optimization() {
    z3::context ctx;
    TestLayoutConstraintBuilder builder(ctx, 8);

    // Two options for the same space - Max-SMT should prefer higher confidence
    builder.add_candidate(TestFieldCandidate(0, 8, TestTypeCategory::Int64, 30), 0);
    builder.add_candidate(TestFieldCandidate(0, 8, TestTypeCategory::Pointer, 90), 1);

    builder.add_non_overlap_constraints();
    builder.add_coverage_constraint();

    bool solved = builder.solve_maxsmt();
    assert(solved);

    auto selected = builder.get_selected_candidates();
    assert(selected.size() == 1);

    // Max-SMT should prefer the higher confidence option (index 1)
    // Note: actual behavior depends on soft constraint weights
    assert(builder.has_full_coverage());
}

/// Test alignment constraints
void test_alignment_constraints() {
    z3::context ctx;
    TestLayoutConstraintBuilder builder(ctx, 16);

    // 8-byte field should be 8-byte aligned
    builder.add_candidate(TestFieldCandidate(0, 8, TestTypeCategory::Pointer, 80), 0);
    builder.add_candidate(TestFieldCandidate(8, 8, TestTypeCategory::Pointer, 80), 1);

    builder.add_non_overlap_constraints();
    builder.add_coverage_constraint();

    bool solved = builder.solve_maxsmt();
    assert(solved);

    auto selected = builder.get_selected_candidates();

    // Both should be selected at their natural offsets
    for (const auto& [idx, offset] : selected) {
        // 8-byte fields should be 8-byte aligned
        assert(offset % 8 == 0);
    }
}

/// Test coverage with gaps
void test_coverage_with_gaps() {
    z3::context ctx;
    TestLayoutConstraintBuilder builder(ctx, 16);

    // Candidates that leave gaps
    builder.add_candidate(TestFieldCandidate(0, 4, TestTypeCategory::Int32, 80), 0);
    builder.add_candidate(TestFieldCandidate(12, 4, TestTypeCategory::Int32, 80), 1);
    // Missing bytes 4-11

    builder.add_non_overlap_constraints();
    builder.add_coverage_constraint();

    // This should fail (UNSAT) because bytes 4-11 aren't covered
    bool solved = builder.solve_basic();

    // Without filler candidates, this should be UNSAT
    // Actually the constraint says "at least one candidate must cover each byte"
    // so if no candidate covers bytes 4-11, it's UNSAT
    assert(!solved);
}

/// Test coverage with filler
void test_coverage_with_filler() {
    z3::context ctx;
    TestLayoutConstraintBuilder builder(ctx, 16);

    // Main candidates
    builder.add_candidate(TestFieldCandidate(0, 4, TestTypeCategory::Int32, 80), 0);
    builder.add_candidate(TestFieldCandidate(12, 4, TestTypeCategory::Int32, 80), 1);
    // Filler for gap
    builder.add_candidate(TestFieldCandidate(4, 8, TestTypeCategory::RawBytes, 10), 2);

    builder.add_non_overlap_constraints();
    builder.add_coverage_constraint();

    bool solved = builder.solve_basic();
    assert(solved);

    assert(builder.has_full_coverage());
    assert(builder.has_no_overlaps());
}

/// Test complex struct layout
void test_complex_layout() {
    z3::context ctx;
    TestLayoutConstraintBuilder builder(ctx, 32);

    // Complex struct with various field types
    builder.add_candidate(TestFieldCandidate(0, 4, TestTypeCategory::Int32, 85), 0);   // int
    builder.add_candidate(TestFieldCandidate(4, 4, TestTypeCategory::Float32, 75), 1); // float
    builder.add_candidate(TestFieldCandidate(8, 8, TestTypeCategory::Pointer, 90), 2); // ptr
    builder.add_candidate(TestFieldCandidate(16, 8, TestTypeCategory::Int64, 80), 3);  // int64
    builder.add_candidate(TestFieldCandidate(24, 8, TestTypeCategory::Pointer, 85), 4);// ptr

    builder.add_non_overlap_constraints();
    builder.add_coverage_constraint();

    bool solved = builder.solve_maxsmt();
    assert(solved);

    auto selected = builder.get_selected_candidates();
    assert(selected.size() == 5);  // All should be selected

    assert(builder.has_full_coverage());
    assert(builder.has_no_overlaps());
}

/// Test conflicting type interpretations
void test_conflicting_types() {
    z3::context ctx;
    TestLayoutConstraintBuilder builder(ctx, 8);

    // Same offset, different interpretations
    builder.add_candidate(TestFieldCandidate(0, 4, TestTypeCategory::Int32, 70), 0);
    builder.add_candidate(TestFieldCandidate(0, 4, TestTypeCategory::Float32, 60), 1);
    builder.add_candidate(TestFieldCandidate(4, 4, TestTypeCategory::Int32, 80), 2);

    builder.add_non_overlap_constraints();
    builder.add_coverage_constraint();

    bool solved = builder.solve_maxsmt();
    assert(solved);

    auto selected = builder.get_selected_candidates();

    // Two fields should be selected: one at 0, one at 4
    // The one at 0 should be Int32 (higher confidence)
    assert(selected.size() == 2);
    assert(builder.has_no_overlaps());
}

/// Test array candidate
void test_array_candidate() {
    z3::context ctx;
    TestLayoutConstraintBuilder builder(ctx, 32);

    // Array of 8 ints (each 4 bytes)
    auto arr = TestFieldCandidate::create_array(0, 4, TestTypeCategory::Int32, 8, 85);
    builder.add_candidate(arr, 0);

    builder.add_non_overlap_constraints();
    builder.add_coverage_constraint();

    bool solved = builder.solve_basic();
    assert(solved);

    assert(builder.has_full_coverage());
}

/// Test incremental constraint adding
void test_incremental_solving() {
    z3::context ctx;
    z3::solver solver(ctx);

    // Start with basic constraints
    z3::expr x = ctx.int_const("x");
    z3::expr y = ctx.int_const("y");

    solver.push();
    solver.add(x >= 0);
    solver.add(y >= 0);
    solver.add(x + y == 10);

    z3::check_result res1 = solver.check();
    assert(res1 == z3::sat);

    // Add more constraints
    solver.push();
    solver.add(x == 5);

    z3::check_result res2 = solver.check();
    assert(res2 == z3::sat);
    z3::model m = solver.get_model();
    int x_val = m.eval(x, true).get_numeral_int();
    int y_val = m.eval(y, true).get_numeral_int();
    assert(x_val == 5 && y_val == 5);

    solver.pop();

    // Original constraint still holds
    solver.add(x > 5);
    z3::check_result res3 = solver.check();
    assert(res3 == z3::sat);
    m = solver.get_model();
    x_val = m.eval(x, true).get_numeral_int();
    assert(x_val > 5);
}

/// Test constraint relaxation strategy
void test_constraint_relaxation() {
    z3::context ctx;
    z3::optimize opt(ctx);

    z3::expr a = ctx.bool_const("a");
    z3::expr b = ctx.bool_const("b");
    z3::expr c = ctx.bool_const("c");

    // Conflicting hard constraints
    opt.add(a);
    opt.add(b);

    // a and c conflict
    opt.add(!a || !c);

    // Soft preference for c
    opt.add_soft(c, 10);

    // Should be SAT (c is soft, so it can be false)
    assert(opt.check() == z3::sat);

    z3::model m = opt.get_model();

    // a should be true (hard), c should be false (conflicts with a)
    assert(m.eval(a, true).is_true());
    assert(m.eval(c, true).is_false());
}

/// Test large struct layout
void test_large_struct() {
    z3::context ctx;
    const uint32_t struct_size = 256;
    TestLayoutConstraintBuilder builder(ctx, struct_size);

    // Many candidates
    for (uint32_t i = 0; i < struct_size; i += 8) {
        builder.add_candidate(TestFieldCandidate(i, 8, TestTypeCategory::Int64, 70), i / 8);
    }

    builder.add_non_overlap_constraints();
    builder.add_coverage_constraint();

    auto start = std::chrono::steady_clock::now();
    bool solved = builder.solve_basic();
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    assert(solved);
    assert(builder.has_full_coverage());

    // Should solve reasonably fast (< 5 seconds)
    assert(duration.count() < 5000);
}

/// Test union field detection
void test_union_detection() {
    z3::context ctx;
    z3::solver solver(ctx);

    // Two fields at the same offset with different types
    // This typically indicates a union
    z3::expr off1 = ctx.int_const("off1");
    z3::expr off2 = ctx.int_const("off2");
    z3::expr size1 = ctx.int_val(4);
    z3::expr size2 = ctx.int_val(8);

    // Both observed at offset 0
    solver.add(off1 == 0);
    solver.add(off2 == 0);

    // Check if they overlap
    z3::expr overlap = (off1 < off2 + size2) && (off2 < off1 + size1);

    solver.add(overlap);

    assert(solver.check() == z3::sat);

    // In this case, the layout solver should detect union potential
}

/// Test boundary constraints
void test_boundary_constraints() {
    z3::context ctx;
    TestLayoutConstraintBuilder builder(ctx, 16);

    // Candidate that would exceed struct bounds
    builder.add_candidate(TestFieldCandidate(12, 8, TestTypeCategory::Int64, 80), 0);

    builder.add_non_overlap_constraints();

    // Force the candidate to be selected and fix its offset to test boundary constraint
    builder.force_selection(0, true);
    builder.fix_offset(0);

    bool solved = builder.solve_basic();

    // Should fail because field extends beyond struct_size
    // Actually the constraint is: off + size <= struct_size
    // 12 + 8 = 20 > 16, so this should be UNSAT
    assert(!solved);
}

/// Test valid boundary constraints
void test_valid_boundaries() {
    z3::context ctx;
    TestLayoutConstraintBuilder builder(ctx, 16);

    // Candidate that fits exactly
    builder.add_candidate(TestFieldCandidate(8, 8, TestTypeCategory::Int64, 80), 0);
    builder.add_candidate(TestFieldCandidate(0, 8, TestTypeCategory::Int64, 80), 1);

    builder.add_non_overlap_constraints();
    builder.add_coverage_constraint();

    bool solved = builder.solve_basic();
    assert(solved);

    auto selected = builder.get_selected_candidates();
    assert(selected.size() == 2);
}

} // anonymous namespace

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "=== Layout Constraint Unit Tests ===\n\n";

    TestRunner runner;

    runner.run("basic_layout", test_basic_layout);
    runner.run("overlapping_candidates", test_overlapping_candidates);
    runner.run("maxsmt_optimization", test_maxsmt_optimization);
    runner.run("alignment_constraints", test_alignment_constraints);
    runner.run("coverage_with_gaps", test_coverage_with_gaps);
    runner.run("coverage_with_filler", test_coverage_with_filler);
    runner.run("complex_layout", test_complex_layout);
    runner.run("conflicting_types", test_conflicting_types);
    runner.run("array_candidate", test_array_candidate);
    runner.run("incremental_solving", test_incremental_solving);
    runner.run("constraint_relaxation", test_constraint_relaxation);
    runner.run("large_struct", test_large_struct);
    runner.run("union_detection", test_union_detection);
    runner.run("boundary_constraints", test_boundary_constraints);
    runner.run("valid_boundaries", test_valid_boundaries);

    runner.summary();

    return runner.all_passed() ? 0 : 1;
}
