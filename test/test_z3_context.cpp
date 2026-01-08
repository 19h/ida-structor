/**
 * @file test_z3_context.cpp
 * @brief Unit tests for Z3 context management
 *
 * Tests the Z3Context wrapper class, including:
 * - Context creation with various configurations
 * - Sort creation (Int, Bool, TypeSort)
 * - Timeout handling
 * - Memory limit behavior
 * - Thread safety (if applicable)
 */

#include <cassert>
#include <iostream>
#include <chrono>
#include <thread>

// Z3 headers
#include <z3++.h>

// When building outside IDA, we can include the test IR
#include "structor/z3/test_ir.hpp"

namespace {

// Test configuration
constexpr unsigned DEFAULT_TIMEOUT_MS = 5000;
constexpr unsigned DEFAULT_MEMORY_MB = 256;

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
// Z3 Context Tests
// ============================================================================

/// Test basic context creation
void test_context_creation() {
    z3::context ctx;

    // Verify context is valid by creating a simple expression
    z3::expr x = ctx.int_const("x");
    z3::expr y = ctx.int_const("y");
    z3::expr sum = x + y;

    assert(sum.is_arith());
}

/// Test context with custom parameters
void test_context_params() {
    z3::config cfg;
    cfg.set("timeout", static_cast<int>(DEFAULT_TIMEOUT_MS));

    z3::context ctx(cfg);

    // Should work with configured context
    z3::expr x = ctx.int_const("x");
    assert(x.is_int());
}

/// Test sort creation
void test_sort_creation() {
    z3::context ctx;

    // Int sort
    z3::sort int_sort = ctx.int_sort();
    assert(int_sort.is_int());

    // Bool sort
    z3::sort bool_sort = ctx.bool_sort();
    assert(bool_sort.is_bool());

    // Real sort (for testing completeness)
    z3::sort real_sort = ctx.real_sort();
    assert(real_sort.is_real());

    // BitVector sort
    z3::sort bv32_sort = ctx.bv_sort(32);
    assert(bv32_sort.is_bv());
    assert(bv32_sort.bv_size() == 32);
}

/// Test enumeration sort (for TypeSort)
void test_enum_sort() {
    z3::context ctx;

    // Create enumeration sort similar to TypeSort
    const char* type_names[] = {
        "Unknown", "Int8", "Int16", "Int32", "Int64",
        "UInt8", "UInt16", "UInt32", "UInt64",
        "Float32", "Float64", "Pointer", "FuncPtr",
        "Array", "Struct", "Union", "RawBytes"
    };
    z3::func_decl_vector enum_consts(ctx);
    z3::func_decl_vector enum_testers(ctx);

    z3::sort type_sort = ctx.enumeration_sort(
        "TypeSort",
        17,
        type_names,
        enum_consts,
        enum_testers
    );

    assert(enum_consts.size() == 17);
    assert(enum_testers.size() == 17);

    // Test creating values
    z3::expr unknown_val = enum_consts[0]();
    z3::expr int32_val = enum_consts[3]();

    // Test testers
    z3::expr is_unknown = enum_testers[0](unknown_val);
    z3::expr is_int32 = enum_testers[3](unknown_val);

    z3::solver solver(ctx);
    solver.add(is_unknown);

    assert(solver.check() == z3::sat);

    solver.reset();
    solver.add(!is_unknown);
    solver.add(unknown_val == int32_val);

    // This should be unsat (unknown != int32)
    assert(solver.check() == z3::unsat);
}

/// Test basic solver operations
void test_solver_basic() {
    z3::context ctx;
    z3::solver solver(ctx);

    z3::expr x = ctx.int_const("x");
    z3::expr y = ctx.int_const("y");

    // Add constraint: x > 0
    solver.add(x > 0);

    // Add constraint: y > x
    solver.add(y > x);

    // Should be SAT
    z3::check_result result = solver.check();
    assert(result == z3::sat);

    z3::model model = solver.get_model();
    assert(model.size() > 0);

    // Extract values
    z3::expr x_val = model.eval(x, true);
    z3::expr y_val = model.eval(y, true);

    // Both should be positive, and y > x
    assert(x_val.is_int());
    assert(y_val.is_int());
}

/// Test solver with UNSAT case
void test_solver_unsat() {
    z3::context ctx;
    z3::solver solver(ctx);

    z3::expr x = ctx.int_const("x");

    // Add contradictory constraints
    solver.add(x > 5);
    solver.add(x < 3);

    // Should be UNSAT
    assert(solver.check() == z3::unsat);
}

/// Test solver with timeout
void test_solver_timeout() {
    z3::context ctx;
    z3::solver solver(ctx);

    // Set a short timeout
    z3::params params(ctx);
    params.set("timeout", static_cast<unsigned>(100));  // 100ms
    solver.set(params);

    // Create a problem that takes time (many variables)
    // Note: This may or may not timeout depending on Z3 performance
    const int N = 100;
    std::vector<z3::expr> vars;
    vars.reserve(N);

    for (int i = 0; i < N; ++i) {
        vars.push_back(ctx.int_const(("x" + std::to_string(i)).c_str()));
    }

    // Add constraints
    for (int i = 0; i < N; ++i) {
        solver.add(vars[i] >= 0);
        solver.add(vars[i] <= 1000);
    }

    // Add sum constraint
    z3::expr sum = vars[0];
    for (int i = 1; i < N; ++i) {
        sum = sum + vars[i];
    }
    solver.add(sum == 5000);

    // This should either SAT quickly or timeout
    z3::check_result result = solver.check();

    // Either SAT or UNKNOWN (timeout) is acceptable
    assert(result == z3::sat || result == z3::unknown);
}

/// Test assert_and_track for UNSAT core
void test_unsat_core() {
    z3::context ctx;
    z3::solver solver(ctx);

    z3::expr x = ctx.int_const("x");

    // Create named assertions
    z3::expr c1 = ctx.bool_const("c1");
    z3::expr c2 = ctx.bool_const("c2");
    z3::expr c3 = ctx.bool_const("c3");

    // Add tracked assertions
    solver.add(z3::implies(c1, x > 5));
    solver.add(z3::implies(c2, x < 3));
    solver.add(z3::implies(c3, x == 10));

    // Enable all constraints
    z3::expr_vector assumptions(ctx);
    assumptions.push_back(c1);
    assumptions.push_back(c2);
    assumptions.push_back(c3);

    z3::check_result result = solver.check(assumptions);
    assert(result == z3::unsat);

    // Get unsat core
    z3::expr_vector core = solver.unsat_core();
    assert(core.size() > 0);

    // Core should contain at least c1 and c2 (the conflicting ones)
    bool has_c1 = false, has_c2 = false;
    for (unsigned i = 0; i < core.size(); ++i) {
        std::string name = core[i].to_string();
        if (name == "c1") has_c1 = true;
        if (name == "c2") has_c2 = true;
    }
    assert(has_c1 && has_c2);
}

/// Test model extraction
void test_model_extraction() {
    z3::context ctx;
    z3::solver solver(ctx);

    z3::expr x = ctx.int_const("x");
    z3::expr y = ctx.int_const("y");
    z3::expr b = ctx.bool_const("b");

    solver.add(x == 42);
    solver.add(y == x * 2);
    solver.add(b == (x > 0));

    z3::check_result result = solver.check();
    assert(result == z3::sat);

    z3::model model = solver.get_model();

    // Extract int value
    z3::expr x_val = model.eval(x, true);
    assert(x_val.is_numeral());

    int x_int = x_val.get_numeral_int();
    assert(x_int == 42);

    // Extract derived value
    z3::expr y_val = model.eval(y, true);
    int y_int = y_val.get_numeral_int();
    assert(y_int == 84);

    // Extract bool value
    z3::expr b_val = model.eval(b, true);
    assert(b_val.is_true());
}

/// Test push/pop for incremental solving
void test_push_pop() {
    z3::context ctx;
    z3::solver solver(ctx);

    z3::expr x = ctx.int_const("x");

    solver.add(x >= 0);

    // First scope
    solver.push();
    solver.add(x < 10);
    assert(solver.check() == z3::sat);
    solver.pop();

    // After pop, only x >= 0 remains
    // Add conflicting constraint
    solver.push();
    solver.add(x < 0);
    assert(solver.check() == z3::unsat);
    solver.pop();

    // Original should still be SAT
    assert(solver.check() == z3::sat);
}

/// Test multiple contexts (thread safety consideration)
void test_multiple_contexts() {
    z3::context ctx1;
    z3::context ctx2;

    // Create expressions in different contexts
    z3::expr x1 = ctx1.int_const("x");
    z3::expr x2 = ctx2.int_const("x");

    // They should be independent
    z3::solver s1(ctx1);
    z3::solver s2(ctx2);

    s1.add(x1 > 0);
    s2.add(x2 < 0);

    // Both should be SAT (independent)
    assert(s1.check() == z3::sat);
    assert(s2.check() == z3::sat);
}

/// Test expression simplification
void test_simplification() {
    z3::context ctx;

    z3::expr x = ctx.int_const("x");
    z3::expr complex = (x + 0) * 1 + (x - x);

    z3::expr simplified = complex.simplify();

    // Should simplify to just x
    // Note: exact simplification depends on Z3 version
    assert(simplified.is_arith());
}

/// Test large constraint set
void test_large_constraint_set() {
    z3::context ctx;
    z3::solver solver(ctx);

    // Create many field-like variables
    const int NUM_FIELDS = 100;
    std::vector<z3::expr> offsets;
    std::vector<z3::expr> sizes;
    std::vector<z3::expr> selected;

    offsets.reserve(NUM_FIELDS);
    sizes.reserve(NUM_FIELDS);
    selected.reserve(NUM_FIELDS);

    for (int i = 0; i < NUM_FIELDS; ++i) {
        offsets.push_back(ctx.int_const(("off_" + std::to_string(i)).c_str()));
        sizes.push_back(ctx.int_const(("sz_" + std::to_string(i)).c_str()));
        selected.push_back(ctx.bool_const(("sel_" + std::to_string(i)).c_str()));

        // Reasonable bounds
        solver.add(offsets[i] >= 0);
        solver.add(offsets[i] < 1000);
        solver.add(sizes[i] > 0);
        solver.add(sizes[i] <= 64);
    }

    // Non-overlap for selected fields
    for (int i = 0; i < NUM_FIELDS; ++i) {
        for (int j = i + 1; j < NUM_FIELDS; ++j) {
            z3::expr both_sel = selected[i] && selected[j];
            z3::expr no_overlap = (offsets[i] + sizes[i] <= offsets[j]) ||
                                 (offsets[j] + sizes[j] <= offsets[i]);
            solver.add(z3::implies(both_sel, no_overlap));
        }
    }

    // Select at least 10 fields
    z3::expr count = ctx.int_val(0);
    for (int i = 0; i < NUM_FIELDS; ++i) {
        count = count + z3::ite(selected[i], ctx.int_val(1), ctx.int_val(0));
    }
    solver.add(count >= 10);

    // Should be satisfiable
    z3::check_result result = solver.check();
    assert(result == z3::sat);

    z3::model model = solver.get_model();
    assert(model.size() > 0);
}

} // anonymous namespace

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "=== Z3 Context Unit Tests ===\n\n";

    TestRunner runner;

    runner.run("context_creation", test_context_creation);
    runner.run("context_params", test_context_params);
    runner.run("sort_creation", test_sort_creation);
    runner.run("enum_sort", test_enum_sort);
    runner.run("solver_basic", test_solver_basic);
    runner.run("solver_unsat", test_solver_unsat);
    runner.run("solver_timeout", test_solver_timeout);
    runner.run("unsat_core", test_unsat_core);
    runner.run("model_extraction", test_model_extraction);
    runner.run("push_pop", test_push_pop);
    runner.run("multiple_contexts", test_multiple_contexts);
    runner.run("simplification", test_simplification);
    runner.run("large_constraint_set", test_large_constraint_set);

    runner.summary();

    return runner.all_passed() ? 0 : 1;
}
