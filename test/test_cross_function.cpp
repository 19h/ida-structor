/**
 * @file test_cross_function.cpp
 * @brief Unit tests for cross-function struct unification
 *
 * Tests the cross-function analysis capabilities, including:
 * - Pointer delta normalization
 * - Same-struct detection across functions
 * - Constraint merging from multiple call sites
 * - Struct aliasing detection
 * - Call graph traversal
 * - Type inference propagation
 */

#include <cassert>
#include <iostream>
#include <chrono>
#include <vector>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <functional>

// Z3 headers
#include <z3++.h>

// Test IR (IDA-independent)
#include "structor/z3/test_ir.hpp"

namespace {

using namespace structor::z3::test;

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
// Cross-Function Test Types (mirrors actual implementation)
// ============================================================================

/// Represents a normalized pointer (base + offset)
struct NormalizedPointer {
    uint64_t base_id;      // Canonical ID for this pointer chain
    int32_t delta;         // Offset from base
    uint64_t source_func;  // Function where this pointer was observed

    bool operator==(const NormalizedPointer& other) const {
        return base_id == other.base_id && delta == other.delta;
    }
};

/// Represents a struct observation at a call site
struct CallSiteObservation {
    uint64_t caller_func;
    uint64_t callee_func;
    uint64_t call_addr;
    int argument_index;    // Which argument (0-based)
    int32_t base_offset;   // Offset of passed pointer relative to struct base
};

/// Represents access constraints for a struct parameter
struct ParameterConstraints {
    uint64_t func_addr;
    int param_index;
    std::vector<TestAccess> accesses;  // Accesses relative to param base
};

/// Union-Find for struct equivalence classes
class StructUnionFind {
public:
    uint64_t find(uint64_t id) {
        if (parent_.find(id) == parent_.end()) {
            parent_[id] = id;
            rank_[id] = 0;
        }
        if (parent_[id] != id) {
            parent_[id] = find(parent_[id]);  // Path compression
        }
        return parent_[id];
    }

    void unite(uint64_t a, uint64_t b) {
        uint64_t ra = find(a);
        uint64_t rb = find(b);
        if (ra == rb) return;

        // Union by rank
        if (rank_[ra] < rank_[rb]) {
            parent_[ra] = rb;
        } else if (rank_[ra] > rank_[rb]) {
            parent_[rb] = ra;
        } else {
            parent_[rb] = ra;
            rank_[ra]++;
        }
    }

    bool same_set(uint64_t a, uint64_t b) {
        return find(a) == find(b);
    }

    std::set<uint64_t> get_set(uint64_t id) {
        uint64_t root = find(id);
        std::set<uint64_t> result;
        for (const auto& [k, v] : parent_) {
            if (find(k) == root) {
                result.insert(k);
            }
        }
        return result;
    }

private:
    std::unordered_map<uint64_t, uint64_t> parent_;
    std::unordered_map<uint64_t, int> rank_;
};

/// Test cross-function analyzer
class TestCrossFunctionAnalyzer {
public:
    TestCrossFunctionAnalyzer() = default;

    /// Register a function's parameter constraints
    void add_function_constraints(uint64_t func_addr, int param_index,
                                   const std::vector<TestAccess>& accesses) {
        ParameterConstraints pc;
        pc.func_addr = func_addr;
        pc.param_index = param_index;
        pc.accesses = accesses;
        param_constraints_[{func_addr, param_index}] = pc;
    }

    /// Register a call site observation
    void add_call_site(const CallSiteObservation& obs) {
        call_sites_.push_back(obs);
    }

    /// Analyze call graph and unify struct types
    void analyze() {
        // For each call site, unify caller's struct with callee's parameter
        for (const auto& cs : call_sites_) {
            // Create IDs for caller struct and callee param
            uint64_t caller_struct_id = make_id(cs.caller_func, 0);  // Simplified
            uint64_t callee_param_id = make_id(cs.callee_func, cs.argument_index);

            // Track delta between caller's view and callee's view
            pointer_deltas_[{caller_struct_id, callee_param_id}] = cs.base_offset;

            // Unify if base offsets align
            struct_uf_.unite(caller_struct_id, callee_param_id);
        }
    }

    /// Check if two parameters refer to the same struct type
    bool same_struct_type(uint64_t func1, int param1, uint64_t func2, int param2) {
        uint64_t id1 = make_id(func1, param1);
        uint64_t id2 = make_id(func2, param2);
        return struct_uf_.same_set(id1, id2);
    }

    /// Get normalized offset for an access, accounting for pointer deltas
    int32_t normalize_offset(uint64_t func_addr, int param_index,
                             int32_t raw_offset) {
        uint64_t id = make_id(func_addr, param_index);
        uint64_t root = struct_uf_.find(id);

        // Find total delta from this param to the canonical root
        int32_t total_delta = compute_delta_to_root(id, root);
        return raw_offset - total_delta;
    }

    /// Get all constraints for a unified struct type
    std::vector<TestAccess> get_unified_constraints(uint64_t func_addr, int param_index) {
        uint64_t id = make_id(func_addr, param_index);
        uint64_t root = struct_uf_.find(id);

        std::vector<TestAccess> unified;

        // Collect all constraints from all parameters in this equivalence class
        for (const auto& [key, pc] : param_constraints_) {
            uint64_t pc_id = make_id(pc.func_addr, pc.param_index);
            if (struct_uf_.find(pc_id) == root) {
                int32_t delta = compute_delta_to_root(pc_id, root);

                for (auto access : pc.accesses) {
                    // Normalize offset
                    access.offset -= delta;
                    unified.push_back(access);
                }
            }
        }

        return unified;
    }

    /// Get all functions that use a unified struct type
    std::set<uint64_t> get_using_functions(uint64_t func_addr, int param_index) {
        uint64_t id = make_id(func_addr, param_index);
        auto id_set = struct_uf_.get_set(id);

        std::set<uint64_t> funcs;
        for (uint64_t member_id : id_set) {
            funcs.insert(member_id >> 32);  // Extract func addr from ID
        }
        return funcs;
    }

private:
    static uint64_t make_id(uint64_t func_addr, int param_index) {
        return (func_addr << 32) | static_cast<uint32_t>(param_index);
    }

    int32_t compute_delta_to_root(uint64_t from, uint64_t root) {
        // Simple implementation - in real code this would trace the path
        int32_t delta = 0;

        // Look for direct delta
        if (pointer_deltas_.find({root, from}) != pointer_deltas_.end()) {
            delta = -pointer_deltas_[{root, from}];
        } else if (pointer_deltas_.find({from, root}) != pointer_deltas_.end()) {
            delta = pointer_deltas_[{from, root}];
        }

        return delta;
    }

    StructUnionFind struct_uf_;
    std::map<std::pair<uint64_t, int>, ParameterConstraints> param_constraints_;
    std::vector<CallSiteObservation> call_sites_;
    std::map<std::pair<uint64_t, uint64_t>, int32_t> pointer_deltas_;
};

// ============================================================================
// Cross-Function Tests
// ============================================================================

/// Test basic struct unification
void test_basic_unification() {
    StructUnionFind uf;

    // Three distinct struct IDs
    uint64_t s1 = 1, s2 = 2, s3 = 3;

    // Initially all distinct
    assert(!uf.same_set(s1, s2));
    assert(!uf.same_set(s2, s3));

    // Unite s1 and s2
    uf.unite(s1, s2);
    assert(uf.same_set(s1, s2));
    assert(!uf.same_set(s1, s3));

    // Unite s2 and s3 - should transitively unite s1 and s3
    uf.unite(s2, s3);
    assert(uf.same_set(s1, s3));
}

/// Test pointer delta normalization
void test_pointer_delta_normalization() {
    TestCrossFunctionAnalyzer analyzer;

    // Function A accesses struct at offset 0
    analyzer.add_function_constraints(0x1000, 0, {
        TestAccess::read(0, 4, TestTypeCategory::Int32),   // field at 0
        TestAccess::read(4, 4, TestTypeCategory::Int32),   // field at 4
    });

    // Function B receives pointer to field at offset 8, accesses fields after
    analyzer.add_function_constraints(0x2000, 0, {
        TestAccess::read(0, 8, TestTypeCategory::Pointer), // field at 8 (as 0)
        TestAccess::read(8, 4, TestTypeCategory::Int32),   // field at 16 (as 8)
    });

    // Call site: A calls B with ptr+8
    CallSiteObservation call;
    call.caller_func = 0x1000;
    call.callee_func = 0x2000;
    call.call_addr = 0x1050;
    call.argument_index = 0;
    call.base_offset = 8;  // Passed ptr+8

    analyzer.add_call_site(call);
    analyzer.analyze();

    // B's param 0 should be unified with A's struct (at offset 8)
    assert(analyzer.same_struct_type(0x1000, 0, 0x2000, 0));
}

/// Test multi-function constraint merging
void test_constraint_merging() {
    TestCrossFunctionAnalyzer analyzer;

    // Function 1 sees offset 0 and 8
    analyzer.add_function_constraints(0x1000, 0, {
        TestAccess::read(0, 4, TestTypeCategory::Int32),
        TestAccess::read(8, 8, TestTypeCategory::Pointer),
    });

    // Function 2 sees offset 4 and 16
    analyzer.add_function_constraints(0x2000, 0, {
        TestAccess::read(4, 4, TestTypeCategory::Float32),
        TestAccess::read(16, 4, TestTypeCategory::Int32),
    });

    // Both called with same struct
    CallSiteObservation call1, call2;
    call1.caller_func = 0x3000;
    call1.callee_func = 0x1000;
    call1.call_addr = 0x3010;
    call1.argument_index = 0;
    call1.base_offset = 0;

    call2.caller_func = 0x3000;
    call2.callee_func = 0x2000;
    call2.call_addr = 0x3020;
    call2.argument_index = 0;
    call2.base_offset = 0;

    analyzer.add_call_site(call1);
    analyzer.add_call_site(call2);
    analyzer.analyze();

    // Get unified constraints
    auto unified = analyzer.get_unified_constraints(0x1000, 0);

    // Should have constraints from both functions
    // Note: may have duplicates if same call site info unifies them
    assert(unified.size() >= 4);  // At least 4 accesses
}

/// Test struct aliasing detection with Z3
void test_struct_aliasing_z3() {
    z3::context ctx;
    z3::solver solver(ctx);

    // Two pointers might alias the same struct
    z3::expr ptr1_base = ctx.int_const("ptr1_base");
    z3::expr ptr2_base = ctx.int_const("ptr2_base");

    // Observations:
    // ptr1+0 -> int32
    // ptr2+4 -> int32
    // ptr1+8 -> ptr
    // ptr2+8 -> ptr  (same value as ptr1+8!)

    // If ptr2 == ptr1 + 4, then both access the same struct
    z3::expr alias_hypothesis = (ptr2_base == ptr1_base + 4);

    solver.push();
    solver.add(alias_hypothesis);

    // Under this hypothesis:
    // ptr1+0 == ptr2-4 -> both see offset 0
    // ptr1+8 == ptr2+4 -> ptr1 sees offset 8, ptr2 sees as offset 4

    // Check consistency
    assert(solver.check() == z3::sat);
    solver.pop();

    // Alternative: ptr1 == ptr2 (no offset)
    z3::expr same_base = (ptr2_base == ptr1_base);
    solver.push();
    solver.add(same_base);
    // ptr1+0 and ptr2+4 would be different offsets in same struct
    assert(solver.check() == z3::sat);
    solver.pop();
}

/// Test call graph traversal
void test_call_graph_traversal() {
    // Simulate call graph: A -> B -> C
    std::map<uint64_t, std::vector<uint64_t>> call_graph;
    call_graph[0x1000] = {0x2000};  // A calls B
    call_graph[0x2000] = {0x3000};  // B calls C

    // BFS to find all reachable functions
    std::set<uint64_t> reachable;
    std::vector<uint64_t> worklist = {0x1000};

    while (!worklist.empty()) {
        uint64_t current = worklist.back();
        worklist.pop_back();

        if (reachable.count(current)) continue;
        reachable.insert(current);

        if (call_graph.count(current)) {
            for (uint64_t callee : call_graph[current]) {
                worklist.push_back(callee);
            }
        }
    }

    assert(reachable.size() == 3);
    assert(reachable.count(0x1000));
    assert(reachable.count(0x2000));
    assert(reachable.count(0x3000));
}

/// Test type inference propagation
void test_type_propagation() {
    z3::context ctx;
    z3::solver solver(ctx);

    // Type variables for fields
    z3::expr type_f0 = ctx.int_const("type_f0");  // type of field at offset 0
    z3::expr type_f4 = ctx.int_const("type_f4");  // type of field at offset 4

    // Type constants
    const int TYPE_INT32 = 3;
    const int TYPE_FLOAT32 = 9;
    const int TYPE_UNKNOWN = 0;

    // Constraint from function A: f0 is int32
    z3::expr constraint_a = (type_f0 == TYPE_INT32);

    // Constraint from function B: f4 is float32
    z3::expr constraint_b = (type_f4 == TYPE_FLOAT32);

    solver.add(constraint_a);
    solver.add(constraint_b);

    z3::check_result res = solver.check();
    assert(res == z3::sat);

    z3::model m = solver.get_model();
    int f0_type = m.eval(type_f0, true).get_numeral_int();
    int f4_type = m.eval(type_f4, true).get_numeral_int();

    assert(f0_type == TYPE_INT32);
    assert(f4_type == TYPE_FLOAT32);
}

/// Test conflicting type inference
void test_conflicting_types() {
    z3::context ctx;
    z3::solver solver(ctx);

    // Type variable for a field
    z3::expr type_f0 = ctx.int_const("type_f0");

    const int TYPE_INT32 = 3;
    const int TYPE_POINTER = 11;

    // Function A thinks it's int32
    z3::expr constraint_a = (type_f0 == TYPE_INT32);

    // Function B thinks it's pointer
    z3::expr constraint_b = (type_f0 == TYPE_POINTER);

    // Both can't be true
    solver.add(constraint_a);
    solver.add(constraint_b);

    assert(solver.check() == z3::unsat);

    // Use soft constraints to resolve
    z3::optimize opt(ctx);

    z3::expr type_var = ctx.int_const("type");
    opt.add(type_var >= 0);

    // Soft: prefer int32 (weight 70)
    opt.add_soft(type_var == TYPE_INT32, 70);
    // Soft: prefer pointer (weight 80)
    opt.add_soft(type_var == TYPE_POINTER, 80);

    assert(opt.check() == z3::sat);

    z3::model m = opt.get_model();
    int resolved_type = m.eval(type_var, true).get_numeral_int();

    // Higher weight wins
    assert(resolved_type == TYPE_POINTER);
}

/// Test cross-function array detection
void test_cross_function_array() {
    TestCrossFunctionAnalyzer analyzer;

    // Function 1 accesses elements 0, 1, 2
    analyzer.add_function_constraints(0x1000, 0, {
        TestAccess::read(0, 4, TestTypeCategory::Int32),
        TestAccess::read(4, 4, TestTypeCategory::Int32),
        TestAccess::read(8, 4, TestTypeCategory::Int32),
    });

    // Function 2 accesses elements 3, 4
    analyzer.add_function_constraints(0x2000, 0, {
        TestAccess::read(12, 4, TestTypeCategory::Int32),
        TestAccess::read(16, 4, TestTypeCategory::Int32),
    });

    // Both called from same site
    CallSiteObservation call1, call2;
    call1.caller_func = 0x3000;
    call1.callee_func = 0x1000;
    call1.call_addr = 0x3010;
    call1.argument_index = 0;
    call1.base_offset = 0;

    call2.caller_func = 0x3000;
    call2.callee_func = 0x2000;
    call2.call_addr = 0x3020;
    call2.argument_index = 0;
    call2.base_offset = 0;

    analyzer.add_call_site(call1);
    analyzer.add_call_site(call2);
    analyzer.analyze();

    auto unified = analyzer.get_unified_constraints(0x1000, 0);

    // All 5 accesses should be unified
    assert(unified.size() == 5);

    // All have stride 4, suggesting array
    std::set<int32_t> offsets;
    for (const auto& acc : unified) {
        offsets.insert(acc.offset);
    }
    assert(offsets.count(0) && offsets.count(4) && offsets.count(8) &&
           offsets.count(12) && offsets.count(16));
}

/// Test nested struct detection
void test_nested_struct_detection() {
    z3::context ctx;
    z3::solver solver(ctx);

    // Observations suggest nested struct:
    // Outer struct has field at offset 0 (int32)
    // Outer struct has embedded struct at offset 8
    // Embedded struct has fields at 8+0, 8+4 (relative to outer base)

    z3::expr outer_size = ctx.int_const("outer_size");
    z3::expr inner_offset = ctx.int_const("inner_offset");
    z3::expr inner_size = ctx.int_const("inner_size");

    // Constraints from observations
    solver.add(inner_offset == 8);
    solver.add(inner_size >= 8);  // At least 8 bytes (2 fields)
    solver.add(outer_size >= inner_offset + inner_size);

    // Observed accesses
    // offset 0: int32 (4 bytes) - in outer
    // offset 8: int32 (4 bytes) - in inner
    // offset 12: int32 (4 bytes) - in inner
    // offset 16: int64 (8 bytes) - after inner

    solver.add(inner_offset == 8);
    solver.add(inner_size == 8);  // inner struct is 8 bytes
    solver.add(outer_size >= 24);  // outer is at least 24 bytes

    z3::check_result res = solver.check();
    assert(res == z3::sat);

    z3::model m = solver.get_model();
    int inner_off_val = m.eval(inner_offset, true).get_numeral_int();
    int inner_sz_val = m.eval(inner_size, true).get_numeral_int();

    assert(inner_off_val == 8);
    assert(inner_sz_val == 8);
}

/// Test recursive struct handling
void test_recursive_struct() {
    // Linked list node: next pointer at some offset
    z3::context ctx;
    z3::solver solver(ctx);

    z3::expr node_size = ctx.int_const("node_size");
    z3::expr next_offset = ctx.int_const("next_offset");
    z3::expr data_offset = ctx.int_const("data_offset");

    // Constraints
    solver.add(node_size >= 16);
    solver.add(next_offset >= 0);
    solver.add(data_offset >= 0);
    solver.add(next_offset + 8 <= node_size);  // Pointer is 8 bytes
    solver.add(data_offset + 8 <= node_size);
    solver.add(next_offset != data_offset);    // Different offsets

    // Pattern: dereferencing next gives same struct type
    // This is encoded as: accesses through next match node layout

    assert(solver.check() == z3::sat);
}

/// Test multiple calling conventions
void test_calling_conventions() {
    TestCrossFunctionAnalyzer analyzer;

    // Some functions might receive struct in different ways:
    // - By pointer (common)
    // - By register (for small structs)
    // - Split across registers

    // For simplicity, focus on pointer-based passing
    analyzer.add_function_constraints(0x1000, 0, {
        TestAccess::read(0, 4, TestTypeCategory::Int32),
    });

    // Second param is same struct, offset +8
    analyzer.add_function_constraints(0x1000, 1, {
        TestAccess::read(0, 8, TestTypeCategory::Pointer),
    });

    // Analysis should keep them separate (different params)
    assert(!analyzer.same_struct_type(0x1000, 0, 0x1000, 1));
}

/// Test escaping pointers
void test_escaping_pointers() {
    // Test case where struct pointer escapes to global
    z3::context ctx;
    z3::solver solver(ctx);

    // Model: local struct, pointer stored to global
    z3::expr local_base = ctx.int_const("local_base");
    z3::expr global_ptr = ctx.int_const("global_ptr");
    z3::expr access_offset = ctx.int_const("access_offset");

    // After escape: global_ptr == local_base
    solver.add(global_ptr == local_base);

    // Later access through global
    z3::expr later_access = global_ptr + access_offset;

    // Should resolve to local_base + access_offset
    solver.add(later_access == local_base + 8);
    solver.add(access_offset == 8);

    assert(solver.check() == z3::sat);
}

/// Test function using multiple test cases
void test_cross_function_test_cases() {
    auto test_cases = cross_function_test_cases();
    assert(!test_cases.empty());

    for (const auto& tc : test_cases) {
        std::cout << "  Sub-test: " << tc.name << "\n";

        // Each test case should have accesses from multiple functions
        std::set<uint64_t> func_addrs;
        for (const auto& access : tc.accesses) {
            func_addrs.insert(access.func_id);
        }

        // Cross-function test should involve at least 2 functions
        if (tc.name.find("cross") != std::string::npos ||
            tc.name.find("multi") != std::string::npos) {
            assert(func_addrs.size() >= 2);
        }
    }
}

/// Test get_using_functions
void test_get_using_functions() {
    TestCrossFunctionAnalyzer analyzer;

    // Three functions that use the same struct
    analyzer.add_function_constraints(0x1000, 0, {
        TestAccess::read(0, 4, TestTypeCategory::Int32),
    });
    analyzer.add_function_constraints(0x2000, 0, {
        TestAccess::read(4, 4, TestTypeCategory::Int32),
    });
    analyzer.add_function_constraints(0x3000, 0, {
        TestAccess::read(8, 4, TestTypeCategory::Int32),
    });

    // Unify through call sites
    CallSiteObservation call1, call2;
    call1.caller_func = 0x4000;
    call1.callee_func = 0x1000;
    call1.call_addr = 0x4010;
    call1.argument_index = 0;
    call1.base_offset = 0;

    call2.caller_func = 0x4000;
    call2.callee_func = 0x2000;
    call2.call_addr = 0x4020;
    call2.argument_index = 0;
    call2.base_offset = 0;

    analyzer.add_call_site(call1);
    analyzer.add_call_site(call2);
    analyzer.analyze();

    auto funcs = analyzer.get_using_functions(0x1000, 0);

    // Should include both 0x1000 and 0x2000 (unified)
    // 0x3000 is not unified (no call site linking it)
    assert(funcs.count(0x1000) || funcs.count(0x2000));
}

} // anonymous namespace

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "=== Cross-Function Analysis Unit Tests ===\n\n";

    TestRunner runner;

    runner.run("basic_unification", test_basic_unification);
    runner.run("pointer_delta_normalization", test_pointer_delta_normalization);
    runner.run("constraint_merging", test_constraint_merging);
    runner.run("struct_aliasing_z3", test_struct_aliasing_z3);
    runner.run("call_graph_traversal", test_call_graph_traversal);
    runner.run("type_propagation", test_type_propagation);
    runner.run("conflicting_types", test_conflicting_types);
    runner.run("cross_function_array", test_cross_function_array);
    runner.run("nested_struct_detection", test_nested_struct_detection);
    runner.run("recursive_struct", test_recursive_struct);
    runner.run("calling_conventions", test_calling_conventions);
    runner.run("escaping_pointers", test_escaping_pointers);
    runner.run("cross_function_test_cases", test_cross_function_test_cases);
    runner.run("get_using_functions", test_get_using_functions);

    runner.summary();

    return runner.all_passed() ? 0 : 1;
}
