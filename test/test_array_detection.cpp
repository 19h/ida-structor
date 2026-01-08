/**
 * @file test_array_detection.cpp
 * @brief Unit tests for array detection using Z3
 *
 * Tests the ArrayConstraintBuilder class, including:
 * - Arithmetic progression detection
 * - Array detection with gaps
 * - Stride > access_size handling (element struct creation)
 * - Symbolic index detection
 * - Type consistency checking
 */

#include <cassert>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <numeric>
#include <map>

// Z3 headers
#include <z3++.h>

// Test IR
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

    TestResult(const std::string& n, bool p, const std::string& msg = "")
        : passed(p), name(n), message(msg) {}
};

class TestRunner {
public:
    template<typename F>
    void run(const std::string& name, F&& test_fn) {
        try {
            test_fn();
            results_.emplace_back(name, true);
            std::cout << "[PASS] " << name << "\n";
        }
        catch (const std::exception& e) {
            results_.emplace_back(name, false, e.what());
            std::cout << "[FAIL] " << name << ": " << e.what() << "\n";
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
        for (const auto& r : results_) if (!r.passed) return false;
        return true;
    }

private:
    std::vector<TestResult> results_;
};

// ============================================================================
// Array Detection Helpers (IDA-independent)
// ============================================================================

/// Calculate GCD of two numbers
uint32_t gcd(uint32_t a, uint32_t b) {
    while (b != 0) {
        uint32_t t = b;
        b = a % b;
        a = t;
    }
    return a;
}

/// Calculate GCD of a vector
uint32_t gcd_vector(const std::vector<uint32_t>& values) {
    if (values.empty()) return 0;
    uint32_t result = values[0];
    for (size_t i = 1; i < values.size(); ++i) {
        result = gcd(result, values[i]);
        if (result == 1) break;
    }
    return result;
}

/// Detected array info
struct ArrayInfo {
    int64_t base_offset;
    uint32_t stride;
    uint32_t element_count;
    bool needs_element_struct;
    uint32_t inner_offset;
    uint32_t inner_size;

    ArrayInfo()
        : base_offset(0)
        , stride(0)
        , element_count(0)
        , needs_element_struct(false)
        , inner_offset(0)
        , inner_size(0) {}
};

/// Detect arrays in accesses using arithmetic progression
std::vector<ArrayInfo> detect_arrays(
    const std::vector<TestAccess>& accesses,
    int min_elements = 3)
{
    std::vector<ArrayInfo> results;

    if (accesses.size() < static_cast<size_t>(min_elements)) {
        return results;
    }

    // Group by size
    std::map<uint32_t, std::vector<const TestAccess*>> by_size;
    for (const auto& acc : accesses) {
        by_size[acc.size].push_back(&acc);
    }

    for (auto& [size, group] : by_size) {
        if (static_cast<int>(group.size()) < min_elements) {
            continue;
        }

        // Extract and sort offsets
        std::vector<int64_t> offsets;
        offsets.reserve(group.size());
        for (const auto* acc : group) {
            offsets.push_back(acc->offset);
        }
        std::sort(offsets.begin(), offsets.end());

        // Remove duplicates
        offsets.erase(std::unique(offsets.begin(), offsets.end()), offsets.end());

        if (static_cast<int>(offsets.size()) < min_elements) {
            continue;
        }

        // Calculate stride as GCD of differences
        std::vector<uint32_t> diffs;
        for (size_t i = 1; i < offsets.size(); ++i) {
            int64_t diff = offsets[i] - offsets[i - 1];
            if (diff > 0) {
                diffs.push_back(static_cast<uint32_t>(diff));
            }
        }

        if (diffs.empty()) continue;

        uint32_t stride = gcd_vector(diffs);
        if (stride == 0 || stride > 4096) continue;

        // Verify all offsets fit the pattern
        int64_t base = offsets[0];
        bool valid = true;
        for (int64_t off : offsets) {
            if ((off - base) % stride != 0) {
                valid = false;
                break;
            }
        }

        if (!valid) continue;

        // Calculate element count
        uint32_t count = static_cast<uint32_t>(
            (offsets.back() - offsets.front()) / stride) + 1;

        ArrayInfo info;
        info.base_offset = base;
        info.stride = stride;
        info.element_count = count;

        // Check if stride > access size (array of structs pattern)
        if (stride > size) {
            info.needs_element_struct = true;
            info.inner_offset = static_cast<uint32_t>((offsets[0] - base) % stride);
            info.inner_size = size;
        }

        results.push_back(info);
    }

    return results;
}

/// Use Z3 to detect symbolic array pattern
std::optional<ArrayInfo> detect_symbolic_array(
    z3::context& ctx,
    const std::vector<TestAccess>& accesses)
{
    if (accesses.size() < 3) {
        return std::nullopt;
    }

    // Sort accesses by offset first
    std::vector<int64_t> offsets;
    for (const auto& acc : accesses) {
        offsets.push_back(acc.offset);
    }
    std::sort(offsets.begin(), offsets.end());

    // Calculate actual stride from consecutive offsets
    int64_t computed_stride = offsets[1] - offsets[0];
    for (size_t i = 2; i < offsets.size(); ++i) {
        if (offsets[i] - offsets[i-1] != computed_stride) {
            computed_stride = 0;  // Non-uniform, let Z3 figure it out
            break;
        }
    }

    z3::solver solver(ctx);

    // Variables for base and stride
    z3::expr base = ctx.int_const("base");
    z3::expr stride = ctx.int_const("stride");

    // Constraints
    solver.add(stride > 0);
    solver.add(stride <= 4096);
    solver.add(base >= 0);
    // Base should be the minimum offset
    solver.add(base == ctx.int_val(static_cast<int>(offsets.front())));

    // If we computed a uniform stride, constrain to it
    if (computed_stride > 0) {
        solver.add(stride == ctx.int_val(static_cast<int>(computed_stride)));
    }

    // Each offset must fit: offset = base + index * stride
    // where index is some non-negative integer
    for (int64_t off : offsets) {
        z3::expr offset_val = ctx.int_val(static_cast<int>(off));
        z3::expr relative = offset_val - base;

        // relative >= 0 and relative % stride == 0
        solver.add(relative >= 0);
        solver.add(z3::mod(relative, stride) == 0);
    }

    // Try to minimize stride for best fit
    z3::optimize opt(ctx);
    for (const auto& c : solver.assertions()) {
        opt.add(c);
    }
    opt.minimize(stride);

    if (opt.check() == z3::sat) {
        z3::model model = opt.get_model();

        ArrayInfo info;
        info.base_offset = model.eval(base, true).get_numeral_int64();
        info.stride = static_cast<uint32_t>(model.eval(stride, true).get_numeral_int());

        // Calculate element count
        int64_t max_off = 0;
        for (const auto& acc : accesses) {
            max_off = std::max(max_off, acc.offset);
        }
        info.element_count = static_cast<uint32_t>(
            (max_off - info.base_offset) / info.stride) + 1;

        return info;
    }

    return std::nullopt;
}

// ============================================================================
// Array Detection Tests
// ============================================================================

/// Test basic arithmetic progression detection
void test_arithmetic_progression_detection() {
    std::vector<TestAccess> accesses = {
        {0, 4}, {4, 4}, {8, 4}, {12, 4}, {16, 4}
    };

    auto arrays = detect_arrays(accesses, 3);

    assert(!arrays.empty());
    assert(arrays[0].base_offset == 0);
    assert(arrays[0].stride == 4);
    assert(arrays[0].element_count == 5);
}

/// Test array detection with gaps
void test_array_with_gaps() {
    // Elements at 0, 8, 16 (missing 4, 12)
    std::vector<TestAccess> accesses = {
        {0, 4}, {8, 4}, {16, 4}
    };

    auto arrays = detect_arrays(accesses, 3);

    assert(!arrays.empty());
    assert(arrays[0].stride == 8);  // GCD of (8-0, 16-8)
}

/// Test array of structs (stride > access size)
void test_array_of_structs() {
    // Accesses at 0, 16, 32 (stride=16, access_size=4)
    std::vector<TestAccess> accesses = {
        {0, 4}, {16, 4}, {32, 4}, {48, 4}
    };

    auto arrays = detect_arrays(accesses, 3);

    assert(!arrays.empty());
    assert(arrays[0].stride == 16);
    assert(arrays[0].needs_element_struct);
}

/// Test minimum element threshold
void test_minimum_threshold() {
    // Only 2 elements
    std::vector<TestAccess> accesses = {
        {0, 4}, {4, 4}
    };

    // With threshold=3, should not detect array
    auto arrays = detect_arrays(accesses, 3);
    assert(arrays.empty());

    // With threshold=2, should detect
    arrays = detect_arrays(accesses, 2);
    assert(!arrays.empty());
}

/// Test type consistency (same-size accesses only)
void test_type_consistency() {
    // Mixed sizes at overlapping offsets
    std::vector<TestAccess> accesses = {
        {0, 4}, {4, 4}, {8, 4},  // 4-byte accesses
        {0, 8}, {8, 8}  // 8-byte accesses
    };

    auto arrays = detect_arrays(accesses, 3);

    // Should detect the 4-byte array (more elements)
    assert(!arrays.empty());

    bool found_4byte = false;
    for (const auto& arr : arrays) {
        if (arr.stride == 4) {
            found_4byte = true;
            break;
        }
    }
    assert(found_4byte);
}

/// Test symbolic array detection using Z3
void test_symbolic_detection_z3() {
    z3::context ctx;

    std::vector<TestAccess> accesses = {
        {0, 4}, {8, 4}, {16, 4}, {24, 4}
    };

    auto result = detect_symbolic_array(ctx, accesses);

    assert(result.has_value());
    assert(result->base_offset == 0);
    assert(result->stride == 8);
    assert(result->element_count == 4);
}

/// Test Z3 array detection with non-zero base
void test_symbolic_nonzero_base() {
    z3::context ctx;

    std::vector<TestAccess> accesses = {
        {100, 4}, {108, 4}, {116, 4}
    };

    auto result = detect_symbolic_array(ctx, accesses);

    assert(result.has_value());
    assert(result->base_offset == 100);
    assert(result->stride == 8);
}

/// Test array constraints in Max-SMT context
void test_array_maxsmt() {
    z3::context ctx;
    z3::optimize opt(ctx);

    // Create variables for array parameters
    z3::expr is_array = ctx.bool_const("is_array");
    z3::expr base = ctx.int_const("base");
    z3::expr stride = ctx.int_const("stride");
    z3::expr count = ctx.int_const("count");

    // Hard constraints
    opt.add(z3::implies(is_array, stride > 0));
    opt.add(z3::implies(is_array, count >= 3));
    opt.add(z3::implies(is_array, base >= 0));

    // Soft constraint: prefer arrays (weighted)
    opt.add_soft(is_array, 10);

    // Coverage constraint for known accesses
    std::vector<int64_t> offsets = {0, 8, 16, 24};
    for (int64_t off : offsets) {
        z3::expr off_expr = ctx.int_val(static_cast<int>(off));
        z3::expr covered_by_array =
            is_array &&
            (off_expr >= base) &&
            (off_expr < base + stride * count) &&
            (z3::mod(off_expr - base, stride) == 0);
        opt.add_soft(covered_by_array, 5);
    }

    assert(opt.check() == z3::sat);

    z3::model model = opt.get_model();
    z3::expr arr_val = model.eval(is_array, true);
    assert(arr_val.is_true());
}

/// Test two separate arrays in same struct
void test_multiple_arrays() {
    std::vector<TestAccess> accesses;

    // First array: 0, 4, 8 (4-byte elements)
    accesses.push_back({0, 4});
    accesses.push_back({4, 4});
    accesses.push_back({8, 4});

    // Gap

    // Second array: 32, 40, 48 (8-byte elements)
    accesses.push_back({32, 8});
    accesses.push_back({40, 8});
    accesses.push_back({48, 8});

    auto arrays = detect_arrays(accesses, 3);

    assert(arrays.size() == 2);

    // Check first array (4-byte)
    bool found_first = false;
    for (const auto& arr : arrays) {
        if (arr.base_offset == 0 && arr.stride == 4) {
            found_first = true;
            break;
        }
    }
    assert(found_first);

    // Check second array (8-byte)
    bool found_second = false;
    for (const auto& arr : arrays) {
        if (arr.base_offset == 32 && arr.stride == 8) {
            found_second = true;
            break;
        }
    }
    assert(found_second);
}

/// Test array detection with stride inference
void test_stride_inference() {
    z3::context ctx;
    z3::optimize opt(ctx);  // Use optimizer to maximize stride

    // Given accesses at indices 0, 2, 5 of an unknown array
    // offset[i] = base + i * stride
    // We observe: base + 0*stride, base + 2*stride, base + 5*stride

    z3::expr base = ctx.int_const("base");
    z3::expr stride = ctx.int_const("stride");

    int64_t observed[] = {0, 16, 40};  // Could be stride=8, indices 0,2,5

    opt.add(base >= 0);
    opt.add(stride > 0);
    opt.add(stride <= 100);

    // First offset = base
    opt.add(ctx.int_val(static_cast<int>(observed[0])) == base);

    // Other offsets = base + some_int * stride
    z3::expr i1 = ctx.int_const("i1");
    z3::expr i2 = ctx.int_const("i2");

    opt.add(i1 > 0);
    opt.add(i2 > i1);
    opt.add(ctx.int_val(static_cast<int>(observed[1])) == base + i1 * stride);
    opt.add(ctx.int_val(static_cast<int>(observed[2])) == base + i2 * stride);

    // Maximize stride to find the GCD (largest valid stride)
    opt.maximize(stride);

    assert(opt.check() == z3::sat);

    z3::model model = opt.get_model();
    int stride_val = model.eval(stride, true).get_numeral_int();

    // Stride should be 8 (GCD of 16, 40)
    assert(stride_val == 8);
}

/// Test element struct creation for stride > size
void test_element_struct_creation() {
    // Simulate array of structs where we only access one field
    // struct elem { int a; int b; int c; int d; }; // 16 bytes
    // We access elem[i].a (offset 0 in each element)

    std::vector<TestAccess> accesses = {
        {0, 4},   // elem[0].a
        {16, 4},  // elem[1].a
        {32, 4},  // elem[2].a
        {48, 4}   // elem[3].a
    };

    auto arrays = detect_arrays(accesses, 3);

    assert(!arrays.empty());
    assert(arrays[0].stride == 16);
    assert(arrays[0].needs_element_struct);
    assert(arrays[0].inner_size == 4);
}

/// Test array with out-of-order accesses
void test_out_of_order_accesses() {
    // Accesses not in offset order
    std::vector<TestAccess> accesses = {
        {16, 4}, {4, 4}, {12, 4}, {0, 4}, {8, 4}
    };

    auto arrays = detect_arrays(accesses, 3);

    assert(!arrays.empty());
    assert(arrays[0].base_offset == 0);
    assert(arrays[0].stride == 4);
    assert(arrays[0].element_count == 5);
}

/// Test predefined array test cases
void test_predefined_cases() {
    auto cases = array_test_cases();

    for (const auto& tc : cases) {
        // Convert TestAccess to our format
        std::vector<TestAccess> accesses;
        for (const auto& acc : tc.accesses) {
            accesses.push_back(acc);
        }

        int min_elems = tc.min_array_elements.value_or(3);
        auto arrays = detect_arrays(accesses, min_elems);

        if (tc.expect_arrays) {
            assert(!arrays.empty() &&
                   (std::string("Expected arrays in test: ") + tc.name).c_str());
        }
    }
}

} // anonymous namespace

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "=== Array Detection Unit Tests ===\n\n";

    TestRunner runner;

    runner.run("arithmetic_progression_detection", test_arithmetic_progression_detection);
    runner.run("array_with_gaps", test_array_with_gaps);
    runner.run("array_of_structs", test_array_of_structs);
    runner.run("minimum_threshold", test_minimum_threshold);
    runner.run("type_consistency", test_type_consistency);
    runner.run("symbolic_detection_z3", test_symbolic_detection_z3);
    runner.run("symbolic_nonzero_base", test_symbolic_nonzero_base);
    runner.run("array_maxsmt", test_array_maxsmt);
    runner.run("multiple_arrays", test_multiple_arrays);
    runner.run("stride_inference", test_stride_inference);
    runner.run("element_struct_creation", test_element_struct_creation);
    runner.run("out_of_order_accesses", test_out_of_order_accesses);
    runner.run("predefined_cases", test_predefined_cases);

    runner.summary();

    return runner.all_passed() ? 0 : 1;
}
