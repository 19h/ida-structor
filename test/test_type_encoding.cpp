/**
 * @file test_type_encoding.cpp
 * @brief Unit tests for Z3 type encoding
 *
 * Tests the TypeEncoder class, including:
 * - Type sort creation and constants
 * - Type category encoding/decoding
 * - Type compatibility constraints
 * - Size-based type inference
 */

#include <cassert>
#include <iostream>
#include <chrono>
#include <vector>
#include <string>

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
        catch (...) {
            results_.emplace_back(name, false, "Unknown exception");
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
// Simulated TypeEncoder (matches the real implementation interface)
// ============================================================================

/// Type category enumeration (mirrors TypeCategory in type_encoding.hpp)
enum class TypeCategory {
    Unknown = 0,
    Int8, Int16, Int32, Int64,
    UInt8, UInt16, UInt32, UInt64,
    Float32, Float64,
    Pointer, FunctionPointer,
    Array, Struct, Union, RawBytes,
    COUNT
};

/// Simulated TypeEncoder for testing without IDA
class TestTypeEncoder {
public:
    explicit TestTypeEncoder(z3::context& ctx)
        : ctx_(ctx)
        , type_sort_(ctx)
        , type_consts_(ctx)
        , type_testers_(ctx) {
        init_type_sort();
    }

    /// Get the TypeSort
    z3::sort type_sort() const { return type_sort_; }

    /// Create a constant for a type category
    z3::expr type_const(TypeCategory cat) const {
        return type_consts_[static_cast<int>(cat)]();
    }

    /// Create a fresh type variable
    z3::expr fresh_type_var(const std::string& name) const {
        return ctx_.constant(name.c_str(), type_sort_);
    }

    /// Create constraint: type is compatible with size
    z3::expr size_type_constraint(const z3::expr& type_var, uint32_t size) const {
        z3::expr_vector compatible(ctx_);

        switch (size) {
            case 1:
                compatible.push_back(type_var == type_const(TypeCategory::Int8));
                compatible.push_back(type_var == type_const(TypeCategory::UInt8));
                break;
            case 2:
                compatible.push_back(type_var == type_const(TypeCategory::Int16));
                compatible.push_back(type_var == type_const(TypeCategory::UInt16));
                break;
            case 4:
                compatible.push_back(type_var == type_const(TypeCategory::Int32));
                compatible.push_back(type_var == type_const(TypeCategory::UInt32));
                compatible.push_back(type_var == type_const(TypeCategory::Float32));
                break;
            case 8:
                compatible.push_back(type_var == type_const(TypeCategory::Int64));
                compatible.push_back(type_var == type_const(TypeCategory::UInt64));
                compatible.push_back(type_var == type_const(TypeCategory::Float64));
                compatible.push_back(type_var == type_const(TypeCategory::Pointer));
                compatible.push_back(type_var == type_const(TypeCategory::FunctionPointer));
                break;
            default:
                // For other sizes, allow Array or RawBytes
                compatible.push_back(type_var == type_const(TypeCategory::Array));
                compatible.push_back(type_var == type_const(TypeCategory::RawBytes));
                break;
        }

        if (compatible.empty()) {
            return ctx_.bool_val(true);
        }

        return z3::mk_or(compatible);
    }

    /// Constraint: two types are compatible
    z3::expr types_compatible(const z3::expr& t1, const z3::expr& t2) const {
        // Same type is always compatible
        z3::expr same = (t1 == t2);

        // Unknown is compatible with anything
        z3::expr unknown = type_const(TypeCategory::Unknown);
        z3::expr either_unknown = (t1 == unknown) || (t2 == unknown);

        // Signed/unsigned int compatibility
        z3::expr int_compat = ctx_.bool_val(false);
        for (int i = 1; i <= 4; ++i) {  // Int8-Int64
            int signed_idx = i;
            int unsigned_idx = i + 4;
            z3::expr both_match =
                ((t1 == type_consts_[signed_idx]()) && (t2 == type_consts_[unsigned_idx]())) ||
                ((t1 == type_consts_[unsigned_idx]()) && (t2 == type_consts_[signed_idx]()));
            int_compat = int_compat || both_match;
        }

        return same || either_unknown || int_compat;
    }

    /// Decode type from model
    TypeCategory decode_type(const z3::model& model, const z3::expr& type_var) const {
        z3::expr val = model.eval(type_var, true);

        for (int i = 0; i < static_cast<int>(TypeCategory::COUNT); ++i) {
            z3::expr cat_val = type_consts_[i]();
            if (z3::eq(val, cat_val)) {
                return static_cast<TypeCategory>(i);
            }
        }

        return TypeCategory::Unknown;
    }

private:
    z3::context& ctx_;
    z3::sort type_sort_;
    z3::func_decl_vector type_consts_;
    z3::func_decl_vector type_testers_;

    void init_type_sort() {
        const char* names[] = {
            "Unknown",
            "Int8", "Int16", "Int32", "Int64",
            "UInt8", "UInt16", "UInt32", "UInt64",
            "Float32", "Float64",
            "Pointer", "FunctionPointer",
            "Array", "Struct", "Union", "RawBytes"
        };

        type_consts_ = z3::func_decl_vector(ctx_);
        type_testers_ = z3::func_decl_vector(ctx_);

        type_sort_ = ctx_.enumeration_sort(
            "TypeCategory",
            static_cast<unsigned>(TypeCategory::COUNT),
            names,
            type_consts_,
            type_testers_
        );
    }
};

// ============================================================================
// Type Encoding Tests
// ============================================================================

/// Test type sort creation
void test_type_sort_creation() {
    z3::context ctx;
    TestTypeEncoder encoder(ctx);

    z3::sort ts = encoder.type_sort();
    assert(!ts.is_int());  // Should be enumeration, not int
}

/// Test type constant creation
void test_type_constants() {
    z3::context ctx;
    TestTypeEncoder encoder(ctx);

    // Create constants for each type category
    z3::expr unknown = encoder.type_const(TypeCategory::Unknown);
    z3::expr int32 = encoder.type_const(TypeCategory::Int32);
    z3::expr ptr = encoder.type_const(TypeCategory::Pointer);

    // They should all have the same sort
    assert(unknown.get_sort().id() == encoder.type_sort().id());
    assert(int32.get_sort().id() == encoder.type_sort().id());
    assert(ptr.get_sort().id() == encoder.type_sort().id());

    // They should be different
    z3::solver solver(ctx);
    solver.add(unknown == int32);
    assert(solver.check() == z3::unsat);
}

/// Test type variable creation
void test_type_variables() {
    z3::context ctx;
    TestTypeEncoder encoder(ctx);

    z3::expr t1 = encoder.fresh_type_var("field_0_type");
    z3::expr t2 = encoder.fresh_type_var("field_4_type");

    // Should be of type sort
    assert(t1.get_sort().id() == encoder.type_sort().id());
    assert(t2.get_sort().id() == encoder.type_sort().id());

    // Should be able to constrain independently
    z3::solver solver(ctx);
    solver.add(t1 == encoder.type_const(TypeCategory::Int32));
    solver.add(t2 == encoder.type_const(TypeCategory::Pointer));

    assert(solver.check() == z3::sat);
}

/// Test size-type constraint for 1-byte
void test_size_constraint_1byte() {
    z3::context ctx;
    TestTypeEncoder encoder(ctx);
    z3::solver solver(ctx);

    z3::expr t = encoder.fresh_type_var("type");
    solver.add(encoder.size_type_constraint(t, 1));

    z3::check_result check = solver.check();
    assert(check == z3::sat);

    z3::model model = solver.get_model();
    TypeCategory result = encoder.decode_type(model, t);

    // Should be Int8 or UInt8
    assert(result == TypeCategory::Int8 || result == TypeCategory::UInt8);
}

/// Test size-type constraint for 4-byte
void test_size_constraint_4byte() {
    z3::context ctx;
    TestTypeEncoder encoder(ctx);
    z3::solver solver(ctx);

    z3::expr t = encoder.fresh_type_var("type");
    solver.add(encoder.size_type_constraint(t, 4));

    // Verify Int32 is possible
    solver.push();
    solver.add(t == encoder.type_const(TypeCategory::Int32));
    assert(solver.check() == z3::sat);
    solver.pop();

    // Verify Float32 is possible
    solver.push();
    solver.add(t == encoder.type_const(TypeCategory::Float32));
    assert(solver.check() == z3::sat);
    solver.pop();

    // Verify Int64 is NOT possible for 4-byte
    solver.push();
    solver.add(t == encoder.type_const(TypeCategory::Int64));
    assert(solver.check() == z3::unsat);
    solver.pop();
}

/// Test size-type constraint for 8-byte (pointer size)
void test_size_constraint_8byte() {
    z3::context ctx;
    TestTypeEncoder encoder(ctx);
    z3::solver solver(ctx);

    z3::expr t = encoder.fresh_type_var("type");
    solver.add(encoder.size_type_constraint(t, 8));

    // Verify Pointer is possible
    solver.push();
    solver.add(t == encoder.type_const(TypeCategory::Pointer));
    assert(solver.check() == z3::sat);
    solver.pop();

    // Verify FunctionPointer is possible
    solver.push();
    solver.add(t == encoder.type_const(TypeCategory::FunctionPointer));
    assert(solver.check() == z3::sat);
    solver.pop();

    // Verify Int64 is possible
    solver.push();
    solver.add(t == encoder.type_const(TypeCategory::Int64));
    assert(solver.check() == z3::sat);
    solver.pop();

    // Verify Float64 is possible
    solver.push();
    solver.add(t == encoder.type_const(TypeCategory::Float64));
    assert(solver.check() == z3::sat);
    solver.pop();
}

/// Test type compatibility - same types
void test_type_compat_same() {
    z3::context ctx;
    TestTypeEncoder encoder(ctx);
    z3::solver solver(ctx);

    z3::expr t1 = encoder.fresh_type_var("t1");
    z3::expr t2 = encoder.fresh_type_var("t2");

    // Force both to Int32
    solver.add(t1 == encoder.type_const(TypeCategory::Int32));
    solver.add(t2 == encoder.type_const(TypeCategory::Int32));

    // Should be compatible
    solver.add(encoder.types_compatible(t1, t2));
    assert(solver.check() == z3::sat);
}

/// Test type compatibility - signed/unsigned
void test_type_compat_signed_unsigned() {
    z3::context ctx;
    TestTypeEncoder encoder(ctx);
    z3::solver solver(ctx);

    z3::expr t1 = encoder.fresh_type_var("t1");
    z3::expr t2 = encoder.fresh_type_var("t2");

    // Force Int32 and UInt32
    solver.add(t1 == encoder.type_const(TypeCategory::Int32));
    solver.add(t2 == encoder.type_const(TypeCategory::UInt32));

    // Should be compatible
    solver.add(encoder.types_compatible(t1, t2));
    assert(solver.check() == z3::sat);
}

/// Test type compatibility - unknown is compatible with anything
void test_type_compat_unknown() {
    z3::context ctx;
    TestTypeEncoder encoder(ctx);
    z3::solver solver(ctx);

    z3::expr t1 = encoder.fresh_type_var("t1");
    z3::expr t2 = encoder.fresh_type_var("t2");

    // t1 is Unknown, t2 is arbitrary
    solver.add(t1 == encoder.type_const(TypeCategory::Unknown));
    solver.add(t2 == encoder.type_const(TypeCategory::FunctionPointer));

    // Should be compatible
    solver.add(encoder.types_compatible(t1, t2));
    assert(solver.check() == z3::sat);
}

/// Test type compatibility - incompatible types
void test_type_compat_incompatible() {
    z3::context ctx;
    TestTypeEncoder encoder(ctx);
    z3::solver solver(ctx);

    z3::expr t1 = encoder.fresh_type_var("t1");
    z3::expr t2 = encoder.fresh_type_var("t2");

    // Force Int32 and Float32 (different categories, same size)
    solver.add(t1 == encoder.type_const(TypeCategory::Int32));
    solver.add(t2 == encoder.type_const(TypeCategory::Float32));

    // In strict mode, these are NOT compatible
    solver.add(!encoder.types_compatible(t1, t2));
    assert(solver.check() == z3::sat);  // SAT because they ARE different
}

/// Test type decoding from model
void test_type_decode() {
    z3::context ctx;
    TestTypeEncoder encoder(ctx);
    z3::solver solver(ctx);

    z3::expr t = encoder.fresh_type_var("type");
    solver.add(t == encoder.type_const(TypeCategory::Pointer));

    z3::check_result check = solver.check();
    assert(check == z3::sat);

    z3::model model = solver.get_model();
    TypeCategory decoded = encoder.decode_type(model, t);

    assert(decoded == TypeCategory::Pointer);
}

/// Test multiple fields with type constraints
void test_multi_field_types() {
    z3::context ctx;
    TestTypeEncoder encoder(ctx);
    z3::solver solver(ctx);

    // Simulate a struct with fields at offsets 0, 4, 8
    z3::expr t0 = encoder.fresh_type_var("field_0_type");
    z3::expr t4 = encoder.fresh_type_var("field_4_type");
    z3::expr t8 = encoder.fresh_type_var("field_8_type");

    // Size constraints
    solver.add(encoder.size_type_constraint(t0, 4));  // 4-byte field
    solver.add(encoder.size_type_constraint(t4, 4));  // 4-byte field
    solver.add(encoder.size_type_constraint(t8, 8));  // 8-byte field

    // Specific hints from accesses
    solver.add(t0 == encoder.type_const(TypeCategory::Int32));
    solver.add(t8 == encoder.type_const(TypeCategory::Pointer));

    z3::check_result check = solver.check();
    assert(check == z3::sat);

    z3::model model = solver.get_model();

    TypeCategory t0_result = encoder.decode_type(model, t0);
    TypeCategory t4_result = encoder.decode_type(model, t4);
    TypeCategory t8_result = encoder.decode_type(model, t8);

    assert(t0_result == TypeCategory::Int32);
    assert(t8_result == TypeCategory::Pointer);
    // t4 can be any 4-byte type
    assert(t4_result == TypeCategory::Int32 ||
           t4_result == TypeCategory::UInt32 ||
           t4_result == TypeCategory::Float32);
}

/// Test type hint propagation
void test_type_hint_propagation() {
    z3::context ctx;
    TestTypeEncoder encoder(ctx);
    z3::solver solver(ctx);

    // Same field accessed with different hints in different functions
    z3::expr t = encoder.fresh_type_var("field_type");

    // Hint 1: Unknown (func1)
    // Hint 2: Int32 (func2)
    // Result should prefer Int32 (more specific)

    solver.add(encoder.size_type_constraint(t, 4));

    // Soft preference for Int32
    z3::expr prefer_int32 = (t == encoder.type_const(TypeCategory::Int32));
    // This could be implemented with weighted soft constraints in practice

    // For now, just verify Int32 is valid
    solver.add(t == encoder.type_const(TypeCategory::Int32));
    assert(solver.check() == z3::sat);
}

} // anonymous namespace

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "=== Type Encoding Unit Tests ===\n\n";

    TestRunner runner;

    runner.run("type_sort_creation", test_type_sort_creation);
    runner.run("type_constants", test_type_constants);
    runner.run("type_variables", test_type_variables);
    runner.run("size_constraint_1byte", test_size_constraint_1byte);
    runner.run("size_constraint_4byte", test_size_constraint_4byte);
    runner.run("size_constraint_8byte", test_size_constraint_8byte);
    runner.run("type_compat_same", test_type_compat_same);
    runner.run("type_compat_signed_unsigned", test_type_compat_signed_unsigned);
    runner.run("type_compat_unknown", test_type_compat_unknown);
    runner.run("type_compat_incompatible", test_type_compat_incompatible);
    runner.run("type_decode", test_type_decode);
    runner.run("multi_field_types", test_multi_field_types);
    runner.run("type_hint_propagation", test_type_hint_propagation);

    runner.summary();

    return runner.all_passed() ? 0 : 1;
}
