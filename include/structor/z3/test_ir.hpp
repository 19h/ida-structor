#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <optional>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <memory>

namespace structor::z3::test {

// ============================================================================
// Test IR Types (IDA-independent for unit testing)
// ============================================================================

/// Type category for test cases (mirrors z3::TypeCategory)
enum class TestTypeCategory {
    Unknown = 0,
    Int8,
    Int16,
    Int32,
    Int64,
    UInt8,
    UInt16,
    UInt32,
    UInt64,
    Float32,
    Float64,
    Pointer,
    FunctionPointer,
    Array,
    Struct,
    Union,
    RawBytes
};

/// Access type for test cases
enum class TestAccessType {
    Unknown = 0,
    Read,
    Write,
    ReadWrite,
    Call,
    AddressTaken
};

/// Minimal access representation for testing (no IDA types)
struct TestAccess {
    int64_t offset;
    uint32_t size;
    TestTypeCategory type_hint;     // Type hint from "decompiler"
    TestTypeCategory type_category; // Alias for type_hint (compatibility)
    TestAccessType access_type;     // Kind of access
    int func_id;                    // Function identifier for cross-function tests
    int64_t delta;                  // Pointer delta for this function
    std::string context;            // Optional context string for debugging

    TestAccess()
        : offset(0)
        , size(0)
        , type_hint(TestTypeCategory::Unknown)
        , type_category(TestTypeCategory::Unknown)
        , access_type(TestAccessType::Unknown)
        , func_id(0)
        , delta(0) {}

    TestAccess(int64_t off, uint32_t sz,
               TestTypeCategory hint = TestTypeCategory::Unknown,
               int fid = 0, int64_t d = 0)
        : offset(off)
        , size(sz)
        , type_hint(hint)
        , type_category(hint)
        , access_type(TestAccessType::Unknown)
        , func_id(fid)
        , delta(d) {}

    /// Factory for read access
    static TestAccess read(int64_t off, uint32_t sz,
                           TestTypeCategory cat = TestTypeCategory::Unknown) {
        TestAccess acc(off, sz, cat);
        acc.access_type = TestAccessType::Read;
        return acc;
    }

    /// Factory for write access
    static TestAccess write(int64_t off, uint32_t sz,
                            TestTypeCategory cat = TestTypeCategory::Unknown) {
        TestAccess acc(off, sz, cat);
        acc.access_type = TestAccessType::Write;
        return acc;
    }

    /// Convenience: check if this overlaps another access
    [[nodiscard]] bool overlaps(const TestAccess& other) const noexcept {
        if (offset >= other.offset + static_cast<int64_t>(other.size)) return false;
        if (other.offset >= offset + static_cast<int64_t>(size)) return false;
        return true;
    }
};

/// Expected field in test output
struct ExpectedField {
    int64_t offset;
    uint32_t size;
    TestTypeCategory type;
    bool is_array;
    uint32_t array_count;
    bool is_union;
    std::vector<ExpectedField> union_members;
    std::string name;           // Optional expected name

    ExpectedField()
        : offset(0)
        , size(0)
        , type(TestTypeCategory::Unknown)
        , is_array(false)
        , array_count(1)
        , is_union(false) {}

    ExpectedField(int64_t off, uint32_t sz)
        : offset(off)
        , size(sz)
        , type(TestTypeCategory::Unknown)
        , is_array(false)
        , array_count(1)
        , is_union(false) {}

    /// Create an array field expectation
    static ExpectedField array(int64_t off, uint32_t elem_size, uint32_t count) {
        ExpectedField f;
        f.offset = off;
        f.size = elem_size * count;
        f.is_array = true;
        f.array_count = count;
        return f;
    }

    /// Create a union field expectation
    static ExpectedField union_field(int64_t off, std::vector<ExpectedField> members) {
        ExpectedField f;
        f.offset = off;
        f.is_union = true;
        f.union_members = std::move(members);

        // Union size is max of members
        uint32_t max_size = 0;
        for (const auto& m : f.union_members) {
            max_size = std::max(max_size, m.size);
        }
        f.size = max_size;

        return f;
    }
};

/// Test case definition
struct TestCase {
    std::string name;
    std::string description;
    std::vector<TestAccess> accesses;
    std::vector<ExpectedField> expected_fields;
    bool expect_sat;
    bool expect_arrays;
    bool expect_unions;
    std::optional<uint32_t> expected_packing;
    std::optional<uint32_t> expected_struct_size;
    int expected_field_count;

    // Configuration overrides for this test
    std::optional<unsigned> timeout_ms;
    std::optional<int> min_array_elements;
    std::optional<bool> allow_unions;

    TestCase()
        : expect_sat(true)
        , expect_arrays(false)
        , expect_unions(false)
        , expected_field_count(-1) {}

    /// Convenience getter for expected_struct_size (returns default if not set)
    [[nodiscard]] uint32_t expected_size() const {
        return expected_struct_size.value_or(compute_expected_size());
    }

private:
    /// Compute expected size from accesses if not explicitly set
    [[nodiscard]] uint32_t compute_expected_size() const {
        uint32_t max_end = 0;
        for (const auto& acc : accesses) {
            max_end = std::max(max_end, static_cast<uint32_t>(acc.offset + acc.size));
        }
        // Round up to alignment (8 bytes)
        return ((max_end + 7) / 8) * 8;
    }

public:

    /// Add an access to the test case
    TestCase& add(int64_t off, uint32_t sz, TestTypeCategory hint = TestTypeCategory::Unknown) {
        accesses.emplace_back(off, sz, hint);
        return *this;
    }

    /// Add an access with function ID and delta
    TestCase& add_cross_func(int64_t off, uint32_t sz, int func_id, int64_t delta = 0) {
        TestAccess acc(off, sz, TestTypeCategory::Unknown, func_id, delta);
        accesses.push_back(acc);
        return *this;
    }

    /// Set expected field
    TestCase& expect(int64_t off, uint32_t sz) {
        expected_fields.emplace_back(off, sz);
        return *this;
    }

    /// Expect an array field
    TestCase& expect_array(int64_t off, uint32_t elem_size, uint32_t count) {
        expected_fields.push_back(ExpectedField::array(off, elem_size, count));
        expect_arrays = true;
        return *this;
    }

    /// Expect a union
    TestCase& expect_union(int64_t off, std::vector<ExpectedField> members) {
        expected_fields.push_back(ExpectedField::union_field(off, std::move(members)));
        expect_unions = true;
        return *this;
    }
};

// ============================================================================
// Test Fixture Builder
// ============================================================================

/// Builder for constructing test cases fluently
class TestCaseBuilder {
public:
    explicit TestCaseBuilder(const std::string& name)
        : case_(std::make_unique<TestCase>()) {
        case_->name = name;
    }

    TestCaseBuilder& description(const std::string& desc) {
        case_->description = desc;
        return *this;
    }

    TestCaseBuilder& access(int64_t off, uint32_t sz,
                            TestTypeCategory hint = TestTypeCategory::Unknown) {
        case_->add(off, sz, hint);
        return *this;
    }

    TestCaseBuilder& access_read(int64_t off, uint32_t sz) {
        TestAccess acc(off, sz);
        acc.access_type = TestAccessType::Read;
        case_->accesses.push_back(acc);
        return *this;
    }

    TestCaseBuilder& access_write(int64_t off, uint32_t sz) {
        TestAccess acc(off, sz);
        acc.access_type = TestAccessType::Write;
        case_->accesses.push_back(acc);
        return *this;
    }

    TestCaseBuilder& access_call(int64_t off, uint32_t sz) {
        TestAccess acc(off, sz);
        acc.access_type = TestAccessType::Call;
        case_->accesses.push_back(acc);
        return *this;
    }

    TestCaseBuilder& cross_func_access(int64_t off, uint32_t sz,
                                       int func_id, int64_t delta = 0) {
        case_->add_cross_func(off, sz, func_id, delta);
        return *this;
    }

    TestCaseBuilder& expect_field(int64_t off, uint32_t sz) {
        case_->expect(off, sz);
        return *this;
    }

    TestCaseBuilder& expect_array_field(int64_t off, uint32_t elem_size, uint32_t count) {
        case_->expect_array(off, elem_size, count);
        return *this;
    }

    TestCaseBuilder& expect_union_field(int64_t off, std::vector<ExpectedField> members) {
        case_->expect_union(off, std::move(members));
        return *this;
    }

    TestCaseBuilder& expect_sat(bool sat = true) {
        case_->expect_sat = sat;
        return *this;
    }

    TestCaseBuilder& expect_unsat() {
        case_->expect_sat = false;
        return *this;
    }

    TestCaseBuilder& expect_arrays(bool has_arrays = true) {
        case_->expect_arrays = has_arrays;
        return *this;
    }

    TestCaseBuilder& expect_unions(bool has_unions = true) {
        case_->expect_unions = has_unions;
        return *this;
    }

    TestCaseBuilder& expect_packing(uint32_t packing) {
        case_->expected_packing = packing;
        return *this;
    }

    TestCaseBuilder& expect_struct_size(uint32_t size) {
        case_->expected_struct_size = size;
        return *this;
    }

    TestCaseBuilder& expect_field_count(int count) {
        case_->expected_field_count = count;
        return *this;
    }

    TestCaseBuilder& with_timeout(unsigned ms) {
        case_->timeout_ms = ms;
        return *this;
    }

    TestCaseBuilder& with_min_array_elements(int count) {
        case_->min_array_elements = count;
        return *this;
    }

    TestCaseBuilder& with_unions_disabled() {
        case_->allow_unions = false;
        return *this;
    }

    [[nodiscard]] TestCase build() {
        return std::move(*case_);
    }

private:
    std::unique_ptr<TestCase> case_;
};

/// Start building a test case
inline TestCaseBuilder test_case(const std::string& name) {
    return TestCaseBuilder(name);
}

// ============================================================================
// Predefined Test Cases
// ============================================================================

/// Standard test cases for constraint validation
inline std::vector<TestCase> standard_test_cases() {
    std::vector<TestCase> cases;

    // Basic struct with two fields
    cases.push_back(
        test_case("basic_two_fields")
            .description("Simple struct with two integer fields")
            .access(0, 4, TestTypeCategory::Int32)
            .access(4, 4, TestTypeCategory::Int32)
            .expect_field(0, 4)
            .expect_field(4, 4)
            .expect_struct_size(8)
            .build()
    );

    // Struct with pointer
    cases.push_back(
        test_case("field_with_pointer")
            .description("Struct with integer and pointer")
            .access(0, 4, TestTypeCategory::Int32)
            .access(8, 8, TestTypeCategory::Pointer)
            .expect_field(0, 4)
            .expect_field(8, 8)
            .build()
    );

    // Array detection
    cases.push_back(
        test_case("array_detection_5_elements")
            .description("Array of 5 int32_t elements")
            .access(0, 4, TestTypeCategory::Int32)
            .access(4, 4, TestTypeCategory::Int32)
            .access(8, 4, TestTypeCategory::Int32)
            .access(12, 4, TestTypeCategory::Int32)
            .access(16, 4, TestTypeCategory::Int32)
            .expect_arrays()
            .expect_array_field(0, 4, 5)
            .build()
    );

    // Overlapping accesses (union candidate)
    cases.push_back(
        test_case("overlapping_accesses_union")
            .description("Same offset accessed with different sizes")
            .access(0, 4, TestTypeCategory::Int32)
            .access(0, 8, TestTypeCategory::Int64)
            .expect_unions()
            .build()
    );

    // Cross-function with delta
    cases.push_back(
        test_case("cross_function_delta")
            .description("Cross-function access with pointer delta")
            .cross_func_access(0, 4, 1, 0)     // func1: *(ptr + 0)
            .cross_func_access(16, 4, 2, 16)   // func2: *(ptr + 16), where ptr = orig - 16
            .expect_field(0, 4)
            .build()
    );

    // Alignment inference
    cases.push_back(
        test_case("alignment_inference")
            .description("Infer 4-byte packing from layout")
            .access(0, 1, TestTypeCategory::Int8)
            .access(4, 4, TestTypeCategory::Int32)
            .expect_packing(4)
            .build()
    );

    // Gap in struct (padding)
    cases.push_back(
        test_case("struct_with_gap")
            .description("Struct with gap requiring padding")
            .access(0, 4, TestTypeCategory::Int32)
            .access(16, 8, TestTypeCategory::Pointer)
            .expect_field(0, 4)
            .expect_field(16, 8)
            .expect_struct_size(24)
            .build()
    );

    // Function pointer access
    cases.push_back(
        test_case("function_pointer_field")
            .description("Field accessed as function pointer (vtable-like)")
            .access_call(0, 8)
            .expect_field(0, 8)
            .build()
    );

    // Many fields for stress testing
    cases.push_back(
        test_case("many_fields")
            .description("Struct with many fields")
            .access(0, 4)
            .access(4, 4)
            .access(8, 4)
            .access(12, 4)
            .access(16, 8)
            .access(24, 8)
            .access(32, 4)
            .access(36, 4)
            .expect_field_count(8)
            .build()
    );

    return cases;
}

/// Array detection test cases
inline std::vector<TestCase> array_test_cases() {
    std::vector<TestCase> cases;

    // Perfect array (no gaps)
    cases.push_back(
        test_case("perfect_array")
            .description("Perfect array with no gaps")
            .access(0, 4).access(4, 4).access(8, 4).access(12, 4).access(16, 4)
            .expect_arrays()
            .expect_array_field(0, 4, 5)
            .build()
    );

    // Array with gaps
    cases.push_back(
        test_case("array_with_gaps")
            .description("Array with missing elements")
            .access(0, 4).access(8, 4).access(16, 4)  // Missing elements 1, 3
            .expect_arrays()
            .build()
    );

    // Array of structs (stride > element size)
    cases.push_back(
        test_case("array_of_structs")
            .description("Array of structs with stride > access size")
            .access(0, 4).access(16, 4).access(32, 4).access(48, 4)
            .expect_arrays()
            .build()
    );

    // Two separate arrays
    cases.push_back(
        test_case("two_arrays")
            .description("Two separate arrays in struct")
            .access(0, 4).access(4, 4).access(8, 4)  // First array
            .access(32, 8).access(40, 8).access(48, 8)  // Second array
            .expect_arrays()
            .build()
    );

    // Array detection threshold (below minimum)
    cases.push_back(
        test_case("below_array_threshold")
            .description("Two elements - below array threshold")
            .access(0, 4).access(4, 4)
            .with_min_array_elements(3)
            .expect_arrays(false)
            .expect_field_count(2)
            .build()
    );

    return cases;
}

/// Cross-function test cases
inline std::vector<TestCase> cross_function_test_cases() {
    std::vector<TestCase> cases;

    // Simple cross-function unification
    cases.push_back(
        test_case("cross_func_simple")
            .description("Two functions accessing same struct")
            .cross_func_access(0, 4, 1, 0)
            .cross_func_access(4, 4, 2, 0)
            .expect_field(0, 4)
            .expect_field(4, 4)
            .build()
    );

    // Cross-function with positive delta
    cases.push_back(
        test_case("cross_func_positive_delta")
            .description("Function receives ptr + 8, accesses offset 0")
            .cross_func_access(0, 4, 1, 0)     // func1: main struct
            .cross_func_access(0, 4, 2, 8)     // func2: receives (ptr+8), accesses offset 0
            // func2's access at delta 8 + offset 0 = canonical offset 8
            .expect_field(0, 4)
            .expect_field(8, 4)
            .build()
    );

    // Cross-function with negative delta
    cases.push_back(
        test_case("cross_func_negative_delta")
            .description("Function receives ptr - 8, accesses offset 8")
            .cross_func_access(0, 4, 1, 0)     // func1: main struct
            .cross_func_access(8, 4, 2, -8)    // func2: receives (ptr-8), accesses offset 8
            // func2's access at delta -8 + offset 8 = canonical offset 0
            .expect_field(0, 4)
            .build()
    );

    // Many functions
    cases.push_back(
        test_case("cross_func_many_functions")
            .description("Multiple functions with various deltas")
            .cross_func_access(0, 4, 1, 0)
            .cross_func_access(4, 4, 2, 0)
            .cross_func_access(8, 4, 3, 0)
            .cross_func_access(0, 4, 4, 12)    // Delta 12, offset 0 → canonical 12
            .expect_field_count(4)
            .build()
    );

    return cases;
}

// ============================================================================
// Test Result Validation
// ============================================================================

/// Validation result
struct ValidationResult {
    bool passed;
    std::string message;

    ValidationResult() : passed(true) {}
    explicit ValidationResult(const std::string& error_msg)
        : passed(false), message(error_msg) {}

    static ValidationResult ok() { return {}; }
    static ValidationResult fail(const std::string& msg) { return ValidationResult(msg); }
};

/// Validate that expected fields are present in result
template<typename SynthStructT>
ValidationResult validate_fields(const TestCase& test_case,
                                 const SynthStructT& result)
{
    if (test_case.expected_field_count >= 0 &&
        static_cast<int>(result.fields.size()) != test_case.expected_field_count) {
        std::ostringstream oss;
        oss << "Expected " << test_case.expected_field_count
            << " fields, got " << result.fields.size();
        return ValidationResult::fail(oss.str());
    }

    for (const auto& expected : test_case.expected_fields) {
        bool found = false;
        for (const auto& field : result.fields) {
            if (field.offset == expected.offset &&
                field.size >= expected.size) {  // Allow larger fields
                found = true;
                break;
            }
        }
        if (!found) {
            std::ostringstream oss;
            oss << "Missing expected field at offset " << expected.offset
                << " with size " << expected.size;
            return ValidationResult::fail(oss.str());
        }
    }

    return ValidationResult::ok();
}

/// Validate struct size
template<typename SynthStructT>
ValidationResult validate_size(const TestCase& test_case,
                               const SynthStructT& result)
{
    if (test_case.expected_struct_size.has_value() &&
        result.size != *test_case.expected_struct_size) {
        std::ostringstream oss;
        oss << "Expected struct size " << *test_case.expected_struct_size
            << ", got " << result.size;
        return ValidationResult::fail(oss.str());
    }
    return ValidationResult::ok();
}

// ============================================================================
// JSON Fixture Loading (Stub - implement with actual JSON parsing)
// ============================================================================

/// Load test cases from JSON fixture file
/// This is a stub - in a real implementation, use nlohmann/json or similar
inline std::vector<TestCase> load_test_cases(const char* fixture_path) {
    // Check if file exists
    std::ifstream file(fixture_path);
    if (!file.is_open()) {
        throw std::runtime_error(
            std::string("Cannot open fixture file: ") + fixture_path);
    }

    // For now, return standard test cases as fallback
    // A full implementation would parse JSON here
    return standard_test_cases();
}

} // namespace structor::z3::test
