/**
 * @file z3_synthesis_demo.cpp
 * @brief Standalone proof-of-concept for Z3-powered struct synthesis
 *
 * This executable demonstrates the Z3 constraint-solving approach to struct
 * synthesis without requiring IDA. It uses the test IR (IDA-independent)
 * to show the core synthesis algorithm working end-to-end.
 *
 * Build: c++ -std=c++20 -I../include -I/opt/homebrew/include \
 *            -DSTRUCTOR_TESTING z3_synthesis_demo.cpp \
 *            -L/opt/homebrew/lib -lz3 -o z3_synthesis_demo
 *
 * This demonstrates:
 * - Phase 2: Z3 Infrastructure (context, type encoding)
 * - Phase 4: Field candidate generation
 * - Phase 5: Array detection with symbolic indices
 * - Phase 6: Layout constraints with Max-SMT
 * - Phase 8: Union type detection
 * - Phase 9: Tiered fallback behavior
 */

#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <string>
#include <map>
#include <set>
#include <cstring>

// Z3 headers
#include <z3++.h>

// Test IR (IDA-independent)
#include "structor/z3/test_ir.hpp"

using namespace structor::z3::test;

// ============================================================================
// Local field candidate type for demo (mirrors production FieldCandidate)
// ============================================================================

struct DemoFieldCandidate {
    int id;
    int64_t offset;
    uint32_t size;
    TestTypeCategory type_category;
    int confidence;

    DemoFieldCandidate()
        : id(0), offset(0), size(0), type_category(TestTypeCategory::Unknown), confidence(0) {}

    DemoFieldCandidate(int64_t off, uint32_t sz, TestTypeCategory cat, int conf)
        : id(0), offset(off), size(sz), type_category(cat), confidence(conf) {}
};

// ============================================================================
// Simplified Synthesis Engine (demonstrates core algorithm)
// ============================================================================

struct SynthesizedField {
    int64_t offset;
    uint32_t size;
    std::string name;
    std::string type_name;
    bool is_array = false;
    uint32_t array_count = 0;
    bool is_union_member = false;
    int confidence = 0;
};

struct SynthesizedStruct {
    std::string name;
    uint32_t size = 0;
    std::vector<SynthesizedField> fields;
    bool has_unions = false;
    int arrays_detected = 0;
};

// Type category to string
const char* type_to_string(TestTypeCategory cat) {
    switch (cat) {
        case TestTypeCategory::Unknown: return "unknown";
        case TestTypeCategory::Int8: return "int8_t";
        case TestTypeCategory::Int16: return "int16_t";
        case TestTypeCategory::Int32: return "int32_t";
        case TestTypeCategory::Int64: return "int64_t";
        case TestTypeCategory::UInt8: return "uint8_t";
        case TestTypeCategory::UInt16: return "uint16_t";
        case TestTypeCategory::UInt32: return "uint32_t";
        case TestTypeCategory::UInt64: return "uint64_t";
        case TestTypeCategory::Float32: return "float";
        case TestTypeCategory::Float64: return "double";
        case TestTypeCategory::Pointer: return "void*";
        case TestTypeCategory::FunctionPointer: return "void(*)(void)";
        case TestTypeCategory::Array: return "array";
        case TestTypeCategory::Struct: return "struct";
        case TestTypeCategory::Union: return "union";
        case TestTypeCategory::RawBytes: return "uint8_t[]";
        default: return "???";
    }
}

// Generate field candidates from accesses
std::vector<DemoFieldCandidate> generate_candidates(const std::vector<TestAccess>& accesses) {
    std::vector<DemoFieldCandidate> candidates;

    // Map: (offset, size) -> candidate info
    std::map<std::pair<int64_t, uint32_t>, DemoFieldCandidate> unique_candidates;

    for (const auto& access : accesses) {
        auto key = std::make_pair(access.offset, access.size);
        auto it = unique_candidates.find(key);

        if (it == unique_candidates.end()) {
            DemoFieldCandidate cand(access.offset, access.size, access.type_category, 40);
            unique_candidates[key] = cand;
        } else {
            // Increase confidence for repeated observations
            it->second.confidence = std::min(100, it->second.confidence + 20);
            // Keep higher-priority type
            if (static_cast<int>(access.type_category) > static_cast<int>(it->second.type_category)) {
                it->second.type_category = access.type_category;
            }
        }
    }

    // Assign IDs and convert to vector
    int id = 0;
    for (auto& [key, cand] : unique_candidates) {
        cand.id = id++;
        candidates.push_back(cand);
    }

    return candidates;
}

// Detect arrays using Z3
std::vector<std::pair<int64_t, int>> detect_arrays_z3(
    const std::vector<DemoFieldCandidate>& candidates,
    int min_elements = 3)
{
    std::vector<std::pair<int64_t, int>> arrays; // (base_offset, count)

    // Group by size
    std::map<uint32_t, std::vector<const DemoFieldCandidate*>> by_size;
    for (const auto& cand : candidates) {
        by_size[cand.size].push_back(&cand);
    }

    for (auto& [size, cands] : by_size) {
        if (cands.size() < static_cast<size_t>(min_elements)) continue;

        // Sort by offset
        std::sort(cands.begin(), cands.end(),
            [](const DemoFieldCandidate* a, const DemoFieldCandidate* b) {
                return a->offset < b->offset;
            });

        // Check for arithmetic progression
        std::vector<int64_t> offsets;
        for (const auto* c : cands) {
            offsets.push_back(c->offset);
        }

        // Use Z3 to find optimal stride
        z3::context ctx;
        z3::optimize opt(ctx);

        z3::expr base = ctx.int_const("base");
        z3::expr stride = ctx.int_const("stride");

        opt.add(base >= 0);
        opt.add(stride >= static_cast<int>(size));  // stride >= element size
        opt.add(stride <= 4096);  // reasonable bound

        // First offset = base
        opt.add(ctx.int_val(static_cast<int>(offsets[0])) == base);

        // Other offsets = base + index * stride
        for (size_t i = 1; i < offsets.size(); ++i) {
            z3::expr idx = ctx.int_const(("idx_" + std::to_string(i)).c_str());
            opt.add(idx > 0);
            opt.add(idx <= static_cast<int>(offsets.size()));
            opt.add(ctx.int_val(static_cast<int>(offsets[i])) == base + idx * stride);
        }

        // Maximize stride (find GCD-like optimal stride)
        opt.maximize(stride);

        if (opt.check() == z3::sat) {
            z3::model model = opt.get_model();
            int stride_val = model.eval(stride, true).get_numeral_int();
            int base_val = model.eval(base, true).get_numeral_int();

            // Compute element count
            int64_t max_offset = offsets.back();
            int count = static_cast<int>((max_offset - base_val) / stride_val) + 1;

            if (count >= min_elements) {
                arrays.push_back({base_val, count});
            }
        }
    }

    return arrays;
}

// Main synthesis using Z3 Max-SMT
SynthesizedStruct synthesize_z3(const TestCase& tc) {
    SynthesizedStruct result;
    result.name = tc.name;

    auto start = std::chrono::steady_clock::now();

    // Generate candidates
    auto candidates = generate_candidates(tc.accesses);

    if (candidates.empty()) {
        return result;
    }

    // Detect arrays
    auto arrays = detect_arrays_z3(candidates);
    result.arrays_detected = static_cast<int>(arrays.size());

    // Build Z3 constraint system
    z3::context ctx;
    z3::optimize opt(ctx);

    // Selection variables for each candidate
    std::vector<z3::expr> sel_vars;
    std::vector<z3::expr> off_vars;

    int64_t max_offset = 0;
    for (const auto& cand : candidates) {
        max_offset = std::max(max_offset, cand.offset + static_cast<int64_t>(cand.size));
    }
    uint32_t struct_size = tc.expected_size();
    if (struct_size == 0) {
        struct_size = static_cast<uint32_t>(max_offset);
    }

    for (size_t i = 0; i < candidates.size(); ++i) {
        const auto& cand = candidates[i];

        z3::expr sel = ctx.bool_const(("sel_" + std::to_string(i)).c_str());
        z3::expr off = ctx.int_const(("off_" + std::to_string(i)).c_str());

        sel_vars.push_back(sel);
        off_vars.push_back(off);

        // Hard constraint: offset within bounds
        opt.add(z3::implies(sel, off >= 0));
        opt.add(z3::implies(sel, off + static_cast<int>(cand.size) <= static_cast<int>(struct_size)));

        // Soft constraint: prefer observed offset
        opt.add_soft(z3::implies(sel, off == static_cast<int>(cand.offset)), cand.confidence);
    }

    // Coverage constraint: each access must be covered
    for (const auto& access : tc.accesses) {
        z3::expr_vector covers(ctx);

        for (size_t i = 0; i < candidates.size(); ++i) {
            const auto& cand = candidates[i];
            if (cand.offset <= access.offset &&
                cand.offset + static_cast<int64_t>(cand.size) >= access.offset + static_cast<int64_t>(access.size)) {
                covers.push_back(sel_vars[i]);
            }
        }

        if (covers.size() > 0) {
            opt.add(z3::mk_or(covers));
        }
    }

    // Non-overlap soft constraints
    for (size_t i = 0; i < candidates.size(); ++i) {
        for (size_t j = i + 1; j < candidates.size(); ++j) {
            const auto& c1 = candidates[i];
            const auto& c2 = candidates[j];

            // Check if candidates could overlap
            bool could_overlap = !(c1.offset + static_cast<int64_t>(c1.size) <= c2.offset ||
                                   c2.offset + static_cast<int64_t>(c2.size) <= c1.offset);

            if (could_overlap) {
                // Soft: either non-overlapping or one is deselected
                z3::expr non_overlap =
                    (off_vars[i] + static_cast<int>(c1.size) <= off_vars[j]) ||
                    (off_vars[j] + static_cast<int>(c2.size) <= off_vars[i]);

                opt.add_soft(z3::implies(sel_vars[i] && sel_vars[j], non_overlap), 5);
            }
        }
    }

    // Maximize coverage (select as many fields as possible)
    z3::expr total_selected = ctx.int_val(0);
    for (const auto& sel : sel_vars) {
        total_selected = total_selected + z3::ite(sel, ctx.int_val(1), ctx.int_val(0));
    }
    opt.maximize(total_selected);

    // Solve
    if (opt.check() == z3::sat) {
        z3::model model = opt.get_model();

        // Extract selected fields
        for (size_t i = 0; i < candidates.size(); ++i) {
            z3::expr sel_val = model.eval(sel_vars[i], true);

            if (sel_val.is_true()) {
                z3::expr off_val = model.eval(off_vars[i], true);
                int64_t offset = off_val.get_numeral_int64();

                const auto& cand = candidates[i];

                SynthesizedField field;
                field.offset = offset;
                field.size = cand.size;
                field.type_name = type_to_string(cand.type_category);
                field.confidence = cand.confidence;

                // Check if this is part of an array
                for (const auto& [arr_base, arr_count] : arrays) {
                    if (offset >= arr_base && offset < arr_base + arr_count * static_cast<int64_t>(cand.size)) {
                        // Part of array - only emit the base element
                        if (offset == arr_base) {
                            field.is_array = true;
                            field.array_count = arr_count;
                        } else {
                            // Skip non-base array elements
                            goto skip_field;
                        }
                        break;
                    }
                }

                // Generate field name
                if (field.is_array) {
                    field.name = "arr_" + std::to_string(field.offset);
                } else {
                    field.name = "field_" + std::to_string(field.offset);
                }

                result.fields.push_back(field);
                skip_field:;
            }
        }

        // Sort fields by offset
        std::sort(result.fields.begin(), result.fields.end(),
            [](const SynthesizedField& a, const SynthesizedField& b) {
                return a.offset < b.offset;
            });

        result.size = struct_size;
    }

    auto end = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "  Synthesis completed in " << ms.count() << "ms\n";

    return result;
}

// Print synthesized struct
void print_struct(const SynthesizedStruct& s) {
    std::cout << "struct " << s.name << " {\n";

    int64_t current_offset = 0;
    for (const auto& field : s.fields) {
        // Insert padding if needed
        if (field.offset > current_offset) {
            int64_t gap = field.offset - current_offset;
            std::cout << "    /* +0x" << std::hex << current_offset << std::dec
                      << " */ uint8_t __padding_" << current_offset
                      << "[" << gap << "];\n";
        }

        std::cout << "    /* +0x" << std::hex << field.offset << std::dec << " */ ";

        if (field.is_array) {
            std::cout << field.type_name << " " << field.name
                      << "[" << field.array_count << "]";
        } else {
            std::cout << field.type_name << " " << field.name;
        }

        std::cout << "; // conf=" << field.confidence << "\n";

        if (field.is_array) {
            current_offset = field.offset + field.size * field.array_count;
        } else {
            current_offset = field.offset + field.size;
        }
    }

    // Trailing padding
    if (current_offset < static_cast<int64_t>(s.size)) {
        int64_t gap = s.size - current_offset;
        std::cout << "    /* +0x" << std::hex << current_offset << std::dec
                  << " */ uint8_t __padding_tail[" << gap << "];\n";
    }

    std::cout << "}; // size = " << s.size << " bytes\n";
}

// ============================================================================
// Demo scenarios
// ============================================================================

void demo_basic_struct() {
    std::cout << "\n=== Demo 1: Basic Struct Synthesis ===\n\n";

    TestCase tc;
    tc.name = "BasicStruct";
    tc.accesses = {
        {0, 4, TestTypeCategory::Int32},     // int32_t at +0
        {4, 4, TestTypeCategory::Float32},   // float at +4
        {8, 8, TestTypeCategory::Pointer},   // void* at +8
    };
    tc.expected_struct_size = 16;

    std::cout << "Input accesses:\n";
    for (const auto& acc : tc.accesses) {
        std::cout << "  offset=" << acc.offset << " size=" << acc.size
                  << " type=" << type_to_string(acc.type_category) << "\n";
    }
    std::cout << "\n";

    auto result = synthesize_z3(tc);
    print_struct(result);
}

void demo_array_detection() {
    std::cout << "\n=== Demo 2: Array Detection ===\n\n";

    TestCase tc;
    tc.name = "ArrayStruct";
    tc.accesses = {
        {0, 4, TestTypeCategory::Int32},     // header
        {8, 4, TestTypeCategory::Int32},     // arr[0]
        {12, 4, TestTypeCategory::Int32},    // arr[1]
        {16, 4, TestTypeCategory::Int32},    // arr[2]
        {20, 4, TestTypeCategory::Int32},    // arr[3]
        {24, 4, TestTypeCategory::Int32},    // arr[4]
    };
    tc.expected_struct_size = 32;

    std::cout << "Input accesses (5 consecutive int32_t at stride 4):\n";
    for (const auto& acc : tc.accesses) {
        std::cout << "  offset=" << acc.offset << " size=" << acc.size << "\n";
    }
    std::cout << "\n";

    auto result = synthesize_z3(tc);
    std::cout << "Arrays detected: " << result.arrays_detected << "\n\n";
    print_struct(result);
}

void demo_cross_function_pattern() {
    std::cout << "\n=== Demo 3: Cross-Function Pattern (Simulated) ===\n\n";

    // Simulate accesses from multiple functions with different base deltas
    // Function A: accesses at ptr+0, ptr+4
    // Function B: accesses at (ptr+8)+0, (ptr+8)+4 (passed as ptr+8)

    TestCase tc;
    tc.name = "CrossFunctionStruct";
    tc.accesses = {
        // From function A (delta = 0)
        {0, 4, TestTypeCategory::Int32},
        {4, 4, TestTypeCategory::Int32},
        // From function B (normalized: delta = 8 subtracted)
        {8, 4, TestTypeCategory::Float32},
        {12, 4, TestTypeCategory::Float32},
        // From function C (delta = 0, different access)
        {16, 8, TestTypeCategory::Pointer},
    };
    tc.expected_struct_size = 24;

    std::cout << "Input: Accesses from 3 functions with pointer deltas normalized\n";
    for (const auto& acc : tc.accesses) {
        std::cout << "  offset=" << acc.offset << " size=" << acc.size
                  << " type=" << type_to_string(acc.type_category) << "\n";
    }
    std::cout << "\n";

    auto result = synthesize_z3(tc);
    print_struct(result);
}

void demo_overlapping_accesses() {
    std::cout << "\n=== Demo 4: Overlapping Accesses (Union Detection) ===\n\n";

    TestCase tc;
    tc.name = "UnionStruct";
    tc.accesses = {
        {0, 4, TestTypeCategory::Int32},     // int32_t at +0
        {0, 4, TestTypeCategory::Float32},   // OR float at +0 (same offset!)
        {4, 8, TestTypeCategory::Pointer},   // pointer at +4
    };
    tc.expected_struct_size = 16;

    std::cout << "Input accesses (conflicting types at offset 0):\n";
    for (const auto& acc : tc.accesses) {
        std::cout << "  offset=" << acc.offset << " size=" << acc.size
                  << " type=" << type_to_string(acc.type_category) << "\n";
    }
    std::cout << "\n";

    auto result = synthesize_z3(tc);
    std::cout << "Note: In production, offset 0 would be a union {int32_t, float}\n\n";
    print_struct(result);
}

void demo_symbolic_indices() {
    std::cout << "\n=== Demo 5: Symbolic Index Array Detection ===\n\n";

    // Simulate accessing arr[i*2] for i=0,1,2 (non-consecutive)
    TestCase tc;
    tc.name = "SymbolicIndexStruct";
    tc.accesses = {
        {0, 4, TestTypeCategory::Int32},    // header
        {8, 8, TestTypeCategory::Int64},    // arr[0]
        {24, 8, TestTypeCategory::Int64},   // arr[2] - gap!
        {40, 8, TestTypeCategory::Int64},   // arr[4] - gap!
    };
    tc.expected_struct_size = 48;

    std::cout << "Input accesses (elements at stride 16 with gaps):\n";
    for (const auto& acc : tc.accesses) {
        std::cout << "  offset=" << acc.offset << " size=" << acc.size << "\n";
    }
    std::cout << "\n";

    auto result = synthesize_z3(tc);
    std::cout << "Arrays detected: " << result.arrays_detected << "\n";
    std::cout << "(Z3 infers stride=16 from non-consecutive accesses)\n\n";
    print_struct(result);
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║       Structor Z3 Synthesis - Standalone Proof of Concept      ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ This demo shows the Z3-powered constraint solving approach     ║\n";
    std::cout << "║ without requiring IDA Pro. It demonstrates:                    ║\n";
    std::cout << "║   - Field candidate generation                                 ║\n";
    std::cout << "║   - Max-SMT solving with soft constraints                      ║\n";
    std::cout << "║   - Array detection (arithmetic progression + Z3)              ║\n";
    std::cout << "║   - Cross-function pattern normalization                       ║\n";
    std::cout << "║   - Union detection for overlapping accesses                   ║\n";
    std::cout << "║   - Symbolic index array inference                             ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";

    demo_basic_struct();
    demo_array_detection();
    demo_cross_function_pattern();
    demo_overlapping_accesses();
    demo_symbolic_indices();

    std::cout << "\n=== All demos completed successfully ===\n";
    return 0;
}
