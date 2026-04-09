# Z3-Powered Struct Synthesis Design Plan

## Status

This document is a design and historical planning note, not a line-by-line description of the current shipped implementation.

### Implemented in the current codebase

- Z3-backed structure synthesis is present and is the preferred synthesis path when enabled.
- Heuristic synthesis still exists and remains the fallback path.
- Cross-function access unification with pointer-delta normalization is implemented.
- Array detection, union handling, relaxed solving, and heuristic fallback are implemented.

### Partially implemented or evolved since this document was written

- Build and dependency handling changed. The current build tries system Z3 first, can fetch Z3 when missing, and also supports `Z3_USE_CUSTOM`.
- Some tuning defaults in this document no longer match current code exactly.
- The current project also includes a function type-fixing pipeline, which is outside the scope of this document.

### How to read this document

- Some sections describe idealized architecture, planned refinements, or solver details more precisely than the current public behavior guarantees.
- Treat concrete build snippets and numeric defaults here as historical unless they match `README.md`, `CMakeLists.txt`, and `config.hpp`.

## Executive Summary

This document outlines the constraint-solving approach that shaped Structor's Z3-based struct synthesis. Z3 is now the primary synthesis engine when enabled, with the heuristic `LayoutSynthesizer` retained as a fallback. The key capabilities discussed here are:

1. **Cross-Function Struct Unification**: Collect access patterns from all functions that touch the same struct type, normalize pointer deltas at call boundaries, and synthesize a unified, complete definition.

2. **Symbolic Array Detection**: Use Z3 to detect array patterns through stride analysis, including computed-index patterns via affine constraint solving.

The implementation uses Z3 as the primary synthesis engine with automatic fallback to the existing heuristic-based approach when Z3 times out or fails.

---

## Formal Soundness Definition

### Access-Soundness

A synthesized layout `L` is **access-sound** for a set of accesses `A` if:

```
∀ (o, w) ∈ A, ∃ f = (O, S, ...) ∈ L:
    O ≤ o ∧ (o + w) ≤ (O + S)
```

Using half-open intervals `[O, O+S)`, `[o, o+w)`.

### Non-Overlap Invariant

For any two fields `f₁`, `f₂` in the same struct layer (not union alternatives):

```
[f₁, f₂ in same struct layer] ⇒ [O₁ + S₁ ≤ O₂ ∨ O₂ + S₂ ≤ O₁]
```

Union alternatives share the same base offset (IDA union semantics).

### Type-Consistency Caveat

Type soundness is necessarily weaker than access-soundness: decompiler hints are imperfect. The achievable target is **type-consistency w.r.t. chosen constraint rules** rather than "ground truth C type recovery". Z3 guarantees only properties encoded in constraints, not properties of the original source program.

---

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Z3 dependency | Historical plan: FetchContent-only | Current build behavior has changed; see status note above |
| C++ standard | Keep C++20 (project standard) | Avoid breaking existing code |
| Offset/size encoding | Unbounded Int with explicit bounds | Avoids bitvector wrap-around semantics |
| Alignment constraints | **Soft** (with packing parameter) | Handle packed structs without UNSAT |
| Array detection threshold | 3+ elements | Balance between sensitivity and false positives |
| Array element semantics | stride == sizeof(element_type) enforced | C array semantics compliance |
| Cross-function default | Full call graph with delta normalization | Maximum struct completeness |
| Shallow analysis option | Depth=1 (direct callers/callees) | For performance-sensitive cases |
| Z3 timeout | Historical planning value | Check `config.hpp` for current defaults |
| Solving strategy | Max-SMT with soft constraints | Conflict-tolerant synthesis |
| Union handling | Create actual C union types | Proper type representation |
| Union configurability | User option to disable | Some users may prefer manual review |
| Fallback behavior | Tiered: relax constraints → heuristics | Maximize Z3 usage |
| UNSAT handling | Extract MUS, relax, re-solve before fallback | Diagnostic-preserving |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              StructorAPI                                    │
│                           (include/structor/api.hpp)                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                    CrossFunctionAnalyzer                            │    │
│  │              (include/structor/cross_function_analyzer.hpp)         │    │
│  │                                                                     │    │
│  │  • Build type equivalence classes across call graph                 │    │
│  │  • Track pointer deltas at call boundaries (ptr+const normalization)│    │
│  │  • Collect AccessPattern from each contributing function            │    │
│  │  • Normalize offsets before merging into UnifiedAccessPattern       │    │
│  └──────────────────────────────┬──────────────────────────────────────┘    │
│                                 │                                           │
│                                 ▼                                           │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                      LayoutSynthesizer                               │   │
│  │              (include/structor/layout_synthesizer.hpp)               │   │
│  │                                                                      │   │
│  │  synthesize(UnifiedAccessPattern)                                    │   │
│  │      │                                                               │   │
│  │      ├──→ synthesize_z3()  ─────────────────────────────┐            │   │
│  │      │         │                                        │            │   │
│  │      │         ▼                                        │            │   │
│  │      │    ┌─────────────────────────────────────┐       │            │   │
│  │      │    │  Z3LayoutSynthesizer                │       │            │   │
│  │      │    │  (include/structor/z3/...)          │       │            │   │
│  │      │    │                                     │       │            │   │
│  │      │    │  • FieldCandidateGenerator          │       │            │   │
│  │      │    │  • ArrayConstraintBuilder           │       │            │   │
│  │      │    │  • LayoutConstraintBuilder          │       │            │   │
│  │      │    │  • MaxSMTSolver                     │       │            │   │
│  │      │    │  • TypeEncoder                      │       │            │   │
│  │      │    └──────────────┬──────────────────────┘       │            │   │
│  │      │                   │                              │            │   │
│  │      │                   ▼                              │            │   │
│  │      │         ┌─────────────────┐                      │            │   │
│  │      │         │  z3::solver     │ (with assert_and_track)           │   │
│  │      │         └────────┬────────┘                      │            │   │
│  │      │                  │                               │            │   │
│  │      │    SAT ──────────┼────────── UNSAT ──────────────┤            │   │
│  │      │     │            │              │                │            │   │
│  │      │     ▼            │              ▼                │            │   │
│  │      │  extract_model() │      extract_unsat_core()     │            │   │
│  │      │     │            │              │                │            │   │
│  │      │     │            │              ▼                │            │   │
│  │      │     │            │      relax_constraints()      │            │   │
│  │      │     │            │              │                │            │   │
│  │      │     │            │    ┌────────┴────────┐        │            │   │
│  │      │     │            │    │ SAT after relax │        │            │   │
│  │      │     │            │    └────────┬────────┘        │            │   │
│  │      │     │            │             │                 │            │   │
│  │      │     ▼            │             ▼                 │            │   │
│  │      │  SynthStruct ◄───┴─────────────┘                 │            │   │
│  │      │     +                                            │            │   │
│  │      │  DroppedConstraints                              │            │   │
│  │      │                                                  │            │   │
│  │      │                        UNKNOWN (timeout) ────────┤            │   │
│  │      │                              │                   │            │   │
│  │      └──→ synthesize_heuristic() ◄──┴───────────────────┘            │   │
│  │                  │                                                   │   │
│  │                  ▼                                                   │   │
│  │            SynthStruct (fallback)                                    │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Z3 Build Integration

Historical note: this section reflects the original integration plan. The current build system no longer matches it exactly.

### 1.1 CMake Configuration

**File: `CMakeLists.txt`**

Add Z3 as a required dependency using FetchContent with commit hash for reproducibility:

```cmake
include(FetchContent)

# Z3 Theorem Prover - use commit hash for reproducibility
FetchContent_Declare(
    z3
    GIT_REPOSITORY https://github.com/Z3Prover/z3.git
    GIT_TAG        3012783a4da9bd6e7686dc9aa26da842cc4ff95d  # v4.12.4
    GIT_SHALLOW    TRUE
)

# Z3 build options - disable unnecessary components
set(Z3_BUILD_LIBZ3_SHARED OFF CACHE BOOL "" FORCE)
set(Z3_BUILD_EXECUTABLE OFF CACHE BOOL "" FORCE)
set(Z3_BUILD_TEST_EXECUTABLES OFF CACHE BOOL "" FORCE)
set(Z3_ENABLE_EXAMPLE_TARGETS OFF CACHE BOOL "" FORCE)
set(Z3_BUILD_DOCUMENTATION OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(z3)

# Link to structor - include BOTH API directories (C and C++)
target_link_libraries(structor PRIVATE libz3)
target_include_directories(structor PRIVATE 
    ${z3_SOURCE_DIR}/src/api      # C API headers (z3.h)
    ${z3_SOURCE_DIR}/src/api/c++  # C++ API headers (z3++.h)
)
```

### 1.2 Compiler Requirements

**Keep project C++20 standard** (do not downgrade to C++17):

```cmake
# Project already uses C++20 - Z3 builds fine under C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
```

### 1.3 Exception Handling

Z3 C++ API throws `z3::exception`. Ensure plugin build does NOT use `-fno-exceptions`:

```cmake
# Verify exceptions are enabled (required for Z3 C++ API)
if(CMAKE_CXX_FLAGS MATCHES "-fno-exceptions")
    message(FATAL_ERROR "Z3 C++ API requires exceptions. Remove -fno-exceptions.")
endif()
```

### 1.4 Build Time Considerations

Z3 is a large project. To minimize build times:

- Use `GIT_SHALLOW TRUE` for faster clone
- Use commit hash (not tag) for reproducibility
- Disable unnecessary Z3 components (tests, examples, executables, docs)
- Cache Z3 build artifacts in CI via `actions/cache`

---

## Phase 2: Z3 Infrastructure Layer

### 2.1 Z3 Context Manager

**New file: `include/structor/z3/context.hpp`**

```cpp
#pragma once

#include <z3++.h>
#include <memory>
#include <chrono>

namespace structor::z3 {

/// Configuration for Z3 solver behavior
struct Z3Config {
    unsigned timeout_ms = 10000;          // 10 second default
    bool produce_unsat_cores = true;      // Enable conflict extraction
    bool produce_models = true;           // Enable model extraction
    unsigned max_memory_mb = 1024;        // Memory limit
    
    // Architecture-dependent settings (queried from IDA)
    uint32_t pointer_size = 8;            // 4 or 8 bytes
    uint32_t default_alignment = 8;       // Default struct alignment
};

/// RAII wrapper for Z3 context with Structor-specific configuration
class Z3Context {
public:
    explicit Z3Context(const Z3Config& config = {});
    ~Z3Context();
    
    // Non-copyable, movable
    Z3Context(const Z3Context&) = delete;
    Z3Context& operator=(const Z3Context&) = delete;
    Z3Context(Z3Context&&) noexcept;
    Z3Context& operator=(Z3Context&&) noexcept;
    
    /// Access underlying Z3 context
    [[nodiscard]] ::z3::context& ctx() noexcept { return *ctx_; }
    [[nodiscard]] const ::z3::context& ctx() const noexcept { return *ctx_; }
    
    /// Create a solver with configured timeout (via global params)
    /// Uses assert_and_track for UNSAT core extraction
    [[nodiscard]] ::z3::solver make_solver();
    
    /// Common sorts used in struct synthesis (all use Int, not BitVec)
    [[nodiscard]] ::z3::sort int_sort();     // Unbounded integers for offsets/sizes
    [[nodiscard]] ::z3::sort bool_sort();    // Boolean for field selection
    [[nodiscard]] ::z3::sort type_sort();    // Enumeration for field types
    
    /// Create bounded integer variable with explicit constraints
    /// Adds: 0 <= var <= max_struct_size
    [[nodiscard]] ::z3::expr make_offset_var(const char* name);
    [[nodiscard]] ::z3::expr make_size_var(const char* name);
    
    /// Get configuration
    [[nodiscard]] const Z3Config& config() const noexcept { return config_; }

private:
    std::unique_ptr<::z3::context> ctx_;
    Z3Config config_;
    
    /// Apply global timeout params (more reliable than solver.set)
    void apply_global_params();
};

} // namespace structor::z3
```

**Implementation notes:**

1. Use **Int sort** (not BitVec) for offsets and sizes to avoid wrap-around semantics
2. Add explicit bounds constraints: `0 <= offset <= max_struct_size`
3. Apply timeout via **global Z3 parameters** (more reliable than `solver.set("timeout", ...)`):
   ```cpp
   void Z3Context::apply_global_params() {
       ::z3::set_param("timeout", static_cast<unsigned>(config_.timeout_ms));
   }
   ```

### 2.2 Type Encoding

**New file: `include/structor/z3/type_encoding.hpp`**

```cpp
#pragma once

#include <z3++.h>
#include <pro.h>
#include <typeinf.hpp>
#include "structor/z3/context.hpp"

namespace structor::z3 {

/// Encoded type categories for Z3 reasoning
/// These are abstract categories, not full type representations
enum class TypeCategory : unsigned {
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
    Pointer,      // Generic pointer (size from config)
    FuncPtr,      // Function pointer (requires separate prototype tracking)
    Array,        // Array (element type tracked separately)
    Struct,       // Nested struct (tid tracked separately)
    Union,        // Union type (tid tracked separately)
    RawBytes,     // Fallback: uint8_t[] for irreconcilable regions
    Void,
    
    _Count  // For enumeration bounds
};

/// Extended type info for complex types
struct ExtendedTypeInfo {
    TypeCategory category;
    
    // For Pointer/FuncPtr: pointed-to type (if known)
    std::optional<TypeCategory> pointee_category;
    
    // For Struct/Union: IDA type ID
    std::optional<tid_t> udt_tid;
    
    // For Array: element info
    std::optional<TypeCategory> element_category;
    std::optional<uint32_t> element_count;
    
    // For FuncPtr: prototype info (simplified)
    std::optional<uint32_t> func_arg_count;
};

/// Encode IDA types to Z3 and back
class TypeEncoder {
public:
    explicit TypeEncoder(Z3Context& ctx);
    
    /// Create the Z3 enumeration sort for types
    [[nodiscard]] ::z3::sort type_sort();
    
    /// Encode an IDA tinfo_t to Z3 type category expression
    [[nodiscard]] ::z3::expr encode(const tinfo_t& type);
    
    /// Encode with extended info extraction
    [[nodiscard]] std::pair<::z3::expr, ExtendedTypeInfo> encode_extended(const tinfo_t& type);
    
    /// Get Z3 expression for a specific category
    [[nodiscard]] ::z3::expr category_expr(TypeCategory cat);
    
    /// Decode Z3 model value back to IDA type
    /// Requires extended info for complex types
    [[nodiscard]] tinfo_t decode(
        TypeCategory category, 
        uint32_t size,
        const ExtendedTypeInfo* extended = nullptr
    );
    
    /// Build type compatibility constraint (SOFT constraint)
    /// Returns (constraint_expr, is_hard)
    /// Two types are compatible if they can coexist at the same offset
    [[nodiscard]] std::pair<::z3::expr, bool> compatible(
        const ::z3::expr& t1, 
        const ::z3::expr& t2
    );
    
    /// Build type-size consistency constraint
    [[nodiscard]] ::z3::expr size_matches_type(
        const ::z3::expr& type, 
        const ::z3::expr& size
    );
    
    /// Get the natural size for a type category (architecture-aware)
    [[nodiscard]] uint32_t natural_size(TypeCategory cat);

private:
    Z3Context& ctx_;
    std::optional<::z3::sort> type_sort_;
    std::vector<::z3::expr> category_exprs_;
    
    void initialize_type_sort();
};

/// Type compatibility matrix
/// Returns true if types t1 and t2 can legally alias at the same memory location
[[nodiscard]] bool types_compatible(TypeCategory t1, TypeCategory t2);

/// Confidence level for type hints (for soft constraint weighting)
enum class TypeConfidence : int {
    Low = 1,       // Inferred from context, may be wrong
    Medium = 5,    // Direct decompiler hint
    High = 10,     // Multiple consistent observations
    Absolute = 100 // User-specified or API-documented
};

} // namespace structor::z3
```

### 2.3 Constraint Tracking for UNSAT Cores

**New file: `include/structor/z3/constraint_tracker.hpp`**

```cpp
#pragma once

#include <z3++.h>
#include <unordered_map>
#include "structor/synth_types.hpp"

namespace structor::z3 {

/// Provenance information for a constraint
struct ConstraintProvenance {
    ea_t func_ea = BADADDR;           // Function where observation occurred
    ea_t insn_ea = BADADDR;           // Instruction address
    int access_idx = -1;              // Index in access pattern
    qstring description;              // Human-readable description
    bool is_soft = false;             // Soft constraint (can be dropped)
    int weight = 1;                   // Weight for Max-SMT (higher = more important)
};

/// Tracks constraints for UNSAT core analysis
class ConstraintTracker {
public:
    explicit ConstraintTracker(::z3::context& ctx);
    
    /// Add a constraint with tracking literal for UNSAT core
    /// Returns the tracking literal
    [[nodiscard]] ::z3::expr add_tracked(
        ::z3::solver& solver,
        const ::z3::expr& constraint,
        const ConstraintProvenance& provenance
    );
    
    /// Add a hard constraint (always required)
    void add_hard(
        ::z3::solver& solver,
        const ::z3::expr& constraint,
        const ConstraintProvenance& provenance
    );
    
    /// Add a soft constraint (can be dropped if needed)
    void add_soft(
        ::z3::solver& solver,
        const ::z3::expr& constraint,
        const ConstraintProvenance& provenance,
        int weight = 1
    );
    
    /// Extract provenance from UNSAT core
    [[nodiscard]] qvector<ConstraintProvenance> analyze_unsat_core(
        const ::z3::expr_vector& core
    );
    
    /// Get all soft constraint tracking literals (for Max-SMT)
    [[nodiscard]] ::z3::expr_vector get_soft_literals() const;
    
    /// Get provenance for a tracking literal
    [[nodiscard]] const ConstraintProvenance* get_provenance(
        const ::z3::expr& tracking_lit
    ) const;

private:
    ::z3::context& ctx_;
    unsigned next_id_ = 0;
    
    // Map tracking literal ID -> provenance
    std::unordered_map<unsigned, ConstraintProvenance> provenance_map_;
    
    // Separate lists for hard vs soft
    std::vector<unsigned> hard_constraint_ids_;
    std::vector<unsigned> soft_constraint_ids_;
};

} // namespace structor::z3
```

### 2.4 Z3 Result Handling

**New file: `include/structor/z3/result.hpp`**

```cpp
#pragma once

#include <z3++.h>
#include <variant>
#include <string>
#include "structor/synth_types.hpp"
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
    
    Status status;
    std::optional<::z3::model> model;
    
    // Constraints that were dropped to achieve SAT (for SatRelaxed)
    qvector<ConstraintProvenance> dropped_constraints;
    
    // Minimal unsatisfiable core (for Unsat)
    qvector<ConstraintProvenance> unsat_core;
    
    qstring error_message;
    std::chrono::milliseconds solve_time;
    
    [[nodiscard]] bool is_sat() const noexcept { 
        return status == Status::Sat || status == Status::SatRelaxed; 
    }
    [[nodiscard]] bool is_unsat() const noexcept { return status == Status::Unsat; }
    [[nodiscard]] bool should_fallback() const noexcept { 
        return status == Status::Unknown || status == Status::Error || status == Status::Unsat;
    }
    [[nodiscard]] bool has_dropped_constraints() const noexcept {
        return !dropped_constraints.empty();
    }
};

} // namespace structor::z3
```

---

## Phase 3: Cross-Function Analysis with Delta Normalization

### 3.1 Pointer Delta Tracking

**Critical fix**: Track constant pointer adjustments at call boundaries.

When a callsite passes `ptr + 0x10` to a callee, all offsets observed in the callee are relative to `ptr + 0x10`, not `ptr`. We must normalize by subtracting the delta before merging.

**New file: `include/structor/cross_function_analyzer.hpp`**

```cpp
#pragma once

#include <pro.h>
#include <hexrays.hpp>
#include <unordered_set>
#include <unordered_map>
#include "structor/synth_types.hpp"
#include "structor/access_collector.hpp"

namespace structor {

/// Identifies a variable in a specific function with its base delta
struct FunctionVariable {
    ea_t func_ea;
    int var_idx;
    sval_t base_delta;  // Constant offset from the "canonical" base pointer
    
    bool operator==(const FunctionVariable& other) const noexcept {
        return func_ea == other.func_ea && var_idx == other.var_idx;
    }
};

/// Hash for FunctionVariable (ignores delta for equivalence class building)
struct FunctionVariableHash {
    std::size_t operator()(const FunctionVariable& fv) const noexcept {
        return std::hash<ea_t>{}(fv.func_ea) ^ (std::hash<int>{}(fv.var_idx) << 1);
    }
};

/// Information about how a pointer flows between functions
struct PointerFlowEdge {
    ea_t caller_ea;
    ea_t callee_ea;
    ea_t call_site;
    int caller_var_idx;
    int callee_param_idx;
    sval_t delta;  // Constant added to pointer at call site (0 if none)
    bool is_direct_call;
};

/// Represents a set of variables across functions that share the same underlying type
struct TypeEquivalenceClass {
    qvector<FunctionVariable> variables;
    qvector<AccessPattern> patterns;
    qvector<PointerFlowEdge> flow_edges;  // How pointers flow between functions
    
    /// Check if a variable is in this equivalence class
    [[nodiscard]] bool contains(ea_t func_ea, int var_idx) const noexcept;
    
    /// Total number of accesses across all patterns
    [[nodiscard]] std::size_t total_accesses() const noexcept;
};

/// Unified access pattern combining observations from multiple functions
/// All offsets are normalized to a canonical base
struct UnifiedAccessPattern {
    qvector<AccessPattern> per_function_patterns;
    qvector<FieldAccess> all_accesses;  // Merged, deduplicated, delta-normalized
    qvector<ea_t> contributing_functions;
    
    // Per-function deltas (how much was subtracted from each function's offsets)
    std::unordered_map<ea_t, sval_t> function_deltas;
    
    sval_t global_min_offset = 0;
    sval_t global_max_offset = 0;
    
    bool has_vtable = false;
    sval_t vtable_offset = 0;
    
    /// Create from a single AccessPattern (no cross-function analysis)
    static UnifiedAccessPattern from_single(AccessPattern&& pattern);
    
    /// Merge multiple patterns with delta normalization
    static UnifiedAccessPattern merge(
        qvector<AccessPattern>&& patterns,
        const std::unordered_map<ea_t, sval_t>& deltas
    );
};

/// Configuration for cross-function analysis
struct CrossFunctionConfig {
    int max_depth = 5;                    // Maximum call graph traversal depth
    bool follow_forward = true;           // Follow caller → callee (parameter passing)
    bool follow_backward = true;          // Follow callee → caller (return values)
    int max_functions = 100;              // Maximum functions to analyze
    bool include_indirect_calls = false;  // Include indirect/virtual calls
    bool track_pointer_deltas = true;     // Track ptr+const adjustments (recommended)
};

/// Analyzes type flow across function boundaries to build equivalence classes
class CrossFunctionAnalyzer {
public:
    explicit CrossFunctionAnalyzer(const CrossFunctionConfig& config = {});
    
    /// Analyze starting from a specific variable, building its equivalence class
    /// Returns a unified access pattern combining all observations
    [[nodiscard]] UnifiedAccessPattern analyze(
        ea_t func_ea, 
        int var_idx,
        const SynthOptions& synth_opts
    );
    
    /// Get the equivalence class for the last analysis
    [[nodiscard]] const TypeEquivalenceClass& equivalence_class() const noexcept {
        return equiv_class_;
    }
    
    /// Get statistics about the last analysis
    struct AnalysisStats {
        int functions_analyzed = 0;
        int total_accesses = 0;
        int max_depth_reached = 0;
        int pointer_deltas_detected = 0;
        std::chrono::milliseconds analysis_time;
    };
    [[nodiscard]] const AnalysisStats& stats() const noexcept { return stats_; }

private:
    CrossFunctionConfig config_;
    TypeEquivalenceClass equiv_class_;
    AnalysisStats stats_;
    
    // Visited set to prevent infinite recursion
    std::unordered_set<FunctionVariable, FunctionVariableHash> visited_;
    
    // Accumulated deltas for each function variable
    std::unordered_map<FunctionVariable, sval_t, FunctionVariableHash> deltas_;
    
    /// Trace type flow forward through parameter passing
    /// Detects and records pointer arithmetic at call sites
    void trace_forward(
        ea_t func_ea, 
        int var_idx,
        sval_t current_delta,
        int current_depth,
        const SynthOptions& synth_opts
    );
    
    /// Trace type flow backward through return values and out parameters
    void trace_backward(
        ea_t func_ea, 
        int var_idx,
        sval_t current_delta,
        int current_depth,
        const SynthOptions& synth_opts
    );
    
    /// Find all callees where var is passed as an argument
    /// Returns call infos with callee, delta, and by-ref metadata
    [[nodiscard]] qvector<CalleeCallInfo> find_callees_with_arg(
        cfunc_t* cfunc, 
        int var_idx
    );
    
    /// Extract constant delta from call argument expression
    /// e.g., for `call(ptr + 0x10)`, returns 0x10
    [[nodiscard]] std::optional<sval_t> extract_arg_delta(
        cexpr_t* arg_expr,
        int target_var_idx
    );
    
    /// Find all callers that pass a value to this function's parameter
    /// Returns call infos with caller var, delta, and by-ref metadata
    [[nodiscard]] qvector<CallerCallInfo> find_callers_with_param(
        ea_t func_ea, 
        int param_idx
    );
    
    /// Collect access pattern for a single function/variable
    [[nodiscard]] AccessPattern collect_pattern(
        ea_t func_ea, 
        int var_idx,
        const SynthOptions& synth_opts
    );
    
    /// Normalize all collected patterns using accumulated deltas
    [[nodiscard]] UnifiedAccessPattern normalize_and_merge();
};

} // namespace structor
```

### 3.2 Call Graph Utilities

**New file: `include/structor/call_graph.hpp`**

```cpp
#pragma once

#include <pro.h>
#include <hexrays.hpp>
#include <funcs.hpp>
#include <xref.hpp>

namespace structor {

/// Utilities for call graph traversal
namespace call_graph {

/// Get all functions that call the given function
[[nodiscard]] qvector<ea_t> get_callers(ea_t func_ea);

/// Get all functions called by the given function
[[nodiscard]] qvector<ea_t> get_callees(ea_t func_ea);

/// Check if a call is direct (not through function pointer)
[[nodiscard]] bool is_direct_call(ea_t call_site);

/// Get the function containing an address
[[nodiscard]] ea_t get_containing_function(ea_t addr);

/// Cache decompiled functions to avoid redundant decompilation
class CfuncCache {
public:
    /// Get or decompile a function (cached)
    [[nodiscard]] cfuncptr_t get(ea_t func_ea);
    
    /// Clear cache (e.g., when analysis is complete)
    void clear();
    
    /// Get cache statistics
    struct Stats {
        size_t hits = 0;
        size_t misses = 0;
        size_t total_cached = 0;
    };
    [[nodiscard]] Stats stats() const noexcept { return stats_; }

private:
    std::unordered_map<ea_t, cfuncptr_t> cache_;
    Stats stats_;
};

/// Visitor pattern for call graph traversal
class CallGraphVisitor {
public:
    virtual ~CallGraphVisitor() = default;
    
    /// Called for each edge in the call graph
    /// Return false to stop traversal
    virtual bool visit_edge(ea_t caller, ea_t callee, ea_t call_site) = 0;
};

/// Traverse call graph breadth-first from a starting function
void traverse_bfs(
    ea_t start_func,
    CallGraphVisitor& visitor,
    int max_depth = 5,
    bool forward = true  // true = callees, false = callers
);

} // namespace call_graph
} // namespace structor
```

---

## Phase 4: Field Candidate Generation

### 4.1 Candidate Universe Definition

**Critical addition**: Explicitly define the candidate field universe before constraint solving.

**New file: `include/structor/z3/field_candidates.hpp`**

```cpp
#pragma once

#include "structor/synth_types.hpp"
#include "structor/z3/context.hpp"
#include "structor/z3/type_encoding.hpp"

namespace structor::z3 {

/// A candidate field that may or may not appear in the final struct
struct FieldCandidate {
    int id;                          // Unique identifier
    sval_t offset;                   // Fixed offset (from access observation)
    uint32_t size;                   // Size in bytes
    TypeCategory type_category;      // Inferred type category
    ExtendedTypeInfo extended_type;  // Extended type info
    
    // Source tracking
    qvector<int> source_access_indices;
    ea_t primary_func_ea = BADADDR;
    TypeConfidence confidence = TypeConfidence::Medium;
    
    // Candidate classification
    enum class Kind {
        DirectAccess,    // Directly observed access
        CoveringField,   // Larger field that covers multiple accesses
        ArrayElement,    // Part of a detected array
        ArrayField,      // The entire array as a single field
        PaddingField,    // Inferred padding
        UnionAlternative // One alternative in a union
    };
    Kind kind = Kind::DirectAccess;
    
    // For array candidates
    std::optional<uint32_t> array_element_count;
    std::optional<uint32_t> array_stride;
};

/// Configuration for candidate generation
struct CandidateGenerationConfig {
    bool generate_covering_candidates = true;  // Larger fields covering multiple accesses
    bool generate_array_candidates = true;     // Array field candidates
    bool generate_padding_candidates = true;   // Padding between fields
    uint32_t max_covering_size = 64;           // Max size for covering candidates
};

/// Generates the universe of candidate fields from access patterns
class FieldCandidateGenerator {
public:
    FieldCandidateGenerator(
        Z3Context& ctx,
        const CandidateGenerationConfig& config = {}
    );
    
    /// Generate all candidates from a unified access pattern
    [[nodiscard]] qvector<FieldCandidate> generate(
        const UnifiedAccessPattern& pattern
    );

private:
    Z3Context& ctx_;
    CandidateGenerationConfig config_;
    TypeEncoder type_encoder_;
    
    /// Generate one candidate per unique (offset, size) pair
    void generate_direct_candidates(
        const UnifiedAccessPattern& pattern,
        qvector<FieldCandidate>& candidates
    );
    
    /// Generate larger covering candidates
    void generate_covering_candidates(
        const UnifiedAccessPattern& pattern,
        qvector<FieldCandidate>& candidates
    );
    
    /// Generate array candidates (delegates to ArrayConstraintBuilder)
    void generate_array_candidates(
        const UnifiedAccessPattern& pattern,
        qvector<FieldCandidate>& candidates
    );
    
    /// Assign unique IDs and sort by offset
    void finalize_candidates(qvector<FieldCandidate>& candidates);
};

} // namespace structor::z3
```

---

## Phase 5: Array Detection

### 5.1 Array Constraint Builder with Symbolic Index Support

**New file: `include/structor/z3/array_constraints.hpp`**

```cpp
#pragma once

#include <z3++.h>
#include <optional>
#include "structor/synth_types.hpp"
#include "structor/z3/context.hpp"
#include "structor/z3/type_encoding.hpp"

namespace structor::z3 {

/// Represents a detected array pattern
struct ArrayCandidate {
    sval_t base_offset;           // Starting offset of array
    uint32_t stride;              // Bytes between elements (== sizeof(element))
    uint32_t element_count;       // Number of elements
    tinfo_t element_type;         // Type of each element
    qvector<sval_t> member_offsets;  // Original offsets covered by this array
    
    // For stride > access_size cases: synthetic element struct
    bool needs_element_struct = false;
    uint32_t inner_access_offset = 0;  // Offset of accessed subfield within element
    
    /// C array semantics check: stride must equal element size
    [[nodiscard]] bool is_valid_c_array() const noexcept {
        return stride == element_type.get_size();
    }
    
    /// Calculate total array size in bytes
    [[nodiscard]] uint32_t total_size() const noexcept {
        return stride * element_count;
    }
    
    /// Check if an offset falls within this array
    [[nodiscard]] bool contains_offset(sval_t offset) const noexcept {
        return offset >= base_offset && 
               offset < base_offset + static_cast<sval_t>(total_size());
    }
};

/// Configuration for array detection
struct ArrayDetectionConfig {
    int min_elements = 3;                    // Minimum elements to form an array
    int max_gap_ratio = 2;                   // Max allowed gap as multiple of stride
    bool require_consistent_types = true;    // All elements must have same type
    bool detect_arrays_of_structs = true;    // When stride > access_size, create element struct
    bool use_symbolic_indices = true;        // Use Z3 for affine index detection
};

/// Builds Z3 constraints for array pattern detection
class ArrayConstraintBuilder {
public:
    ArrayConstraintBuilder(Z3Context& ctx, const ArrayDetectionConfig& config = {});
    
    /// Analyze accesses and detect array patterns
    /// Returns all detected array candidates, sorted by base offset
    [[nodiscard]] qvector<ArrayCandidate> detect_arrays(
        const qvector<FieldAccess>& accesses
    );
    
    /// Build Z3 constraint for affine index detection
    /// Solves: offset[i] = base + index[i] * stride + inner_offset
    /// where index[i] are unknown integers
    [[nodiscard]] std::optional<ArrayCandidate> detect_symbolic_array(
        const qvector<const FieldAccess*>& accesses
    );

private:
    Z3Context& ctx_;
    ArrayDetectionConfig config_;
    TypeEncoder type_encoder_;
    
    /// Pre-filter: group accesses by size (potential array elements)
    [[nodiscard]] std::unordered_map<uint32_t, qvector<const FieldAccess*>>
    group_by_size(const qvector<FieldAccess>& accesses);
    
    /// Fast path: check if offsets form perfect arithmetic progression
    [[nodiscard]] std::optional<std::pair<sval_t, uint32_t>>  // (base, stride)
    find_arithmetic_progression(const qvector<sval_t>& offsets);
    
    /// Verify type consistency for potential array elements
    [[nodiscard]] bool verify_type_consistency(
        const qvector<const FieldAccess*>& accesses
    );
    
    /// Handle stride > access_size: create element struct type
    [[nodiscard]] tinfo_t create_element_struct_type(
        uint32_t stride,
        uint32_t inner_offset,
        const tinfo_t& inner_type
    );
    
    /// Use Z3 to find optimal stride when simple AP detection fails
    [[nodiscard]] std::optional<ArrayCandidate> solve_stride_z3(
        const qvector<const FieldAccess*>& accesses
    );
};

/// Quick check: can these offsets possibly form an array?
[[nodiscard]] bool could_be_array(
    const qvector<sval_t>& offsets, 
    uint32_t element_size,
    int min_elements = 3
);

} // namespace structor::z3
```

### 5.2 Array Semantics: stride == sizeof(element_type)

When `stride > access_size` (only a subfield of each element is accessed):

```cpp
// Example: accesses at 0x10, 0x20, 0x30 with size 4
// Stride = 0x10 (16 bytes), but access size = 4 bytes
// This is NOT int32_t arr[3] (which would have stride 4)
// This IS: struct { int32_t field_0; char pad[12]; } arr[3];

tinfo_t ArrayConstraintBuilder::create_element_struct_type(
    uint32_t stride,
    uint32_t inner_offset,
    const tinfo_t& inner_type
) {
    // Create synthetic element struct:
    //   struct __element_N {
    //       char __pad_0[inner_offset];  // if inner_offset > 0
    //       <inner_type> accessed_field;
    //       char __pad_1[stride - inner_offset - inner_type.size()];
    //   };
    
    qstring name;
    name.sprnt("__array_elem_%u", stride);
    
    // ... create struct in IDB ...
}
```

---

## Phase 6: Layout Synthesis Constraints

### 6.1 Constraint Builder with Soft Constraints and Max-SMT

**New file: `include/structor/z3/layout_constraints.hpp`**

```cpp
#pragma once

#include <z3++.h>
#include "structor/synth_types.hpp"
#include "structor/z3/context.hpp"
#include "structor/z3/type_encoding.hpp"
#include "structor/z3/array_constraints.hpp"
#include "structor/z3/field_candidates.hpp"
#include "structor/z3/constraint_tracker.hpp"
#include "structor/z3/result.hpp"

namespace structor::z3 {

/// Z3 variables representing a candidate field
struct FieldVariables {
    int candidate_id;              // Links to FieldCandidate
    ::z3::expr selected;           // Bool: is this candidate selected?
    ::z3::expr offset;             // Int: byte offset (fixed from candidate)
    ::z3::expr size;               // Int: field size (fixed from candidate)
    ::z3::expr type;               // TypeSort: field type category
    ::z3::expr is_array;           // Bool: is this an array field?
    ::z3::expr array_count;        // Int: number of elements (1 if not array)
    ::z3::expr is_union_member;    // Bool: is this part of a union?
    ::z3::expr union_group;        // Int: which union group (if any)
};

/// Configuration for layout constraint building
struct LayoutConstraintConfig {
    // Packing/alignment (modeled as soft constraint with variable p)
    uint32_t default_alignment = 8;
    bool model_packing = true;           // Infer packing parameter
    qvector<uint32_t> packing_options = {1, 2, 4, 8, 16};  // Possible packing values
    
    // Union handling
    bool allow_unions = true;
    bool create_actual_unions = true;
    
    // Optimization weights (for Max-SMT)
    int weight_coverage = 100;           // Hard: every access must be covered
    int weight_type_consistency = 10;    // Soft: prefer consistent types
    int weight_alignment = 5;            // Soft: prefer aligned fields
    int weight_minimize_fields = 2;      // Soft: prefer fewer fields
    int weight_minimize_padding = 1;     // Soft: prefer compact layout
    int weight_prefer_arrays = 3;        // Soft: prefer array detection
    
    // Limits
    uint32_t max_struct_size = 0x10000;
    uint32_t max_union_alternatives = 8;
};

/// Builds and solves Z3 constraints for struct layout synthesis
class LayoutConstraintBuilder {
public:
    LayoutConstraintBuilder(
        Z3Context& ctx, 
        const LayoutConstraintConfig& config = {}
    );
    
    /// Build all constraints from unified access pattern
    void build_constraints(
        const UnifiedAccessPattern& pattern,
        const qvector<FieldCandidate>& candidates
    );
    
    /// Solve with Max-SMT: maximize satisfied soft constraints
    /// On UNSAT of hard constraints: extract core, relax, re-solve
    [[nodiscard]] Z3Result solve();
    
    /// Extract synthesized struct from SAT model
    [[nodiscard]] SynthStruct extract_struct(const ::z3::model& model);
    
    /// Get detected arrays (available after build_constraints)
    [[nodiscard]] const qvector<ArrayCandidate>& detected_arrays() const noexcept {
        return arrays_;
    }

private:
    Z3Context& ctx_;
    LayoutConstraintConfig config_;
    TypeEncoder type_encoder_;
    ArrayConstraintBuilder array_builder_;
    ConstraintTracker constraint_tracker_;
    
    ::z3::solver solver_;
    qvector<FieldVariables> field_vars_;
    qvector<ArrayCandidate> arrays_;
    qvector<FieldCandidate> candidates_;
    
    // Packing parameter variable (if modeling packing)
    std::optional<::z3::expr> packing_var_;
    
    // The pattern being analyzed
    const UnifiedAccessPattern* pattern_ = nullptr;
    
    /// Create Z3 variables for each candidate
    void create_field_variables();
    
    /// Add HARD constraints (coverage is non-negotiable)
    void add_coverage_constraints();       // Every access covered by selected field
    
    /// Add SOFT constraints (can be relaxed if needed)
    void add_non_overlap_constraints();    // Fields don't overlap (or form union)
    void add_alignment_constraints();      // Alignment as soft with packing var
    void add_type_constraints();           // Type consistency
    void add_size_bound_constraints();     // Size limits
    void add_array_constraints();          // Array-specific constraints
    
    /// Add optimization objectives
    void add_optimization_objectives();
    
    /// Relaxation loop for UNSAT cases
    [[nodiscard]] Z3Result solve_with_relaxation();
    
    /// Extract minimal unsatisfiable subset (MUS)
    [[nodiscard]] qvector<ConstraintProvenance> extract_mus();
    
    /// Create union type when fields must overlap
    [[nodiscard]] SynthField create_union_field(
        const qvector<const FieldVariables*>& overlapping,
        const ::z3::model& model
    );
    
    /// Create fallback raw bytes field for irreconcilable regions
    [[nodiscard]] SynthField create_raw_bytes_field(
        sval_t offset,
        uint32_t size
    );
    
    /// Helper: get concrete value from model
    template<typename T>
    [[nodiscard]] T get_model_value(const ::z3::model& model, const ::z3::expr& e);
};

} // namespace structor::z3
```

### 6.2 Constraint Encoding Details

#### Coverage Constraints (HARD)

Every observed access must be covered by at least one selected field:

```cpp
void LayoutConstraintBuilder::add_coverage_constraints() {
    for (size_t i = 0; i < pattern_->all_accesses.size(); ++i) {
        const auto& access = pattern_->all_accesses[i];
        
        // Build: OR of all candidates that cover this access
        ::z3::expr_vector covering(ctx_.ctx());
        
        for (const auto& fv : field_vars_) {
            const auto& cand = candidates_[fv.candidate_id];
            
            // Candidate covers access if:
            //   cand.offset <= access.offset AND
            //   cand.offset + cand.size >= access.offset + access.size
            if (cand.offset <= access.offset && 
                cand.offset + cand.size >= access.offset + access.size) {
                covering.push_back(fv.selected);
            }
        }
        
        // At least one covering field must be selected
        ::z3::expr coverage = ::z3::mk_or(covering);
        
        ConstraintProvenance prov;
        prov.func_ea = access.insn_ea;  // Approximate
        prov.access_idx = static_cast<int>(i);
        prov.description.sprnt("Access at offset 0x%X size %u must be covered",
                               access.offset, access.size);
        prov.is_soft = false;
        prov.weight = config_.weight_coverage;
        
        constraint_tracker_.add_hard(solver_, coverage, prov);
    }
}
```

#### Alignment Constraints (SOFT with Packing)

Model alignment as soft constraint with packing parameter:

```cpp
void LayoutConstraintBuilder::add_alignment_constraints() {
    if (config_.model_packing) {
        // Create packing parameter variable
        ::z3::expr_vector packing_options(ctx_.ctx());
        for (uint32_t p : config_.packing_options) {
            packing_options.push_back(packing_var_.value() == static_cast<int>(p));
        }
        solver_.add(::z3::mk_or(packing_options));
    }
    
    for (const auto& fv : field_vars_) {
        const auto& cand = candidates_[fv.candidate_id];
        uint32_t natural_align = type_encoder_.natural_size(cand.type_category);
        
        // Effective alignment = min(natural_align, packing)
        ::z3::expr effective_align = config_.model_packing
            ? ::z3::min(ctx_.ctx().int_val(natural_align), packing_var_.value())
            : ctx_.ctx().int_val(natural_align);
        
        // Soft constraint: offset % effective_align == 0
        ::z3::expr aligned = (fv.offset % effective_align == 0);
        ::z3::expr constraint = ::z3::implies(fv.selected, aligned);
        
        ConstraintProvenance prov;
        prov.description.sprnt("Field at 0x%X alignment", cand.offset);
        prov.is_soft = true;
        prov.weight = config_.weight_alignment;
        
        constraint_tracker_.add_soft(solver_, constraint, prov, config_.weight_alignment);
    }
}
```

#### Non-Overlap Constraints (SOFT with Union Option)

```cpp
void LayoutConstraintBuilder::add_non_overlap_constraints() {
    for (size_t i = 0; i < field_vars_.size(); ++i) {
        for (size_t j = i + 1; j < field_vars_.size(); ++j) {
            const auto& fv1 = field_vars_[i];
            const auto& fv2 = field_vars_[j];
            const auto& c1 = candidates_[fv1.candidate_id];
            const auto& c2 = candidates_[fv2.candidate_id];
            
            // Check if candidates could overlap
            bool could_overlap = !(c1.offset + c1.size <= c2.offset || 
                                   c2.offset + c2.size <= c1.offset);
            
            if (could_overlap) {
                if (config_.allow_unions) {
                    // Either non-overlapping OR both are union members in same group
                    ::z3::expr non_overlap = 
                        (fv1.offset + ctx_.ctx().int_val(c1.size) <= fv2.offset) ||
                        (fv2.offset + ctx_.ctx().int_val(c2.size) <= fv1.offset);
                    
                    ::z3::expr same_union = 
                        fv1.is_union_member && fv2.is_union_member && 
                        (fv1.union_group == fv2.union_group);
                    
                    ::z3::expr constraint = ::z3::implies(
                        fv1.selected && fv2.selected,
                        non_overlap || same_union
                    );
                    
                    ConstraintProvenance prov;
                    prov.description = "Non-overlap or union";
                    prov.is_soft = true;  // Can force union if needed
                    prov.weight = config_.weight_minimize_fields;
                    
                    constraint_tracker_.add_soft(solver_, constraint, prov);
                } else {
                    // Hard non-overlap (no unions allowed)
                    // ... similar but as hard constraint
                }
            }
        }
    }
}
```

---

## Phase 7: Integrated Layout Synthesizer

### 7.1 Updated Layout Synthesizer

**Modify: `include/structor/layout_synthesizer.hpp`**

```cpp
#pragma once

#include "structor/synth_types.hpp"
#include "structor/cross_function_analyzer.hpp"
#include "structor/z3/layout_constraints.hpp"
#include "structor/z3/field_candidates.hpp"
#include "structor/z3/result.hpp"
#include <memory>
#include <chrono>

namespace structor {

/// Result of synthesis attempt with detailed metadata
struct SynthesisResult {
    SynthStruct structure;
    qvector<AccessConflict> conflicts;
    
    // Synthesis metadata
    bool used_z3 = false;
    bool fell_back_to_heuristic = false;
    qstring fallback_reason;
    
    // Constraint satisfaction info
    bool had_relaxation = false;
    qvector<z3::ConstraintProvenance> dropped_constraints;
    qvector<z3::ConstraintProvenance> unsat_core;  // If truly unsatisfiable
    
    // Inferred parameters
    std::optional<uint32_t> inferred_packing;
    
    // Statistics
    int arrays_detected = 0;
    int unions_created = 0;
    int functions_analyzed = 0;
    int raw_bytes_regions = 0;  // Fallback regions
    std::chrono::milliseconds synthesis_time;
    std::chrono::milliseconds z3_solve_time;
};

/// Configuration for layout synthesis
struct LayoutSynthConfig {
    // Z3 configuration
    unsigned z3_timeout_ms = 10000;
    bool use_z3 = true;
    
    // Cross-function analysis
    bool cross_function = true;
    int cross_function_depth = 5;
    bool track_pointer_deltas = true;
    
    // Array detection
    int min_array_elements = 3;
    bool detect_symbolic_arrays = true;
    
    // Union handling
    bool create_unions = true;
    
    // Alignment/packing
    bool infer_packing = true;
    uint32_t default_alignment = 8;
    
    // Fallback behavior (tiered)
    bool relax_alignment_on_unsat = true;
    bool relax_types_on_unsat = true;
    bool use_raw_bytes_fallback = true;
    bool fallback_to_heuristics = true;
};

/// Main layout synthesizer - uses Z3 as primary engine with tiered fallback
class LayoutSynthesizer {
public:
    explicit LayoutSynthesizer(const LayoutSynthConfig& config = {});
    
    /// Synthesize struct from a single function's access pattern
    [[nodiscard]] SynthesisResult synthesize(
        const AccessPattern& pattern,
        const SynthOptions& opts
    );
    
    /// Synthesize struct from pre-computed unified pattern
    [[nodiscard]] SynthesisResult synthesize(
        const UnifiedAccessPattern& unified_pattern
    );
    
    [[nodiscard]] const LayoutSynthConfig& config() const noexcept { return config_; }

private:
    LayoutSynthConfig config_;
    std::unique_ptr<z3::Z3Context> z3_ctx_;
    
    /// Primary synthesis using Z3 with Max-SMT
    [[nodiscard]] std::optional<SynthesisResult> synthesize_z3(
        const UnifiedAccessPattern& pattern
    );
    
    /// Fallback synthesis using heuristics
    [[nodiscard]] SynthesisResult synthesize_heuristic(
        const UnifiedAccessPattern& pattern
    );
    
    /// Tiered fallback strategy
    [[nodiscard]] std::optional<SynthesisResult> try_relaxed_solve(
        z3::LayoutConstraintBuilder& builder,
        const z3::Z3Result& initial_result
    );
    
    // Heuristic methods (existing, for fallback)
    void group_accesses_heuristic(
        const UnifiedAccessPattern& pattern, 
        qvector<OffsetGroup>& groups
    );
    void resolve_conflicts_heuristic(qvector<OffsetGroup>& groups);
    void generate_fields_heuristic(
        const qvector<OffsetGroup>& groups, 
        SynthStruct& result
    );
    void insert_padding_heuristic(SynthStruct& result);
    void infer_field_types_heuristic(
        SynthStruct& result, 
        const UnifiedAccessPattern& pattern
    );
    void generate_field_names(SynthStruct& result);
    void compute_struct_size(SynthStruct& result);
};

} // namespace structor
```

### 7.2 API Integration

**Modify: `include/structor/api.hpp`**

```cpp
struct SynthOptions {
    // ... existing options ...
    
    // === Z3-related options ===
    
    /// Z3 solver timeout in milliseconds
    unsigned z3_timeout_ms = 10000;
    
    /// Enable cross-function analysis with delta normalization
    bool cross_function_analysis = true;
    
    /// Maximum call graph depth for cross-function analysis
    int cross_function_depth = 5;
    
    /// Track pointer arithmetic at call boundaries (ptr+const)
    bool track_pointer_deltas = true;
    
    /// Minimum elements required to detect an array
    int min_array_elements = 3;
    
    /// Use symbolic index detection for arrays
    bool symbolic_array_detection = true;
    
    /// Create actual C union types when overlapping fields detected
    bool create_union_types = true;
    
    /// Infer struct packing from access patterns
    bool infer_packing = true;
    
    /// Fall back to heuristic synthesis if Z3 fails
    bool z3_fallback = true;
};

struct SynthResult {
    // ... existing fields ...
    
    // === Z3-related result fields ===
    
    bool used_z3 = false;
    bool fell_back = false;
    bool had_constraint_relaxation = false;
    qstring fallback_reason;
    
    /// Constraints that were dropped to achieve satisfiability
    qvector<qstring> dropped_constraint_descriptions;
    
    /// Functions that contributed to the unified struct
    qvector<ea_t> unified_from_functions;
    
    /// Pointer deltas detected at call boundaries
    std::unordered_map<ea_t, sval_t> function_pointer_deltas;
    
    int arrays_detected = 0;
    int unions_created = 0;
    std::optional<uint32_t> inferred_packing;
    unsigned z3_solve_time_ms = 0;
};
```

---

## Phase 8: Union Type Creation

### 8.1 Union Type Synthesis

**Modify: `include/structor/structure_persistence.hpp`**

```cpp
/// Create a union type in the IDB
/// Returns the tid_t of the created union, or BADADDR on failure
/// (Note: IDA uses BADADDR for invalid tid_t, not BADNODE)
[[nodiscard]] tid_t create_union(
    const qstring& name,
    const qvector<SynthField>& members
);

/// Create a struct field that is itself an embedded union
/// Union members are added at offset 0 within the union
[[nodiscard]] bool add_union_field(
    struc_t* sptr,
    sval_t outer_offset,          // Offset of union within parent struct
    const qstring& union_name,
    const qvector<SynthField>& union_members
);

/// Compute union size (max of member sizes)
[[nodiscard]] uint32_t compute_union_size(const qvector<SynthField>& members);
```

### 8.2 Raw Bytes Fallback

For truly irreconcilable regions, create `uint8_t __raw_N[size]`:

```cpp
SynthField LayoutConstraintBuilder::create_raw_bytes_field(
    sval_t offset,
    uint32_t size
) {
    SynthField field;
    field.offset = offset;
    field.size = size;
    field.name.sprnt("__raw_%X", static_cast<unsigned>(offset));
    
    // Create uint8_t[size] type
    tinfo_t element_type;
    element_type.create_simple_type(BT_INT8 | BTMT_USIGNED);
    
    tinfo_t array_type;
    array_type.create_array(element_type, size);
    
    field.type = array_type;
    field.semantic = SemanticType::Unknown;
    field.comment = "Irreconcilable access pattern - raw bytes";
    field.is_padding = false;  // Not padding, actual fallback
    
    return field;
}
```

---

## Phase 9: Testing Strategy

### 9.1 IDA-Independent Testing Architecture

**Critical**: Define an IDA-independent IR for Z3 constraint testing:

**New file: `include/structor/z3/test_ir.hpp`**

```cpp
#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <optional>

namespace structor::z3::test {

/// Minimal access representation for testing (no IDA types)
struct TestAccess {
    int64_t offset;
    uint32_t size;
    int type_hint;  // -1 = unknown, 0-N = type category index
    int func_id;    // Function identifier for cross-function tests
    int64_t delta;  // Pointer delta for this function
};

/// Expected field in test output
struct ExpectedField {
    int64_t offset;
    uint32_t size;
    bool is_array;
    uint32_t array_count;
    bool is_union;
    std::vector<ExpectedField> union_members;
};

/// Test case definition
struct TestCase {
    std::string name;
    std::vector<TestAccess> accesses;
    std::vector<ExpectedField> expected_fields;
    bool expect_sat;
    bool expect_arrays;
    bool expect_unions;
    std::optional<uint32_t> expected_packing;
};

/// Load test cases from JSON fixture
std::vector<TestCase> load_test_cases(const char* fixture_path);

} // namespace structor::z3::test
```

### 9.2 Unit Tests

**New file: `test/test_z3_constraints.cpp`**

```cpp
// Pure C++ tests (no IDA dependency)
// - Test constraint building with TestAccess → Z3 constraints
// - Test SAT/UNSAT cases
// - Test model extraction
// - Test UNSAT core extraction
```

**New file: `test/test_array_detection.cpp`**

```cpp
// - Test arithmetic progression detection
// - Test array detection with gaps
// - Test stride > access_size handling (element struct creation)
// - Test symbolic index detection
// - Test type consistency checking
```

**New file: `test/test_cross_function.cpp`**

```cpp
// - Test pointer delta extraction
// - Test offset normalization
// - Test equivalence class building
// - Test with ptr+const at call sites
```

### 9.3 Stress Tests (Per Assumption Register)

```cpp
// ST1: Decompiler offset stability across optimization levels
// ST2: Proportion of non-constant offsets in real binaries
// ST3: Packed struct / unaligned access handling
// ST4: Type hint disagreement frequency
// ST5: Equivalence class explosion with void* plumbing
// ST6: Argument tracking with casts/ternaries
// ST7: Solver timeout behavior
// ST8: Build compatibility across platforms
```

---

## Phase 10: Additional Z3 Opportunities

### 10.1 High-Impact Opportunities (Included in Plan)

1. **Symbolic Index Arrays**: Already included via `detect_symbolic_array()`
2. **Max-SMT Conflict Tolerance**: Already included via soft constraints
3. **Packing/Alignment Inference**: Already included via packing variable
4. **Delta-Aware Cross-Function Unification**: Already included

### 10.2 Medium-Impact Opportunities (Future Work)

5. **Nested Struct Discovery via Factorization**
   ```cpp
   // If accesses cluster into regions with internal patterns,
   // infer nested structs by partitioning offset ranges
   ```

6. **Bitfield Inference**
   ```cpp
   // When observed uses include masks/shifts, infer bitfield ranges
   // Requires bit-precise modeling or range analysis
   ```

7. **Incremental/Cached Solving**
   ```cpp
   // Use push/pop to add new accesses incrementally
   // Amortize solve cost as user analyzes more functions
   ```

8. **Multiple VTable Pointers / MI**
   ```cpp
   // Model multiple vptrs at different offsets
   // Detect base-class layouts from vtable slot relationships
   ```

### 10.3 Lower-Impact Opportunities (Consider Later)

9. **Provenance-Driven Confidence Weights**
   ```cpp
   // Weight constraints by evidence quality:
   // writes > reads, constant offsets > computed,
   // direct deref > casted, multiple functions > single
   ```

---

## Implementation Order

### Sprint 1: Z3 Foundation (1-2 weeks)
1. CMake Z3 integration with FetchContent (commit hash)
2. `z3/context.hpp` - Context with Int-based offsets, global timeout
3. `z3/type_encoding.hpp` - Type encoding with extended info
4. `z3/constraint_tracker.hpp` - UNSAT core tracking
5. `z3/result.hpp` - Result handling with relaxation support
6. Basic unit tests (IDA-independent)

### Sprint 2: Field Candidates & Array Detection (1 week)
1. `z3/field_candidates.hpp` - Candidate universe generation
2. `z3/array_constraints.hpp` - Array detection with stride semantics
3. Element struct creation for stride > access_size
4. Symbolic index detection
5. Array unit tests

### Sprint 3: Layout Constraints (1-2 weeks)
1. `z3/layout_constraints.hpp` - Full constraint builder
2. Hard coverage constraints
3. Soft alignment/type/overlap constraints with weights
4. Packing inference
5. Max-SMT solving with relaxation loop
6. Layout constraint unit tests

### Sprint 4: Cross-Function Analysis (1 week)
1. `call_graph.hpp` - Call graph utilities with caching
2. `cross_function_analyzer.hpp` - Type flow analysis
3. Pointer delta tracking and normalization
4. `UnifiedAccessPattern` implementation
5. Cross-function unit tests with delta cases

### Sprint 5: Integration (1 week)
1. Update `LayoutSynthesizer` with tiered fallback
2. Update `StructorAPI` with new options
3. Union type creation in `StructurePersistence`
4. Raw bytes fallback for irreconcilable regions
5. Integration tests

### Sprint 6: Polish (1 week)
1. Performance optimization (cfunc caching, solver reuse)
2. Documentation
3. Configuration handling
4. Detailed error messages and diagnostics
5. CI updates for Z3 build

---

## File Summary

| Action | Path | Description |
|--------|------|-------------|
| Modify | `CMakeLists.txt` | Add Z3 via FetchContent with both include dirs |
| New | `include/structor/z3/context.hpp` | Z3 context with Int-based sorts |
| New | `include/structor/z3/type_encoding.hpp` | Type encoding with extended info |
| New | `include/structor/z3/constraint_tracker.hpp` | UNSAT core tracking |
| New | `include/structor/z3/result.hpp` | Z3 result with relaxation support |
| New | `include/structor/z3/field_candidates.hpp` | Candidate universe generation |
| New | `include/structor/z3/array_constraints.hpp` | Array detection with stride semantics |
| New | `include/structor/z3/layout_constraints.hpp` | Layout constraint builder with Max-SMT |
| New | `include/structor/z3/test_ir.hpp` | IDA-independent test IR |
| New | `include/structor/call_graph.hpp` | Call graph utilities with caching |
| New | `include/structor/cross_function_analyzer.hpp` | Delta-aware cross-function analysis |
| Modify | `include/structor/synth_types.hpp` | Add UnifiedAccessPattern with deltas |
| Modify | `include/structor/layout_synthesizer.hpp` | Z3 primary with tiered fallback |
| Modify | `include/structor/structure_persistence.hpp` | Union + raw bytes creation |
| Modify | `include/structor/api.hpp` | New options and result fields |
| Modify | `include/structor/config.hpp` | Z3 configuration options |
| New | `test/test_z3_context.cpp` | Z3 context tests |
| New | `test/test_type_encoding.cpp` | Type encoding tests |
| New | `test/test_array_detection.cpp` | Array detection tests |
| New | `test/test_layout_constraints.cpp` | Layout constraint tests |
| New | `test/test_cross_function.cpp` | Cross-function tests with deltas |
| New | `test/test_z3_synthesis_integration.cpp` | Integration tests |
| New | `test/fixtures/access_patterns.json` | JSON test fixtures |
| Modify | `README.md` | Document Z3 features |

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Z3 build time slows CI | Cache Z3 build artifacts; use shallow clone + commit hash |
| Z3 binary size increases plugin | Static link with LTO; strip symbols in release |
| Z3 timeout on complex structs | Configurable timeout; tiered relaxation; heuristic fallback |
| Cross-function analysis too slow | Depth limit; cfunc caching; early termination |
| Array false positives | Require min 3 elements; type consistency; stride semantics |
| Union over-detection | Only create union when Z3 proves necessity |
| Packed struct UNSAT | Soft alignment constraints; packing inference |
| Exception handling | Verify no -fno-exceptions in build |
| UI thread blocking | Consider async/execute_sync patterns (future) |

---

## Assumption Register

| ID | Assumption | Stress Test | Dependencies |
|----|------------|-------------|--------------|
| A1 | Decompiler offsets are correct/stable | Compile with O0/O2/O3, verify offsets | All synthesis |
| A2 | Most offsets are constant integers | Measure non-constant proportion | Array detection |
| A3 | Alignment can be soft (packed structs exist) | Test with packed structs | Z3 SAT rate |
| A4 | Type hints are reliable enough to constrain | Count cross-function conflicts | Type encoding |
| A5 | Call graph traversal produces true equivalence | Test void* plumbing | Cross-function |
| A6 | Argument tracking works through casts/phi | Complex callsite tests | Forward tracing |
| A7 | Z3 can handle typical structs in <10s | Benchmark with large patterns | Timeout config |
| A8 | Z3 C++ API is compatible with plugin build | Build on Win/macOS/Linux | Entire Z3 approach |

---

## Success Criteria

1. **Correctness**: Z3-synthesized structs pass all existing tests
2. **Access-Soundness**: Every access is covered by a field in the layout
3. **Array Detection**: Detect arrays in >90% of obvious cases (3+ elements, regular stride)
4. **Cross-Function**: Unify struct definitions with correct delta normalization
5. **Performance**: Synthesis completes in <15 seconds for typical structs
6. **Fallback**: Graceful tiered degradation (relax → raw bytes → heuristics)
7. **Union Accuracy**: Create unions only when Z3 proves mathematical necessity
8. **Packed Struct Support**: Handle unaligned accesses without unnecessary UNSAT

---

## References

- de Moura, L.; Bjørner, N. "Z3: An Efficient SMT Solver." TACAS 2008. DOI: 10.1007/978-3-540-78800-3_24
- Z3 project license: MIT License (Z3Prover/z3 repository)
- Z3 C++ API documentation: https://z3prover.github.io/api/html/classz3_1_1solver.html
- CMake FetchContent: https://cmake.org/cmake/help/latest/module/FetchContent.html
- IDA structure/union API: `ida_struct.add_struc(..., is_union=...)`
- Hex-Rays decompiler API: `ida_hexrays` module documentation
