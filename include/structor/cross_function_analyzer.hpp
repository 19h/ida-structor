#pragma once

#ifndef STRUCTOR_TESTING
#include <pro.h>
#include <hexrays.hpp>
#endif
#include <utility>
#include <unordered_set>
#include <unordered_map>
#include <chrono>
#include "structor/synth_types.hpp"
#include "structor/access_collector.hpp"

namespace structor {

/// Identifies a variable in a specific function with its base delta
struct FunctionVariable {
    ea_t func_ea;
    int var_idx;
    sval_t base_delta;  // Constant offset from the "canonical" base pointer

    FunctionVariable()
        : func_ea(BADADDR)
        , var_idx(-1)
        , base_delta(0) {}

    FunctionVariable(ea_t f, int v, sval_t d = 0)
        : func_ea(f)
        , var_idx(v)
        , base_delta(d) {}

    bool operator==(const FunctionVariable& other) const noexcept {
        return func_ea == other.func_ea && var_idx == other.var_idx;
    }

    bool operator!=(const FunctionVariable& other) const noexcept {
        return !(*this == other);
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
    ea_t caller_ea;         // Calling function
    ea_t callee_ea;         // Called function
    ea_t call_site;         // Address of call instruction
    int caller_var_idx;     // Variable in caller being passed
    int callee_param_idx;   // Parameter index in callee
    sval_t delta;           // Constant added to pointer at call site (0 if none)
    bool is_direct_call;    // True if direct call, false if indirect/virtual

    PointerFlowEdge()
        : caller_ea(BADADDR)
        , callee_ea(BADADDR)
        , call_site(BADADDR)
        , caller_var_idx(-1)
        , callee_param_idx(-1)
        , delta(0)
        , is_direct_call(true) {}
};

/// Call site metadata for cross-function flow
struct CalleeCallInfo {
    ea_t call_ea = BADADDR;
    ea_t callee_ea = BADADDR;
    int arg_idx = -1;
    sval_t delta = 0;
    bool is_direct = false;
    bool by_ref = false;
    tinfo_t funcptr_type;
};

/// Caller metadata for backward flow
struct CallerCallInfo {
    ea_t call_ea = BADADDR;
    ea_t caller_ea = BADADDR;
    int var_idx = -1;
    sval_t delta = 0;
    bool by_ref = false;
};

/// Represents a set of variables across functions that share the same underlying type
struct TypeEquivalenceClass {
    qvector<FunctionVariable> variables;
    qvector<AccessPattern> patterns;
    qvector<PointerFlowEdge> flow_edges;  // How pointers flow between functions

    /// Check if a variable is in this equivalence class
    [[nodiscard]] bool contains(ea_t func_ea, int var_idx) const noexcept {
        for (const auto& var : variables) {
            if (var.func_ea == func_ea && var.var_idx == var_idx) {
                return true;
            }
        }
        return false;
    }

    /// Total number of accesses across all patterns
    [[nodiscard]] std::size_t total_accesses() const noexcept {
        std::size_t total = 0;
        for (const auto& pattern : patterns) {
            total += pattern.accesses.size();
        }
        return total;
    }

    /// Get all unique functions in this equivalence class
    [[nodiscard]] qvector<ea_t> unique_functions() const {
        qvector<ea_t> result;
        for (const auto& var : variables) {
            bool found = false;
            for (const auto& f : result) {
                if (f == var.func_ea) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                result.push_back(var.func_ea);
            }
        }
        return result;
    }
};

/// Unified access pattern combining observations from multiple functions
/// All offsets are normalized to a canonical base
struct UnifiedAccessPattern {
    qvector<AccessPattern> per_function_patterns;
    qvector<FieldAccess> all_accesses;  // Merged, deduplicated, delta-normalized
    qvector<ea_t> contributing_functions;
    qvector<PointerFlowEdge> flow_edges;

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

    /// Get total size estimate (max_offset - min_offset)
    [[nodiscard]] sval_t estimated_size() const noexcept {
        return global_max_offset - global_min_offset;
    }

    /// Get unique access locations (by offset + size)
    [[nodiscard]] std::size_t unique_access_locations() const;

    /// Check if pattern has any accesses
    [[nodiscard]] bool empty() const noexcept {
        return all_accesses.empty();
    }
};

/// Configuration for cross-function analysis
struct CrossFunctionConfig {
    int max_depth = 5;                    // Maximum call graph traversal depth
    bool follow_forward = true;           // Follow caller -> callee (parameter passing)
    bool follow_backward = true;          // Follow callee -> caller (return values)
    int max_functions = 100;              // Maximum functions to analyze
    bool include_indirect_calls = false;  // Include indirect/virtual calls
    bool track_pointer_deltas = true;     // Track ptr+const adjustments (recommended)
};

/// Forward declarations for SynthOptions
struct SynthOptions;

/// Statistics about a cross-function analysis run
struct CrossFunctionStats {
    int functions_analyzed = 0;
    int total_accesses = 0;
    int max_depth_reached = 0;
    int pointer_deltas_detected = 0;
    int flow_edges_found = 0;
    std::chrono::milliseconds analysis_time{0};

    [[nodiscard]] qstring summary() const {
        qstring result;
        result.sprnt("Cross-Function Analysis:\n");
        result.cat_sprnt("  Functions: %d\n", functions_analyzed);
        result.cat_sprnt("  Accesses: %d\n", total_accesses);
        result.cat_sprnt("  Max depth: %d\n", max_depth_reached);
        result.cat_sprnt("  Deltas detected: %d\n", pointer_deltas_detected);
        result.cat_sprnt("  Flow edges: %d\n", flow_edges_found);
        result.cat_sprnt("  Time: %lldms\n",
                        static_cast<long long>(analysis_time.count()));
        return result;
    }
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
    [[nodiscard]] const CrossFunctionStats& stats() const noexcept { return stats_; }

    /// Find all callees where var is passed as an argument
    /// Returns: vector of call site infos (callee, arg index, delta, by-ref)
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

    /// Reset analysis state for a new analysis
    void reset();

private:
    CrossFunctionConfig config_;
    TypeEquivalenceClass equiv_class_;
    CrossFunctionStats stats_;

    // Visited set to prevent infinite recursion
    std::unordered_set<FunctionVariable, FunctionVariableHash> visited_;

    // Tracks base-indirection adjustments applied per function variable
    std::unordered_set<FunctionVariable, FunctionVariableHash> base_indirection_adjusted_;

    // Accumulated deltas for each function variable
    std::unordered_map<FunctionVariable, sval_t, FunctionVariableHash> deltas_;

    // Collected patterns before normalization
    qvector<AccessPattern> collected_patterns_;

    // Current synthesis options (for pattern collection)
    const SynthOptions* current_opts_ = nullptr;

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

    /// Add a variable to the equivalence class
    void add_variable(ea_t func_ea, int var_idx, sval_t delta);

    /// Add a flow edge
    void add_flow_edge(const PointerFlowEdge& edge);

    /// Check if analysis limits have been reached
    [[nodiscard]] bool limits_reached() const noexcept;

    /// Get or decompile a function (with caching)
    [[nodiscard]] cfuncptr_t get_cfunc(ea_t func_ea);

    /// Collect return sources as (var_idx, delta) pairs
    [[nodiscard]] qvector<std::pair<int, sval_t>> find_return_sources(cfunc_t* cfunc);

    /// Find assignments of call return values in the current function
    [[nodiscard]] qvector<std::pair<ea_t, int>> find_return_assignments(cfunc_t* cfunc);

    /// Find callers that assign this function's return to a variable
    [[nodiscard]] qvector<std::pair<ea_t, int>> find_callers_with_return(ea_t func_ea);

    /// Internal function cache to avoid redundant decompilation
    std::unordered_map<ea_t, cfuncptr_t> cfunc_cache_;
};

/// Expression visitor for finding variable references in call arguments
class ArgDeltaExtractor : public ctree_visitor_t {
public:
    ArgDeltaExtractor(int target_var_idx);

    int idaapi visit_expr(cexpr_t* e) override;

    /// Get the extracted delta (if found)
    [[nodiscard]] std::optional<sval_t> delta() const noexcept { return delta_; }

    /// Check if the target variable was found
    [[nodiscard]] bool found() const noexcept { return found_; }

    /// Check if the target variable was passed by reference
    [[nodiscard]] bool by_ref() const noexcept { return by_ref_; }

private:
    int target_var_idx_;
    std::optional<sval_t> delta_;
    bool found_ = false;
    bool by_ref_ = false;

    /// Check if an expression is a reference to target variable
    [[nodiscard]] bool is_target_var(cexpr_t* e) noexcept;
};

/// Expression visitor for finding call sites that pass a specific variable
class CallSiteFinder : public ctree_visitor_t {
public:
    CallSiteFinder(int target_var_idx);

    int idaapi visit_expr(cexpr_t* e) override;

    /// Information about a found call site
    struct CallInfo {
        ea_t call_ea;           // Address of call instruction
        ea_t callee_ea;         // Address of called function (BADADDR if indirect)
        int arg_idx;            // Argument index where variable is passed
        sval_t delta;           // Delta applied to variable (0 if none)
        bool is_direct;         // True if direct call
        bool by_ref;            // True if argument is passed by reference
        tinfo_t funcptr_type;   // Inferred function pointer type (if any)

        CallInfo()
            : call_ea(BADADDR)
            , callee_ea(BADADDR)
            , arg_idx(-1)
            , delta(0)
            , is_direct(false)
            , by_ref(false) {}
    };

    /// Get all found call sites
    [[nodiscard]] const qvector<CallInfo>& calls() const noexcept { return calls_; }

private:
    int target_var_idx_;
    qvector<CallInfo> calls_;
    std::unordered_map<int, std::pair<int, sval_t>> aliases_;

    /// Process a call expression
    void process_call(cexpr_t* call_expr);
    void bind_or_clear_alias(int lhs_var_idx, const cexpr_t* rhs);

    [[nodiscard]] bool contains_ref(const cexpr_t* expr) const;
    [[nodiscard]] bool resolve_var_delta(const cexpr_t* expr, int& var_idx, sval_t& delta) const;

    /// Extract callee address from call expression
    [[nodiscard]] ea_t get_callee_address(cexpr_t* call_expr) const;

    /// Check if call is direct
    [[nodiscard]] bool is_direct_call(cexpr_t* call_expr) const;
};

/// Expression visitor for finding callers that pass to a specific parameter
class CallerFinder {
public:
    CallerFinder(ea_t target_func, int param_idx);

    /// Find all callers and their corresponding variables with pointer deltas
    /// Returns caller metadata with delta and by-ref information
    [[nodiscard]] qvector<CallerCallInfo> find_callers();

private:
    ea_t target_func_;
    int param_idx_;

    /// Process a single caller function
    void process_caller(ea_t caller_ea, ea_t call_site, qvector<CallerCallInfo>& result);
};

} // namespace structor
