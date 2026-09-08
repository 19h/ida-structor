#pragma once

#include <z3++.h>
#include "structor/z3/context.hpp"
#include "structor/z3/calling_convention_model.hpp"
#include "structor/z3/type_lattice.hpp"
#include "structor/z3/instruction_semantics.hpp"
#include "structor/z3/alias_analysis.hpp"
#include "structor/z3/layout_constraints.hpp"
#include "structor/synth_types.hpp"
#include "structor/cross_function_analyzer.hpp"

#ifndef STRUCTOR_TESTING
#include <hexrays.hpp>
#endif

#include <chrono>
#include <cstdint>
#include <functional>

namespace structor::z3 {

/// Configuration for the experimental type inference adjunct.
///
/// This pipeline is independent of the production structure-layout solver.
/// It is disabled by default because memory-location inference, signature
/// inference, and interprocedural fixed-point inference are not implemented.
struct TypeInferenceConfig {
    /// Explicit opt-in required by every inference entry point.
    bool enable_experimental_pipeline = false;

    // Phase enables
    bool phase_constraint_extraction = true;
    bool phase_alias_analysis = true;
    bool phase_soft_constraints = true;
    
    // Constraint generation
    InstructionSemanticsConfig semantics_config;
    
    // Alias analysis
    AliasAnalysisConfig alias_config;
    
    // Solver configuration
    unsigned solver_timeout_ms = 10000;
    
    // Type preference weights (for MaxSMT)
    int weight_signed_over_unsigned = 5;
    int weight_from_signature = 20;
};

/// Stable result category for the experimental inference adjunct.
enum class TypeInferenceStatus : std::uint8_t {
    ExperimentalDisabled = 0,
    InvalidInput,
    SolverFailure,
    UnsupportedOperation,
    InternalError,
    Success,
    NoModelWithinSymbolicBounds,
    SymbolicQueryBudgetExceeded,
};

/// Statistics from type inference
struct TypeInferenceStats {
    // Phase timings
    std::chrono::milliseconds constraint_extraction_time{0};
    std::chrono::milliseconds alias_analysis_time{0};
    std::chrono::milliseconds constraint_building_time{0};
    std::chrono::milliseconds solving_time{0};
    std::chrono::milliseconds total_time{0};
    
    // Counts
    unsigned functions_analyzed = 0;
    unsigned variables_typed = 0;
    unsigned type_constraints_hard = 0;
    unsigned type_constraints_soft = 0;
    // Compatibility counters: the adjunct has no relaxation phase and these
    // remain zero/false in engine-produced results.
    unsigned constraints_relaxed = 0;
    unsigned alias_pairs_found = 0;
    
    // Results
    unsigned types_inferred = 0;
    unsigned types_pointer = 0;
    unsigned types_integer = 0;
    unsigned types_floating = 0;
    unsigned types_unknown = 0;
    
    // Solver iterations
    unsigned solve_iterations = 0;
    bool used_relaxation = false;
    
    [[nodiscard]] qstring summary() const;
};

/// Result of type inference for a single variable
struct InferredVariableType {
    int var_idx;
    qstring var_name;
    InferredType type;
    TypeConfidence confidence;
    
    // Reserved provenance slots. The current engine does not populate them.
    qvector<ea_t> source_constraints;
    bool from_signature = false;
    bool from_decompiler = false;
    bool from_alias = false;
    bool from_usage = false;
    
    InferredVariableType()
        : var_idx(-1)
        , confidence(TypeConfidence::Low) {}
};

/// Result of type inference for a function
struct FunctionTypeInferenceResult {
    ea_t func_ea = BADADDR;
    qstring func_name;
    
    // Inferred types for local variables
    qvector<InferredVariableType> local_types;
    
    // External-result slots. The current engine leaves memory and signature
    // outputs empty; callers may populate them only in explicitly constructed
    // FunctionTypeInferenceResult values.
    std::unordered_map<std::size_t, InferredType> memory_types;  // hash -> type
    std::optional<InferredType> return_type;
    qvector<InferredType> param_types;
    
    // Status
    TypeInferenceStatus status = TypeInferenceStatus::ExperimentalDisabled;
    bool success = false;
    qstring error_message;
    TypeInferenceStats stats;
    
    // Present only for an explicitly enabled inference run. The flag records
    // whether a non-ground predicate used the configured finite type domain.
    std::optional<SymbolicTypeQueryBounds> symbolic_query_bounds;
    bool used_bounded_symbolic_queries = false;
    bool used_explicit_symbolic_candidates = false;

    /// Get inferred type for a variable
    [[nodiscard]] std::optional<InferredType> get_var_type(int var_idx) const;
    
    /// Get inferred type for a memory location
    [[nodiscard]] std::optional<InferredType> get_mem_type(ea_t base, sval_t offset) const;
    
    /// Convert all inferred types to IDA tinfo_t
    [[nodiscard]] std::unordered_map<int, tinfo_t> to_ida_types() const;
};

/// Callback for progress reporting
using InferenceProgressCallback = std::function<void(
    const char* phase,
    int progress,      // 0-100
    const char* message
)>;

/// Main type inference engine
/// Orchestrates all phases of the type inference pipeline
class TypeInferenceEngine {
public:
    TypeInferenceEngine(
        Z3Context& ctx,
        const TypeInferenceConfig& config = {}
    );
    
    /// Infer types for all variables in a function
    [[nodiscard]] FunctionTypeInferenceResult infer_function(cfunc_t* cfunc);
    
    /// Infer a specific variable. Throws std::runtime_error when the pipeline
    /// is disabled or the containing function inference fails; use
    /// infer_function() when typed failure status is required.
    [[nodiscard]] InferredVariableType infer_variable(
        cfunc_t* cfunc,
        int var_idx
    );
    
    /// Interprocedural fixed-point inference is not implemented. This method
    /// returns UnsupportedOperation for every supplied function and performs
    /// no analysis or mutation.
    [[deprecated("interprocedural type inference is unavailable; use infer_function for explicit experimental per-function analysis")]]
    [[nodiscard]] std::vector<FunctionTypeInferenceResult> infer_cross_function(
        const qvector<cfunc_t*>& cfuncs
    );
    
    /// Set progress callback
    void set_progress_callback(InferenceProgressCallback callback) {
        progress_callback_ = std::move(callback);
    }
    
    /// Get configuration
    [[nodiscard]] const TypeInferenceConfig& config() const noexcept { return config_; }
    
    /// Modify configuration
    TypeInferenceConfig& config() noexcept { return config_; }
    
    /// Get statistics from last inference
    [[nodiscard]] const TypeInferenceStats& last_stats() const noexcept { return last_stats_; }

private:
#if defined(STRUCTOR_LIVE_TEST_HOOKS)
    friend struct TypeInferenceSignatureTestAccess;
    friend struct TypeInferenceQueryStatusTestAccess;
#endif
    Z3Context& ctx_;
    TypeInferenceConfig config_;
    TypeInferenceStats last_stats_;
    InferenceProgressCallback progress_callback_;
    
    // Sub-analyzers
    std::unique_ptr<InstructionSemanticsExtractor> semantics_extractor_;
    std::unique_ptr<AliasAnalyzer> alias_analyzer_;
    TypeLatticeEncoder type_encoder_;
    
    // Current analysis state
    cfunc_t* current_cfunc_ = nullptr;
    TypeConstraintSet current_constraints_;
    std::unordered_map<int, TypeVariable> var_to_type_var_;
    
    /// Phase 1: Extract type constraints from ctree
    void phase_constraint_extraction(cfunc_t* cfunc);
    
    /// Phase 2: Perform alias analysis
    void phase_alias_analysis(cfunc_t* cfunc);
    
    /// Phase 3: Generate soft constraints (heuristics)
    void phase_soft_constraints(cfunc_t* cfunc);
    
    /// Phase 4: Build Z3 constraints
    ::z3::optimize build_z3_constraints();
    
    /// Phase 5: Solve constraints
    ::z3::check_result phase_solve(::z3::optimize& opt, ::z3::model& out_model);
    
    /// Phase 6: Extract results from model
    void extract_results(
        const ::z3::model& model,
        FunctionTypeInferenceResult& result
    );
    
    /// Report progress
    void report_progress(const char* phase, int progress, const char* message);
    
    /// Initialize sub-analyzers
    void initialize_analyzers();
    
    /// Reset analysis state
    void reset_state();
    
    /// Get or create TypeVariable for a local variable
    [[nodiscard]] TypeVariable get_type_var(int var_idx);
    
    /// Add type preference soft constraints
    void add_type_preferences();
    
    /// Add calling convention constraints
    void add_calling_convention_constraints(cfunc_t* cfunc);
};

/// Experimental type-scheme descriptor. InferredType currently has no type-
/// parameter node, so non-trivial instantiation fails explicitly.
struct TypeScheme {
    struct TypeParam {
        int id;
        qstring name;
    };
    
    qvector<TypeParam> type_params;  // Universally quantified variables
    InferredType body;               // The actual type with type params as unknowns
    
    /// Check if this is a polymorphic (non-trivial) type scheme
    [[nodiscard]] bool is_polymorphic() const noexcept { return !type_params.empty(); }
    
    /// Instantiate a monomorphic scheme. Throws std::logic_error when
    /// type_params is non-empty; substituting those parameters is unsupported.
    [[deprecated("non-trivial polymorphic type-scheme instantiation is unsupported")]]
    [[nodiscard]] std::pair<InferredType, std::unordered_map<int, TypeVariable>> 
    instantiate(int call_site_id, std::function<TypeVariable(int, const char*)> make_var) const;
};

/// Explicit catalog of caller-registered polymorphic function descriptors.
/// No name-, import-, or usage-based automatic detection is performed.
class PolymorphicFunctionDetector {
public:
    PolymorphicFunctionDetector(Z3Context& ctx);
    
    /// Check whether a descriptor was explicitly registered for this address.
    [[nodiscard]] bool is_polymorphic(ea_t func_ea) const;
    
    /// Get an explicitly registered type scheme.
    [[nodiscard]] std::optional<TypeScheme> get_type_scheme(ea_t func_ea) const;
    
    /// Register a known polymorphic function
    void register_polymorphic(ea_t func_ea, TypeScheme scheme);
    
private:
    std::unordered_map<ea_t, TypeScheme> known_schemes_;
};

/// Calling convention detector
class CallingConventionDetector {
public:
    using Convention = CallingConvention;
    
    CallingConventionDetector(Z3Context& ctx);
    
    /// Select a represented convention from the recovered prototype or target
    /// default. This does not prove that a function obeys the default: an
    /// unrecognized per-function ABI override can be absent from IDA metadata.
    /// Unknown/custom target variants remain Unknown; the host is irrelevant.
    [[nodiscard]] CallingConventionDetection detect_with_evidence(cfunc_t* cfunc);
    [[nodiscard]] Convention detect(cfunc_t* cfunc);
    
    /// Get parameter types based on convention
    [[nodiscard]] qvector<InferredType> get_param_constraints(
        Convention conv,
        cfunc_t* cfunc
    );
    
    /// Get return type constraints based on convention
    [[nodiscard]] std::optional<InferredType> get_return_constraint(
        Convention conv,
        cfunc_t* cfunc
    );
    
    /// Get fixed-prototype x64 scalar/pointer locations. Unsupported conventions,
    /// types, variadic calls, or unspecified prototype mode return an empty
    /// vector. Stack offsets are bytes from the callee-entry stack pointer.
    /// FixedPrototype asserts the supplied convention and complete ABI argument
    /// list, including hidden arguments. TargetDefault detection alone does not
    /// discharge this precondition.
    struct ParamLocation {
        bool is_register = false;
        qstring reg_name;      // If is_register
        sval_t stack_offset = 0;   // If !is_register
    };
    [[nodiscard]] std::vector<ParamLocation> get_param_locations(
        Convention conv,
        const qvector<InferredType>& param_types,
        ParameterPassingMode mode = ParameterPassingMode::Unspecified
    );

private:
    Z3Context& ctx_;
    
    /// Heuristics to detect convention
    [[nodiscard]] Convention detect_from_prologue(cfunc_t* cfunc);
    [[nodiscard]] Convention detect_from_param_usage(cfunc_t* cfunc);
};

} // namespace structor::z3
