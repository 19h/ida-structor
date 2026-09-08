#pragma once

#include <z3++.h>
#include "structor/z3/context.hpp"
#include "structor/z3/calling_convention_model.hpp"
#include "structor/z3/type_lattice.hpp"
#include "structor/z3/model_value_evidence.hpp"
#include "structor/z3/instruction_semantics.hpp"
#include "structor/z3/memory_type_evidence.hpp"
#include "structor/z3/constraint_source_evidence.hpp"
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
/// It is disabled by default. Memory inference is limited to constrained
/// absolute/global scalar views; signature-result inference and interprocedural
/// fixed-point inference are not implemented.
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

    /// Shared budget for checking selected local values against hard constraints.
    ModelEvidenceBudget model_evidence_budget;
    
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
    unsigned memory_locations_typed = 0;
    unsigned memory_locations_omitted = 0;
    unsigned unresolved_memory_accesses = 0;
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
    unsigned model_evidence_queries = 0;
    unsigned model_values_determined = 0;
    unsigned model_values_ambiguous = 0;
    unsigned model_values_unverified = 0;
    std::chrono::milliseconds model_evidence_time{0};
    
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

    // Engine values are selected candidates. Absence of a status denotes an
    // externally constructed result whose evidence is the caller's contract.
    std::optional<ModelValueStatus> model_value_status;
    std::optional<InferredType> alternative_type;
    qstring model_value_reason;
    // Present when the supplied hard formulas used generic symbolic bounds.
    // Such uniqueness is relative to those formulas, not the full type domain.
    std::optional<SymbolicTypeQueryBounds> evidence_query_bounds;

    [[nodiscard]] bool may_apply_model_value(bool allow_candidates = false) const noexcept {
        return allow_candidates || !model_value_status ||
            (*model_value_status == ModelValueStatus::DeterminedByHardConstraints &&
             !evidence_query_bounds);
    }
    
    // Source records from the connected effective-constraint component.
    // The flags describe available origins, not causes or independent evidence.
    std::vector<ConstraintSourceEvidence> source_evidence;
    qvector<ea_t> source_constraints;
    bool from_signature = false;
    bool from_decompiler = false;
    bool from_alias = false;
    bool from_usage = false;
    
    void record_source_evidence(VariableSourceEvidence sources) {
        source_evidence = std::move(sources.records);
        source_constraints.clear();
        for (const auto site : sources.source_sites) source_constraints.push_back(site);
        from_signature = sources.from_signature;
        from_decompiler = sources.from_decompiler;
        from_alias = sources.from_alias;
        from_usage = sources.from_usage;
    }

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
    
    // Exact absolute/global locations; these are not selected-pointer-relative
    // structure fields. Conflicting or unsupported views remain diagnostic.
    InferredMemoryTypes memory_types;
    ExactMemoryLocationMap<MemoryTypeProvenance> memory_provenance;
    std::vector<MemoryInferenceDiagnostic> memory_diagnostics;
    // Signature-result inference remains unavailable.
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

    /// Get the selected candidate; inspect local_types for its model evidence
    [[nodiscard]] std::optional<InferredType> get_var_type(int var_idx) const;
    
    /// Get one exact memory view, including its access width in bytes.
    [[nodiscard]] std::optional<InferredType> get_mem_type(
        ea_t base, sval_t offset, std::uint32_t size) const;
    /// Compatibility lookup returns no result when multiple widths exist.
    [[deprecated("supply the memory access width for an exact lookup")]]
    [[nodiscard]] std::optional<InferredType> get_mem_type(ea_t base, sval_t offset) const;
    
    /// Convert determined unbounded values, or explicitly include candidates.
    /// Externally constructed results retain their caller-provided semantics.
    [[nodiscard]] std::unordered_map<int, tinfo_t> to_ida_types(
        bool include_model_candidates = false) const;
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
    friend struct TypeInferenceMemoryTestAccess;
    friend struct TypeInferenceSourceTestAccess;
    friend struct TypeInferenceQueryStatusTestAccess;
    friend struct TypeInferenceModelEvidenceTestAccess;
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
    bool hard_constraints_use_symbolic_bounds_ = false;
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
        const ::z3::expr_vector& hard_constraints,
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
