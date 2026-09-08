#pragma once

#include "structor/z3/type_inference_engine.hpp"
#include "structor/z3/type_lattice.hpp"
#include "structor/type_propagator.hpp"
#include "structor/synth_types.hpp"
#include "structor/config.hpp"

#ifndef STRUCTOR_TESTING
#include <hexrays.hpp>
#endif

#include <unordered_map>
#include <functional>

namespace structor::z3 {

/// Configuration for type application
struct TypeApplicationConfig {
    /// Minimum confidence level to apply a type
    TypeConfidence min_confidence = TypeConfidence::Medium;

    /// Explicitly allow ambiguous, unverified, or bounded-domain model values.
    /// The confidence threshold is still checked independently.
    bool allow_model_candidates = false;
    
    /// Whether to propagate types to callers/callees. Disabled unless the
    /// caller explicitly expands mutation beyond the selected function.
    bool propagate_types = false;
    
    /// Whether to overwrite existing non-default types
    bool overwrite_existing = false;
    
    /// Whether to apply pointer types (often the most impactful)
    bool apply_pointer_types = true;
    
    /// Whether to apply scalar types (int, float, etc.)
    bool apply_scalar_types = true;
    
    /// Whether to apply inferred function signatures
    bool apply_signatures = false;
    
    /// Whether to force decompiler refresh after applying types
    bool force_refresh = true;
    
    /// Callback for reporting application progress
    std::function<void(int var_idx, const char* var_name, bool success, const char* reason)> 
        application_callback;
};

/// Result of applying types to a function
struct TypeApplicationResult {
    ea_t func_ea = BADADDR;
    qstring error_message;
    
    /// Types successfully applied
    struct AppliedType {
        int var_idx;
        qstring var_name;
        InferredType inferred;
        tinfo_t applied;
        TypeConfidence confidence;
    };
    qvector<AppliedType> applied;
    
    /// Types that failed to apply
    struct FailedType {
        int var_idx;
        qstring var_name;
        InferredType inferred;
        qstring reason;
    };
    qvector<FailedType> failed;
    
    /// Types that were skipped (e.g., low confidence, already typed)
    struct SkippedType {
        int var_idx;
        qstring var_name;
        qstring reason;
    };
    qvector<SkippedType> skipped;
    
    /// Propagation results (if enabled)
    PropagationResult propagation;
    
    /// Statistics
    unsigned total_variables = 0;
    unsigned applied_count = 0;
    unsigned failed_count = 0;
    unsigned skipped_count = 0;
    unsigned propagated_count = 0;
    bool signature_requested = false;
    bool signature_applied = false;
    bool signature_failed = false;
    bool signature_rollback_failed = false;
    bool incomplete = false;
    
    /// Overall success
    [[nodiscard]] bool success() const {
        return (applied_count > 0 || signature_applied) &&
            failed_count == 0 && !signature_failed && !incomplete;
    }
    
    /// Get summary string
    [[nodiscard]] qstring summary() const;
};

/// Applies inferred types from TypeInferenceEngine to the IDA decompiler
class TypeApplicator {
public:
    TypeApplicator(const TypeApplicationConfig& config = {});
    
    /// Apply successful inference belonging to this exact function address.
    /// Unknown or foreign function identities are rejected before mutation.
    [[nodiscard]] TypeApplicationResult apply(
        cfunc_t* cfunc,
        const FunctionTypeInferenceResult& inference_result
    );
    
    /// Apply a single inferred type to a variable
    [[nodiscard]] bool apply_variable(
        cfunc_t* cfunc,
        int var_idx,
        const InferredType& type,
        TypeConfidence confidence,
        qstring* out_reason = nullptr
    );

    /// Reports whether the most recent variable application could not restore
    /// its saved local/prototype state. Callers that own referenced named
    /// types must retain them when this is true.
    [[nodiscard]] bool last_application_rollback_failed() const noexcept {
        return propagator_.last_application_rollback_failed();
    }
    
    /// Apply inferred types and propagate across call graph
    [[nodiscard]] TypeApplicationResult apply_and_propagate(
        cfunc_t* cfunc,
        const FunctionTypeInferenceResult& inference_result
    );
    
    /// Run the full type inference and application pipeline
    /// Combines TypeInferenceEngine::infer_function() with apply()
    [[nodiscard]] TypeApplicationResult infer_and_apply(
        Z3Context& ctx,
        cfunc_t* cfunc,
        const TypeInferenceConfig& inference_config = {}
    );
    
    /// Apply inferred function signature (return type + parameters), requiring
    /// a successful result belonging to this exact function address.
    [[nodiscard]] bool apply_signature(
        cfunc_t* cfunc,
        const FunctionTypeInferenceResult& inference_result
    );
    
    /// Refresh the decompiler view after type changes
    void refresh_decompiler(cfunc_t* cfunc);
    
    /// Get/set configuration
    [[nodiscard]] const TypeApplicationConfig& config() const noexcept { return config_; }
    TypeApplicationConfig& config() noexcept { return config_; }

private:
    TypeApplicationConfig config_;
    TypePropagator propagator_;
    bool last_signature_rollback_failed_ = false;
    
    /// Check if a type should be applied based on config and current state
    [[nodiscard]] bool should_apply(
        cfunc_t* cfunc,
        int var_idx,
        const InferredType& type,
        TypeConfidence confidence,
        qstring* out_reason = nullptr
    );
    
    /// Convert InferredType to tinfo_t and validate
    [[nodiscard]] tinfo_t prepare_type(
        const InferredType& type,
        cfunc_t* cfunc,
        int var_idx
    );
    
    /// Apply tinfo_t to a local variable
    [[nodiscard]] bool apply_tinfo(
        cfunc_t* cfunc,
        int var_idx,
        const tinfo_t& type,
        qstring* out_reason = nullptr
    );
    
    /// Check if variable already has a meaningful (non-default) type
    [[nodiscard]] bool has_meaningful_type(cfunc_t* cfunc, int var_idx);
    
    /// Report application result via callback
    void report_application(
        int var_idx, 
        const char* var_name, 
        bool success, 
        const char* reason
    );
};

/// Convenience function: run inference and apply types to a function
[[nodiscard]] TypeApplicationResult infer_and_apply_types(
    cfunc_t* cfunc,
    const TypeInferenceConfig& inference_config = {},
    const TypeApplicationConfig& application_config = {}
);

/// Convenience function: apply types from inference result
[[nodiscard]] TypeApplicationResult apply_inferred_types(
    cfunc_t* cfunc,
    const FunctionTypeInferenceResult& result,
    const TypeApplicationConfig& config = {}
);

} // namespace structor::z3
