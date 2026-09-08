#pragma once

#include "synth_types.hpp"
#include "config.hpp"
#include "utils.hpp"
#include "cross_function_analyzer.hpp"
#include "access_collector.hpp"
#include "structure_persistence.hpp"
#include "type_propagator.hpp"
#include "z3/context.hpp"
#include "z3/layout_constraints.hpp"
#include "z3/field_candidates.hpp"
#include "z3/result.hpp"
#include "z3/type_inference_engine.hpp"
#include "z3/type_applicator.hpp"
#include <memory>
#include <chrono>
#include <unordered_map>
#include <unordered_set>

#ifndef STRUCTOR_TESTING
#include <pro.h>
#include <kernwin.hpp>
#endif

namespace structor {

struct SubStructInfo;

namespace detail {
    // Helper for conditional logging in header
    inline void synth_log(const char* fmt, ...) {
#ifndef STRUCTOR_TESTING
        va_list va;
        va_start(va, fmt);
        vmsg(fmt, va);
        va_end(va);
#endif
    }
}

/// Result of synthesis attempt with detailed metadata
struct SynthesisResult {
    SynthStruct structure;
    qvector<SubStructInfo> sub_structs;
    qvector<AccessConflict> conflicts;
    std::optional<UnifiedAccessPattern> unified_pattern;

    SynthError error = SynthError::Success;
    qstring error_message;
    std::optional<ResourceLimitViolation> resource_limit;
    qvector<FlowAnalysisDiagnostic> flow_diagnostics;
    bool arrays_suppressed_by_flow_budget = false;


    // Synthesis metadata
    bool used_z3 = false;
    bool fell_back_to_heuristic = false;
    qstring fallback_reason;

    // Context-independent diagnostics. Returned records never retain a
    // tracking_literal from the temporary synthesis solver.
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
    std::chrono::milliseconds synthesis_time{0};
    std::chrono::milliseconds z3_solve_time{0};

    // Z3 result details
    z3::Z3Statistics z3_stats;

    /// Check if synthesis was successful
    [[nodiscard]] bool success() const noexcept {
        return error == SynthError::Success && !structure.fields.empty();
    }

    /// Check if any fields were created
    [[nodiscard]] bool has_fields() const noexcept {
        return !structure.fields.empty();
    }

    /// Get summary string
    [[nodiscard]] qstring summary() const {
        qstring result;
        result.sprnt("Synthesis Result:\n");
        result.cat_sprnt("  Fields: %zu\n", structure.fields.size());
        result.cat_sprnt("  Size: %u bytes\n", structure.size);
        result.cat_sprnt("  Used Z3: %s\n", used_z3 ? "yes" : "no");
        for (const auto& diagnostic : flow_diagnostics) {
            if (diagnostic.analysis.precision_lost()) {
                result.cat_sprnt("  Collection precision reduced: function 0x%llX variable %d (%zu sites)\n",
                    static_cast<unsigned long long>(diagnostic.func_ea), diagnostic.var_idx,
                    diagnostic.analysis.precision_events.size());
            }
        }
        if (arrays_suppressed_by_flow_budget) {
            result.cat_sprnt("  Array aggregation suppressed: flow-analysis budget exhausted\n");
        }
        if (fell_back_to_heuristic) {
            result.cat_sprnt("  Fallback: %s\n", fallback_reason.c_str());
        }
        if (arrays_detected > 0) {
            result.cat_sprnt("  Arrays: %d\n", arrays_detected);
        }
        if (unions_created > 0) {
            result.cat_sprnt("  Unions: %d\n", unions_created);
        }
        if (!conflicts.empty()) {
            result.cat_sprnt("  Conflicts: %zu\n", conflicts.size());
        }
        result.cat_sprnt("  Time: %lldms\n",
                        static_cast<long long>(synthesis_time.count()));
        return result;
    }
};

/// Configuration for layout synthesis
struct LayoutSynthConfig {
    // Z3 configuration
    unsigned z3_timeout_ms = 10000;
    unsigned z3_memory_mb = 0; // 0 is explicit unlimited; Optimize has no local memory cap
    bool use_z3 = true;
    bool enable_maxsmt = true;
    bool enable_unsat_core = true;
    bool relax_on_unsat = true;
    uint32_t max_relaxation_iterations = 5;

    // Hard operational limits. A violation terminates synthesis and is not
    // eligible for an unbounded heuristic fallback.
    uint32_t max_accesses = 10000;
    uint32_t max_candidates = 1000;
    uint32_t max_fields = 4096;
    // Optional inference cap: an aggregate array candidate above this count is
    // omitted while mandatory scalar evidence remains available for recovery.
    uint32_t max_array_elements = 1024;
    uint32_t max_struct_size = 0x10000;
    uint64_t max_constraint_pairs = 500000; // Pair + union-cardinality relation budget
    std::uint8_t min_confidence_percent = 20;

    // Cross-function analysis
    bool cross_function = true;
    int cross_function_depth = 5;
    int max_functions = 100;
    bool track_pointer_deltas = true;
    bool emit_substructs = true;

    // Array detection
    bool detect_arrays = true;
    uint32_t min_array_elements = 3;
    bool detect_symbolic_arrays = true;
    uint32_t max_array_stride = 4096;

    // Union handling
    bool create_unions = true;
    uint32_t max_union_alternatives = 8;

    // Alignment/packing
    bool infer_packing = true;
    uint32_t default_alignment = 8;
    bool generate_comments = true;

    // Fallback behavior (tiered)
    bool relax_alignment_on_unsat = true;
    bool relax_types_on_unsat = true;
    bool use_raw_bytes_fallback = true;
    bool fallback_to_heuristics = true;

    // Max-SMT weights
    int weight_coverage = 100;
    int weight_type_consistency = 10;
    int weight_alignment = 5;
    int weight_minimize_fields = 2;
    int weight_minimize_padding = 1;
    int weight_prefer_non_union = 2;
    int weight_prefer_arrays = 3;
    
    // Experimental type-inference adjunct. The production structure recovery
    // path does not depend on it and never enables it implicitly.
    bool use_type_inference = false;
    bool apply_inferred_types = false;
    z3::TypeInferenceConfig type_inference_config;
    z3::TypeApplicationConfig type_application_config;  // Configuration for type application
};

/// Main layout synthesizer - uses Z3 as primary engine with tiered fallback
class LayoutSynthesizer {
public:
    explicit LayoutSynthesizer(const LayoutSynthConfig& config = {});
    explicit LayoutSynthesizer(const SynthOptions& opts);

    /// Synthesize struct from a single function's access pattern
    [[nodiscard]] SynthesisResult synthesize(
        const AccessPattern& pattern,
        const SynthOptions& opts
    );

    /// Synthesize struct from a single function's access pattern (using default options)
    [[nodiscard]] SynthesisResult synthesize(const AccessPattern& pattern);

    /// Synthesize struct from pre-computed unified pattern
    [[nodiscard]] SynthesisResult synthesize(
        const UnifiedAccessPattern& unified_pattern,
        const SynthOptions& opts,
        ea_t source_func_hint = BADADDR
    );

    /// Synthesize struct from pre-computed unified pattern
    [[nodiscard]] SynthesisResult synthesize(
        const UnifiedAccessPattern& unified_pattern
    );

    /// Get any detected conflicts from last synthesis
    [[nodiscard]] const qvector<AccessConflict>& conflicts() const noexcept {
        return conflicts_;
    }

    /// Check if there were conflicts during last synthesis
    [[nodiscard]] bool has_conflicts() const noexcept {
        return !conflicts_.empty();
    }

    /// Get configuration
    [[nodiscard]] const LayoutSynthConfig& config() const noexcept { return config_; }

    /// Get mutable configuration
    [[nodiscard]] LayoutSynthConfig& mutable_config() noexcept { return config_; }
    
    /// Experimental adjunct. Both use_type_inference and
    /// type_inference_config.enable_experimental_pipeline must be true;
    /// otherwise the result fails with ExperimentalFeatureDisabled.
    [[deprecated("experimental type-inference adjunct is disabled by default and is not part of production structure recovery")]]
    [[nodiscard]] SynthesisResult synthesize_with_type_inference(
        cfunc_t* cfunc,
        int var_idx,
        const SynthOptions& opts = Config::instance().options()
    );
    
    /// Apply synthesized struct and inferred types to decompiler
    [[nodiscard]] z3::TypeApplicationResult apply_synthesis_result(
        cfunc_t* cfunc,
        int var_idx,
        const SynthesisResult& result
    );

private:
    LayoutSynthConfig config_;
    std::unique_ptr<z3::Z3Context> z3_ctx_;
    qvector<AccessConflict> conflicts_;
    
    // Type inference results (cached from last synthesis_with_type_inference)
    std::optional<z3::FunctionTypeInferenceResult> last_type_inference_;

    /// Group accesses by offset range (for heuristic fallback)
    struct OffsetGroup {
        sval_t          offset;
        std::uint32_t   size;
        qvector<FieldAccess> accesses;
        bool            is_union;

        OffsetGroup() : offset(0), size(0), is_union(false) {}
    };

    /// Primary synthesis using Z3 with Max-SMT
    [[nodiscard]] SynthesisResult synthesize_z3(
        const UnifiedAccessPattern& pattern
    );

    /// Fallback synthesis using heuristics
    [[nodiscard]] SynthesisResult synthesize_heuristic(
        const UnifiedAccessPattern& pattern
    );

    /// Tiered fallback strategy
    [[nodiscard]] SynthesisResult try_relaxed_solve(
        z3::LayoutConstraintBuilder& builder,
        const z3::Z3Result& initial_result,
        SynthesisResult& result
    );

    // Heuristic methods (for fallback)
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
    void detect_subobjects(const UnifiedAccessPattern& pattern,
                           const SynthOptions& opts,
                           SynthesisResult& result);
    void apply_bitfield_recovery(const UnifiedAccessPattern& pattern, SynthStruct& result);

    [[nodiscard]] tinfo_t select_best_type(const qvector<FieldAccess>& accesses);
    [[nodiscard]] SemanticType select_best_semantic(const qvector<FieldAccess>& accesses);

    /// Convert LayoutSynthConfig to Z3 configs
    [[nodiscard]] z3::Z3Config make_z3_config() const;
    [[nodiscard]] z3::LayoutConstraintConfig make_layout_config() const;
    [[nodiscard]] z3::CandidateGenerationConfig make_candidate_config() const;
};

} // namespace structor
