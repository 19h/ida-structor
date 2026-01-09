#pragma once

#include "synth_types.hpp"
#include "config.hpp"
#include "utils.hpp"
#include "cross_function_analyzer.hpp"
#include "z3/context.hpp"
#include "z3/layout_constraints.hpp"
#include "z3/field_candidates.hpp"
#include "z3/result.hpp"
#include <memory>
#include <chrono>

#ifndef STRUCTOR_TESTING
#include <pro.h>
#include <kernwin.hpp>
#endif

namespace structor {

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
    std::chrono::milliseconds synthesis_time{0};
    std::chrono::milliseconds z3_solve_time{0};

    // Z3 result details
    z3::Z3Statistics z3_stats;

    /// Check if synthesis was successful
    [[nodiscard]] bool success() const noexcept {
        return !structure.fields.empty();
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
    unsigned z3_memory_mb = 512;
    bool use_z3 = true;

    // Cross-function analysis
    bool cross_function = true;
    int cross_function_depth = 5;
    int max_functions = 100;
    bool track_pointer_deltas = true;

    // Array detection
    int min_array_elements = 3;
    bool detect_symbolic_arrays = true;
    uint32_t max_array_stride = 4096;

    // Union handling
    bool create_unions = true;
    int max_union_alternatives = 8;

    // Alignment/packing
    bool infer_packing = true;
    uint32_t default_alignment = 8;

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
    int weight_prefer_arrays = 3;
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

private:
    LayoutSynthConfig config_;
    std::unique_ptr<z3::Z3Context> z3_ctx_;
    qvector<AccessConflict> conflicts_;

    /// Group accesses by offset range (for heuristic fallback)
    struct OffsetGroup {
        sval_t          offset;
        std::uint32_t   size;
        qvector<FieldAccess> accesses;
        bool            is_union;

        OffsetGroup() : offset(0), size(0), is_union(false) {}
    };

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

    [[nodiscard]] tinfo_t select_best_type(const qvector<FieldAccess>& accesses);
    [[nodiscard]] SemanticType select_best_semantic(const qvector<FieldAccess>& accesses);

    /// Convert LayoutSynthConfig to Z3 configs
    [[nodiscard]] z3::Z3Config make_z3_config() const;
    [[nodiscard]] z3::LayoutConstraintConfig make_layout_config() const;
    [[nodiscard]] z3::CandidateGenerationConfig make_candidate_config() const;
};

// ============================================================================
// Implementation
// ============================================================================

inline LayoutSynthesizer::LayoutSynthesizer(const LayoutSynthConfig& config)
    : config_(config) {}

inline LayoutSynthesizer::LayoutSynthesizer(const SynthOptions& opts)
    : config_() {
    // Map SynthOptions to LayoutSynthConfig
    config_.default_alignment = opts.alignment;
    config_.cross_function = opts.propagate_to_callees || opts.propagate_to_callers;
    config_.cross_function_depth = opts.max_propagation_depth;
}

inline SynthesisResult LayoutSynthesizer::synthesize(
    const AccessPattern& pattern,
    const SynthOptions& opts)
{
    auto start_time = std::chrono::steady_clock::now();
    conflicts_.clear();

    SynthesisResult result;
    result.structure.source_func = pattern.func_ea;
    result.structure.source_var = pattern.var_name;
    result.structure.alignment = config_.default_alignment;
    result.structure.name = generate_struct_name(pattern.func_ea);
    result.structure.add_provenance(pattern.func_ea);

    if (pattern.accesses.empty()) {
        return result;
    }

    // Perform cross-function analysis if enabled
    UnifiedAccessPattern unified_pattern;

    if (config_.cross_function) {
        CrossFunctionConfig cf_config;
        cf_config.max_depth = config_.cross_function_depth;
        cf_config.max_functions = config_.max_functions;
        cf_config.track_pointer_deltas = config_.track_pointer_deltas;
        cf_config.follow_forward = opts.propagate_to_callees;
        cf_config.follow_backward = opts.propagate_to_callers;

        CrossFunctionAnalyzer analyzer(cf_config);
        unified_pattern = analyzer.analyze(pattern.func_ea, pattern.var_idx, opts);
        result.functions_analyzed = static_cast<int>(
            analyzer.equivalence_class().variables.size());
    } else {
        // Single-function mode
        AccessPattern mutable_pattern = pattern;
        unified_pattern = UnifiedAccessPattern::from_single(std::move(mutable_pattern));
        result.functions_analyzed = 1;
    }

    // Synthesize from unified pattern
    SynthesisResult synth_result = synthesize(unified_pattern);

    // Copy metadata
    synth_result.structure.source_func = pattern.func_ea;
    synth_result.structure.source_var = pattern.var_name;
    synth_result.structure.name = generate_struct_name(pattern.func_ea);
    synth_result.functions_analyzed = result.functions_analyzed;

    auto end_time = std::chrono::steady_clock::now();
    synth_result.synthesis_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time);

    conflicts_ = synth_result.conflicts;
    return synth_result;
}

inline SynthesisResult LayoutSynthesizer::synthesize(const AccessPattern& pattern) {
    return synthesize(pattern, Config::instance().options());
}

inline SynthesisResult LayoutSynthesizer::synthesize(
    const UnifiedAccessPattern& unified_pattern)
{
    auto start_time = std::chrono::steady_clock::now();

    SynthesisResult result;

    if (unified_pattern.all_accesses.empty()) {
        return result;
    }

    // Try Z3 synthesis first if enabled
    if (config_.use_z3) {
        auto z3_result = synthesize_z3(unified_pattern);
        if (z3_result.has_value()) {
            result = std::move(*z3_result);
            result.used_z3 = true;

            auto end_time = std::chrono::steady_clock::now();
            result.synthesis_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                end_time - start_time);
            return result;
        }
    }

    // Fallback to heuristic synthesis
    if (config_.fallback_to_heuristics) {
        result = synthesize_heuristic(unified_pattern);
        result.fell_back_to_heuristic = true;
        if (result.fallback_reason.empty()) {
            result.fallback_reason = "Z3 disabled or failed";
        }
    }

    auto end_time = std::chrono::steady_clock::now();
    result.synthesis_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time);

    return result;
}

inline std::optional<SynthesisResult> LayoutSynthesizer::synthesize_z3(
    const UnifiedAccessPattern& pattern)
{
    SynthesisResult result;

    detail::synth_log("[Structor] Starting Z3-based structure synthesis...\n");

    try {
        // Create Z3 context
        z3::Z3Config z3_config = make_z3_config();
        z3_ctx_ = std::make_unique<z3::Z3Context>(z3_config);

        // Generate field candidates
        z3::CandidateGenerationConfig cand_config = make_candidate_config();
        z3::FieldCandidateGenerator generator(*z3_ctx_, cand_config);
        auto candidates = generator.generate(pattern);

        detail::synth_log("[Structor] Generated %zu field candidates from %zu accesses\n",
                          candidates.size(), pattern.all_accesses.size());

        if (candidates.empty()) {
            detail::synth_log("[Structor] No field candidates - falling back to heuristics\n");
            result.fallback_reason = "No field candidates generated";
            return std::nullopt;
        }

        // Build and solve constraints
        z3::LayoutConstraintConfig layout_config = make_layout_config();
        z3::LayoutConstraintBuilder builder(*z3_ctx_, layout_config);
        builder.build_constraints(pattern, candidates);

        auto z3_result = builder.solve();
        result.z3_solve_time = z3_result.solve_time;
        result.z3_stats = builder.statistics();

        if (z3_result.is_sat()) {
            // Extract struct from model
            result.structure = builder.extract_struct(*z3_result.model);
            result.inferred_packing = builder.inferred_packing();

            // Count detected features
            result.arrays_detected = static_cast<int>(builder.detected_arrays().size());
            result.unions_created = static_cast<int>(builder.union_resolutions().size());

            // Handle relaxed constraints
            if (z3_result.has_dropped_constraints()) {
                result.had_relaxation = true;
                result.dropped_constraints = z3_result.dropped_constraints;
                detail::synth_log("[Structor] Z3 synthesis completed with %zu relaxed constraints\n",
                                  z3_result.dropped_constraints.size());
            } else {
                detail::synth_log("[Structor] Z3 synthesis completed successfully\n");
            }

            detail::synth_log("[Structor] Result: %zu fields, %u bytes",
                              result.structure.fields.size(), result.structure.size);
            if (result.arrays_detected > 0) {
                detail::synth_log(", %d arrays", result.arrays_detected);
            }
            if (result.unions_created > 0) {
                detail::synth_log(", %d unions", result.unions_created);
            }
            detail::synth_log("\n");

            // Set struct metadata
            result.structure.alignment = config_.default_alignment;
            if (result.inferred_packing) {
                result.structure.alignment = std::min(
                    result.structure.alignment, *result.inferred_packing);
            }

            return result;
        }
        else if (z3_result.is_unsat()) {
            detail::synth_log("[Structor] Z3 returned UNSAT - constraints unsatisfiable\n");
            // Try relaxation if configured
            if (config_.relax_alignment_on_unsat || config_.relax_types_on_unsat) {
                return try_relaxed_solve(builder, z3_result, result);
            }

            result.unsat_core = z3_result.unsat_core;
            result.fallback_reason = "Z3 UNSAT: ";
            if (!z3_result.unsat_core.empty()) {
                result.fallback_reason.append(z3_result.unsat_core[0].description.c_str());
            }
            detail::synth_log("[Structor] Falling back to heuristic synthesis\n");
            return std::nullopt;
        }
        else {
            // Unknown or error
            detail::synth_log("[Structor] Z3 returned unknown/timeout - falling back to heuristics\n");
            result.fallback_reason = "Z3 ";
            result.fallback_reason.append(z3_result.status_string());
            if (!z3_result.error_message.empty()) {
                result.fallback_reason.append(": ");
                result.fallback_reason.append(z3_result.error_message.c_str());
            }
            return std::nullopt;
        }
    }
    catch (const std::exception& e) {
        detail::synth_log("[Structor] Z3 exception: %s\n", e.what());
        result.fallback_reason = "Z3 exception: ";
        result.fallback_reason.append(e.what());
        return std::nullopt;
    }
    catch (...) {
        detail::synth_log("[Structor] Unknown Z3 exception\n");
        result.fallback_reason = "Unknown Z3 exception";
        return std::nullopt;
    }
}

inline std::optional<SynthesisResult> LayoutSynthesizer::try_relaxed_solve(
    z3::LayoutConstraintBuilder& builder,
    const z3::Z3Result& initial_result,
    SynthesisResult& result)
{
    // The solve() method already calls solve_with_relaxation() internally
    // when UNSAT is encountered. If we got here, relaxation was attempted
    // but failed to produce SAT.
    //
    // At this point we have options:
    // 1. Accept partial results with raw bytes for irreconcilable regions
    // 2. Return to heuristic fallback
    //
    // Check if we have any dropped constraints - if so, some relaxation worked
    // but ultimately failed. Log this for debugging.

    if (!initial_result.dropped_constraints.empty()) {
        qstring dropped_info;
        dropped_info.sprnt("Relaxed %zu constraints but still UNSAT",
            initial_result.dropped_constraints.size());
        result.fallback_reason = dropped_info;
        result.dropped_constraints = initial_result.dropped_constraints;
    }

    // Record the UNSAT core for diagnostics
    result.unsat_core = initial_result.unsat_core;

    // If use_raw_bytes_fallback is enabled, we could try creating raw byte fields
    // for the problematic regions identified in the UNSAT core
    if (config_.use_raw_bytes_fallback && !initial_result.unsat_core.empty()) {
        // Identify the minimum region that must be covered by examining core
        // For now, signal that fallback to heuristics should use raw bytes
        result.fallback_reason = "Z3 UNSAT - using raw bytes for ambiguous regions";
    }

    if (result.fallback_reason.empty()) {
        result.fallback_reason = "Z3 constraints unsatisfiable";
    }

    // Return nullopt to trigger heuristic fallback
    return std::nullopt;
}

inline SynthesisResult LayoutSynthesizer::synthesize_heuristic(
    const UnifiedAccessPattern& pattern)
{
    detail::synth_log("[Structor] Using heuristic structure synthesis\n");

    SynthesisResult result;
    result.used_z3 = false;

    // Set basic struct properties
    result.structure.alignment = config_.default_alignment;

    if (!pattern.contributing_functions.empty()) {
        result.structure.source_func = pattern.contributing_functions[0];
        for (ea_t func : pattern.contributing_functions) {
            result.structure.add_provenance(func);
        }
    }

    if (pattern.all_accesses.empty()) {
        return result;
    }

    // Group accesses by offset
    qvector<OffsetGroup> groups;
    group_accesses_heuristic(pattern, groups);

    // Resolve any conflicts
    resolve_conflicts_heuristic(groups);

    // Generate fields from groups
    generate_fields_heuristic(groups, result.structure);

    // Insert padding where needed
    insert_padding_heuristic(result.structure);

    // Infer and set field types
    infer_field_types_heuristic(result.structure, pattern);

    // Generate meaningful field names
    generate_field_names(result.structure);

    // Compute final structure size
    compute_struct_size(result.structure);

    // Copy conflicts
    result.conflicts = conflicts_;

    detail::synth_log("[Structor] Heuristic synthesis completed: %zu fields, %u bytes\n",
                      result.structure.fields.size(), result.structure.size);
    if (!conflicts_.empty()) {
        detail::synth_log("[Structor] Warning: %zu conflicts detected\n", conflicts_.size());
    }

    return result;
}

inline void LayoutSynthesizer::group_accesses_heuristic(
    const UnifiedAccessPattern& pattern,
    qvector<OffsetGroup>& groups)
{
    // Sort accesses by offset
    qvector<FieldAccess> sorted = pattern.all_accesses;
    std::sort(sorted.begin(), sorted.end());

    // Group overlapping accesses
    for (const auto& access : sorted) {
        bool merged = false;

        for (auto& group : groups) {
            // Check for overlap
            sval_t group_end = group.offset + static_cast<sval_t>(group.size);
            sval_t access_end = access.offset + static_cast<sval_t>(access.size);

            if (access.offset < group_end && access_end > group.offset) {
                // Overlapping - merge into group
                group.accesses.push_back(access);
                group.offset = std::min(group.offset, access.offset);
                group.size = std::max(group_end, access_end) - group.offset;

                // Mark as potential union if different sizes at same offset
                if (access.offset == group.accesses[0].offset &&
                    access.size != group.accesses[0].size) {
                    group.is_union = true;
                }

                merged = true;
                break;
            }
        }

        if (!merged) {
            OffsetGroup new_group;
            new_group.offset = access.offset;
            new_group.size = access.size;
            new_group.accesses.push_back(access);
            groups.push_back(std::move(new_group));
        }
    }

    // Sort groups by offset
    std::sort(groups.begin(), groups.end(), [](const OffsetGroup& a, const OffsetGroup& b) {
        return a.offset < b.offset;
    });
}

inline void LayoutSynthesizer::resolve_conflicts_heuristic(qvector<OffsetGroup>& groups) {
    for (auto& group : groups) {
        if (group.accesses.size() <= 1) continue;

        // Check for conflicting access sizes at the same offset
        std::unordered_map<sval_t, qvector<FieldAccess*>> by_offset;
        for (auto& access : group.accesses) {
            by_offset[access.offset].push_back(&access);
        }

        for (auto& [off, acc_list] : by_offset) {
            if (acc_list.size() <= 1) continue;

            // Check for size conflicts
            std::uint32_t first_size = acc_list[0]->size;
            bool has_conflict = false;

            for (size_t i = 1; i < acc_list.size(); ++i) {
                if (acc_list[i]->size != first_size) {
                    has_conflict = true;
                    break;
                }
            }

            if (has_conflict) {
                AccessConflict conflict;
                conflict.offset = off;
                conflict.description.sprnt("Conflicting access sizes at offset 0x%X",
                    static_cast<unsigned>(off));

                for (auto* acc : acc_list) {
                    conflict.conflicting_accesses.push_back(*acc);
                }

                conflicts_.push_back(std::move(conflict));
                group.is_union = true;
            }
        }
    }
}

inline void LayoutSynthesizer::generate_fields_heuristic(
    const qvector<OffsetGroup>& groups,
    SynthStruct& result)
{
    for (const auto& group : groups) {
        SynthField field;
        field.offset = group.offset;
        field.size = group.size;
        field.is_union_candidate = group.is_union;
        field.source_accesses = group.accesses;

        // Select best type and semantic from all accesses
        field.type = select_best_type(group.accesses);
        field.semantic = select_best_semantic(group.accesses);

        result.fields.push_back(std::move(field));
    }

    // Sort fields by offset
    std::sort(result.fields.begin(), result.fields.end(),
        [](const SynthField& a, const SynthField& b) {
            return a.offset < b.offset;
        });
}

inline void LayoutSynthesizer::insert_padding_heuristic(SynthStruct& result) {
    if (result.fields.empty()) return;

    qvector<SynthField> with_padding;
    sval_t current_offset = 0;

    for (auto& field : result.fields) {
        // Insert padding if there's a gap
        if (field.offset > current_offset) {
            std::uint32_t gap = field.offset - current_offset;
            with_padding.push_back(SynthField::create_padding(current_offset, gap));
        }

        with_padding.push_back(std::move(field));
        current_offset = with_padding.back().offset + with_padding.back().size;
    }

    result.fields = std::move(with_padding);
}

inline void LayoutSynthesizer::infer_field_types_heuristic(
    SynthStruct& result,
    const UnifiedAccessPattern& pattern)
{
    std::uint32_t ptr_size = get_ptr_size();

    for (auto& field : result.fields) {
        if (field.is_padding) continue;
        if (!field.type.empty()) continue;

        // Infer type from semantic and size
        switch (field.semantic) {
            case SemanticType::VTablePointer: {
                if (result.has_vtable() && result.vtable->tid != BADADDR) {
                    tinfo_t vtbl_type;
                    if (vtbl_type.get_type_by_tid(result.vtable->tid)) {
                        field.type.create_ptr(vtbl_type);
                    }
                }
                if (field.type.empty()) {
                    tinfo_t void_type;
                    void_type.create_simple_type(BTF_VOID);
                    tinfo_t void_ptr;
                    void_ptr.create_ptr(void_type);
                    field.type.create_ptr(void_ptr);
                }
                break;
            }

            case SemanticType::FunctionPointer: {
                func_type_data_t ftd;
                ftd.rettype.create_simple_type(BTF_VOID);
                ftd.set_cc(CM_CC_UNKNOWN);
                tinfo_t func_type;
                func_type.create_func(ftd);
                field.type.create_ptr(func_type);
                break;
            }

            case SemanticType::Pointer: {
                tinfo_t void_type;
                void_type.create_simple_type(BTF_VOID);
                field.type.create_ptr(void_type);
                break;
            }

            case SemanticType::Float:
                field.type.create_simple_type(BTF_FLOAT);
                break;

            case SemanticType::Double:
                field.type.create_simple_type(BTF_DOUBLE);
                break;

            case SemanticType::UnsignedInteger:
                field.type = utils::create_basic_type(field.size, SemanticType::UnsignedInteger);
                break;

            case SemanticType::Integer:
            case SemanticType::Unknown:
            default:
                if (field.size == ptr_size) {
                    bool any_deref = false;
                    for (const auto& acc : field.source_accesses) {
                        if (acc.semantic_type == SemanticType::Pointer ||
                            acc.semantic_type == SemanticType::FunctionPointer) {
                            any_deref = true;
                            break;
                        }
                    }

                    if (any_deref) {
                        tinfo_t void_type;
                        void_type.create_simple_type(BTF_VOID);
                        field.type.create_ptr(void_type);
                    } else {
                        field.type = utils::create_basic_type(field.size, SemanticType::Integer);
                    }
                } else {
                    field.type = utils::create_basic_type(field.size, SemanticType::Integer);
                }
                break;
        }
    }
}

inline void LayoutSynthesizer::generate_field_names(SynthStruct& result) {
    const SynthOptions& opts = Config::instance().options();

    for (auto& field : result.fields) {
        if (field.is_padding) continue;
        if (!field.name.empty()) continue;

        field.name = generate_field_name(field.offset, field.semantic);

        // Generate comment if enabled
        if (opts.generate_comments) {
            qstring comment;
            comment.sprnt("size: %u, accesses: %zu", field.size, field.source_accesses.size());

            if (!field.source_accesses.empty()) {
                const auto& first_access = field.source_accesses[0];
                comment.cat_sprnt(", %s", access_type_str(first_access.access_type));
            }

            if (field.is_union_candidate) {
                comment.append(" [union candidate]");
            }

            field.comment = std::move(comment);
        }
    }
}

inline void LayoutSynthesizer::compute_struct_size(SynthStruct& result) {
    if (result.fields.empty()) {
        result.size = 0;
        return;
    }

    const auto& last_field = result.fields.back();
    sval_t end = last_field.offset + last_field.size;

    // Align to structure alignment
    result.size = align_offset(end, result.alignment);
}

inline tinfo_t LayoutSynthesizer::select_best_type(const qvector<FieldAccess>& accesses) {
    tinfo_t best;

    for (const auto& access : accesses) {
        if (access.inferred_type.empty()) continue;

        if (best.empty()) {
            best = access.inferred_type;
            continue;
        }

        best = resolve_type_conflict(best, access.inferred_type);
    }

    return best;
}

inline SemanticType LayoutSynthesizer::select_best_semantic(const qvector<FieldAccess>& accesses) {
    SemanticType best = SemanticType::Unknown;
    int best_priority = 0;

    for (const auto& access : accesses) {
        int priority = semantic_priority(access.semantic_type);
        if (priority > best_priority) {
            best_priority = priority;
            best = access.semantic_type;
        }
    }

    return best;
}

inline z3::Z3Config LayoutSynthesizer::make_z3_config() const {
    z3::Z3Config cfg;
    cfg.timeout_ms = config_.z3_timeout_ms;
    cfg.max_memory_mb = config_.z3_memory_mb;
    cfg.pointer_size = get_ptr_size();
    cfg.default_alignment = config_.default_alignment;
    return cfg;
}

inline z3::LayoutConstraintConfig LayoutSynthesizer::make_layout_config() const {
    z3::LayoutConstraintConfig cfg;
    cfg.default_alignment = config_.default_alignment;
    cfg.model_packing = config_.infer_packing;
    cfg.allow_unions = config_.create_unions;
    cfg.max_union_alternatives = config_.max_union_alternatives;
    cfg.weight_coverage = config_.weight_coverage;
    cfg.weight_type_consistency = config_.weight_type_consistency;
    cfg.weight_alignment = config_.weight_alignment;
    cfg.weight_minimize_fields = config_.weight_minimize_fields;
    cfg.weight_prefer_arrays = config_.weight_prefer_arrays;
    return cfg;
}

inline z3::CandidateGenerationConfig LayoutSynthesizer::make_candidate_config() const {
    z3::CandidateGenerationConfig cfg;
    cfg.min_array_elements = config_.min_array_elements;
    return cfg;
}

} // namespace structor
