#pragma once

#include "synth_types.hpp"
#include "config.hpp"
#include "utils.hpp"
#include <map>
#include <unordered_map>
#include <unordered_set>

namespace structor {

struct BitfieldInfo;

/// Visitor that collects all access patterns for a specific variable
class AccessPatternVisitor : public ctree_visitor_t {
public:
    AccessPatternVisitor(cfunc_t* cfunc, int target_var_idx,
                         const FlowAnalysisOptions& flow = {});

    int idaapi visit_expr(cexpr_t* expr) override;
    int idaapi leave_expr(cexpr_t* expr) override;
    int idaapi visit_insn(cinsn_t* insn) override;

    [[nodiscard]] const qvector<FieldAccess>& accesses() const noexcept {
        return accesses_;
    }

    [[nodiscard]] qvector<FieldAccess>& mutable_accesses() noexcept {
        return accesses_;
    }

    [[nodiscard]] const FlowAnalysisInfo& flow_analysis() const noexcept {
        return flow_analysis_;
    }

private:
    struct IndexRange {
        sval_t first = std::numeric_limits<sval_t>::min();
        sval_t last = std::numeric_limits<sval_t>::max();
        bool first_known = false;
        bool last_known = false;

        [[nodiscard]] IndexRange intersect(const IndexRange& other) const {
            return {std::max(first, other.first), std::min(last, other.last),
                    first_known || other.first_known, last_known || other.last_known};
        }
        [[nodiscard]] IndexRange unite(const IndexRange& other) const {
            return {std::min(first, other.first), std::max(last, other.last),
                    first_known && other.first_known, last_known && other.last_known};
        }
    };

    struct LoopIndexEffects {
        std::unordered_set<int> written_or_referenced_vars;
        bool has_call = false;
    };

    struct IndexComparison {
        int var_idx = -1;
        std::size_t version = 0;
        IndexRange when_true;
        IndexRange when_false;
    };

    enum class FlowExit { Normal, Return, Break, Continue };
    enum class PredicateRelation { Equal, SignedLess, SignedLessEqual,
                                   UnsignedLess, UnsignedLessEqual };
    struct PathPredicate {
        int var_idx = -1;
        std::size_t version = 0;
        PredicateRelation relation = PredicateRelation::Equal;
        std::uint64_t value = 0;
        unsigned width = 0;
        bool truth = false;
    };

    // Each alternative describes one reaching definition environment. An
    // alias present on only one branch is never installed in another branch.
    struct FlowState {
        std::unordered_map<int, FieldAccess> aliases;
        std::unordered_set<int> address_aliases;
        std::unordered_map<int, qvector<std::uint64_t>> pending_constants;
        std::unordered_map<const cexpr_t*, IndexComparison> comparisons;
        std::unordered_map<int, std::size_t> versions;
        std::unordered_set<int> escaped;
        std::vector<PathPredicate> predicates;
        std::unordered_map<const cexpr_t*, std::pair<int, std::size_t>> variable_uses;
        std::unordered_map<const cexpr_t*, const cexpr_t*> expression_values;
        std::unordered_map<const cexpr_t*, sval_t> pointer_expression_values;
        FlowExit exit = FlowExit::Normal;
        bool aliases_widened = false;
    };
    using FlowStates = std::vector<FlowState>;
    void record_precision_loss(FlowPrecisionLoss reason, std::size_t states_before);

    [[nodiscard]] FlowState take_flow_state();
    void restore_flow_state(FlowState state);
    [[nodiscard]] FlowStates walk_item(citem_t* item, citem_t* parent, FlowStates states);
    [[nodiscard]] FlowStates walk_block(cblock_t* block, citem_t* parent, FlowStates states);
    [[nodiscard]] FlowStates walk_loop(cinsn_t* loop, FlowStates states);
    [[nodiscard]] FlowStates assume_condition(const cexpr_t* condition, bool truth,
                                              FlowStates states, int depth = 0);
    [[nodiscard]] std::optional<PathPredicate> condition_predicate(
        const cexpr_t* condition, bool truth, const FlowState& state) const;
    [[nodiscard]] bool add_path_predicate(FlowState& state, const PathPredicate& predicate) const;
    [[nodiscard]] bool same_flow_state(const FlowState& lhs, const FlowState& rhs) const;
    [[nodiscard]] FlowState widen_flow_states(const FlowStates& states);
    void normalize_flow_states(FlowStates& states);
    void publish_flow_states(FlowStates states);
    int observe_expr(cexpr_t* expr);
    [[nodiscard]] const cexpr_t* evaluated_expression(const cexpr_t* expr) const;
    [[nodiscard]] std::optional<std::uint64_t> known_scalar_value(const cexpr_t* expr, int depth = 0) const;
    void remember_scalar_value(int var_idx, const tinfo_t& type, std::uint64_t value);
    [[nodiscard]] std::optional<FieldAccess> adjusted_address_alias(
        const cexpr_t* variable, sval_t element_delta) const;

    void process_dereference(cexpr_t* expr, const cexpr_t* ptr_expr);
    void process_memptr_access(cexpr_t* expr);
    void process_call_argument_use(const cexpr_t* call_expr, const cexpr_t* argument);
    void process_call_through_ptr(cexpr_t* call_expr);
    void process_array_access(cexpr_t* expr);
    void process_assignment(cexpr_t* expr);
    void process_constant_comparison(cexpr_t* expr);
    void process_index_bound(cexpr_t* expr);
    [[nodiscard]] IndexRange condition_index_range(
        const cexpr_t* condition, int var_idx, bool truth, int depth = 0) const;
    [[nodiscard]] std::optional<IndexRange> bounded_index_range(
        const cexpr_t* access_expr, int var_idx) const;
    [[nodiscard]] bool loop_may_change_index(const cinsn_t* loop, int var_idx) const;
    [[nodiscard]] bool call_sibling_may_change_index(
        const cexpr_t* call, const citem_t* active_child, int var_idx) const;
    void invalidate_local_var_state(int var_idx, bool clear_pending_constants);

    void record_bitfield_access(const cexpr_t* expr, sval_t offset, uint32_t size,
                                const BitfieldInfo& info,
                                const std::optional<std::uint8_t>& base_indirection);
    [[nodiscard]] bool extract_access(const cexpr_t* expr, sval_t& offset, uint32_t& size,
                                      std::optional<std::uint8_t>* base_indirection) const;
    [[nodiscard]] utils::PtrArithInfo resolve_ptr_arith(const cexpr_t* expr, int depth = 0) const;
    void extract_and_add_rhs_constant(FieldAccess& access, const cexpr_t* rhs) const;
    [[nodiscard]] bool compute_bitfield(std::uint64_t mask, int shift,
                                        std::uint16_t& bit_offset,
                                        std::uint16_t& bit_size) const;
    [[nodiscard]] tinfo_t build_funcptr_type(const cexpr_t* call_expr) const;

    [[nodiscard]] bool involves_target_var(const cexpr_t* expr) const;
    [[nodiscard]] bool is_call_argument_use(const cexpr_t* expr) const;
    [[nodiscard]] SemanticType infer_semantic_from_usage(const cexpr_t* expr, const cexpr_t* parent);
    [[nodiscard]] AccessType determine_access_type(const cexpr_t* expr, const cexpr_t** out_rhs = nullptr);
    [[nodiscard]] bool is_zero_initialization(const cexpr_t* expr) const;

    cfunc_t* cfunc_;
    int target_var_idx_;
    bool has_unstructured_control_flow_;
    qvector<FieldAccess> accesses_;
    std::unordered_map<int, FieldAccess> local_aliases_;
    // Distinguish copies of the base address from values loaded from a field.
    // Address copies support later dereferences, but are not field reads.
    std::unordered_set<int> address_aliases_;
    std::unordered_map<int, qvector<std::uint64_t>> pending_constants_;
    // A comparison is usable only on the control-flow edge where it holds and
    // while the index still has the value tested by that comparison.
    std::unordered_map<const cexpr_t*, IndexComparison> index_comparisons_;
    std::unordered_map<int, std::size_t> local_var_versions_;
    std::unordered_set<int> escaped_local_vars_;
    mutable std::unordered_map<const cinsn_t*, LoopIndexEffects> loop_index_effects_;
    std::vector<PathPredicate> path_predicates_;
    std::unordered_map<const cexpr_t*, std::pair<int, std::size_t>> variable_uses_;
    std::unordered_map<const cexpr_t*, const cexpr_t*> expression_values_;
    std::unordered_map<const cexpr_t*, sval_t> pointer_expression_values_;
    FlowExit flow_exit_ = FlowExit::Normal;
    bool aliases_widened_ = false;
    std::optional<FlowStates> node_results_;
    // Epoch allocation is deliberately not rolled back with branch snapshots.
    std::size_t next_value_epoch_ = 1;
    FlowAnalysisInfo flow_analysis_;
    const citem_t* flow_site_ = nullptr;
    std::unordered_map<const citem_t*, std::uint64_t> node_ordinals_;
    std::map<std::pair<FlowPrecisionLoss, std::uint64_t>, std::size_t> precision_event_indexes_;
    bool flow_budget_exhausted_ = false;
};

/// Collects all access patterns for a variable in a function
class AccessCollector {
public:
    explicit AccessCollector(const SynthOptions& opts = Config::instance().options())
        : options_(opts) {}

    /// Collect all accesses to a variable in a function
    [[nodiscard]] AccessPattern collect(ea_t func_ea, int var_idx);

    /// Collect accesses using existing cfunc
    [[nodiscard]] AccessPattern collect(cfunc_t* cfunc, int var_idx);

    /// Collect accesses for a variable by name
    [[nodiscard]] AccessPattern collect(ea_t func_ea, const char* var_name);

private:
    void analyze_accesses(AccessPattern& pattern);
    void deduplicate_accesses(AccessPattern& pattern);
    void detect_vtable_pattern(AccessPattern& pattern);

    // Own the options snapshot. Public construction with SynthOptions{} must
    // not retain a reference to a temporary, and collection must remain
    // isolated from later global Config mutations.
    SynthOptions options_;
};

} // namespace structor
