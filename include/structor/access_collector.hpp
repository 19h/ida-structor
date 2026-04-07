#pragma once

#include "synth_types.hpp"
#include "config.hpp"
#include "utils.hpp"
#include <unordered_map>

namespace structor {

struct BitfieldInfo;

/// Visitor that collects all access patterns for a specific variable
class AccessPatternVisitor : public ctree_visitor_t {
public:
    AccessPatternVisitor(cfunc_t* cfunc, int target_var_idx)
        : ctree_visitor_t(CV_PARENTS)
        , cfunc_(cfunc)
        , target_var_idx_(target_var_idx) {}

    int idaapi visit_expr(cexpr_t* expr) override;

    [[nodiscard]] const qvector<FieldAccess>& accesses() const noexcept {
        return accesses_;
    }

    [[nodiscard]] qvector<FieldAccess>& mutable_accesses() noexcept {
        return accesses_;
    }

private:
    void process_dereference(cexpr_t* expr, const cexpr_t* ptr_expr);
    void process_memptr_access(cexpr_t* expr);
    void process_call_through_ptr(cexpr_t* call_expr);
    void process_array_access(cexpr_t* expr);
    void process_assignment(cexpr_t* expr);
    void process_constant_comparison(cexpr_t* expr);

    void record_bitfield_access(const cexpr_t* expr, sval_t offset, uint32_t size,
                                const BitfieldInfo& info,
                                const std::optional<std::uint8_t>& base_indirection);
    [[nodiscard]] bool extract_access(const cexpr_t* expr, sval_t& offset, uint32_t& size,
                                      std::optional<std::uint8_t>* base_indirection) const;
    [[nodiscard]] bool compute_bitfield(std::uint64_t mask, int shift,
                                        std::uint16_t& bit_offset,
                                        std::uint16_t& bit_size) const;
    [[nodiscard]] tinfo_t build_funcptr_type(const cexpr_t* call_expr) const;

    [[nodiscard]] bool involves_target_var(const cexpr_t* expr) const;
    [[nodiscard]] SemanticType infer_semantic_from_usage(const cexpr_t* expr, const cexpr_t* parent);
    [[nodiscard]] AccessType determine_access_type(const cexpr_t* expr);
    [[nodiscard]] bool is_zero_initialization(const cexpr_t* expr) const;

    cfunc_t* cfunc_;
    int target_var_idx_;
    qvector<FieldAccess> accesses_;
    std::unordered_map<int, FieldAccess> local_aliases_;
    std::unordered_map<int, qvector<std::uint64_t>> pending_constants_;
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

    const SynthOptions& options_;
};

} // namespace structor
