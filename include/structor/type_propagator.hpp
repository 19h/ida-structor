#pragma once

#include "synth_types.hpp"
#include "config.hpp"
#include "utils.hpp"
#include <queue>
#include <unordered_map>

namespace structor {

/// Propagates synthesized types to related functions and variables
class TypePropagator {
public:
    using CfuncCache = std::unordered_map<ea_t, cfuncptr_t>;

    explicit TypePropagator(
        const SynthOptions& opts = Config::instance().options(),
        CfuncCache* shared_cfunc_cache = nullptr)
        : options_(opts)
        , shared_cfunc_cache_(shared_cfunc_cache) {}

    /// Propagate type to related functions
    [[nodiscard]] PropagationResult propagate(
        ea_t origin_func,
        int origin_var_idx,
        const tinfo_t& new_type,
        PropagationDirection direction = PropagationDirection::Both);

    /// Propagate type within a single function
    [[nodiscard]] PropagationResult propagate_local(
        cfunc_t* cfunc,
        int var_idx,
        const tinfo_t& new_type);

    /// Apply type to a variable
    [[nodiscard]] bool apply_type(cfunc_t* cfunc, int var_idx, const tinfo_t& type);

private:
    struct PropagationWork {
        ea_t        func_ea;
        int         var_idx;
        int         depth;
        PropagationDirection direction;
    };

    struct CalleeArgInfo {
        ea_t callee_ea = BADADDR;
        int param_idx = -1;
        bool by_ref = false;
        tinfo_t passed_type;
        sval_t member_offset = -1;
    };

    struct CallerArgInfo {
        ea_t caller_ea = BADADDR;
        int var_idx = -1;
        bool by_ref = false;
        sval_t member_offset = -1;
    };

    void propagate_forward(
        ea_t func_ea,
        int var_idx,
        const tinfo_t& type,
        int depth,
        PropagationResult& result);

    void propagate_backward(
        ea_t func_ea,
        int var_idx,
        const tinfo_t& type,
        int depth,
        PropagationResult& result);

    void find_callees_with_arg(
        cfunc_t* cfunc,
        int var_idx,
        qvector<CalleeArgInfo>& callees);

    void find_callers_with_param(
        ea_t func_ea,
        int param_idx,
        qvector<CallerArgInfo>& callers);

    void find_aliased_vars(
        cfunc_t* cfunc,
        int var_idx,
        qvector<int>& aliases);

    void find_assigned_from(
        cfunc_t* cfunc,
        int var_idx,
        qvector<std::pair<ea_t, int>>& sources);

    void find_return_sources(
        cfunc_t* cfunc,
        qvector<std::pair<int, sval_t>>& sources);

    void find_callers_with_return(
        ea_t func_ea,
        qvector<std::pair<ea_t, int>>& callers);

    [[nodiscard]] bool is_parameter(cfunc_t* cfunc, int var_idx);
    [[nodiscard]] int get_param_index(cfunc_t* cfunc, int var_idx);
    [[nodiscard]] cfuncptr_t get_cfunc(ea_t func_ea);

    const SynthOptions& options_;
    std::unordered_set<std::uint64_t> visited_;
    CfuncCache* shared_cfunc_cache_ = nullptr;
    CfuncCache local_cfunc_cache_;

    std::uint64_t make_visit_key(ea_t func_ea, int var_idx) {
        return (static_cast<std::uint64_t>(func_ea) << 16) | static_cast<std::uint64_t>(var_idx & 0xFFFF);
    }
};

} // namespace structor
