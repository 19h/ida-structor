#pragma once

#include "synth_types.hpp"
#include "config.hpp"
#include "utils.hpp"
#include <queue>

namespace structor {

/// Propagates synthesized types to related functions and variables
class TypePropagator {
public:
    explicit TypePropagator(const SynthOptions& opts = Config::instance().options())
        : options_(opts) {}

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
    };

    struct CallerArgInfo {
        ea_t caller_ea = BADADDR;
        int var_idx = -1;
        bool by_ref = false;
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

    const SynthOptions& options_;
    std::unordered_set<std::uint64_t> visited_;

    std::uint64_t make_visit_key(ea_t func_ea, int var_idx) {
        return (static_cast<std::uint64_t>(func_ea) << 16) | static_cast<std::uint64_t>(var_idx & 0xFFFF);
    }
};

// ============================================================================
// Implementation
// ============================================================================

inline PropagationResult TypePropagator::propagate(
    ea_t origin_func,
    int origin_var_idx,
    const tinfo_t& new_type,
    PropagationDirection direction)
{
    visited_.clear();
    PropagationResult result;

    // Mark origin as visited
    visited_.insert(make_visit_key(origin_func, origin_var_idx));

    // Apply to origin first
    cfuncptr_t cfunc = utils::get_cfunc(origin_func);
    if (cfunc) {
        if (apply_type(cfunc, origin_var_idx, new_type)) {
            PropagationSite site;
            site.func_ea = origin_func;
            site.var_idx = origin_var_idx;

            lvars_t& lvars = *cfunc->get_lvars();
            if (origin_var_idx >= 0 && static_cast<size_t>(origin_var_idx) < lvars.size()) {
                site.var_name = lvars[origin_var_idx].name;
                site.old_type = lvars[origin_var_idx].type();
            }

            site.new_type = new_type;
            site.direction = PropagationDirection::Forward;
            result.add_success(std::move(site));
        }
    }

    // Propagate in requested directions
    if (direction == PropagationDirection::Forward || direction == PropagationDirection::Both) {
        if (options_.propagate_to_callees) {
            propagate_forward(origin_func, origin_var_idx, new_type, 0, result);
        }
    }

    if (direction == PropagationDirection::Backward || direction == PropagationDirection::Both) {
        if (options_.propagate_to_callers) {
            propagate_backward(origin_func, origin_var_idx, new_type, 0, result);
        }
    }

    return result;
}

inline PropagationResult TypePropagator::propagate_local(
    cfunc_t* cfunc,
    int var_idx,
    const tinfo_t& new_type)
{
    PropagationResult result;

    if (!cfunc) return result;

    // Find all aliases
    qvector<int> aliases;
    find_aliased_vars(cfunc, var_idx, aliases);

    // Apply to original
    if (apply_type(cfunc, var_idx, new_type)) {
        PropagationSite site;
        site.func_ea = cfunc->entry_ea;
        site.var_idx = var_idx;
        site.new_type = new_type;
        result.add_success(std::move(site));
    }

    // Apply to aliases
    for (int alias_idx : aliases) {
        if (alias_idx == var_idx) continue;

        if (apply_type(cfunc, alias_idx, new_type)) {
            PropagationSite site;
            site.func_ea = cfunc->entry_ea;
            site.var_idx = alias_idx;
            site.new_type = new_type;
            result.add_success(std::move(site));
        }
    }

    return result;
}

inline bool TypePropagator::apply_type(cfunc_t* cfunc, int var_idx, const tinfo_t& type) {
    if (!cfunc || type.empty()) return false;

    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars || var_idx < 0 || static_cast<size_t>(var_idx) >= lvars->size()) {
        return false;
    }

    lvar_t& var = lvars->at(var_idx);

    // Create pointer type to the synthesized struct
    tinfo_t ptr_type = type;
    if (!ptr_type.is_ptr()) {
        ptr_type.create_ptr(type);
    }

    // Apply type
    lvar_saved_info_t lsi;
    lsi.ll = var;
    lsi.type = ptr_type;

    if (!modify_user_lvar_info(cfunc->entry_ea, MLI_TYPE, lsi)) {
        return false;
    }

    // Force refresh
    var.set_lvar_type(ptr_type);

    return true;
}

inline void TypePropagator::propagate_forward(
    ea_t func_ea,
    int var_idx,
    const tinfo_t& type,
    int depth,
    PropagationResult& result)
{
    if (depth >= options_.max_propagation_depth) return;

    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) return;

    // Find all callees where this variable is passed as an argument
    qvector<CalleeArgInfo> callees;
    find_callees_with_arg(cfunc, var_idx, callees);

    for (const auto& info : callees) {
        auto key = make_visit_key(info.callee_ea, info.param_idx);
        if (visited_.count(key)) continue;
        visited_.insert(key);

        cfuncptr_t callee_cfunc = utils::get_cfunc(info.callee_ea);
        if (!callee_cfunc) continue;

        tinfo_t callee_type = type;
        if (info.by_ref) {
            tinfo_t ptr_type;
            ptr_type.create_ptr(type);
            callee_type = ptr_type;
        }

        PropagationSite site;
        site.func_ea = info.callee_ea;
        site.var_idx = info.param_idx;
        site.new_type = callee_type;
        site.direction = PropagationDirection::Forward;

        lvars_t& callee_lvars = *callee_cfunc->get_lvars();
        if (info.param_idx >= 0 && static_cast<size_t>(info.param_idx) < callee_lvars.size()) {
            site.var_name = callee_lvars[info.param_idx].name;
            site.old_type = callee_lvars[info.param_idx].type();
        }

        if (apply_type(callee_cfunc, info.param_idx, callee_type)) {
            result.add_success(std::move(site));

            // Continue propagation
            propagate_forward(info.callee_ea, info.param_idx, callee_type, depth + 1, result);
        } else {
            site.failure_reason = "Failed to apply type";
            result.add_failure(std::move(site));
        }
    }

    // Propagate through return-value assignments: var = callee()
    qvector<std::pair<ea_t, int>> return_sources;
    find_assigned_from(cfunc, var_idx, return_sources);
    for (const auto& [callee_ea, ret_marker] : return_sources) {
        (void)ret_marker;
        cfuncptr_t callee_cfunc = utils::get_cfunc(callee_ea);
        if (!callee_cfunc) continue;

        qvector<std::pair<int, sval_t>> return_vars;
        find_return_sources(callee_cfunc, return_vars);

        for (const auto& [return_var_idx, return_delta] : return_vars) {
            (void)return_delta;
            auto key = make_visit_key(callee_ea, return_var_idx);
            if (visited_.count(key)) continue;
            visited_.insert(key);

            PropagationSite site;
            site.func_ea = callee_ea;
            site.var_idx = return_var_idx;
            site.new_type = type;
            site.direction = PropagationDirection::Forward;

            lvars_t& callee_lvars = *callee_cfunc->get_lvars();
            if (return_var_idx >= 0 && static_cast<size_t>(return_var_idx) < callee_lvars.size()) {
                site.var_name = callee_lvars[return_var_idx].name;
                site.old_type = callee_lvars[return_var_idx].type();
            }

            if (apply_type(callee_cfunc, return_var_idx, type)) {
                result.add_success(std::move(site));
                propagate_forward(callee_ea, return_var_idx, type, depth + 1, result);
            } else {
                site.failure_reason = "Failed to apply type";
                result.add_failure(std::move(site));
            }
        }
    }
}

inline void TypePropagator::propagate_backward(
    ea_t func_ea,
    int var_idx,
    const tinfo_t& type,
    int depth,
    PropagationResult& result)
{
    if (depth >= options_.max_propagation_depth) return;

    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) return;

    // Propagate through return-value assignments: caller_var = func()
    qvector<std::pair<int, sval_t>> return_vars;
    find_return_sources(cfunc, return_vars);
    for (const auto& [return_var_idx, return_delta] : return_vars) {
        if (return_var_idx != var_idx) continue;
        (void)return_delta;

        qvector<std::pair<ea_t, int>> callers;
        find_callers_with_return(func_ea, callers);

        for (const auto& [caller_ea, caller_var_idx] : callers) {
            auto key = make_visit_key(caller_ea, caller_var_idx);
            if (visited_.count(key)) continue;
            visited_.insert(key);

            cfuncptr_t caller_cfunc = utils::get_cfunc(caller_ea);
            if (!caller_cfunc) continue;

            PropagationSite site;
            site.func_ea = caller_ea;
            site.var_idx = caller_var_idx;
            site.new_type = type;
            site.direction = PropagationDirection::Backward;

            lvars_t& caller_lvars = *caller_cfunc->get_lvars();
            if (caller_var_idx >= 0 && static_cast<size_t>(caller_var_idx) < caller_lvars.size()) {
                site.var_name = caller_lvars[caller_var_idx].name;
                site.old_type = caller_lvars[caller_var_idx].type();
            }

            if (apply_type(caller_cfunc, caller_var_idx, type)) {
                result.add_success(std::move(site));

                // Continue backward propagation
                propagate_backward(caller_ea, caller_var_idx, type, depth + 1, result);

                // Also propagate forward to reach siblings
                propagate_forward(caller_ea, caller_var_idx, type, depth + 1, result);
            } else {
                site.failure_reason = "Failed to apply type";
                result.add_failure(std::move(site));
            }
        }
    }

    // Check if this is a parameter
    if (!is_parameter(cfunc, var_idx)) return;

    int param_idx = get_param_index(cfunc, var_idx);
    if (param_idx < 0) return;

    // Find all callers that pass to this parameter
    qvector<CallerArgInfo> callers;
    find_callers_with_param(func_ea, param_idx, callers);

    for (const auto& info : callers) {
        auto key = make_visit_key(info.caller_ea, info.var_idx);
        if (visited_.count(key)) continue;
        visited_.insert(key);

        cfuncptr_t caller_cfunc = utils::get_cfunc(info.caller_ea);
        if (!caller_cfunc) continue;

        tinfo_t caller_type = type;
        if (info.by_ref && type.is_ptr()) {
            tinfo_t deref = type.get_pointed_object();
            if (!deref.empty()) {
                caller_type = deref;
            }
        }

        PropagationSite site;
        site.func_ea = info.caller_ea;
        site.var_idx = info.var_idx;
        site.new_type = caller_type;
        site.direction = PropagationDirection::Backward;

        lvars_t& caller_lvars = *caller_cfunc->get_lvars();
        if (info.var_idx >= 0 && static_cast<size_t>(info.var_idx) < caller_lvars.size()) {
            site.var_name = caller_lvars[info.var_idx].name;
            site.old_type = caller_lvars[info.var_idx].type();
        }

        if (apply_type(caller_cfunc, info.var_idx, caller_type)) {
            result.add_success(std::move(site));

            // Continue backward propagation
            propagate_backward(info.caller_ea, info.var_idx, caller_type, depth + 1, result);
            
            // IMPORTANT: Also propagate forward from the caller to reach sibling callees
            // This ensures that if main() calls both init_simple() and process_simple()
            // with the same struct, process_simple() also gets the type
            propagate_forward(info.caller_ea, info.var_idx, caller_type, depth + 1, result);
        } else {
            site.failure_reason = "Failed to apply type";
            result.add_failure(std::move(site));
        }
    }
}

inline void TypePropagator::find_callees_with_arg(
    cfunc_t* cfunc,
    int var_idx,
    qvector<CalleeArgInfo>& callees)
{
    if (!cfunc) return;

    // Visit all call expressions
    struct CallVisitor : public ctree_visitor_t {
        int target_var_idx;
        qvector<CalleeArgInfo>& results;

        CallVisitor(int var_idx, qvector<CalleeArgInfo>& r)
            : ctree_visitor_t(CV_FAST)
            , target_var_idx(var_idx)
            , results(r) {}

        static const cexpr_t* find_base_var(const cexpr_t* expr) {
            while (expr) {
                if (expr->op == cot_var) return expr;
                if (expr->op == cot_cast || expr->op == cot_ref || expr->op == cot_ptr) {
                    expr = expr->x;
                } else if (expr->op == cot_add || expr->op == cot_sub) {
                    const cexpr_t* left = find_base_var(expr->x);
                    if (left) return left;
                    expr = expr->y;
                } else if (expr->op == cot_memref || expr->op == cot_memptr) {
                    expr = expr->x;
                } else if (expr->op == cot_idx) {
                    expr = expr->x;
                } else {
                    break;
                }
            }
            return nullptr;
        }

        static bool contains_ref(const cexpr_t* expr) {
            if (!expr) return false;
            if (expr->op == cot_ref) return true;

            switch (expr->op) {
                case cot_cast:
                case cot_ptr:
                case cot_memref:
                case cot_memptr:
                case cot_idx:
                    return contains_ref(expr->x);
                case cot_add:
                case cot_sub:
                    return contains_ref(expr->x) || contains_ref(expr->y);
                default:
                    return false;
            }
        }

        int idaapi visit_expr(cexpr_t* expr) override {
            if (expr->op != cot_call || !expr->a) return 0;

            // Check if target is a direct call
            ea_t callee_ea = BADADDR;
            if (expr->x->op == cot_obj) {
                callee_ea = expr->x->obj_ea;
            } else if (expr->x->op == cot_helper) {
                // Helper function - skip
                return 0;
            }

            if (callee_ea == BADADDR) return 0;

            // Check each argument
            for (size_t i = 0; i < expr->a->size(); ++i) {
                const carg_t& arg = expr->a->at(i);
                const cexpr_t* base = find_base_var(&arg);

                if (base && base->op == cot_var && base->v.idx == target_var_idx) {
                    CalleeArgInfo info;
                    info.callee_ea = callee_ea;
                    info.param_idx = static_cast<int>(i);
                    info.by_ref = contains_ref(&arg);
                    results.push_back(info);
                    break;
                }
            }

            return 0;
        }
    };

    CallVisitor visitor(var_idx, callees);
    visitor.apply_to(&cfunc->body, nullptr);
}

inline void TypePropagator::find_callers_with_param(
    ea_t func_ea,
    int param_idx,
    qvector<CallerArgInfo>& callers)
{
    // Get all callers
    qvector<ea_t> caller_funcs = utils::get_callers(func_ea);

    for (ea_t caller_ea : caller_funcs) {
        cfuncptr_t caller_cfunc = utils::get_cfunc(caller_ea);
        if (!caller_cfunc) continue;

        // Find calls to our function
        struct CallerFinder : public ctree_visitor_t {
            ea_t target_func;
            int target_param;
            qvector<CallerArgInfo>& results;
            ea_t caller_ea;

            CallerFinder(ea_t func, int param, ea_t caller, qvector<CallerArgInfo>& r)
                : ctree_visitor_t(CV_FAST)
                , target_func(func)
                , target_param(param)
                , results(r)
                , caller_ea(caller) {}

            // Helper to extract base variable from complex expressions
            static cexpr_t* find_base_var(cexpr_t* expr) {
                while (expr) {
                    if (expr->op == cot_var) return expr;
                    if (expr->op == cot_cast || expr->op == cot_ref || expr->op == cot_ptr) {
                        expr = expr->x;
                    } else if (expr->op == cot_add || expr->op == cot_sub) {
                        // Try both sides for (ptr + offset) or (offset + ptr)
                        cexpr_t* left = find_base_var(expr->x);
                        if (left) return left;
                        expr = expr->y;
                    } else if (expr->op == cot_memref || expr->op == cot_memptr) {
                        expr = expr->x;
                    } else if (expr->op == cot_idx) {
                        expr = expr->x;
                    } else {
                        break;
                    }
                }
                return nullptr;
            }

            static bool contains_ref(const cexpr_t* expr) {
                if (!expr) return false;
                if (expr->op == cot_ref) return true;

                switch (expr->op) {
                    case cot_cast:
                    case cot_ptr:
                    case cot_memref:
                    case cot_memptr:
                    case cot_idx:
                        return contains_ref(expr->x);
                    case cot_add:
                    case cot_sub:
                        return contains_ref(expr->x) || contains_ref(expr->y);
                    default:
                        return false;
                }
            }

            int idaapi visit_expr(cexpr_t* expr) override {
                if (expr->op != cot_call || !expr->a) return 0;

                ea_t callee_ea = BADADDR;
                if (expr->x->op == cot_obj) {
                    callee_ea = expr->x->obj_ea;
                }

                if (callee_ea != target_func) return 0;

                // Found a call - check the argument at target_param
                if (static_cast<size_t>(target_param) >= expr->a->size()) return 0;

                const carg_t& arg = expr->a->at(target_param);

                // Use helper to find base variable through complex expressions
                cexpr_t* base_var = find_base_var(const_cast<cexpr_t*>(static_cast<const cexpr_t*>(&arg)));
                if (base_var && base_var->op == cot_var) {
                    CallerArgInfo info;
                    info.caller_ea = caller_ea;
                    info.var_idx = base_var->v.idx;
                    info.by_ref = contains_ref(&arg);
                    results.push_back(info);
                }

                return 0;
            }
        };

        CallerFinder finder(func_ea, param_idx, caller_ea, callers);
        finder.apply_to(&caller_cfunc->body, nullptr);
    }
}

inline void TypePropagator::find_aliased_vars(
    cfunc_t* cfunc,
    int var_idx,
    qvector<int>& aliases)
{
    if (!cfunc) return;

    // Find all assignments of our variable to other variables
    struct AliasVisitor : public ctree_visitor_t {
        int target_var;
        qvector<int>& aliases;

        AliasVisitor(int var, qvector<int>& a)
            : ctree_visitor_t(CV_FAST)
            , target_var(var)
            , aliases(a) {}

        int idaapi visit_expr(cexpr_t* expr) override {
            if (expr->op != cot_asg) return 0;

            // Check if right side is our variable
            cexpr_t* rhs = expr->y;
            while (rhs->op == cot_cast) {
                rhs = rhs->x;
            }

            if (rhs->op == cot_var && rhs->v.idx == target_var) {
                // Check if left side is a variable
                cexpr_t* lhs = expr->x;
                if (lhs->op == cot_var) {
                    aliases.push_back(lhs->v.idx);
                }
            }

            // Also check reverse (our variable assigned from another)
            cexpr_t* lhs = expr->x;
            if (lhs->op == cot_var && lhs->v.idx == target_var) {
                rhs = expr->y;
                while (rhs->op == cot_cast) {
                    rhs = rhs->x;
                }
                if (rhs->op == cot_var) {
                    aliases.push_back(rhs->v.idx);
                }
            }

            return 0;
        }
    };

    AliasVisitor visitor(var_idx, aliases);
    visitor.apply_to(&cfunc->body, nullptr);
}

inline void TypePropagator::find_assigned_from(
    cfunc_t* cfunc,
    int var_idx,
    qvector<std::pair<ea_t, int>>& sources)
{
    if (!cfunc) return;

    // Find assignments to our variable from call results
    struct SourceVisitor : public ctree_visitor_t {
        int target_var;
        qvector<std::pair<ea_t, int>>& sources;

        SourceVisitor(int var, qvector<std::pair<ea_t, int>>& s)
            : ctree_visitor_t(CV_FAST)
            , target_var(var)
            , sources(s) {}

        int idaapi visit_expr(cexpr_t* expr) override {
            if (expr->op != cot_asg) return 0;

            // Check if left side is our variable
            cexpr_t* lhs = expr->x;
            if (lhs->op != cot_var || lhs->v.idx != target_var) return 0;

            // Check if right side is a call
            cexpr_t* rhs = expr->y;
            while (rhs->op == cot_cast) {
                rhs = rhs->x;
            }

            if (rhs->op == cot_call && rhs->x->op == cot_obj) {
                ea_t callee = rhs->x->obj_ea;
                sources.push_back({callee, -1});  // -1 indicates return value
            }

            return 0;
        }
    };

    SourceVisitor visitor(var_idx, sources);
    visitor.apply_to(&cfunc->body, nullptr);
}

inline void TypePropagator::find_return_sources(
    cfunc_t* cfunc,
    qvector<std::pair<int, sval_t>>& sources)
{
    if (!cfunc) return;

    struct ReturnVisitor : public ctree_visitor_t {
        qvector<std::pair<int, sval_t>>& sources;

        ReturnVisitor(qvector<std::pair<int, sval_t>>& s)
            : ctree_visitor_t(CV_FAST)
            , sources(s) {}

        int idaapi visit_insn(cinsn_t* insn) override {
            if (!insn || insn->op != cit_return) return 0;
            if (!insn->creturn) return 0;

            cexpr_t* expr = &insn->creturn->expr;
            if (!expr || expr->op == cot_empty) return 0;

            auto info = utils::extract_ptr_arith(expr);
            if (!info.valid || info.var_idx < 0) return 0;

            for (const auto& entry : sources) {
                if (entry.first == info.var_idx && entry.second == info.offset) {
                    return 0;
                }
            }

            sources.push_back({info.var_idx, info.offset});
            return 0;
        }
    };

    ReturnVisitor visitor(sources);
    visitor.apply_to(&cfunc->body, nullptr);
}

inline void TypePropagator::find_callers_with_return(
    ea_t func_ea,
    qvector<std::pair<ea_t, int>>& callers)
{
    qvector<ea_t> caller_funcs = utils::get_callers(func_ea);

    for (ea_t caller_ea : caller_funcs) {
        cfuncptr_t caller_cfunc = utils::get_cfunc(caller_ea);
        if (!caller_cfunc) continue;

        struct ReturnCallerFinder : public ctree_visitor_t {
            ea_t target_func;
            ea_t caller_ea;
            qvector<std::pair<ea_t, int>>& results;

            ReturnCallerFinder(ea_t func, ea_t caller, qvector<std::pair<ea_t, int>>& r)
                : ctree_visitor_t(CV_FAST)
                , target_func(func)
                , caller_ea(caller)
                , results(r) {}

            static cexpr_t* find_base_var(cexpr_t* expr) {
                while (expr) {
                    if (expr->op == cot_var) return expr;
                    if (expr->op == cot_cast || expr->op == cot_ref) {
                        expr = expr->x;
                    } else if (expr->op == cot_add || expr->op == cot_sub) {
                        cexpr_t* left = find_base_var(expr->x);
                        if (left) return left;
                        expr = expr->y;
                    } else if (expr->op == cot_memref || expr->op == cot_memptr) {
                        expr = expr->x;
                    } else if (expr->op == cot_idx) {
                        expr = expr->x;
                    } else {
                        break;
                    }
                }
                return nullptr;
            }

            int idaapi visit_expr(cexpr_t* expr) override {
                if (!expr || expr->op != cot_asg) return 0;

                cexpr_t* lhs = expr->x;
                cexpr_t* rhs = expr->y;
                while (rhs && rhs->op == cot_cast) {
                    rhs = rhs->x;
                }

                if (!rhs || rhs->op != cot_call || !rhs->x) return 0;
                if (rhs->x->op != cot_obj || rhs->x->obj_ea != target_func) return 0;

                cexpr_t* base = find_base_var(lhs);
                if (!base || base->op != cot_var) return 0;

                results.push_back({caller_ea, base->v.idx});
                return 0;
            }
        };

        ReturnCallerFinder finder(func_ea, caller_ea, callers);
        finder.apply_to(&caller_cfunc->body, nullptr);
    }
}

inline bool TypePropagator::is_parameter(cfunc_t* cfunc, int var_idx) {
    if (!cfunc || var_idx < 0) return false;

    lvars_t& lvars = *cfunc->get_lvars();
    if (static_cast<size_t>(var_idx) >= lvars.size()) return false;

    return lvars[var_idx].is_arg_var();
}

inline int TypePropagator::get_param_index(cfunc_t* cfunc, int var_idx) {
    if (!cfunc || var_idx < 0) return -1;

    lvars_t& lvars = *cfunc->get_lvars();
    if (static_cast<size_t>(var_idx) >= lvars.size()) return -1;

    if (!lvars[var_idx].is_arg_var()) return -1;

    // Count parameters before this one
    int param_idx = 0;
    for (int i = 0; i < var_idx; ++i) {
        if (lvars[i].is_arg_var()) {
            ++param_idx;
        }
    }

    return param_idx;
}

} // namespace structor
