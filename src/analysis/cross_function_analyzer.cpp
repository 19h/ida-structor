#include "structor/cross_function_analyzer.hpp"
#include "structor/access_collector.hpp"
#include "structor/config.hpp"
#include "structor/utils.hpp"
#include <algorithm>
#include <queue>

#ifndef STRUCTOR_TESTING
#include <nalt.hpp>
#include <funcs.hpp>
#endif

namespace structor {

namespace {
    tinfo_t build_funcptr_type_from_call(const cexpr_t* call_expr) {
        tinfo_t result;
        if (!call_expr || call_expr->op != cot_call) {
            return result;
        }

        func_type_data_t ftd;
        if (!call_expr->type.empty()) {
            ftd.rettype = call_expr->type;
        } else {
            ftd.rettype.create_simple_type(BTF_VOID);
        }
        ftd.set_cc(CM_CC_UNKNOWN);

        if (call_expr->a) {
            for (const auto& arg : *call_expr->a) {
                tinfo_t arg_type = arg.type;
                if (arg_type.empty()) {
                    tinfo_t void_type;
                    void_type.create_simple_type(BTF_VOID);
                    arg_type.create_ptr(void_type);
                }
                funcarg_t farg;
                farg.type = arg_type;
                ftd.push_back(farg);
            }
        }

        tinfo_t func_type;
        if (func_type.create_func(ftd)) {
            result.create_ptr(func_type);
        }

        return result;
    }

    tinfo_t get_call_funcptr_type(const cexpr_t* call_expr) {
        tinfo_t result;
        if (!call_expr) {
            return result;
        }

        if (call_expr->x && !call_expr->x->type.empty()) {
            tinfo_t callee_type = call_expr->x->type;
            if (callee_type.is_funcptr()) {
                return callee_type;
            }
            if (callee_type.is_ptr()) {
                tinfo_t pointed = callee_type.get_pointed_object();
                if (!pointed.empty() && pointed.is_func()) {
                    return callee_type;
                }
            }
            if (callee_type.is_func()) {
                tinfo_t ptr_type;
                ptr_type.create_ptr(callee_type);
                return ptr_type;
            }
        }

        return build_funcptr_type_from_call(call_expr);
    }

    bool extract_func_type(const tinfo_t& type, tinfo_t& out) {
        if (type.empty()) {
            return false;
        }

        if (type.is_func()) {
            out = type;
            return true;
        }

        if (type.is_funcptr()) {
            tinfo_t pointed = type.get_pointed_object();
            if (!pointed.empty()) {
                out = pointed;
                return true;
            }
        }

        if (type.is_ptr()) {
            tinfo_t pointed = type.get_pointed_object();
            if (!pointed.empty() && pointed.is_func()) {
                out = pointed;
                return true;
            }
        }

        return false;
    }

    qvector<ea_t> resolve_indirect_callees(const tinfo_t& funcptr_type, size_t max_results) {
        qvector<ea_t> matches;

#ifndef STRUCTOR_TESTING
        if (funcptr_type.empty() || max_results == 0) {
            return matches;
        }

        tinfo_t target_func;
        if (!extract_func_type(funcptr_type, target_func)) {
            return matches;
        }

        static std::unordered_map<std::string, qvector<ea_t>> cache;
        std::string key = utils::type_to_string(funcptr_type).c_str();
        auto it = cache.find(key);
        if (it != cache.end()) {
            return it->second;
        }

        int target_nargs = target_func.get_nargs();
        size_t func_qty = get_func_qty();

        for (size_t i = 0; i < func_qty; ++i) {
            func_t* fn = getn_func(i);
            if (!fn) {
                continue;
            }

            tinfo_t fn_type;
            if (!get_tinfo(&fn_type, fn->start_ea)) {
                continue;
            }

            tinfo_t fn_func;
            if (!extract_func_type(fn_type, fn_func)) {
                continue;
            }

            if (target_nargs >= 0) {
                int fn_nargs = fn_func.get_nargs();
                if (fn_nargs >= 0 && fn_nargs != target_nargs) {
                    continue;
                }
            }

            if (fn_func.compare_with(target_func, TCMP_IGNMODS | TCMP_CALL)) {
                matches.push_back(fn->start_ea);
                if (matches.size() >= max_results) {
                    break;
                }
            }
        }

        cache[key] = matches;
#else
        (void)funcptr_type;
        (void)max_results;
#endif

        return matches;
    }

    void recompute_pattern_bounds(AccessPattern& pattern) {
        if (pattern.accesses.empty()) {
            pattern.min_offset = 0;
            pattern.max_offset = 0;
            return;
        }

        pattern.sort_by_offset();
        pattern.min_offset = pattern.accesses.front().offset;
        pattern.max_offset = pattern.accesses.front().offset +
                             static_cast<sval_t>(pattern.accesses.front().size);

        for (const auto& access : pattern.accesses) {
            pattern.min_offset = std::min(pattern.min_offset, access.offset);
            pattern.max_offset = std::max(pattern.max_offset,
                access.offset + static_cast<sval_t>(access.size));
        }
    }

    void adjust_pattern_for_base_indirection(AccessPattern& pattern, std::uint8_t adjust) {
        if (adjust == 0 || pattern.accesses.empty()) {
            return;
        }

        qvector<FieldAccess> adjusted;
        adjusted.reserve(pattern.accesses.size());

        for (auto& access : pattern.accesses) {
            if (!access.base_indirection.has_value()) {
                adjusted.push_back(std::move(access));
                continue;
            }
            if (*access.base_indirection < adjust) {
                continue;
            }

            std::uint8_t new_depth = static_cast<std::uint8_t>(*access.base_indirection - adjust);
            if (new_depth == 0) {
                access.base_indirection.reset();
            } else {
                access.base_indirection = new_depth;
            }

            adjusted.push_back(std::move(access));
        }

        pattern.accesses = std::move(adjusted);
        recompute_pattern_bounds(pattern);
    }
}

// ============================================================================
// UnifiedAccessPattern Implementation
// ============================================================================

UnifiedAccessPattern UnifiedAccessPattern::from_single(AccessPattern&& pattern) {
    UnifiedAccessPattern result;

    result.contributing_functions.push_back(pattern.func_ea);
    result.function_deltas[pattern.func_ea] = 0;  // No delta for single pattern

    result.global_min_offset = pattern.min_offset;
    result.global_max_offset = pattern.max_offset;
    result.has_vtable = pattern.has_vtable;
    result.vtable_offset = pattern.vtable_offset;

    // Copy accesses
    result.all_accesses = std::move(pattern.accesses);

    // Store original pattern
    result.per_function_patterns.push_back(std::move(pattern));

    return result;
}

UnifiedAccessPattern UnifiedAccessPattern::merge(
    qvector<AccessPattern>&& patterns,
    const std::unordered_map<ea_t, sval_t>& deltas)
{
    UnifiedAccessPattern result;

    if (patterns.empty()) {
        return result;
    }

    result.function_deltas = deltas;

    // Initialize bounds
    bool first = true;

    for (auto& pattern : patterns) {
        ea_t func_ea = pattern.func_ea;
        result.contributing_functions.push_back(func_ea);

        // Get delta for this function (default 0)
        sval_t delta = 0;
        auto it = deltas.find(func_ea);
        if (it != deltas.end()) {
            delta = it->second;
        }

        // Copy and normalize accesses
        // When a function receives ptr = (original + delta), an access at offset X
        // corresponds to original + delta + X, so normalized offset = X + delta
        for (auto& access : pattern.accesses) {
            FieldAccess normalized = access;
            normalized.offset += delta;  // Add delta to normalize to caller's coordinate system

            // Update bounds
            if (first) {
                result.global_min_offset = normalized.offset;
                result.global_max_offset = normalized.offset + normalized.size;
                first = false;
            } else {
                result.global_min_offset = std::min(result.global_min_offset, normalized.offset);
                result.global_max_offset = std::max(result.global_max_offset,
                    normalized.offset + static_cast<sval_t>(normalized.size));
            }

            // Check for vtable
            if (normalized.is_vtable_access) {
                result.has_vtable = true;
                result.vtable_offset = normalized.offset;
            }

            result.all_accesses.push_back(std::move(normalized));
        }

        result.per_function_patterns.push_back(std::move(pattern));
    }

    // Deduplicate merged accesses by (offset, size)
    std::sort(result.all_accesses.begin(), result.all_accesses.end(),
        [](const FieldAccess& a, const FieldAccess& b) {
            if (a.offset != b.offset) return a.offset < b.offset;
            return a.size < b.size;
        });

    qvector<FieldAccess> deduped;
    deduped.reserve(result.all_accesses.size());

    for (auto& access : result.all_accesses) {
        bool found = false;
        for (auto& existing : deduped) {
            if (existing.offset == access.offset && existing.size == access.size) {
                // Merge: prefer more specific type
                if (semantic_priority(access.semantic_type) > semantic_priority(existing.semantic_type)) {
                    existing.semantic_type = access.semantic_type;
                }
                if (!access.inferred_type.empty()) {
                    existing.inferred_type = resolve_type_conflict(existing.inferred_type, access.inferred_type);
                }
                if (access.is_vtable_access) {
                    existing.is_vtable_access = true;
                    existing.vtable_slot = access.vtable_slot;
                }
                if (!access.bitfields.empty()) {
                    for (const auto& bf : access.bitfields) {
                        existing.add_bitfield(bf);
                    }
                }

                if (access.array_stride_hint.has_value()) {
                    if (!existing.array_stride_hint.has_value()) {
                        existing.array_stride_hint = access.array_stride_hint;
                    } else if (*existing.array_stride_hint != *access.array_stride_hint) {
                        existing.array_stride_hint.reset();
                    }
                }

                if (access.base_indirection.has_value()) {
                    if (!existing.base_indirection.has_value()) {
                        existing.base_indirection = access.base_indirection;
                    } else if (*existing.base_indirection != *access.base_indirection) {
                        existing.base_indirection.reset();
                    }
                }

                found = true;
                break;

            }
        }
        if (!found) {
            deduped.push_back(std::move(access));
        }
    }

    result.all_accesses = std::move(deduped);

    return result;
}

std::size_t UnifiedAccessPattern::unique_access_locations() const {
    std::unordered_set<uint64_t> locations;
    for (const auto& access : all_accesses) {
        // Combine offset and size into a single key
        uint64_t key = (static_cast<uint64_t>(access.offset) << 32) |
                       static_cast<uint64_t>(access.size);
        locations.insert(key);
    }
    return locations.size();
}

// ============================================================================
// ArgDeltaExtractor Implementation
// ============================================================================

ArgDeltaExtractor::ArgDeltaExtractor(int target_var_idx)
    : ctree_visitor_t(CV_FAST)
    , target_var_idx_(target_var_idx) {}

int ArgDeltaExtractor::visit_expr(cexpr_t* e) {
    if (!e) return 0;

    // Check if this is a reference to our target variable
    if (is_target_var(e)) {
        found_ = true;
        delta_ = 0;  // Direct reference, no delta
        return 1;  // Stop traversal
    }

    // Check for ptr + const pattern
    if (e->op == cot_add) {
        if (is_target_var(e->x) && e->y && e->y->op == cot_num) {
            found_ = true;
            delta_ = e->y->numval();
            return 1;
        }
        if (is_target_var(e->y) && e->x && e->x->op == cot_num) {
            found_ = true;
            delta_ = e->x->numval();
            return 1;
        }
    }

    // Check for ptr - const pattern (negative delta)
    if (e->op == cot_sub) {
        if (is_target_var(e->x) && e->y && e->y->op == cot_num) {
            found_ = true;
            delta_ = -static_cast<sval_t>(e->y->numval());
            return 1;
        }
    }

    // Check through casts
    if (e->op == cot_cast && is_target_var(e->x)) {
        found_ = true;
        delta_ = 0;
        return 1;
    }

    return 0;
}

bool ArgDeltaExtractor::is_target_var(cexpr_t* e) noexcept {
    if (!e) return false;

    // Direct variable reference
    if (e->op == cot_var && e->v.idx == target_var_idx_) {
        return true;
    }

    if (e->op == cot_cast) {
        return is_target_var(e->x);
    }

    if (e->op == cot_ref) {
        if (is_target_var(e->x)) {
            by_ref_ = true;
            return true;
        }
        return false;
    }

    return false;
}

// ============================================================================
// CallSiteFinder Implementation
// ============================================================================

CallSiteFinder::CallSiteFinder(int target_var_idx)
    : ctree_visitor_t(CV_FAST)
    , target_var_idx_(target_var_idx) {}

int CallSiteFinder::visit_expr(cexpr_t* e) {
    if (!e) return 0;

    if (e->op == cot_call) {
        process_call(e);
    }

    return 0;
}

void CallSiteFinder::process_call(cexpr_t* call_expr) {
    if (!call_expr || !call_expr->a) return;

    carglist_t& args = *call_expr->a;

    for (size_t i = 0; i < args.size(); ++i) {
        carg_t& arg = args[i];

        // Check if this argument involves our target variable
        ArgDeltaExtractor extractor(target_var_idx_);
        extractor.apply_to(&arg, nullptr);

        if (extractor.found()) {
            CallInfo info;
            info.call_ea = call_expr->ea;
            info.callee_ea = get_callee_address(call_expr);
            info.arg_idx = static_cast<int>(i);
            info.delta = extractor.delta().value_or(0);
            info.is_direct = is_direct_call(call_expr);
            info.by_ref = extractor.by_ref();
            info.funcptr_type = get_call_funcptr_type(call_expr);

            calls_.push_back(info);
        }
    }
}

ea_t CallSiteFinder::get_callee_address(cexpr_t* call_expr) const {
    if (!call_expr || !call_expr->x) return BADADDR;

    cexpr_t* callee = call_expr->x;

    // Direct call to a function
    if (callee->op == cot_obj) {
        return callee->obj_ea;
    }

    // Call through helper function
    if (callee->op == cot_helper) {
        // Helper functions don't have direct addresses
        return BADADDR;
    }

    // Indirect call - cannot determine target statically
    return BADADDR;
}

bool CallSiteFinder::is_direct_call(cexpr_t* call_expr) const {
    if (!call_expr || !call_expr->x) return false;

    cexpr_t* callee = call_expr->x;

    // Direct call to a known function
    return callee->op == cot_obj || callee->op == cot_helper;
}

// ============================================================================
// CallerFinder Implementation
// ============================================================================

CallerFinder::CallerFinder(ea_t target_func, int param_idx)
    : target_func_(target_func)
    , param_idx_(param_idx) {}

qvector<CallerCallInfo> CallerFinder::find_callers() {
    qvector<CallerCallInfo> result;

    // Find all cross-references to this function
    xrefblk_t xref;
    for (bool ok = xref.first_to(target_func_, XREF_ALL); ok; ok = xref.next_to()) {
        if (xref.type != fl_CF && xref.type != fl_CN) {
            continue;  // Not a call reference
        }

        ea_t call_site = xref.from;
        ea_t caller_ea = BADADDR;

        // Get containing function
        func_t* caller_func = get_func(call_site);
        if (caller_func) {
            caller_ea = caller_func->start_ea;
        }

        if (caller_ea == BADADDR) continue;

        process_caller(caller_ea, call_site, result);
    }

    return result;
}

void CallerFinder::process_caller(ea_t caller_ea, ea_t call_site, qvector<CallerCallInfo>& result) {
    // Decompile the caller
    cfuncptr_t cfunc = utils::get_cfunc(caller_ea);
    if (!cfunc) return;

    // Find the call expression at call_site
    struct CallLocator : public ctree_visitor_t {
        ea_t target_ea;
        ea_t callee_ea;
        int param_idx;
        qvector<CallerCallInfo>* result;
        cfunc_t* cfunc;
        std::unordered_map<int, std::pair<int, sval_t>> aliases;

        CallLocator(ea_t ea, ea_t callee, int idx, qvector<CallerCallInfo>* r, cfunc_t* cf)
            : ctree_visitor_t(CV_FAST)
            , target_ea(ea)
            , callee_ea(callee)
            , param_idx(idx)
            , result(r)
            , cfunc(cf) {}

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

        bool resolve_var_delta(const cexpr_t* expr, int& var_idx, sval_t& delta) const {
            if (!expr) {
                return false;
            }

            switch (expr->op) {
                case cot_var: {
                    auto it = aliases.find(expr->v.idx);
                    if (it != aliases.end()) {
                        var_idx = it->second.first;
                        delta += it->second.second;
                    } else {
                        var_idx = expr->v.idx;
                    }
                    return true;
                }
                case cot_cast:
                case cot_ref:
                case cot_ptr:
                    return resolve_var_delta(expr->x, var_idx, delta);
                case cot_add: {
                    if (expr->y && expr->y->op == cot_num && resolve_var_delta(expr->x, var_idx, delta)) {
                        delta += static_cast<sval_t>(expr->y->numval());
                        return true;
                    }
                    if (expr->x && expr->x->op == cot_num && resolve_var_delta(expr->y, var_idx, delta)) {
                        delta += static_cast<sval_t>(expr->x->numval());
                        return true;
                    }
                    return false;
                }
                case cot_sub:
                    if (expr->y && expr->y->op == cot_num && resolve_var_delta(expr->x, var_idx, delta)) {
                        delta -= static_cast<sval_t>(expr->y->numval());
                        return true;
                    }
                    return false;
                case cot_memptr:
                case cot_memref:
                    if (resolve_var_delta(expr->x, var_idx, delta)) {
                        delta += expr->m;
                        return true;
                    }
                    return false;
                default:
                    return false;
            }
        }

        int idaapi visit_expr(cexpr_t* e) override {
            if (!e) return 0;

            if (e->op == cot_asg && e->x && e->x->op == cot_var && e->y) {
                int base_var = -1;
                sval_t delta = 0;
                if (resolve_var_delta(e->y, base_var, delta)) {
                    aliases[e->x->v.idx] = {base_var, delta};
                }
                return 0;
            }

            if (e->op != cot_call) return 0;

            // Check if this is the right call site
            if (e->ea != target_ea) return 0;

            // Check if calling our target function
            if (e->x && e->x->op == cot_obj && e->x->obj_ea == callee_ea) {
                // Found the call - extract the argument and delta
                if (e->a && static_cast<size_t>(param_idx) < e->a->size()) {
                    carg_t& arg = (*e->a)[param_idx];
                    const bool by_ref = contains_ref(&arg);
                    auto push_info = [&](int var_idx, sval_t delta) {
                        CallerCallInfo info;
                        info.call_ea = target_ea;
                        info.caller_ea = cfunc->entry_ea;
                        info.var_idx = var_idx;
                        info.delta = delta;
                        info.by_ref = by_ref;
                        result->push_back(std::move(info));
                    };

                    int base_var = -1;
                    sval_t delta = 0;
                    if (resolve_var_delta(&arg, base_var, delta)) {
                        push_info(base_var, delta);
                    }
                }
            }
            return 0;
        }
    };

    CallLocator locator(call_site, target_func_, param_idx_, &result, cfunc);
    locator.apply_to(&cfunc->body, nullptr);
}

// ============================================================================
// Return Flow Helpers
// ============================================================================

struct ReturnSource {
    int   var_idx = -1;
    sval_t delta = 0;
};

static void add_return_source(qvector<ReturnSource>& sources, int var_idx, sval_t delta) {
    for (const auto& src : sources) {
        if (src.var_idx == var_idx && src.delta == delta) {
            return;
        }
    }
    ReturnSource src;
    src.var_idx = var_idx;
    src.delta = delta;
    sources.push_back(src);
}

class ReturnSourceFinder : public ctree_visitor_t {
public:
    ReturnSourceFinder() : ctree_visitor_t(CV_FAST) {}

    int idaapi visit_insn(cinsn_t* insn) override {
        if (!insn || insn->op != cit_return) return 0;
        if (!insn->creturn) return 0;
        cexpr_t* expr = &insn->creturn->expr;
        if (!expr || expr->op == cot_empty) return 0;

        auto info = utils::extract_ptr_arith(expr);
        if (!info.valid || info.var_idx < 0) return 0;

        add_return_source(sources_, info.var_idx, info.offset);
        return 0;
    }

    [[nodiscard]] const qvector<ReturnSource>& sources() const noexcept { return sources_; }

private:
    qvector<ReturnSource> sources_;
};

class ReturnAssignmentFinder : public ctree_visitor_t {
public:
    explicit ReturnAssignmentFinder(qvector<std::pair<ea_t, int>>& results)
        : ctree_visitor_t(CV_FAST)
        , results_(results) {}

    int idaapi visit_expr(cexpr_t* e) override {
        if (!e || e->op != cot_asg) return 0;

        cexpr_t* lhs = e->x;
        cexpr_t* rhs = e->y;
        while (rhs && rhs->op == cot_cast) {
            rhs = rhs->x;
        }

        if (!rhs || rhs->op != cot_call || !rhs->x) return 0;
        if (rhs->x->op != cot_obj) return 0;

        cexpr_t* base = find_base_var(lhs);
        if (!base || base->op != cot_var) return 0;

        results_.push_back({rhs->x->obj_ea, base->v.idx});
        return 0;
    }

private:
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

    qvector<std::pair<ea_t, int>>& results_;
};

// ============================================================================
// CrossFunctionAnalyzer Implementation
// ============================================================================

CrossFunctionAnalyzer::CrossFunctionAnalyzer(const CrossFunctionConfig& config)
    : config_(config) {}

void CrossFunctionAnalyzer::reset() {
    equiv_class_ = TypeEquivalenceClass();
    stats_ = CrossFunctionStats();
    visited_.clear();
    base_indirection_adjusted_.clear();
    deltas_.clear();
    collected_patterns_.clear();
    cfunc_cache_.clear();
    current_opts_ = nullptr;
}

UnifiedAccessPattern CrossFunctionAnalyzer::analyze(
    ea_t func_ea,
    int var_idx,
    const SynthOptions& synth_opts)
{
    auto start_time = std::chrono::steady_clock::now();

    // Reset state for new analysis
    reset();
    current_opts_ = &synth_opts;

    // Add initial variable with delta 0
    add_variable(func_ea, var_idx, 0);

    // Collect initial pattern
    AccessPattern initial_pattern = collect_pattern(func_ea, var_idx, synth_opts);
    if (!initial_pattern.accesses.empty()) {
        collected_patterns_.push_back(std::move(initial_pattern));
    }

    // Trace through call graph
    if (config_.follow_forward) {
        trace_forward(func_ea, var_idx, 0, 0, synth_opts);
    }

    if (config_.follow_backward) {
        trace_backward(func_ea, var_idx, 0, 0, synth_opts);
    }

    // Build result
    UnifiedAccessPattern result = normalize_and_merge();

    // Record statistics
    auto end_time = std::chrono::steady_clock::now();
    stats_.analysis_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    stats_.functions_analyzed = static_cast<int>(equiv_class_.variables.size());
    stats_.total_accesses = static_cast<int>(result.all_accesses.size());
    stats_.flow_edges_found = static_cast<int>(equiv_class_.flow_edges.size());

    // Count detected deltas
    for (const auto& [fv, delta] : deltas_) {
        if (delta != 0) {
            stats_.pointer_deltas_detected++;
        }
    }

    return result;
}

void CrossFunctionAnalyzer::trace_forward(
    ea_t func_ea,
    int var_idx,
    sval_t current_delta,
    int current_depth,
    const SynthOptions& synth_opts)
{
    if (limits_reached() || current_depth >= config_.max_depth) {
        stats_.max_depth_reached = std::max(stats_.max_depth_reached, current_depth);
        return;
    }

    cfuncptr_t cfunc = get_cfunc(func_ea);
    if (!cfunc) return;

    // Find all call sites where this variable is passed as an argument
    auto callees = find_callees_with_arg(cfunc, var_idx);

    for (const auto& call : callees) {
        qvector<ea_t> targets;
        if (call.callee_ea != BADADDR) {
            targets.push_back(call.callee_ea);
        } else if (config_.include_indirect_calls && !call.funcptr_type.empty()) {
            size_t max_results = config_.max_functions > 0
                ? static_cast<size_t>(config_.max_functions)
                : static_cast<size_t>(32);
            targets = resolve_indirect_callees(call.funcptr_type, max_results);
        }

        if (targets.empty()) {
            continue;
        }

        for (ea_t callee_ea : targets) {
            int param_idx = call.arg_idx;
            sval_t arg_delta = call.delta;

            // Check if we've already visited this function/param
            FunctionVariable fv(callee_ea, param_idx, 0);
            if (visited_.count(fv)) continue;

            // Calculate cumulative delta
            sval_t cumulative_delta = current_delta + arg_delta;

            // Add to equivalence class
            add_variable(callee_ea, param_idx, cumulative_delta);

            // Record flow edge
            PointerFlowEdge edge;
            edge.caller_ea = func_ea;
            edge.callee_ea = callee_ea;
            edge.call_site = call.call_ea;
            edge.caller_var_idx = var_idx;
            edge.callee_param_idx = param_idx;
            edge.delta = arg_delta;
            edge.is_direct_call = call.is_direct;
            add_flow_edge(edge);

            // Collect pattern for this function
            AccessPattern pattern = collect_pattern(callee_ea, param_idx, synth_opts);
            if (call.by_ref) {
                FunctionVariable adjusted_key(callee_ea, param_idx, 0);
                if (base_indirection_adjusted_.insert(adjusted_key).second) {
                    adjust_pattern_for_base_indirection(pattern, 1);
                }
            }
            if (!pattern.accesses.empty()) {
                collected_patterns_.push_back(std::move(pattern));
            }

            // Recurse
            trace_forward(callee_ea, param_idx, cumulative_delta, current_depth + 1, synth_opts);
        }
    }

    // Follow return assignments for this variable
    auto return_assignments = find_return_assignments(cfunc);
    for (const auto& [callee_ea, caller_var_idx] : return_assignments) {
        if (caller_var_idx != var_idx) continue;
        if (callee_ea == BADADDR) continue;

        cfuncptr_t callee_cfunc = get_cfunc(callee_ea);
        if (!callee_cfunc) continue;

        auto return_sources = find_return_sources(callee_cfunc);
        for (const auto& [return_var_idx, return_delta] : return_sources) {
            FunctionVariable fv(callee_ea, return_var_idx, 0);
            if (visited_.count(fv)) continue;

            sval_t cumulative_delta = current_delta - return_delta;
            add_variable(callee_ea, return_var_idx, cumulative_delta);

            PointerFlowEdge edge;
            edge.caller_ea = func_ea;
            edge.callee_ea = callee_ea;
            edge.caller_var_idx = var_idx;
            edge.callee_param_idx = -1;  // return value
            edge.delta = return_delta;
            edge.is_direct_call = true;
            add_flow_edge(edge);

            AccessPattern pattern = collect_pattern(callee_ea, return_var_idx, synth_opts);
            if (!pattern.accesses.empty()) {
                collected_patterns_.push_back(std::move(pattern));
            }

            trace_forward(callee_ea, return_var_idx, cumulative_delta, current_depth + 1, synth_opts);
        }
    }
}

void CrossFunctionAnalyzer::trace_backward(
    ea_t func_ea,
    int var_idx,
    sval_t current_delta,
    int current_depth,
    const SynthOptions& synth_opts)
{
    if (limits_reached() || current_depth >= config_.max_depth) {
        stats_.max_depth_reached = std::max(stats_.max_depth_reached, current_depth);
        return;
    }

    // Check if var_idx is a parameter
    cfuncptr_t cfunc = get_cfunc(func_ea);
    if (!cfunc) return;

    lvars_t& lvars = *cfunc->get_lvars();
    if (var_idx < 0 || static_cast<size_t>(var_idx) >= lvars.size()) return;

    lvar_t& var = lvars[var_idx];

    // Return-flow: connect callee return values to caller-assigned variables
    auto return_sources = find_return_sources(cfunc);
    for (const auto& [return_var_idx, return_delta] : return_sources) {
        if (return_var_idx != var_idx) continue;

        if (return_delta != 0) {
            FunctionVariable current_fv(func_ea, var_idx, 0);
            if (deltas_.count(current_fv)) {
                deltas_[current_fv] -= return_delta;
            }
        }

        auto callers = find_callers_with_return(func_ea);
        for (const auto& [caller_ea, caller_var_idx] : callers) {
            FunctionVariable fv(caller_ea, caller_var_idx, 0);
            if (visited_.count(fv)) continue;

            add_variable(caller_ea, caller_var_idx, 0);


            PointerFlowEdge edge;
            edge.caller_ea = caller_ea;
            edge.callee_ea = func_ea;
            edge.caller_var_idx = caller_var_idx;
            edge.callee_param_idx = -1;  // return value
            edge.delta = return_delta;
            edge.is_direct_call = true;
            add_flow_edge(edge);

            AccessPattern pattern = collect_pattern(caller_ea, caller_var_idx, synth_opts);
            if (!pattern.accesses.empty()) {
                collected_patterns_.push_back(std::move(pattern));
            }

            trace_backward(caller_ea, caller_var_idx, 0, current_depth + 1, synth_opts);
            if (config_.follow_forward) {
                trace_forward(caller_ea, caller_var_idx, 0, current_depth + 1, synth_opts);
            }
        }
    }

    // Only trace back through parameters if this is an argument
    if (!var.is_arg_var()) return;

    // Find which parameter index this corresponds to
    int param_idx = -1;
    for (size_t i = 0; i < lvars.size(); ++i) {
        if (lvars[i].is_arg_var()) {
            ++param_idx;
            if (static_cast<int>(i) == var_idx) break;
        }
    }

    if (param_idx < 0) return;

    // Find callers that pass to this parameter (includes delta from call expression)
    auto callers = find_callers_with_param(func_ea, param_idx);

    for (const auto& call : callers) {
        if (call.caller_ea == BADADDR) continue;

        if (call.by_ref) {
            FunctionVariable adjusted_key(func_ea, var_idx, 0);
            if (base_indirection_adjusted_.insert(adjusted_key).second) {
                for (auto& pattern : collected_patterns_) {
                    if (pattern.func_ea == func_ea && pattern.var_idx == var_idx) {
                        adjust_pattern_for_base_indirection(pattern, 1);
                        break;
                    }
                }
            }
        }

        // Check if we've already visited
        FunctionVariable fv(call.caller_ea, call.var_idx, 0);
        if (visited_.count(fv)) continue;

        // The arg_delta is extracted from the call expression.
        // For example, if the call is `func((char*)ptr + 0x10)`, arg_delta = 0x10.
        // This means the callee (current function) sees offsets relative to (ptr + 0x10).
        //
        // When going backward, we want to normalize to the CALLER's coordinate system
        // (since the caller has the "original" struct). So:
        // - The CURRENT function's (callee's) delta should be updated: delta += arg_delta
        // - The CALLER gets delta = 0 (it has the original struct)
        //
        // Example: process_data receives (node + 0x10) from process_node_d
        // - process_data's accesses at offset 0,4 should become 0x10,0x14
        // - process_data's delta should be 0x10
        // - process_node_d's accesses at 0,0x10 stay at 0,0x10
        // - process_node_d's delta should be 0

        // Update current function's delta if arg_delta is non-zero
        if (call.delta != 0) {
            FunctionVariable current_fv(func_ea, var_idx, 0);
            if (deltas_.count(current_fv)) {
                deltas_[current_fv] += call.delta;
            }
        }

        // Caller gets delta = 0 (it has the original struct)
        add_variable(call.caller_ea, call.var_idx, 0);

        // Record flow edge (reversed direction)
        PointerFlowEdge edge;
        edge.caller_ea = call.caller_ea;
        edge.callee_ea = func_ea;
        edge.caller_var_idx = call.var_idx;
        edge.callee_param_idx = var_idx;
        edge.delta = call.delta;
        edge.is_direct_call = true;
        add_flow_edge(edge);

        // Collect pattern
        AccessPattern pattern = collect_pattern(call.caller_ea, call.var_idx, synth_opts);
        if (!pattern.accesses.empty()) {
            collected_patterns_.push_back(std::move(pattern));
        }

        // Recurse backward with delta=0 (caller has original struct)
        trace_backward(call.caller_ea, call.var_idx, 0, current_depth + 1, synth_opts);

        // IMPORTANT: Also trace forward from the caller to discover sibling callees.
        // This ensures that if main() calls both traverse_list() and sum_list()
        // with the same struct, we collect access patterns from all siblings.
        if (config_.follow_forward) {
            trace_forward(call.caller_ea, call.var_idx, 0, current_depth + 1, synth_opts);
        }
    }
}

qvector<CalleeCallInfo> CrossFunctionAnalyzer::find_callees_with_arg(
    cfunc_t* cfunc,
    int var_idx)
{
    qvector<CalleeCallInfo> result;

    if (!cfunc) return result;

    CallSiteFinder finder(var_idx);
    finder.apply_to(&cfunc->body, nullptr);

    for (const auto& call : finder.calls()) {
        if (call.callee_ea != BADADDR || config_.include_indirect_calls) {
            CalleeCallInfo info;
            info.call_ea = call.call_ea;
            info.callee_ea = call.callee_ea;
            info.arg_idx = call.arg_idx;
            info.delta = call.delta;
            info.is_direct = call.is_direct;
            info.by_ref = call.by_ref;
            info.funcptr_type = call.funcptr_type;
            result.push_back(std::move(info));
        }
    }

    return result;
}

std::optional<sval_t> CrossFunctionAnalyzer::extract_arg_delta(
    cexpr_t* arg_expr,
    int target_var_idx)
{
    ArgDeltaExtractor extractor(target_var_idx);
    extractor.apply_to(arg_expr, nullptr);
    return extractor.delta();
}

qvector<CallerCallInfo> CrossFunctionAnalyzer::find_callers_with_param(
    ea_t func_ea,
    int param_idx)
{
    CallerFinder finder(func_ea, param_idx);
    return finder.find_callers();
}

qvector<std::pair<int, sval_t>> CrossFunctionAnalyzer::find_return_sources(cfunc_t* cfunc) {
    qvector<std::pair<int, sval_t>> result;
    if (!cfunc) return result;

    ReturnSourceFinder finder;
    finder.apply_to(&cfunc->body, nullptr);

    for (const auto& src : finder.sources()) {
        result.push_back({src.var_idx, src.delta});
    }

    return result;
}

qvector<std::pair<ea_t, int>> CrossFunctionAnalyzer::find_return_assignments(cfunc_t* cfunc) {
    qvector<std::pair<ea_t, int>> result;
    if (!cfunc) return result;

    ReturnAssignmentFinder finder(result);
    finder.apply_to(&cfunc->body, nullptr);

    return result;
}

qvector<std::pair<ea_t, int>> CrossFunctionAnalyzer::find_callers_with_return(ea_t func_ea) {
    qvector<std::pair<ea_t, int>> result;

    qvector<ea_t> caller_funcs = utils::get_callers(func_ea);
    for (ea_t caller_ea : caller_funcs) {
        cfuncptr_t caller_cfunc = get_cfunc(caller_ea);
        if (!caller_cfunc) continue;

        auto assignments = find_return_assignments(caller_cfunc);
        for (const auto& [callee_ea, caller_var_idx] : assignments) {
            if (callee_ea == func_ea) {
                result.push_back({caller_ea, caller_var_idx});
            }
        }
    }

    return result;
}

AccessPattern CrossFunctionAnalyzer::collect_pattern(
    ea_t func_ea,
    int var_idx,
    const SynthOptions& synth_opts)
{
    AccessCollector collector(synth_opts);
    return collector.collect(func_ea, var_idx);
}

UnifiedAccessPattern CrossFunctionAnalyzer::normalize_and_merge() {
    if (collected_patterns_.empty()) {
        return UnifiedAccessPattern();
    }

    // Build delta map from function EA
    std::unordered_map<ea_t, sval_t> delta_map;
    for (const auto& [fv, delta] : deltas_) {
        delta_map[fv.func_ea] = delta;
    }

    return UnifiedAccessPattern::merge(std::move(collected_patterns_), delta_map);
}

void CrossFunctionAnalyzer::add_variable(ea_t func_ea, int var_idx, sval_t delta) {
    FunctionVariable fv(func_ea, var_idx, delta);

    if (visited_.insert(fv).second) {
        equiv_class_.variables.push_back(fv);
        deltas_[fv] = delta;
    }
}

void CrossFunctionAnalyzer::add_flow_edge(const PointerFlowEdge& edge) {
    equiv_class_.flow_edges.push_back(edge);
}

bool CrossFunctionAnalyzer::limits_reached() const noexcept {
    return static_cast<int>(equiv_class_.variables.size()) >= config_.max_functions;
}

cfuncptr_t CrossFunctionAnalyzer::get_cfunc(ea_t func_ea) {
    auto it = cfunc_cache_.find(func_ea);
    if (it != cfunc_cache_.end()) {
        return it->second;
    }

    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (cfunc) {
        cfunc_cache_.emplace(func_ea, cfunc);
    }
    return cfunc;
}

} // namespace structor
