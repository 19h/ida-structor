#include "structor/cross_function_analyzer.hpp"
#include "structor/access_collector.hpp"
#include "structor/config.hpp"
#include "structor/utils.hpp"
#include <algorithm>
#include <queue>

namespace structor {

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

bool ArgDeltaExtractor::is_target_var(cexpr_t* e) const noexcept {
    if (!e) return false;

    // Direct variable reference
    if (e->op == cot_var && e->v.idx == target_var_idx_) {
        return true;
    }

    // Through cast
    if (e->op == cot_cast) {
        return is_target_var(e->x);
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

qvector<std::tuple<ea_t, int, sval_t>> CallerFinder::find_callers() {
    qvector<std::tuple<ea_t, int, sval_t>> result;

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

void CallerFinder::process_caller(ea_t caller_ea, ea_t call_site, qvector<std::tuple<ea_t, int, sval_t>>& result) {
    // Decompile the caller
    cfuncptr_t cfunc = utils::get_cfunc(caller_ea);
    if (!cfunc) return;

    // Find the call expression at call_site
    struct CallLocator : public ctree_visitor_t {
        ea_t target_ea;
        ea_t callee_ea;
        int param_idx;
        qvector<std::tuple<ea_t, int, sval_t>>* result;
        cfunc_t* cfunc;

        CallLocator(ea_t ea, ea_t callee, int idx, qvector<std::tuple<ea_t, int, sval_t>>* r, cfunc_t* cf)
            : ctree_visitor_t(CV_FAST)
            , target_ea(ea)
            , callee_ea(callee)
            , param_idx(idx)
            , result(r)
            , cfunc(cf) {}

        int idaapi visit_expr(cexpr_t* e) override {
            if (!e || e->op != cot_call) return 0;

            // Check if this is the right call site
            if (e->ea != target_ea) return 0;

            // Check if calling our target function
            if (e->x && e->x->op == cot_obj && e->x->obj_ea == callee_ea) {
                // Found the call - extract the argument and delta
                if (e->a && static_cast<size_t>(param_idx) < e->a->size()) {
                    carg_t& arg = (*e->a)[param_idx];

                    // Check if argument is a simple variable reference (delta = 0)
                    if (arg.op == cot_var) {
                        result->push_back({cfunc->entry_ea, arg.v.idx, 0});
                    }
                    // Also handle casts (delta = 0)
                    else if (arg.op == cot_cast && arg.x && arg.x->op == cot_var) {
                        result->push_back({cfunc->entry_ea, arg.x->v.idx, 0});
                    }
                    // Handle ptr + delta (including casts like (char*)ptr + offset)
                    else if (arg.op == cot_add) {
                        cexpr_t* var_side = nullptr;
                        sval_t delta = 0;

                        // Helper lambda to unwrap casts and find underlying cot_var
                        auto find_var = [](cexpr_t* expr) -> cexpr_t* {
                            while (expr) {
                                if (expr->op == cot_var) return expr;
                                if (expr->op == cot_cast && expr->x) {
                                    expr = expr->x;
                                } else {
                                    break;
                                }
                            }
                            return nullptr;
                        };

                        // Try to find var and number on each side
                        var_side = find_var(arg.x);
                        if (var_side) {
                            // x is the variable side, y might be the delta
                            if (arg.y && arg.y->op == cot_num) {
                                delta = static_cast<sval_t>(arg.y->numval());
                            }
                        } else {
                            var_side = find_var(arg.y);
                            if (var_side && arg.x && arg.x->op == cot_num) {
                                delta = static_cast<sval_t>(arg.x->numval());
                            }
                        }

                        if (var_side) {
                            result->push_back({cfunc->entry_ea, var_side->v.idx, delta});
                        }
                    }
                    // Handle ptr - delta (negative offset)
                    else if (arg.op == cot_sub) {
                        cexpr_t* var_side = nullptr;
                        sval_t delta = 0;

                        auto find_var = [](cexpr_t* expr) -> cexpr_t* {
                            while (expr) {
                                if (expr->op == cot_var) return expr;
                                if (expr->op == cot_cast && expr->x) {
                                    expr = expr->x;
                                } else {
                                    break;
                                }
                            }
                            return nullptr;
                        };

                        var_side = find_var(arg.x);
                        if (var_side && arg.y && arg.y->op == cot_num) {
                            delta = -static_cast<sval_t>(arg.y->numval());
                            result->push_back({cfunc->entry_ea, var_side->v.idx, delta});
                        }
                    }
                    // Handle &struct.field (cot_ref of member access)
                    else if (arg.op == cot_ref && arg.x) {
                        cexpr_t* inner = arg.x;
                        sval_t field_offset = 0;

                        // Unwrap to find the base variable and accumulate field offsets
                        while (inner) {
                            if (inner->op == cot_var) {
                                result->push_back({cfunc->entry_ea, inner->v.idx, field_offset});
                                break;
                            }
                            if (inner->op == cot_memref || inner->op == cot_memptr) {
                                // Accumulate the member offset
                                field_offset += inner->m;
                                inner = inner->x;
                            } else if (inner->op == cot_idx && inner->y && inner->y->op == cot_num) {
                                // Array indexing: accumulate index * element_size
                                // For now, just track the index offset
                                inner = inner->x;
                            } else if (inner->op == cot_cast) {
                                inner = inner->x;
                            } else {
                                break;
                            }
                        }
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
// CrossFunctionAnalyzer Implementation
// ============================================================================

CrossFunctionAnalyzer::CrossFunctionAnalyzer(const CrossFunctionConfig& config)
    : config_(config) {}

void CrossFunctionAnalyzer::reset() {
    equiv_class_ = TypeEquivalenceClass();
    stats_ = CrossFunctionStats();
    visited_.clear();
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

    for (const auto& [callee_ea, param_idx, arg_delta] : callees) {
        if (callee_ea == BADADDR) continue;  // Skip indirect calls

        if (!config_.include_indirect_calls && callee_ea == BADADDR) {
            continue;
        }

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
        edge.caller_var_idx = var_idx;
        edge.callee_param_idx = param_idx;
        edge.delta = arg_delta;
        edge.is_direct_call = true;  // We only track direct calls for now
        add_flow_edge(edge);

        // Collect pattern for this function
        AccessPattern pattern = collect_pattern(callee_ea, param_idx, synth_opts);
        if (!pattern.accesses.empty()) {
            collected_patterns_.push_back(std::move(pattern));
        }

        // Recurse
        trace_forward(callee_ea, param_idx, cumulative_delta, current_depth + 1, synth_opts);
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

    // Only trace back if this is an argument
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

    for (const auto& [caller_ea, caller_var_idx, arg_delta] : callers) {
        if (caller_ea == BADADDR) continue;

        // Check if we've already visited
        FunctionVariable fv(caller_ea, caller_var_idx, 0);
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
        if (arg_delta != 0) {
            FunctionVariable current_fv(func_ea, var_idx, 0);
            if (deltas_.count(current_fv)) {
                deltas_[current_fv] += arg_delta;
            }
        }

        // Caller gets delta = 0 (it has the original struct)
        add_variable(caller_ea, caller_var_idx, 0);

        // Record flow edge (reversed direction)
        PointerFlowEdge edge;
        edge.caller_ea = caller_ea;
        edge.callee_ea = func_ea;
        edge.caller_var_idx = caller_var_idx;
        edge.callee_param_idx = var_idx;
        edge.delta = arg_delta;
        edge.is_direct_call = true;
        add_flow_edge(edge);

        // Collect pattern
        AccessPattern pattern = collect_pattern(caller_ea, caller_var_idx, synth_opts);
        if (!pattern.accesses.empty()) {
            collected_patterns_.push_back(std::move(pattern));
        }

        // Recurse backward with delta=0 (caller has original struct)
        trace_backward(caller_ea, caller_var_idx, 0, current_depth + 1, synth_opts);

        // IMPORTANT: Also trace forward from the caller to discover sibling callees.
        // This ensures that if main() calls both traverse_list() and sum_list()
        // with the same struct, we collect access patterns from all siblings.
        if (config_.follow_forward) {
            trace_forward(caller_ea, caller_var_idx, 0, current_depth + 1, synth_opts);
        }
    }
}

qvector<std::tuple<ea_t, int, sval_t>> CrossFunctionAnalyzer::find_callees_with_arg(
    cfunc_t* cfunc,
    int var_idx)
{
    qvector<std::tuple<ea_t, int, sval_t>> result;

    if (!cfunc) return result;

    CallSiteFinder finder(var_idx);
    finder.apply_to(&cfunc->body, nullptr);

    for (const auto& call : finder.calls()) {
        if (call.callee_ea != BADADDR || config_.include_indirect_calls) {
            result.push_back({call.callee_ea, call.arg_idx, call.delta});
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

qvector<std::tuple<ea_t, int, sval_t>> CrossFunctionAnalyzer::find_callers_with_param(
    ea_t func_ea,
    int param_idx)
{
    CallerFinder finder(func_ea, param_idx);
    return finder.find_callers();
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
