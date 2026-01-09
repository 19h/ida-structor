#pragma once

#ifndef STRUCTOR_TESTING
#include <pro.h>
#include <hexrays.hpp>
#include <funcs.hpp>
#include <xref.hpp>
#endif
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <functional>

namespace structor {

/// Utilities for call graph traversal
namespace call_graph {

/// Get all functions that call the given function
[[nodiscard]] inline qvector<ea_t> get_callers(ea_t func_ea) {
    qvector<ea_t> result;
    std::unordered_set<ea_t> seen;

    xrefblk_t xref;
    for (bool ok = xref.first_to(func_ea, XREF_ALL); ok; ok = xref.next_to()) {
        // Only process call references
        if (xref.type != fl_CF && xref.type != fl_CN) {
            continue;
        }

        // Get the containing function
        func_t* caller_func = get_func(xref.from);
        if (!caller_func) continue;

        ea_t caller_ea = caller_func->start_ea;

        // Avoid duplicates
        if (seen.insert(caller_ea).second) {
            result.push_back(caller_ea);
        }
    }

    return result;
}

/// Get all functions called by the given function
[[nodiscard]] inline qvector<ea_t> get_callees(ea_t func_ea) {
    qvector<ea_t> result;
    std::unordered_set<ea_t> seen;

    func_t* func = get_func(func_ea);
    if (!func) return result;

    // Iterate through all addresses in the function
    for (ea_t ea = func->start_ea; ea < func->end_ea; ) {
        insn_t insn;
        if (decode_insn(&insn, ea) <= 0) {
            ++ea;
            continue;
        }

        // Check for call instructions
        xrefblk_t xref;
        for (bool ok = xref.first_from(ea, XREF_ALL); ok; ok = xref.next_from()) {
            if (xref.type != fl_CF && xref.type != fl_CN) {
                continue;
            }

            ea_t target = xref.to;
            func_t* target_func = get_func(target);

            if (target_func && seen.insert(target_func->start_ea).second) {
                result.push_back(target_func->start_ea);
            }
        }

        ea += insn.size;
    }

    return result;
}

/// Information about a call site
struct CallSiteInfo {
    ea_t call_ea;           // Address of call instruction
    ea_t callee_ea;         // Address of called function (BADADDR if indirect)
    bool is_direct;         // True if direct call
    int arg_count;          // Number of arguments (if known)
};

/// Get all call sites within a function
[[nodiscard]] inline qvector<CallSiteInfo> get_call_sites(ea_t func_ea) {
    qvector<CallSiteInfo> result;

    func_t* func = get_func(func_ea);
    if (!func) return result;

    for (ea_t ea = func->start_ea; ea < func->end_ea; ) {
        insn_t insn;
        if (decode_insn(&insn, ea) <= 0) {
            ++ea;
            continue;
        }

        // Check if this is a call instruction
        xrefblk_t xref;
        for (bool ok = xref.first_from(ea, XREF_ALL); ok; ok = xref.next_from()) {
            if (xref.type != fl_CF && xref.type != fl_CN) {
                continue;
            }

            CallSiteInfo info;
            info.call_ea = ea;
            info.is_direct = (xref.type == fl_CF);  // fl_CF = direct call

            func_t* target = get_func(xref.to);
            info.callee_ea = target ? target->start_ea : BADADDR;
            info.arg_count = -1;  // Unknown

            result.push_back(info);
            break;  // Only one call per instruction
        }

        ea += insn.size;
    }

    return result;
}

/// Check if a call is direct (not through function pointer)
[[nodiscard]] inline bool is_direct_call(ea_t call_site) {
    xrefblk_t xref;
    for (bool ok = xref.first_from(call_site, XREF_ALL); ok; ok = xref.next_from()) {
        if (xref.type == fl_CF) {
            return true;  // Direct call
        }
        if (xref.type == fl_CN) {
            return false;  // Indirect call
        }
    }
    return false;
}

/// Get the function containing an address
[[nodiscard]] inline ea_t get_containing_function(ea_t addr) {
    func_t* func = get_func(addr);
    return func ? func->start_ea : BADADDR;
}

/// Get function name or generate placeholder
[[nodiscard]] inline qstring get_function_name(ea_t func_ea) {
    qstring name;
    if (get_func_name(&name, func_ea) <= 0) {
        name.sprnt("sub_%llX", static_cast<unsigned long long>(func_ea));
    }
    return name;
}

/// Cache decompiled functions to avoid redundant decompilation
class CfuncCache {
public:
    /// Get or decompile a function (cached)
    [[nodiscard]] cfuncptr_t get(ea_t func_ea) {
        auto it = cache_.find(func_ea);
        if (it != cache_.end()) {
            ++stats_.hits;
            return it->second;
        }

        ++stats_.misses;

        // Decompile
        hexrays_failure_t hf;
        cfuncptr_t cfunc = decompile(func_ea, &hf, DECOMP_NO_WAIT);

        if (cfunc) {
            cache_[func_ea] = cfunc;
            ++stats_.total_cached;
        }

        return cfunc;
    }

    /// Check if function is cached
    [[nodiscard]] bool is_cached(ea_t func_ea) const {
        return cache_.count(func_ea) > 0;
    }

    /// Clear cache (e.g., when analysis is complete)
    void clear() {
        cache_.clear();
        stats_ = Stats();
    }

    /// Remove a specific entry
    void evict(ea_t func_ea) {
        cache_.erase(func_ea);
    }

    /// Get cache size
    [[nodiscard]] size_t size() const noexcept {
        return cache_.size();
    }

    /// Get cache statistics
    struct Stats {
        size_t hits = 0;
        size_t misses = 0;
        size_t total_cached = 0;

        [[nodiscard]] double hit_rate() const noexcept {
            size_t total = hits + misses;
            return total > 0 ? static_cast<double>(hits) / total : 0.0;
        }
    };
    [[nodiscard]] const Stats& stats() const noexcept { return stats_; }

private:
    std::unordered_map<ea_t, cfuncptr_t> cache_;
    Stats stats_;
};

/// Visitor pattern for call graph traversal
class CallGraphVisitor {
public:
    virtual ~CallGraphVisitor() = default;

    /// Called for each edge in the call graph
    /// Return false to stop traversal of this branch
    virtual bool visit_edge(ea_t caller, ea_t callee, ea_t call_site) = 0;

    /// Called when entering a function
    /// Return false to skip this function's edges
    virtual bool enter_function(ea_t func_ea) { (void)func_ea; return true; }

    /// Called when leaving a function
    virtual void leave_function(ea_t func_ea) { (void)func_ea; }
};

/// Simple visitor that collects all reachable functions
class ReachableFunctionsVisitor : public CallGraphVisitor {
public:
    bool visit_edge(ea_t caller, ea_t callee, ea_t call_site) override {
        (void)caller;
        (void)call_site;

        if (callee != BADADDR) {
            functions_.insert(callee);
        }
        return true;
    }

    [[nodiscard]] const std::unordered_set<ea_t>& functions() const noexcept {
        return functions_;
    }

private:
    std::unordered_set<ea_t> functions_;
};

/// Visitor that builds an adjacency list representation
class AdjacencyListVisitor : public CallGraphVisitor {
public:
    bool visit_edge(ea_t caller, ea_t callee, ea_t call_site) override {
        (void)call_site;

        if (caller != BADADDR && callee != BADADDR) {
            adjacency_[caller].insert(callee);
        }
        return true;
    }

    [[nodiscard]] const std::unordered_map<ea_t, std::unordered_set<ea_t>>&
    adjacency() const noexcept {
        return adjacency_;
    }

private:
    std::unordered_map<ea_t, std::unordered_set<ea_t>> adjacency_;
};

/// Traverse call graph breadth-first from a starting function
inline void traverse_bfs(
    ea_t start_func,
    CallGraphVisitor& visitor,
    int max_depth = 5,
    bool forward = true)  // true = callees, false = callers
{
    if (start_func == BADADDR) return;

    std::unordered_set<ea_t> visited;
    std::queue<std::pair<ea_t, int>> queue;  // (func_ea, depth)

    queue.push({start_func, 0});
    visited.insert(start_func);

    while (!queue.empty()) {
        auto [func_ea, depth] = queue.front();
        queue.pop();

        if (depth >= max_depth) continue;

        if (!visitor.enter_function(func_ea)) {
            continue;
        }

        // Get neighbors
        qvector<ea_t> neighbors = forward ? get_callees(func_ea) : get_callers(func_ea);

        for (ea_t neighbor : neighbors) {
            if (neighbor == BADADDR) continue;

            // Get call site (for forward traversal)
            ea_t call_site = BADADDR;
            if (forward) {
                // Find the call site in the current function
                auto call_sites = get_call_sites(func_ea);
                for (const auto& site : call_sites) {
                    if (site.callee_ea == neighbor) {
                        call_site = site.call_ea;
                        break;
                    }
                }
            }

            // Visit edge
            ea_t caller = forward ? func_ea : neighbor;
            ea_t callee = forward ? neighbor : func_ea;

            if (!visitor.visit_edge(caller, callee, call_site)) {
                continue;  // Stop this branch
            }

            // Add to queue if not visited
            if (visited.insert(neighbor).second) {
                queue.push({neighbor, depth + 1});
            }
        }

        visitor.leave_function(func_ea);
    }
}

/// Traverse call graph depth-first
inline void traverse_dfs(
    ea_t start_func,
    CallGraphVisitor& visitor,
    int max_depth = 5,
    bool forward = true)
{
    if (start_func == BADADDR) return;

    std::unordered_set<ea_t> visited;

    std::function<void(ea_t, int)> dfs = [&](ea_t func_ea, int depth) {
        if (depth >= max_depth) return;
        if (!visited.insert(func_ea).second) return;

        if (!visitor.enter_function(func_ea)) {
            return;
        }

        qvector<ea_t> neighbors = forward ? get_callees(func_ea) : get_callers(func_ea);

        for (ea_t neighbor : neighbors) {
            if (neighbor == BADADDR) continue;

            ea_t call_site = BADADDR;
            if (forward) {
                auto call_sites = get_call_sites(func_ea);
                for (const auto& site : call_sites) {
                    if (site.callee_ea == neighbor) {
                        call_site = site.call_ea;
                        break;
                    }
                }
            }

            ea_t caller = forward ? func_ea : neighbor;
            ea_t callee = forward ? neighbor : func_ea;

            if (visitor.visit_edge(caller, callee, call_site)) {
                dfs(neighbor, depth + 1);
            }
        }

        visitor.leave_function(func_ea);
    };

    dfs(start_func, 0);
}

/// Count the number of callers for a function
[[nodiscard]] inline size_t caller_count(ea_t func_ea) {
    return get_callers(func_ea).size();
}

/// Count the number of callees for a function
[[nodiscard]] inline size_t callee_count(ea_t func_ea) {
    return get_callees(func_ea).size();
}

/// Check if a function is likely a leaf function (no calls)
[[nodiscard]] inline bool is_leaf_function(ea_t func_ea) {
    return get_callees(func_ea).empty();
}

/// Check if a function is likely an entry point (no callers)
[[nodiscard]] inline bool is_entry_point(ea_t func_ea) {
    return get_callers(func_ea).empty();
}

/// Find common callers between two functions
[[nodiscard]] inline qvector<ea_t> common_callers(ea_t func1, ea_t func2) {
    qvector<ea_t> result;

    auto callers1 = get_callers(func1);
    auto callers2 = get_callers(func2);

    std::unordered_set<ea_t> set1(callers1.begin(), callers1.end());

    for (ea_t caller : callers2) {
        if (set1.count(caller)) {
            result.push_back(caller);
        }
    }

    return result;
}

/// Find common callees between two functions
[[nodiscard]] inline qvector<ea_t> common_callees(ea_t func1, ea_t func2) {
    qvector<ea_t> result;

    auto callees1 = get_callees(func1);
    auto callees2 = get_callees(func2);

    std::unordered_set<ea_t> set1(callees1.begin(), callees1.end());

    for (ea_t callee : callees2) {
        if (set1.count(callee)) {
            result.push_back(callee);
        }
    }

    return result;
}

/// Get the shortest call path between two functions
/// Returns empty if no path exists within max_depth
[[nodiscard]] inline qvector<ea_t> find_call_path(
    ea_t from_func,
    ea_t to_func,
    int max_depth = 10)
{
    qvector<ea_t> result;

    if (from_func == BADADDR || to_func == BADADDR) return result;
    if (from_func == to_func) {
        result.push_back(from_func);
        return result;
    }

    // BFS to find shortest path
    std::unordered_map<ea_t, ea_t> parent;  // child -> parent
    std::queue<std::pair<ea_t, int>> queue;

    queue.push({from_func, 0});
    parent[from_func] = BADADDR;  // Mark as visited

    while (!queue.empty()) {
        auto [func_ea, depth] = queue.front();
        queue.pop();

        if (depth >= max_depth) continue;

        for (ea_t callee : get_callees(func_ea)) {
            if (callee == BADADDR) continue;
            if (parent.count(callee)) continue;  // Already visited

            parent[callee] = func_ea;

            if (callee == to_func) {
                // Found! Reconstruct path
                ea_t current = to_func;
                while (current != BADADDR) {
                    result.push_back(current);
                    current = parent[current];
                }

                // Reverse to get from->to order
                std::reverse(result.begin(), result.end());
                return result;
            }

            queue.push({callee, depth + 1});
        }
    }

    return result;  // No path found
}

} // namespace call_graph
} // namespace structor
