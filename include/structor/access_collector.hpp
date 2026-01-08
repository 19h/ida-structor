#pragma once

#include "synth_types.hpp"
#include "config.hpp"
#include "utils.hpp"

namespace structor {

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

    [[nodiscard]] bool involves_target_var(const cexpr_t* expr) const;
    [[nodiscard]] SemanticType infer_semantic_from_usage(const cexpr_t* expr, const cexpr_t* parent);
    [[nodiscard]] AccessType determine_access_type(const cexpr_t* expr);

    cfunc_t* cfunc_;
    int target_var_idx_;
    qvector<FieldAccess> accesses_;
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

// ============================================================================
// AccessPatternVisitor Implementation
// ============================================================================

inline int AccessPatternVisitor::visit_expr(cexpr_t* expr) {
    if (!expr) return 0;

    switch (expr->op) {
        case cot_ptr:
            // Dereference: *(ptr + offset) or *ptr
            if (involves_target_var(expr->x)) {
                process_dereference(expr, expr->x);
            }
            break;

        case cot_memptr:
            // Member pointer access: ptr->member
            if (involves_target_var(expr->x)) {
                process_memptr_access(expr);
            }
            break;

        case cot_idx:
            // Array indexing: ptr[idx]
            if (involves_target_var(expr->x)) {
                process_array_access(expr);
            }
            break;

        case cot_call:
            // Check for indirect calls through our variable
            process_call_through_ptr(expr);
            break;

        default:
            break;
    }

    return 0;
}

inline void AccessPatternVisitor::process_dereference(cexpr_t* expr, const cexpr_t* ptr_expr) {
    auto arith = utils::extract_ptr_arith(ptr_expr);

    if (!arith.valid || arith.var_idx != target_var_idx_) {
        return;
    }

    FieldAccess access;
    access.insn_ea = expr->ea;
    access.offset = arith.offset;

    // Determine size from expression type
    if (!expr->type.empty()) {
        access.size = utils::get_type_size(expr->type, get_ptr_size());
    } else {
        access.size = get_ptr_size();
    }

    // Determine if this is a read or write
    access.access_type = determine_access_type(expr);

    // Infer semantic type from context
    const cexpr_t* parent = parent_expr();
    access.semantic_type = infer_semantic_from_usage(expr, parent);

    // Check for vtable access pattern: *(*var + offset)
    // This is a double dereference where the inner deref is at offset 0
    if (ptr_expr->op == cot_ptr) {
        auto inner_arith = utils::extract_ptr_arith(ptr_expr->x);
        if (inner_arith.valid && inner_arith.var_idx == target_var_idx_ && inner_arith.offset == 0) {
            // This is accessing through a pointer at offset 0 (vtable pointer)
            access.is_vtable_access = true;
            access.vtable_slot = arith.offset / get_ptr_size();
        }
    }

    access.context_expr = utils::expr_to_string(expr, cfunc_);
    access.inferred_type = expr->type;

    accesses_.push_back(std::move(access));
}

inline void AccessPatternVisitor::process_memptr_access(cexpr_t* expr) {
    auto arith = utils::extract_ptr_arith(expr->x);
    if (!arith.valid || arith.var_idx != target_var_idx_) {
        return;
    }

    FieldAccess access;
    access.insn_ea = expr->ea;
    access.offset = arith.offset + expr->m;  // Add member offset

    if (!expr->type.empty()) {
        access.size = utils::get_type_size(expr->type, get_ptr_size());
    } else {
        access.size = get_ptr_size();
    }

    access.access_type = determine_access_type(expr);
    const cexpr_t* parent = parent_expr();
    access.semantic_type = infer_semantic_from_usage(expr, parent);
    access.context_expr = utils::expr_to_string(expr, cfunc_);
    access.inferred_type = expr->type;

    accesses_.push_back(std::move(access));
}

inline void AccessPatternVisitor::process_array_access(cexpr_t* expr) {
    auto arith = utils::extract_ptr_arith(expr->x);
    if (!arith.valid || arith.var_idx != target_var_idx_) {
        return;
    }

    // Calculate offset
    sval_t offset = arith.offset;
    if (expr->y->op == cot_num) {
        tinfo_t elem_type = expr->x->type.get_pointed_object();
        if (!elem_type.empty()) {
            offset += expr->y->numval() * elem_type.get_size();
        } else {
            offset += expr->y->numval();
        }
    }

    FieldAccess access;
    access.insn_ea = expr->ea;
    access.offset = offset;

    if (!expr->type.empty()) {
        access.size = utils::get_type_size(expr->type, get_ptr_size());
    } else {
        access.size = get_ptr_size();
    }

    access.access_type = determine_access_type(expr);
    const cexpr_t* parent = parent_expr();
    access.semantic_type = infer_semantic_from_usage(expr, parent);
    access.context_expr = utils::expr_to_string(expr, cfunc_);
    access.inferred_type = expr->type;

    accesses_.push_back(std::move(access));
}

inline void AccessPatternVisitor::process_call_through_ptr(cexpr_t* call_expr) {
    if (!call_expr || call_expr->op != cot_call) return;

    cexpr_t* callee = call_expr->x;
    if (!callee) return;

    // Pattern 1: Direct call through dereferenced var: (*var)(args)
    // Pattern 2: VTable call: (*(*(type**)var + slot))(args)

    // Check if callee is a dereference
    if (callee->op == cot_ptr) {
        const cexpr_t* ptr = callee->x;

        // Check for double dereference (vtable pattern)
        if (ptr->op == cot_add || ptr->op == cot_ptr) {
            const cexpr_t* base_ptr = ptr;
            sval_t slot_offset = 0;

            // Handle (*(var) + offset) pattern
            if (ptr->op == cot_add) {
                if (ptr->y->op == cot_num) {
                    slot_offset = ptr->y->numval();
                }
                base_ptr = ptr->x;
            }

            // Check if base is a dereference of our variable
            if (base_ptr->op == cot_ptr) {
                auto arith = utils::extract_ptr_arith(base_ptr->x);
                if (arith.valid && arith.var_idx == target_var_idx_) {
                    // This is a vtable call!
                    FieldAccess access;
                    access.insn_ea = call_expr->ea;
                    access.offset = arith.offset;  // Offset of vtable pointer
                    access.size = get_ptr_size();
                    access.access_type = AccessType::Call;
                    access.semantic_type = SemanticType::VTablePointer;
                    access.is_vtable_access = true;
                    access.vtable_slot = slot_offset / get_ptr_size();
                    access.context_expr = utils::expr_to_string(call_expr, cfunc_);

                    accesses_.push_back(std::move(access));
                    return;
                }
            }
        }

        // Simple dereference call: (*var)(args)
        auto arith = utils::extract_ptr_arith(ptr);
        if (arith.valid && arith.var_idx == target_var_idx_) {
            FieldAccess access;
            access.insn_ea = call_expr->ea;
            access.offset = arith.offset;
            access.size = get_ptr_size();
            access.access_type = AccessType::Call;
            access.semantic_type = SemanticType::FunctionPointer;
            access.context_expr = utils::expr_to_string(call_expr, cfunc_);

            accesses_.push_back(std::move(access));
        }
    }
}

inline bool AccessPatternVisitor::involves_target_var(const cexpr_t* expr) const {
    if (!expr) return false;

    if (expr->op == cot_var) {
        return expr->v.idx == target_var_idx_;
    }

    // Recurse through common operations
    switch (expr->op) {
        case cot_cast:
        case cot_ref:
        case cot_ptr:
            return involves_target_var(expr->x);

        case cot_add:
        case cot_sub:
            return involves_target_var(expr->x) || involves_target_var(expr->y);

        case cot_idx:
            return involves_target_var(expr->x);

        default:
            return false;
    }
}

inline SemanticType AccessPatternVisitor::infer_semantic_from_usage(const cexpr_t* expr, const cexpr_t* parent) {
    if (!expr) return SemanticType::Unknown;

    // Check the type first
    if (!expr->type.empty()) {
        if (expr->type.is_ptr()) {
            return SemanticType::Pointer;
        }
        if (expr->type.is_funcptr()) {
            return SemanticType::FunctionPointer;
        }
        if (expr->type.is_floating()) {
            return expr->type.get_size() == 4 ? SemanticType::Float : SemanticType::Double;
        }
    }

    // Check parent context
    if (parent) {
        switch (parent->op) {
            case cot_call:
                // Value is used as function pointer
                if (parent->x == expr) {
                    return SemanticType::FunctionPointer;
                }
                break;

            case cot_ptr:
                // Value is being dereferenced - it's a pointer
                return SemanticType::Pointer;

            case cot_fadd:
            case cot_fsub:
            case cot_fmul:
            case cot_fdiv:
                return SemanticType::Double;

            case cot_ult:
            case cot_ule:
            case cot_ugt:
            case cot_uge:
                return SemanticType::UnsignedInteger;

            default:
                break;
        }
    }

    // Default based on size
    std::uint32_t size = utils::get_type_size(expr->type, get_ptr_size());
    if (size == get_ptr_size()) {
        // Could be pointer or integer - check if it's ever dereferenced
        return SemanticType::Unknown;
    }

    return SemanticType::Integer;
}

inline AccessType AccessPatternVisitor::determine_access_type(const cexpr_t* expr) {
    // Walk up parents to determine if this is a read or write
    const cexpr_t* current = expr;

    for (size_t i = 0; i < parents.size(); ++i) {
        const citem_t* parent_item = parents[parents.size() - 1 - i];
        if (!parent_item || !parent_item->is_expr()) {
            continue;
        }

        const cexpr_t* parent = static_cast<const cexpr_t*>(parent_item);

        switch (parent->op) {
            case cot_asg:
            case cot_asgbor:
            case cot_asgxor:
            case cot_asgband:
            case cot_asgadd:
            case cot_asgsub:
            case cot_asgmul:
            case cot_asgsshr:
            case cot_asgushr:
            case cot_asgshl:
            case cot_asgsdiv:
            case cot_asgudiv:
            case cot_asgsmod:
            case cot_asgumod:
                // If current is the left side, it's a write
                if (parent->x == current) {
                    // For compound assignments, it's both read and write
                    if (parent->op != cot_asg) {
                        return AccessType::ReadWrite;
                    }
                    return AccessType::Write;
                }
                return AccessType::Read;

            case cot_preinc:
            case cot_predec:
            case cot_postinc:
            case cot_postdec:
                return AccessType::ReadWrite;

            case cot_ref:
                return AccessType::AddressTaken;

            default:
                current = parent;
                break;
        }
    }

    return AccessType::Read;
}

// ============================================================================
// AccessCollector Implementation
// ============================================================================

inline AccessPattern AccessCollector::collect(ea_t func_ea, int var_idx) {
    AccessPattern pattern;
    pattern.func_ea = func_ea;
    pattern.var_idx = var_idx;

    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) {
        return pattern;
    }

    return collect(cfunc, var_idx);
}

inline AccessPattern AccessCollector::collect(cfunc_t* cfunc, int var_idx) {
    AccessPattern pattern;
    if (!cfunc) return pattern;

    func_t* func = cfunc->entry_ea != BADADDR ? get_func(cfunc->entry_ea) : nullptr;
    pattern.func_ea = func ? func->start_ea : BADADDR;
    pattern.var_idx = var_idx;

    // Get variable info
    lvars_t& lvars = *cfunc->get_lvars();
    if (var_idx >= 0 && static_cast<size_t>(var_idx) < lvars.size()) {
        lvar_t& var = lvars[var_idx];
        pattern.var_name = var.name;
        pattern.original_type = var.type();
    }

    // Collect accesses
    AccessPatternVisitor visitor(cfunc, var_idx);
    visitor.apply_to(&cfunc->body, nullptr);

    pattern.accesses = std::move(visitor.mutable_accesses());

    // Post-process
    analyze_accesses(pattern);
    deduplicate_accesses(pattern);

    if (options_.vtable_detection) {
        detect_vtable_pattern(pattern);
    }

    return pattern;
}

inline AccessPattern AccessCollector::collect(ea_t func_ea, const char* var_name) {
    AccessPattern pattern;
    pattern.func_ea = func_ea;

    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) {
        return pattern;
    }

    lvar_t* var = utils::find_lvar_by_name(cfunc, var_name);
    if (!var) {
        return pattern;
    }

    // Find index
    lvars_t& lvars = *cfunc->get_lvars();
    for (size_t i = 0; i < lvars.size(); ++i) {
        if (&lvars[i] == var) {
            return collect(cfunc, static_cast<int>(i));
        }
    }

    return pattern;
}

inline void AccessCollector::analyze_accesses(AccessPattern& pattern) {
    if (pattern.accesses.empty()) return;

    pattern.sort_by_offset();

    // Recalculate min/max
    pattern.min_offset = pattern.accesses.front().offset;
    pattern.max_offset = pattern.accesses.front().offset + pattern.accesses.front().size;

    for (const auto& access : pattern.accesses) {
        pattern.min_offset = std::min(pattern.min_offset, access.offset);
        pattern.max_offset = std::max(pattern.max_offset, access.offset + static_cast<sval_t>(access.size));
    }
}

inline void AccessCollector::deduplicate_accesses(AccessPattern& pattern) {
    if (pattern.accesses.size() <= 1) return;

    // Apply predicate filter first (adopted from Suture)
    if (options_.access_filter) {
        qvector<FieldAccess> filtered;
        filtered.reserve(pattern.accesses.size());
        for (auto& access : pattern.accesses) {
            if (options_.access_filter(access)) {
                filtered.push_back(std::move(access));
            }
        }
        pattern.accesses = std::move(filtered);

        utils::debug_log("After predicate filtering: %zu accesses remain", pattern.accesses.size());
    }

    if (pattern.accesses.size() <= 1) return;

    qvector<FieldAccess> unique;
    unique.reserve(pattern.accesses.size());

    for (auto& access : pattern.accesses) {
        bool found = false;
        for (auto& existing : unique) {
            if (existing.offset == access.offset && existing.size == access.size) {
                // Merge access types
                if (existing.access_type == AccessType::Read && access.access_type == AccessType::Write) {
                    existing.access_type = AccessType::ReadWrite;
                } else if (existing.access_type == AccessType::Write && access.access_type == AccessType::Read) {
                    existing.access_type = AccessType::ReadWrite;
                }

                // Prefer more specific semantic type (using Suture-style priority)
                if (semantic_priority(access.semantic_type) > semantic_priority(existing.semantic_type)) {
                    existing.semantic_type = access.semantic_type;
                }

                // Merge inferred types using conflict resolution
                if (!access.inferred_type.empty()) {
                    existing.inferred_type = resolve_type_conflict(existing.inferred_type, access.inferred_type);
                }

                // Keep vtable info
                if (access.is_vtable_access) {
                    existing.is_vtable_access = true;
                    existing.vtable_slot = access.vtable_slot;
                }

                // Merge nested info if present
                if (access.nested_info && !existing.nested_info) {
                    existing.nested_info = access.nested_info;
                }

                found = true;
                break;
            }
        }

        if (!found) {
            unique.push_back(std::move(access));
        }
    }

    pattern.accesses = std::move(unique);
    utils::debug_log("After deduplication: %zu unique accesses", pattern.accesses.size());
}

inline void AccessCollector::detect_vtable_pattern(AccessPattern& pattern) {
    // Look for vtable access patterns
    for (const auto& access : pattern.accesses) {
        if (access.is_vtable_access) {
            pattern.has_vtable = true;
            pattern.vtable_offset = access.offset;
            break;
        }
    }

    // Also check for pointer at offset 0 that's always dereferenced and called through
    if (!pattern.has_vtable) {
        int deref_calls_at_zero = 0;
        for (const auto& access : pattern.accesses) {
            if (access.offset == 0 &&
                access.semantic_type == SemanticType::VTablePointer) {
                ++deref_calls_at_zero;
            }
        }
        if (deref_calls_at_zero >= 1) {
            pattern.has_vtable = true;
            pattern.vtable_offset = 0;
        }
    }
}

} // namespace structor
