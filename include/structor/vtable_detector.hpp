#pragma once

#include "synth_types.hpp"
#include "config.hpp"
#include "utils.hpp"

namespace structor {

/// Detects and synthesizes vtable structures from access patterns
class VTableDetector {
public:
    explicit VTableDetector(const SynthOptions& opts = Config::instance().options())
        : options_(opts) {}

    /// Detect vtable patterns in access pattern and create vtable structure
    [[nodiscard]] std::optional<SynthVTable> detect(const AccessPattern& pattern, cfunc_t* cfunc);

    /// Analyze a specific vtable call to extract slot information
    void analyze_vtable_call(const FieldAccess& access, cfunc_t* cfunc, SynthVTable& vtable);

    /// Try to recover function signature from call site
    [[nodiscard]] tinfo_t recover_slot_signature(ea_t call_site, cfunc_t* cfunc, int slot_idx);

private:
    /// Visitor to find all vtable calls in a function
    class VTableCallVisitor : public ctree_visitor_t {
    public:
        VTableCallVisitor(cfunc_t* cfunc, int var_idx, sval_t vtable_offset)
            : ctree_visitor_t(CV_PARENTS)
            , cfunc_(cfunc)
            , var_idx_(var_idx)
            , vtable_offset_(vtable_offset) {}

        int idaapi visit_expr(cexpr_t* expr) override;

        struct CallInfo {
            ea_t        call_ea;
            int         slot_idx;
            cexpr_t*    call_expr;
        };

        [[nodiscard]] const qvector<CallInfo>& calls() const noexcept { return calls_; }

    private:
        cfunc_t* cfunc_;
        int var_idx_;
        sval_t vtable_offset_;
        qvector<CallInfo> calls_;
    };

    void collect_vtable_calls(const AccessPattern& pattern, cfunc_t* cfunc, SynthVTable& vtable);
    void generate_slot_names(SynthVTable& vtable);
    void infer_slot_signatures(SynthVTable& vtable, cfunc_t* cfunc);

    const SynthOptions& options_;
};

// ============================================================================
// VTableCallVisitor Implementation
// ============================================================================

inline int VTableDetector::VTableCallVisitor::visit_expr(cexpr_t* expr) {
    if (!expr || expr->op != cot_call) return 0;

    cexpr_t* callee = expr->x;
    if (!callee || callee->op != cot_ptr) return 0;

    // Looking for: (*(*(var + vtable_offset) + slot_offset))(args)
    // Or: (*(*var + slot_offset))(args) when vtable_offset == 0

    const cexpr_t* slot_expr = callee->x;
    if (!slot_expr) return 0;

    sval_t slot_offset = 0;
    const cexpr_t* vtbl_deref = slot_expr;

    // Handle (vtbl_ptr + slot_offset) pattern
    if (slot_expr->op == cot_add) {
        if (slot_expr->y && slot_expr->y->op == cot_num) {
            slot_offset = slot_expr->y->numval();
        }
        vtbl_deref = slot_expr->x;
    }

    // vtbl_deref should be *(var + vtable_offset) or *var
    if (!vtbl_deref || vtbl_deref->op != cot_ptr) return 0;

    const cexpr_t* var_expr = vtbl_deref->x;
    auto arith = utils::extract_ptr_arith(var_expr);

    if (!arith.valid || arith.var_idx != var_idx_) return 0;

    // Check if offset matches expected vtable offset
    if (arith.offset != vtable_offset_) return 0;

    // Found a vtable call!
    CallInfo info;
    info.call_ea = expr->ea;
    info.slot_idx = slot_offset / get_ptr_size();
    info.call_expr = expr;

    calls_.push_back(info);
    return 0;
}

// ============================================================================
// VTableDetector Implementation
// ============================================================================

inline std::optional<SynthVTable> VTableDetector::detect(const AccessPattern& pattern, cfunc_t* cfunc) {
    if (!pattern.has_vtable || !cfunc) {
        return std::nullopt;
    }

    SynthVTable vtable;
    vtable.name = generate_vtable_name(pattern.func_ea);
    vtable.source_func = pattern.func_ea;
    vtable.parent_offset = pattern.vtable_offset;

    // Collect all vtable calls
    collect_vtable_calls(pattern, cfunc, vtable);

    if (vtable.slots.empty()) {
        return std::nullopt;
    }

    // Infer slot signatures from call sites
    infer_slot_signatures(vtable, cfunc);

    // Generate slot names
    generate_slot_names(vtable);

    return vtable;
}

inline void VTableDetector::analyze_vtable_call(const FieldAccess& access, cfunc_t* cfunc, SynthVTable& vtable) {
    if (!access.is_vtable_access || access.vtable_slot < 0) return;

    // Check if slot already exists
    for (auto& slot : vtable.slots) {
        if (slot.index == static_cast<std::uint32_t>(access.vtable_slot)) {
            slot.call_sites.push_back(access.insn_ea);
            return;
        }
    }

    // Create new slot
    VTableSlot slot;
    slot.index = access.vtable_slot;
    slot.offset = access.vtable_slot * get_ptr_size();
    slot.call_sites.push_back(access.insn_ea);

    // Try to recover signature
    slot.func_type = recover_slot_signature(access.insn_ea, cfunc, access.vtable_slot);

    vtable.slots.push_back(std::move(slot));
}

inline tinfo_t VTableDetector::recover_slot_signature(ea_t call_site, cfunc_t* cfunc, int slot_idx) {
    tinfo_t result;

    if (!cfunc) return result;

    // Find the call expression at this site
    struct CallFinder : public ctree_visitor_t {
        ea_t target_ea;
        cexpr_t* found_call = nullptr;

        CallFinder(ea_t ea) : ctree_visitor_t(CV_FAST), target_ea(ea) {}

        int idaapi visit_expr(cexpr_t* e) override {
            if (e->op == cot_call && e->ea == target_ea) {
                found_call = e;
                return 1;  // Stop
            }
            return 0;
        }
    };

    CallFinder finder(call_site);
    finder.apply_to(&cfunc->body, nullptr);

    if (!finder.found_call) return result;

    cexpr_t* call = finder.found_call;

    // Build function type from arguments
    func_type_data_t ftd;
    ftd.set_cc(CM_CC_FASTCALL);  // Default to fastcall for virtual functions

    // Return type - try to infer from usage
    ftd.rettype.create_simple_type(BTF_VOID);

    // Check if call result is used
    // Walk up to find if result is assigned or used
    struct ReturnTypeInferrer : public ctree_visitor_t {
        cexpr_t* call;
        tinfo_t inferred_ret;
        bool found = false;

        ReturnTypeInferrer(cexpr_t* c) : ctree_visitor_t(CV_PARENTS), call(c) {}

        int idaapi visit_expr(cexpr_t* e) override {
            if (e == call) {
                // Check parent for assignment
                if (parents.size() > 0) {
                    const citem_t* parent = parents.back();
                    if (parent->is_expr()) {
                        const cexpr_t* pexpr = static_cast<const cexpr_t*>(parent);
                        if (pexpr->op == cot_asg && pexpr->y == call) {
                            // Return type is type of left side
                            inferred_ret = pexpr->x->type;
                            found = true;
                        } else if (pexpr->op == cot_cast) {
                            inferred_ret = pexpr->type;
                            found = true;
                        }
                    }
                }
            }
            return 0;
        }
    };

    ReturnTypeInferrer ret_inf(call);
    ret_inf.apply_to(&cfunc->body, nullptr);
    if (ret_inf.found && !ret_inf.inferred_ret.empty()) {
        ftd.rettype = ret_inf.inferred_ret;
    }

    // Arguments
    if (call->a) {
        for (size_t i = 0; i < call->a->size(); ++i) {
            const carg_t& arg = call->a->at(i);
            funcarg_t fa;
            fa.type = arg.type;
            if (fa.type.empty()) {
                fa.type.create_simple_type(BTF_INT64);  // Default
            }
            fa.name.sprnt("a%zu", i + 1);
            ftd.push_back(fa);
        }
    }

    tinfo_t func_type;
    func_type.create_func(ftd);
    result.create_ptr(func_type);

    return result;
}

inline void VTableDetector::collect_vtable_calls(const AccessPattern& pattern, cfunc_t* cfunc, SynthVTable& vtable) {
    // First, collect from already-identified vtable accesses
    for (const auto& access : pattern.accesses) {
        if (access.is_vtable_access) {
            analyze_vtable_call(access, cfunc, vtable);
        }
    }

    // Then search for additional vtable calls that might have been missed
    VTableCallVisitor visitor(cfunc, pattern.var_idx, pattern.vtable_offset);
    visitor.apply_to(&cfunc->body, nullptr);

    for (const auto& call_info : visitor.calls()) {
        // Check if slot already exists
        bool exists = false;
        for (auto& slot : vtable.slots) {
            if (slot.index == static_cast<std::uint32_t>(call_info.slot_idx)) {
                if (std::find(slot.call_sites.begin(), slot.call_sites.end(), call_info.call_ea) == slot.call_sites.end()) {
                    slot.call_sites.push_back(call_info.call_ea);
                }
                exists = true;
                break;
            }
        }

        if (!exists) {
            VTableSlot slot;
            slot.index = call_info.slot_idx;
            slot.offset = call_info.slot_idx * get_ptr_size();
            slot.call_sites.push_back(call_info.call_ea);
            slot.func_type = recover_slot_signature(call_info.call_ea, cfunc, call_info.slot_idx);

            vtable.slots.push_back(std::move(slot));
        }
    }

    // Sort slots by index
    std::sort(vtable.slots.begin(), vtable.slots.end(),
        [](const VTableSlot& a, const VTableSlot& b) {
            return a.index < b.index;
        });

    // Fill in missing slots between 0 and max
    if (!vtable.slots.empty()) {
        std::uint32_t max_slot = vtable.slots.back().index;
        qvector<VTableSlot> filled;

        for (std::uint32_t i = 0; i <= max_slot && i < MAX_VTABLE_SLOTS; ++i) {
            bool found = false;
            for (const auto& slot : vtable.slots) {
                if (slot.index == i) {
                    filled.push_back(slot);
                    found = true;
                    break;
                }
            }

            if (!found) {
                // Create placeholder slot
                VTableSlot placeholder;
                placeholder.index = i;
                placeholder.offset = i * get_ptr_size();

                // Generic function pointer type
                func_type_data_t ftd;
                ftd.rettype.create_simple_type(BTF_VOID);
                ftd.set_cc(CM_CC_UNKNOWN);
                tinfo_t func_type;
                func_type.create_func(ftd);
                placeholder.func_type.create_ptr(func_type);

                filled.push_back(std::move(placeholder));
            }
        }

        vtable.slots = std::move(filled);
    }
}

inline void VTableDetector::generate_slot_names(SynthVTable& vtable) {
    for (auto& slot : vtable.slots) {
        if (slot.name.empty()) {
            slot.name.sprnt("slot_%u", slot.index);
        }
    }
}

inline void VTableDetector::infer_slot_signatures(SynthVTable& vtable, cfunc_t* cfunc) {
    for (auto& slot : vtable.slots) {
        if (!slot.func_type.empty()) continue;
        if (slot.call_sites.empty()) continue;

        // Try to recover from first call site
        slot.func_type = recover_slot_signature(slot.call_sites[0], cfunc, slot.index);

        // Generate signature hint
        if (!slot.func_type.empty()) {
            slot.func_type.print(&slot.signature_hint);
        }
    }
}

} // namespace structor
