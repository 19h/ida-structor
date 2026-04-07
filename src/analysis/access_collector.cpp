/// @file access_collector.cpp
/// @brief Access pattern collection implementation

#include <structor/access_collector.hpp>

namespace structor {

// ============================================================================
// AccessPatternVisitor Implementation
// ============================================================================

int AccessPatternVisitor::visit_expr(cexpr_t* expr) {
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

        case cot_asg:
            process_assignment(expr);
            break;

        case cot_band: {
            const cexpr_t* mask_expr = nullptr;
            const cexpr_t* value_expr = nullptr;
            if (expr->x && expr->x->op == cot_num) {
                mask_expr = expr->x;
                value_expr = expr->y;
            } else if (expr->y && expr->y->op == cot_num) {
                mask_expr = expr->y;
                value_expr = expr->x;
            }

            if (mask_expr && value_expr) {
                const cexpr_t* base_expr = value_expr;
                int shift = 0;

                if (base_expr->op == cot_sshr || base_expr->op == cot_ushr) {
                    if (base_expr->y && base_expr->y->op == cot_num) {
                        shift = static_cast<int>(base_expr->y->numval());
                        base_expr = base_expr->x;
                    }
                }

                while (base_expr && base_expr->op == cot_cast) {
                    base_expr = base_expr->x;
                }

                sval_t offset = 0;
                uint32_t size = 0;
                std::optional<std::uint8_t> base_indirection;
                BitfieldInfo info;
                bool resolved = extract_access(base_expr, offset, size, &base_indirection);
                if (!resolved && base_expr && base_expr->op == cot_var) {
                    auto it = local_aliases_.find(base_expr->v.idx);
                    if (it != local_aliases_.end()) {
                        offset = it->second.offset;
                        size = it->second.size;
                        base_indirection = it->second.base_indirection;
                        resolved = true;
                    }
                }

                if (resolved &&
                    compute_bitfield(static_cast<std::uint64_t>(mask_expr->numval()),
                                     shift, info.bit_offset, info.bit_size)) {
                    if (static_cast<unsigned>(info.bit_offset + info.bit_size) <= size * 8) {
                        record_bitfield_access(expr, offset, size, info, base_indirection);
                    }
                }
            }
            break;
        }

        case cot_eq:
        case cot_ne:
            process_constant_comparison(expr);
            break;

        case cot_ult:
        case cot_ule:
            process_index_bound(expr);
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

void AccessPatternVisitor::process_assignment(cexpr_t* expr) {
    if (!expr || expr->op != cot_asg || !expr->x || !expr->y) {
        return;
    }

    cexpr_t* lhs = expr->x;
    cexpr_t* rhs = expr->y;
    while (rhs && rhs->op == cot_cast) {
        rhs = rhs->x;
    }

    if (!lhs || lhs->op != cot_var || !rhs) {
        return;
    }

    FieldAccess alias;
    bool resolved = false;

    sval_t offset = 0;
    uint32_t size = 0;
    std::optional<std::uint8_t> base_indirection;
    if (extract_access(rhs, offset, size, &base_indirection)) {
        alias.insn_ea = expr->ea;
        alias.source_func_ea = cfunc_->entry_ea;
        alias.offset = offset;
        alias.size = size;
        alias.access_type = AccessType::Read;
        alias.semantic_type = infer_semantic_from_usage(rhs, parent_expr());
        alias.context_expr = utils::expr_to_string(rhs, cfunc_);
        alias.inferred_type = rhs->type;
        alias.base_indirection = base_indirection;
        resolved = true;
    } else if (rhs->op == cot_var) {
        auto it = local_aliases_.find(rhs->v.idx);
        if (it != local_aliases_.end()) {
            alias = it->second;
            resolved = true;
        }
    }

    if (resolved) {
        auto pending_it = pending_constants_.find(lhs->v.idx);
        if (pending_it != pending_constants_.end()) {
            msg("Structor:   Applying %zu pending constants to local v%d\n",
                pending_it->second.size(), lhs->v.idx);
            for (auto value : pending_it->second) {
                alias.add_observed_constant(value);
            }
            pending_constants_.erase(pending_it);
        }
        local_aliases_[lhs->v.idx] = std::move(alias);
    }
}

void AccessPatternVisitor::process_constant_comparison(cexpr_t* expr) {
    if (!expr || !expr->x || !expr->y) {
        return;
    }

    const cexpr_t* value_expr = nullptr;
    std::uint64_t constant = 0;

    if (expr->x->op == cot_num) {
        constant = static_cast<std::uint64_t>(expr->x->numval());
        value_expr = expr->y;
    } else if (expr->y->op == cot_num) {
        constant = static_cast<std::uint64_t>(expr->y->numval());
        value_expr = expr->x;
    } else {
        return;
    }

    while (value_expr && value_expr->op == cot_cast) {
        value_expr = value_expr->x;
    }
    if (!value_expr) {
        return;
    }

    sval_t offset = 0;
    uint32_t size = 0;
    std::optional<std::uint8_t> base_indirection;
    bool resolved = extract_access(value_expr, offset, size, &base_indirection);

    FieldAccess access;
    if (!resolved && value_expr->op == cot_var) {
        auto it = local_aliases_.find(value_expr->v.idx);
        if (it == local_aliases_.end()) {
            msg("Structor:   Queueing constant 0x%llX for unresolved local v%d\n",
                static_cast<unsigned long long>(constant), value_expr->v.idx);
            pending_constants_[value_expr->v.idx].push_back(constant);
            return;
        }
        access = it->second;
        resolved = true;
    }

    if (!resolved) {
        return;
    }

    if (access.size == 0) {
        access.insn_ea = expr->ea;
        access.source_func_ea = cfunc_->entry_ea;
        access.offset = offset;
        access.size = size;
        access.access_type = AccessType::Read;
        access.semantic_type = infer_semantic_from_usage(value_expr, parent_expr());
        access.context_expr = utils::expr_to_string(value_expr, cfunc_);
        access.inferred_type = value_expr->type;
        access.base_indirection = base_indirection;
    }

    msg("Structor:   Observed comparison constant 0x%llX at offset 0x%llX size=%u\n",
        static_cast<unsigned long long>(constant),
        static_cast<unsigned long long>(access.offset), access.size);
    access.add_observed_constant(constant);
    accesses_.push_back(std::move(access));
}

void AccessPatternVisitor::process_index_bound(cexpr_t* expr) {
    if (!expr || !expr->x || !expr->y) {
        return;
    }

    const cexpr_t* var_expr = nullptr;
    std::uint32_t bound = 0;

    if (expr->x->op == cot_num && expr->y->op == cot_var) {
        bound = static_cast<std::uint32_t>(expr->x->numval());
        var_expr = expr->y;
    } else if (expr->y->op == cot_num && expr->x->op == cot_var) {
        bound = static_cast<std::uint32_t>(expr->y->numval());
        var_expr = expr->x;
    } else if (expr->y->op == cot_num && expr->x->op == cot_cast && expr->x->x && expr->x->x->op == cot_var) {
        bound = static_cast<std::uint32_t>(expr->y->numval());
        var_expr = expr->x->x;
    } else {
        return;
    }

    if (!var_expr || var_expr->op != cot_var || bound == 0 || bound > 32) {
        return;
    }

    local_index_bounds_[var_expr->v.idx] = bound;
}

void AccessPatternVisitor::process_dereference(cexpr_t* expr, const cexpr_t* ptr_expr) {
    auto arith = utils::extract_ptr_arith(expr);

    if (!arith.valid && ptr_expr) {
        struct SymbolicPtrInfo {
            bool has_base = false;
            int index_var = -1;
            sval_t const_index = 0;
        } info;

        std::function<void(const cexpr_t*)> walk = [&](const cexpr_t* e) {
            if (!e) {
                return;
            }
            switch (e->op) {
                case cot_var:
                    if (e->v.idx == target_var_idx_) {
                        info.has_base = true;
                    } else if (info.index_var < 0) {
                        info.index_var = e->v.idx;
                    }
                    break;
                case cot_num:
                    info.const_index += static_cast<sval_t>(e->numval());
                    break;
                case cot_cast:
                case cot_ref:
                    walk(e->x);
                    break;
                case cot_add:
                    walk(e->x);
                    walk(e->y);
                    break;
                case cot_sub:
                    walk(e->x);
                    if (e->y && e->y->op == cot_num) {
                        info.const_index -= static_cast<sval_t>(e->y->numval());
                    }
                    break;
                default:
                    break;
            }
        };

        walk(ptr_expr);

        if (info.has_base && info.index_var >= 0) {
            auto bound_it = local_index_bounds_.find(info.index_var);
            tinfo_t pointed = ptr_expr->type.get_pointed_object();
            size_t stride = pointed.empty() ? 0 : pointed.get_size();
            if (stride == BADSIZE || stride == 0) {
                stride = !expr->type.empty() ? utils::get_type_size(expr->type, get_ptr_size()) : 0;
            }

            if (stride > 0) {
                if (bound_it != local_index_bounds_.end() && bound_it->second > 0 && bound_it->second <= 32) {
                    for (std::uint32_t idx = 0; idx < bound_it->second; ++idx) {
                        FieldAccess access;
                        access.insn_ea = expr->ea;
                        access.offset = (info.const_index + static_cast<sval_t>(idx)) * static_cast<sval_t>(stride);
                        access.size = !expr->type.empty()
                            ? utils::get_type_size(expr->type, get_ptr_size())
                            : get_ptr_size();
                        access.access_type = determine_access_type(expr);
                        const cexpr_t* parent = parent_expr();
                        access.semantic_type = infer_semantic_from_usage(expr, parent);
                        access.context_expr = utils::expr_to_string(expr, cfunc_);
                        access.inferred_type = expr->type;
                        access.source_func_ea = cfunc_->entry_ea;
                        access.array_stride_hint = static_cast<std::uint32_t>(stride);
                        accesses_.push_back(std::move(access));
                    }
                    return;
                } else {
                    PendingSymbolicAccess pending;
                    pending.insn_ea = expr->ea;
                    pending.base_offset = (info.const_index) * static_cast<sval_t>(stride);
                    pending.stride = static_cast<std::uint32_t>(stride);
                    pending.size = !expr->type.empty()
                        ? utils::get_type_size(expr->type, get_ptr_size())
                        : get_ptr_size();
                    pending.access_type = determine_access_type(expr);
                    const cexpr_t* parent = parent_expr();
                    pending.semantic_type = infer_semantic_from_usage(expr, parent);
                    pending.context_expr = utils::expr_to_string(expr, cfunc_);
                    pending.inferred_type = expr->type;
                    if (arith.base_indirection > 0) {
                        pending.base_indirection = arith.base_indirection;
                    }
                    pending_symbolic_accesses_[info.index_var].push_back(std::move(pending));
                }
            }
        }
    }

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

    // Check if this is a zero-initialization write
    if (access.access_type == AccessType::Write) {
        access.is_zero_init = is_zero_initialization(expr);
    }

    // Infer semantic type from context
    const cexpr_t* parent = parent_expr();
    access.semantic_type = infer_semantic_from_usage(expr, parent);

    if (arith.base_indirection > 0) {
        access.base_indirection = arith.base_indirection;
    }

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
    access.source_func_ea = cfunc_->entry_ea;

    accesses_.push_back(std::move(access));
}

void AccessPatternVisitor::process_memptr_access(cexpr_t* expr) {
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
    if (arith.base_indirection > 0) {
        access.base_indirection = arith.base_indirection;
    }
    access.context_expr = utils::expr_to_string(expr, cfunc_);
    access.inferred_type = expr->type;
    access.source_func_ea = cfunc_->entry_ea;

    accesses_.push_back(std::move(access));
}

void AccessPatternVisitor::process_array_access(cexpr_t* expr) {
    auto arith = utils::extract_ptr_arith(expr->x);
    if (!arith.valid || arith.var_idx != target_var_idx_) {
        return;
    }

    // Calculate offset
    sval_t offset = arith.offset;
    std::optional<std::uint32_t> stride_hint;

    tinfo_t elem_type = expr->type;
    if (!elem_type.empty()) {
        size_t elem_size = elem_type.get_size();
        if (elem_size != BADSIZE && elem_size > 0) {
            stride_hint = static_cast<std::uint32_t>(elem_size);
        }
    }

    if (!stride_hint.has_value()) {
        tinfo_t ptr_elem = expr->x->type.get_pointed_object();
        if (!ptr_elem.empty()) {
            size_t elem_size = ptr_elem.get_size();
            if (elem_size != BADSIZE && elem_size > 0) {
                stride_hint = static_cast<std::uint32_t>(elem_size);
            }
        }
    }

    if (expr->y->op == cot_num) {
        if (stride_hint.has_value()) {
            offset += expr->y->numval() * static_cast<sval_t>(*stride_hint);
        } else {
            offset += expr->y->numval();
        }
    }

    if (expr->y->op == cot_var && stride_hint.has_value()) {
        auto it = local_index_bounds_.find(expr->y->v.idx);
        if (it != local_index_bounds_.end()) {
            const std::uint32_t bound = it->second;
            for (std::uint32_t idx = 0; idx < bound; ++idx) {
                FieldAccess bounded;
                bounded.insn_ea = expr->ea;
                bounded.offset = offset + static_cast<sval_t>(idx) * static_cast<sval_t>(*stride_hint);
                bounded.size = !expr->type.empty()
                    ? utils::get_type_size(expr->type, get_ptr_size())
                    : get_ptr_size();
                bounded.access_type = determine_access_type(expr);
                const cexpr_t* parent = parent_expr();
                bounded.semantic_type = infer_semantic_from_usage(expr, parent);
                if (arith.base_indirection > 0) {
                    bounded.base_indirection = arith.base_indirection;
                }
                bounded.context_expr = utils::expr_to_string(expr, cfunc_);
                bounded.inferred_type = expr->type;
                bounded.source_func_ea = cfunc_->entry_ea;
                bounded.array_stride_hint = stride_hint;
                accesses_.push_back(std::move(bounded));
            }
            return;
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
    if (arith.base_indirection > 0) {
        access.base_indirection = arith.base_indirection;
    }
    access.context_expr = utils::expr_to_string(expr, cfunc_);
    access.inferred_type = expr->type;
    access.source_func_ea = cfunc_->entry_ea;
    access.array_stride_hint = stride_hint;

    accesses_.push_back(std::move(access));
}

void AccessPatternVisitor::process_call_through_ptr(cexpr_t* call_expr) {
    if (!call_expr || call_expr->op != cot_call) return;

    cexpr_t* callee = call_expr->x;
    if (!callee) return;

    while (callee->op == cot_cast) {
        callee = callee->x;
    }

    tinfo_t funcptr_type = build_funcptr_type(call_expr);

    auto add_fp_access = [&](sval_t offset, SemanticType sem, bool is_vtable, sval_t slot_offset) {
        FieldAccess access;
        access.insn_ea = call_expr->ea;
        access.source_func_ea = cfunc_->entry_ea;
        access.offset = offset;
        access.size = get_ptr_size();
        access.access_type = AccessType::Call;
        access.semantic_type = sem;
        access.context_expr = utils::expr_to_string(call_expr, cfunc_);
        if (!funcptr_type.empty()) {
            access.inferred_type = funcptr_type;
        }

        if (is_vtable) {
            access.is_vtable_access = true;
            access.vtable_slot = slot_offset / get_ptr_size();
            access.set_vtable_nested_access(offset, slot_offset, funcptr_type);
        }

        accesses_.push_back(std::move(access));
    };

    // Pattern 1: Direct call through dereferenced var: (*var)(args)
    // Pattern 2: VTable call: (*(*(type**)var + slot))(args)
    if (callee->op == cot_ptr) {
        const cexpr_t* ptr = callee->x;

        // Check for double dereference (vtable pattern)
        if (ptr->op == cot_add || ptr->op == cot_ptr) {
            const cexpr_t* base_ptr = ptr;
            sval_t slot_offset = 0;

            if (ptr->op == cot_add) {
                if (ptr->y->op == cot_num) {
                    slot_offset = ptr->y->numval();
                }
                base_ptr = ptr->x;
            }

            if (base_ptr->op == cot_ptr) {
                auto arith = utils::extract_ptr_arith(base_ptr->x);
                if (arith.valid && arith.var_idx == target_var_idx_) {
                    add_fp_access(arith.offset, SemanticType::VTablePointer, true, slot_offset);
                    return;
                }
            }
        }

        // Simple dereference call: (*var)(args)
        auto arith = utils::extract_ptr_arith(ptr);
        if (arith.valid && arith.var_idx == target_var_idx_) {
            add_fp_access(arith.offset, SemanticType::FunctionPointer, false, 0);
            return;
        }
    }

    // Member function pointer call: obj->fp(args)
    if (callee->op == cot_memptr || callee->op == cot_memref) {
        auto arith = utils::extract_ptr_arith(callee->x);
        if (arith.valid && arith.var_idx == target_var_idx_) {
            add_fp_access(arith.offset + callee->m, SemanticType::FunctionPointer, false, 0);
            return;
        }
    }

    // Indexed function pointer call: fp_array[idx](args)
    if (callee->op == cot_idx) {
        auto arith = utils::extract_ptr_arith(callee->x);
        if (arith.valid && arith.var_idx == target_var_idx_) {
            sval_t offset = arith.offset;
            if (callee->y && callee->y->op == cot_num) {
                offset += callee->y->numval() * get_ptr_size();
            }
            add_fp_access(offset, SemanticType::FunctionPointer, false, 0);
            return;
        }
    }
}

void AccessPatternVisitor::record_bitfield_access(const cexpr_t* expr, sval_t offset,
                                                    uint32_t size, const BitfieldInfo& info,
                                                    const std::optional<std::uint8_t>& base_indirection) {
    FieldAccess access;
    access.insn_ea = expr->ea;
    access.source_func_ea = cfunc_->entry_ea;
    access.offset = offset;
    access.size = size;
    access.access_type = AccessType::Read;
    access.semantic_type = SemanticType::UnsignedInteger;
    access.context_expr = utils::expr_to_string(expr, cfunc_);
    access.inferred_type = expr->type;
    if (base_indirection.has_value()) {
        access.base_indirection = base_indirection;
    }
    access.add_bitfield(info);

    accesses_.push_back(std::move(access));
}


bool AccessPatternVisitor::extract_access(const cexpr_t* expr, sval_t& offset, uint32_t& size,
                                              std::optional<std::uint8_t>* base_indirection) const {
    if (base_indirection) {
        base_indirection->reset();
    }

    if (!expr) return false;

    if (expr->op == cot_ptr) {
        auto arith = utils::extract_ptr_arith(expr);
        if (!arith.valid || arith.var_idx != target_var_idx_) return false;
        offset = arith.offset;
        size = expr->type.empty() ? get_ptr_size() : utils::get_type_size(expr->type, get_ptr_size());
        if (base_indirection && arith.base_indirection > 0) {
            *base_indirection = arith.base_indirection;
        }
        return true;
    }

    if (expr->op == cot_memptr || expr->op == cot_memref) {
        auto arith = utils::extract_ptr_arith(expr->x);
        if (!arith.valid || arith.var_idx != target_var_idx_) return false;
        offset = arith.offset + expr->m;
        size = expr->type.empty() ? get_ptr_size() : utils::get_type_size(expr->type, get_ptr_size());
        if (base_indirection && arith.base_indirection > 0) {
            *base_indirection = arith.base_indirection;
        }
        return true;
    }

    return false;
}

bool AccessPatternVisitor::compute_bitfield(std::uint64_t mask, int shift,
                                               std::uint16_t& bit_offset,
                                               std::uint16_t& bit_size) const {
    if (mask == 0 || shift < 0 || shift > 63) return false;

    int lsb = 0;
    while (lsb < 64 && ((mask >> lsb) & 1ULL) == 0) {
        ++lsb;
    }

    int msb = 63;
    while (msb >= 0 && ((mask >> msb) & 1ULL) == 0) {
        --msb;
    }

    if (lsb > msb) return false;

    int width = msb - lsb + 1;
    std::uint64_t contig = (width >= 64) ? ~0ULL : ((1ULL << width) - 1);
    if ((mask >> lsb) != contig) return false;

    bit_offset = static_cast<std::uint16_t>(lsb + shift);
    bit_size = static_cast<std::uint16_t>(width);
    return bit_size > 0;
}

tinfo_t AccessPatternVisitor::build_funcptr_type(const cexpr_t* call_expr) const {
    tinfo_t result;
    if (!call_expr || call_expr->op != cot_call) return result;

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

bool AccessPatternVisitor::involves_target_var(const cexpr_t* expr) const {
    if (!expr) return false;

    if (expr->op == cot_var) {
        return expr->v.idx == target_var_idx_;
    }

    // Recurse through common operations
    switch (expr->op) {
        case cot_cast:
        case cot_ref:
        case cot_ptr:
        case cot_memref:
        case cot_memptr:
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

SemanticType AccessPatternVisitor::infer_semantic_from_usage(const cexpr_t* expr, const cexpr_t* parent) {
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

AccessType AccessPatternVisitor::determine_access_type(const cexpr_t* expr) {
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

bool AccessPatternVisitor::is_zero_initialization(const cexpr_t* expr) const {
    // Walk up parents to find an assignment
    const cexpr_t* current = expr;

    for (size_t i = 0; i < parents.size(); ++i) {
        const citem_t* parent_item = parents[parents.size() - 1 - i];
        if (!parent_item || !parent_item->is_expr()) {
            continue;
        }

        const cexpr_t* parent = static_cast<const cexpr_t*>(parent_item);

        if (parent->op == cot_asg && parent->x == current) {
            // This is a write - check if the value is zero
            const cexpr_t* rhs = parent->y;
            if (!rhs) return false;

            // Check for numeric constant 0
            if (rhs->op == cot_num && rhs->numval() == 0) {
                return true;
            }

            // Check for cast of 0: (type)0
            if (rhs->op == cot_cast && rhs->x && 
                rhs->x->op == cot_num && rhs->x->numval() == 0) {
                return true;
            }

            return false;
        }

        current = parent;
    }

    return false;
}

// ============================================================================
// AccessCollector Implementation
// ============================================================================

AccessPattern AccessCollector::collect(ea_t func_ea, int var_idx) {
    AccessPattern pattern;
    pattern.func_ea = func_ea;
    pattern.var_idx = var_idx;

    cfuncptr_t cfunc = utils::get_cfunc(func_ea);
    if (!cfunc) {
        return pattern;
    }

    return collect(cfunc, var_idx);
}

AccessPattern AccessCollector::collect(cfunc_t* cfunc, int var_idx) {
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

AccessPattern AccessCollector::collect(ea_t func_ea, const char* var_name) {
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

void AccessCollector::analyze_accesses(AccessPattern& pattern) {
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

void AccessCollector::deduplicate_accesses(AccessPattern& pattern) {
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

                if (!access.bitfields.empty()) {
                    for (const auto& bf : access.bitfields) {
                        existing.add_bitfield(bf);
                    }
                }

                for (auto value : access.observed_constants) {
                    existing.add_observed_constant(value);
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
            unique.push_back(std::move(access));
        }
    }

    pattern.accesses = std::move(unique);

    // Drop coarse aggregate accesses when we already observed finer-grained
    // accesses inside the same region. These usually come from decompiler-
    // synthesized array/struct expressions and can overwhelm real field
    // recovery by forcing overly large direct candidates.
    qvector<FieldAccess> filtered;
    filtered.reserve(pattern.accesses.size());

    for (const auto& access : pattern.accesses) {
        bool redundant_aggregate = false;
        if (!access.inferred_type.empty() &&
            (access.inferred_type.is_array() || access.inferred_type.is_struct())) {
            int contained_smaller = 0;
            const sval_t access_end = access.offset + static_cast<sval_t>(access.size);

            for (const auto& other : pattern.accesses) {
                if (&other == &access) {
                    continue;
                }
                const sval_t other_end = other.offset + static_cast<sval_t>(other.size);
                if (other.offset >= access.offset && other_end <= access_end &&
                    (other.size < access.size || other.offset != access.offset)) {
                    ++contained_smaller;
                }
            }

            redundant_aggregate = contained_smaller >= 2;
        }

        if (!redundant_aggregate) {
            filtered.push_back(access);
        }
    }

    pattern.accesses = std::move(filtered);
    utils::debug_log("After deduplication: %zu unique accesses", pattern.accesses.size());
}

void AccessCollector::detect_vtable_pattern(AccessPattern& pattern) {
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
