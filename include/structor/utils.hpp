#pragma once

#include "synth_types.hpp"

namespace structor {
namespace utils {

// ============================================================================
// Hex-Rays Utilities
// ============================================================================

/// Get the cfunc_t for a function address
[[nodiscard]] inline cfuncptr_t get_cfunc(ea_t func_ea) {
    func_t* func = get_func(func_ea);
    if (!func) {
        cfuncptr_t empty{static_cast<cfunc_t*>(nullptr)};
        return empty;
    }

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(func, &hf, DECOMP_NO_WAIT);
    return cfunc;
}

/// Find a local variable by name in a function
[[nodiscard]] inline lvar_t* find_lvar_by_name(cfunc_t* cfunc, const char* name) {
    if (!cfunc || !name) return nullptr;

    lvars_t& lvars = *cfunc->get_lvars();
    for (size_t i = 0; i < lvars.size(); ++i) {
        if (lvars[i].name == name) {
            return &lvars[i];
        }
    }
    return nullptr;
}

/// Find a local variable by index in a function
[[nodiscard]] inline lvar_t* find_lvar_by_idx(cfunc_t* cfunc, int idx) {
    if (!cfunc || idx < 0) return nullptr;

    lvars_t& lvars = *cfunc->get_lvars();
    if (static_cast<size_t>(idx) >= lvars.size()) return nullptr;

    return &lvars[idx];
}

/// Get the variable at cursor position in pseudocode
[[nodiscard]] inline std::pair<lvar_t*, int> get_var_at_cursor(vdui_t* vdui) {
    if (!vdui || !vdui->cfunc) return {nullptr, -1};

    // Get item under cursor
    if (!vdui->item.is_citem()) return {nullptr, -1};

    const citem_t* item = vdui->item.it;
    if (!item) return {nullptr, -1};

    // Traverse to find variable reference
    const cexpr_t* expr = nullptr;
    if (item->is_expr()) {
        expr = static_cast<const cexpr_t*>(item);
    }

    if (!expr) return {nullptr, -1};

    // Handle different expression types that reference variables
    while (expr) {
        if (expr->op == cot_var) {
            int idx = expr->v.idx;
            lvar_t* var = find_lvar_by_idx(vdui->cfunc, idx);
            return {var, idx};
        }

        // Navigate through common expression wrappers
        if (expr->op == cot_cast || expr->op == cot_ref) {
            expr = expr->x;
        } else if (expr->op == cot_ptr || expr->op == cot_memptr) {
            expr = expr->x;
        } else if (expr->op == cot_idx) {
            expr = expr->x;
        } else {
            break;
        }
    }

    return {nullptr, -1};
}

/// Check if a cexpr is a dereference operation
[[nodiscard]] inline bool is_dereference(const cexpr_t* expr) {
    if (!expr) return false;
    return expr->op == cot_ptr || expr->op == cot_memptr ||
           expr->op == cot_memref || expr->op == cot_idx;
}

/// Check if expression is a call
[[nodiscard]] inline bool is_call_expr(const cexpr_t* expr) {
    if (!expr) return false;
    return expr->op == cot_call;
}

/// Extract base variable and offset from pointer arithmetic
struct PtrArithInfo {
    int         var_idx;
    sval_t      offset;
    bool        valid;

    PtrArithInfo() : var_idx(-1), offset(0), valid(false) {}
};

[[nodiscard]] inline PtrArithInfo extract_ptr_arith(const cexpr_t* expr, int depth = 0) {
    PtrArithInfo info;
    if (!expr) return info;

    // Prevent infinite recursion
    if (depth > 50) {
        return info;
    }

    // Direct variable access
    if (expr->op == cot_var) {
        info.var_idx = expr->v.idx;
        info.offset = 0;
        info.valid = true;
        return info;
    }

    // Cast expression - recurse
    if (expr->op == cot_cast) {
        return extract_ptr_arith(expr->x, depth + 1);
    }

    // Add expression: var + offset or offset + var
    // Handle scaled pointer arithmetic: (type*)ptr + n means ptr + n*sizeof(type)
    if (expr->op == cot_add) {
        auto left = extract_ptr_arith(expr->x, depth + 1);
        auto right = extract_ptr_arith(expr->y, depth + 1);

        if (left.valid && !right.valid && expr->y->op == cot_num) {
            info = left;
            sval_t num_val = expr->y->numval();

            // Check if left operand is a pointer type - if so, scale by element size
            if (expr->x->type.is_ptr()) {
                tinfo_t pointed = expr->x->type.get_pointed_object();
                if (!pointed.empty()) {
                    size_t elem_size = pointed.get_size();
                    if (elem_size != BADSIZE && elem_size > 0) {
                        num_val *= elem_size;
                    }
                }
            }

            info.offset += num_val;
            return info;
        }
        if (right.valid && !left.valid && expr->x->op == cot_num) {
            info = right;
            sval_t num_val = expr->x->numval();

            // Check if right operand (the pointer) has a pointer type
            if (expr->y->type.is_ptr()) {
                tinfo_t pointed = expr->y->type.get_pointed_object();
                if (!pointed.empty()) {
                    size_t elem_size = pointed.get_size();
                    if (elem_size != BADSIZE && elem_size > 0) {
                        num_val *= elem_size;
                    }
                }
            }

            info.offset += num_val;
            return info;
        }
        if (left.valid && right.valid) {
            // Both are variables - can't handle this case simply
            return info;
        }
    }

    // Subtract expression: var - offset
    // Handle scaled pointer arithmetic: (type*)ptr - n means ptr - n*sizeof(type)
    if (expr->op == cot_sub) {
        auto left = extract_ptr_arith(expr->x, depth + 1);
        if (left.valid && expr->y->op == cot_num) {
            info = left;
            sval_t num_val = expr->y->numval();

            // Check if left operand is a pointer type - if so, scale by element size
            if (expr->x->type.is_ptr()) {
                tinfo_t pointed = expr->x->type.get_pointed_object();
                if (!pointed.empty()) {
                    size_t elem_size = pointed.get_size();
                    if (elem_size != BADSIZE && elem_size > 0) {
                        num_val *= elem_size;
                    }
                }
            }

            info.offset -= num_val;
            return info;
        }
    }

    // Index expression: var[idx]
    if (expr->op == cot_idx) {
        auto base = extract_ptr_arith(expr->x, depth + 1);
        if (base.valid && expr->y->op == cot_num) {
            info = base;
            // Get element size from type
            tinfo_t elem_type = expr->x->type.get_pointed_object();
            if (!elem_type.empty()) {
                info.offset += expr->y->numval() * elem_type.get_size();
            } else {
                info.offset += expr->y->numval();
            }
            return info;
        }
    }

    return info;
}

// ============================================================================
// Type Utilities
// ============================================================================

/// Create a basic type from size and semantics
[[nodiscard]] inline tinfo_t create_basic_type(std::uint32_t size, SemanticType semantic) {
    tinfo_t type;

    switch (semantic) {
        case SemanticType::Float:
            if (size == 4) {
                type.create_simple_type(BTF_FLOAT);
            } else if (size == 8) {
                type.create_simple_type(BTF_DOUBLE);
            }
            return type;

        case SemanticType::Double:
            type.create_simple_type(BTF_DOUBLE);
            return type;

        case SemanticType::Pointer:
        case SemanticType::VTablePointer: {
            tinfo_t void_type;
            void_type.create_simple_type(BTF_VOID);
            type.create_ptr(void_type);
            return type;
        }

        case SemanticType::FunctionPointer: {
            // Create generic function pointer: void (*)()
            func_type_data_t ftd;
            ftd.rettype.create_simple_type(BTF_VOID);
            ftd.set_cc(CM_CC_UNKNOWN);
            tinfo_t func_type;
            func_type.create_func(ftd);
            type.create_ptr(func_type);
            return type;
        }

        case SemanticType::UnsignedInteger:
            switch (size) {
                case 1: type.create_simple_type(BTF_UINT8); break;
                case 2: type.create_simple_type(BTF_UINT16); break;
                case 4: type.create_simple_type(BTF_UINT32); break;
                case 8: type.create_simple_type(BTF_UINT64); break;
                default: type.create_simple_type(BTF_UINT32); break;
            }
            return type;

        case SemanticType::Integer:
        default:
            switch (size) {
                case 1: type.create_simple_type(BTF_INT8); break;
                case 2: type.create_simple_type(BTF_INT16); break;
                case 4: type.create_simple_type(BTF_INT32); break;
                case 8: type.create_simple_type(BTF_INT64); break;
                default: type.create_simple_type(BTF_INT32); break;
            }
            return type;
    }
}

/// Create a pointer to a named type
[[nodiscard]] inline tinfo_t create_named_ptr(const char* type_name) {
    tinfo_t base_type;
    if (!base_type.get_named_type(nullptr, type_name)) {
        // Fallback to void pointer if type not found
        tinfo_t void_type;
        void_type.create_simple_type(BTF_VOID);
        base_type.create_ptr(void_type);
        return base_type;
    }

    tinfo_t ptr_type;
    ptr_type.create_ptr(base_type);
    return ptr_type;
}

/// Get size of a type, with fallback
[[nodiscard]] inline std::uint32_t get_type_size(const tinfo_t& type, std::uint32_t default_size = 0) {
    if (type.empty()) return default_size;
    size_t size = type.get_size();
    if (size == BADSIZE) return default_size;
    return static_cast<std::uint32_t>(size);
}

// ============================================================================
// Expression Printing
// ============================================================================

/// Print an expression to string
[[nodiscard]] inline qstring expr_to_string(const cexpr_t* expr, const cfunc_t* cfunc = nullptr) {
    if (!expr) return "<null>";

    qstring result;

    // Use the expression's built-in printing if available
    expr->print1(&result, nullptr);
    tag_remove(&result);

    return result;
}

/// Print a type to string
[[nodiscard]] inline qstring type_to_string(const tinfo_t& type) {
    if (type.empty()) return "<unknown>";

    qstring result;
    type.print(&result);
    return result;
}

// ============================================================================
// Function Utilities
// ============================================================================

/// Get function name
[[nodiscard]] inline qstring get_func_name(ea_t ea) {
    qstring name;
    get_func_name(&name, ea);
    if (name.empty()) {
        name.sprnt("sub_%llX", static_cast<unsigned long long>(ea));
    }
    return name;
}

/// Get all callers of a function
[[nodiscard]] inline qvector<ea_t> get_callers(ea_t func_ea) {
    qvector<ea_t> callers;

    xrefblk_t xref;
    for (bool ok = xref.first_to(func_ea, XREF_FAR); ok; ok = xref.next_to()) {
        if (xref.iscode && (xref.type == fl_CN || xref.type == fl_CF)) {
            func_t* caller_func = get_func(xref.from);
            if (caller_func) {
                ea_t caller_ea = caller_func->start_ea;
                if (std::find(callers.begin(), callers.end(), caller_ea) == callers.end()) {
                    callers.push_back(caller_ea);
                }
            }
        }
    }

    return callers;
}

/// Get all callees of a function
[[nodiscard]] inline qvector<ea_t> get_callees(ea_t func_ea) {
    qvector<ea_t> callees;

    func_t* func = get_func(func_ea);
    if (!func) return callees;

    func_item_iterator_t fii;
    for (bool ok = fii.set(func); ok; ok = fii.next_code()) {
        ea_t ea = fii.current();

        xrefblk_t xref;
        for (bool xok = xref.first_from(ea, XREF_FAR); xok; xok = xref.next_from()) {
            if (xref.iscode && (xref.type == fl_CN || xref.type == fl_CF)) {
                if (std::find(callees.begin(), callees.end(), xref.to) == callees.end()) {
                    callees.push_back(xref.to);
                }
            }
        }
    }

    return callees;
}

// ============================================================================
// UI Utilities
// ============================================================================

/// Show status bar message
inline void show_status(const char* fmt, ...) {
    va_list va;
    va_start(va, fmt);
    qstring text;
    text.vsprnt(fmt, va);
    va_end(va);

    msg("%s\n", text.c_str());
}

/// Show warning dialog
inline void show_warning(const char* fmt, ...) {
    va_list va;
    va_start(va, fmt);
    qstring msg;
    msg.vsprnt(fmt, va);
    va_end(va);

    warning("%s", msg.c_str());
}

/// Show info dialog
inline void show_info(const char* fmt, ...) {
    va_list va;
    va_start(va, fmt);
    qstring msg;
    msg.vsprnt(fmt, va);
    va_end(va);

    info("%s", msg.c_str());
}

/// Ask yes/no question
[[nodiscard]] inline bool ask_yes_no(const char* fmt, ...) {
    va_list va;
    va_start(va, fmt);
    qstring msg;
    msg.vsprnt(fmt, va);
    va_end(va);

    return ::ask_yn(ASKBTN_YES, "%s", msg.c_str()) == ASKBTN_YES;
}

// ============================================================================
// Debug Logging Utilities (adopted from Suture)
// ============================================================================

/// Debug logging flag - set to true to enable verbose output
inline bool g_debug_enabled = false;

/// Enable/disable debug logging
inline void set_debug_enabled(bool enabled) {
    g_debug_enabled = enabled;
}

/// Check if debug logging is enabled
[[nodiscard]] inline bool is_debug_enabled() noexcept {
    return g_debug_enabled;
}

/// Debug log function - only outputs if debugging is enabled
inline void debug_log(const char* fmt, ...) {
    if (!g_debug_enabled) return;

    va_list va;
    va_start(va, fmt);
    qstring text;
    text.vsprnt(fmt, va);
    va_end(va);

    msg("[STRUCTOR DEBUG] %s\n", text.c_str());
}

/// Get readable name for cexpr operation (adopted from Suture's PrintItem)
[[nodiscard]] inline const char* cot_name(ctype_t op) {
    switch (op) {
        case cot_comma:    return "cot_comma";
        case cot_asg:      return "cot_asg";
        case cot_asgbor:   return "cot_asgbor";
        case cot_asgxor:   return "cot_asgxor";
        case cot_asgband:  return "cot_asgband";
        case cot_asgadd:   return "cot_asgadd";
        case cot_asgsub:   return "cot_asgsub";
        case cot_asgmul:   return "cot_asgmul";
        case cot_asgsshr:  return "cot_asgsshr";
        case cot_asgushr:  return "cot_asgushr";
        case cot_asgshl:   return "cot_asgshl";
        case cot_asgsdiv:  return "cot_asgsdiv";
        case cot_asgudiv:  return "cot_asgudiv";
        case cot_asgsmod:  return "cot_asgsmod";
        case cot_asgumod:  return "cot_asgumod";
        case cot_tern:     return "cot_tern";
        case cot_lor:      return "cot_lor";
        case cot_land:     return "cot_land";
        case cot_bor:      return "cot_bor";
        case cot_xor:      return "cot_xor";
        case cot_band:     return "cot_band";
        case cot_eq:       return "cot_eq";
        case cot_ne:       return "cot_ne";
        case cot_sge:      return "cot_sge";
        case cot_uge:      return "cot_uge";
        case cot_sle:      return "cot_sle";
        case cot_ule:      return "cot_ule";
        case cot_sgt:      return "cot_sgt";
        case cot_ugt:      return "cot_ugt";
        case cot_slt:      return "cot_slt";
        case cot_ult:      return "cot_ult";
        case cot_sshr:     return "cot_sshr";
        case cot_ushr:     return "cot_ushr";
        case cot_shl:      return "cot_shl";
        case cot_add:      return "cot_add";
        case cot_sub:      return "cot_sub";
        case cot_mul:      return "cot_mul";
        case cot_sdiv:     return "cot_sdiv";
        case cot_udiv:     return "cot_udiv";
        case cot_smod:     return "cot_smod";
        case cot_umod:     return "cot_umod";
        case cot_fadd:     return "cot_fadd";
        case cot_fsub:     return "cot_fsub";
        case cot_fmul:     return "cot_fmul";
        case cot_fdiv:     return "cot_fdiv";
        case cot_fneg:     return "cot_fneg";
        case cot_neg:      return "cot_neg";
        case cot_cast:     return "cot_cast";
        case cot_lnot:     return "cot_lnot";
        case cot_bnot:     return "cot_bnot";
        case cot_ptr:      return "cot_ptr";
        case cot_ref:      return "cot_ref";
        case cot_postinc:  return "cot_postinc";
        case cot_postdec:  return "cot_postdec";
        case cot_preinc:   return "cot_preinc";
        case cot_predec:   return "cot_predec";
        case cot_call:     return "cot_call";
        case cot_idx:      return "cot_idx";
        case cot_memref:   return "cot_memref";
        case cot_memptr:   return "cot_memptr";
        case cot_num:      return "cot_num";
        case cot_fnum:     return "cot_fnum";
        case cot_str:      return "cot_str";
        case cot_obj:      return "cot_obj";
        case cot_var:      return "cot_var";
        case cot_insn:     return "cot_insn";
        case cot_sizeof:   return "cot_sizeof";
        case cot_helper:   return "cot_helper";
        case cot_type:     return "cot_type";
        default:           return "cot_unknown";
    }
}

/// Print expression item for debugging (adopted from Suture's PrintItem)
inline void debug_print_expr(const cexpr_t* expr, int indent = 0) {
    if (!g_debug_enabled || !expr) return;

    qstring type_str = type_to_string(expr->type);
    qstring indent_str;
    for (int i = 0; i < indent; ++i) indent_str.append("  ");

    qstring extra;
    if (expr->op == cot_num) {
        extra.sprnt(" value=%lld", static_cast<long long>(expr->numval()));
    } else if (expr->op == cot_var) {
        extra.sprnt(" idx=%d", expr->v.idx);
    }

    msg("[STRUCTOR DEBUG] %s%-15s%s  type=%s\n",
        indent_str.c_str(),
        cot_name(expr->op),
        extra.c_str(),
        type_str.c_str());
}

/// Print access pattern for debugging
inline void debug_print_access(const FieldAccess& access) {
    if (!g_debug_enabled) return;

    msg("[STRUCTOR DEBUG]   offset=0x%llX size=%u type=%s semantic=%s%s%s\n",
        static_cast<unsigned long long>(access.offset),
        access.size,
        access_type_str(access.access_type),
        semantic_type_str(access.semantic_type),
        access.is_vtable_access ? " [VTABLE]" : "",
        access.is_nested_access() ? " [NESTED]" : "");
}

/// Print all accesses in a pattern for debugging
inline void debug_print_pattern(const AccessPattern& pattern) {
    if (!g_debug_enabled) return;

    msg("[STRUCTOR DEBUG] AccessPattern for var '%s' (idx=%d) in func 0x%llX\n",
        pattern.var_name.c_str(),
        pattern.var_idx,
        static_cast<unsigned long long>(pattern.func_ea));
    msg("[STRUCTOR DEBUG]   %zu accesses, range [0x%llX - 0x%llX)\n",
        pattern.accesses.size(),
        static_cast<unsigned long long>(pattern.min_offset),
        static_cast<unsigned long long>(pattern.max_offset));

    for (const auto& access : pattern.accesses) {
        debug_print_access(access);
    }
}

/// RAII debug scope - prints entry/exit messages
class DebugScope {
public:
    explicit DebugScope(const char* name) : name_(name) {
        if (g_debug_enabled) {
            msg("[STRUCTOR DEBUG] >>> %s\n", name_);
        }
    }

    ~DebugScope() {
        if (g_debug_enabled) {
            msg("[STRUCTOR DEBUG] <<< %s\n", name_);
        }
    }

private:
    const char* name_;
};

/// Macro for easy debug scoping
#define STRUCTOR_DEBUG_SCOPE(name) ::structor::utils::DebugScope _debug_scope_##__LINE__(name)

} // namespace utils
} // namespace structor
