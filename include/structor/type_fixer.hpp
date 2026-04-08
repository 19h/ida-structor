#pragma once

#include "synth_types.hpp"
#include "config.hpp"
#include "type_propagator.hpp"
#include "access_collector.hpp"
#include "layout_synthesizer.hpp"
#include "structure_persistence.hpp"

#ifndef STRUCTOR_TESTING
#include <hexrays.hpp>
#endif

#include <algorithm>
#include <cctype>
#include <functional>
#include <string>
#include <unordered_map>

namespace structor {

// ============================================================================
// Type Difference Classification
// ============================================================================

/// Classification of how different two types are
enum class TypeDifference : std::uint8_t {
    None = 0,           // Types are identical or equivalent
    Minor,              // Minor difference (e.g., signed vs unsigned same size)
    Moderate,           // Moderate difference (e.g., int vs pointer, size mismatch)
    Significant,        // Significant difference (e.g., void* used as struct*)
    Critical            // Critical difference (e.g., wrong pointer indirection level)
};

/// Get string representation of TypeDifference
[[nodiscard]] inline const char* type_difference_str(TypeDifference diff) noexcept {
    switch (diff) {
        case TypeDifference::None:        return "none";
        case TypeDifference::Minor:       return "minor";
        case TypeDifference::Moderate:    return "moderate";
        case TypeDifference::Significant: return "significant";
        case TypeDifference::Critical:    return "critical";
        default:                          return "unknown";
    }
}

/// Specific reason for type difference
enum class DifferenceReason : std::uint8_t {
    None = 0,
    SignednessMismatch,         // int vs uint
    SizeMismatch,               // int32 vs int64
    VoidPointerToTyped,         // void* -> typed*
    GenericToFuncPtr,           // void* -> func*
    GenericToStructPtr,         // void* -> struct*
    PointerLevelMismatch,       // void** vs void*
    IntegerToPointer,           // int64 -> void*
    PointerToInteger,           // void* -> int64
    FloatToInteger,             // float/double vs int
    ArrayDetected,              // scalar -> array
    StructureDetected,          // void* -> synthesized_struct*
    VTableDetected,             // void* -> vtable pattern
    TypeQualifierDifference,    // const, volatile, etc.
    CompletelyDifferent         // No relation between types
};

/// Get string representation of DifferenceReason
[[nodiscard]] inline const char* difference_reason_str(DifferenceReason reason) noexcept {
    switch (reason) {
        case DifferenceReason::None:                    return "none";
        case DifferenceReason::SignednessMismatch:      return "signedness_mismatch";
        case DifferenceReason::SizeMismatch:            return "size_mismatch";
        case DifferenceReason::VoidPointerToTyped:      return "void_ptr_to_typed";
        case DifferenceReason::GenericToFuncPtr:        return "generic_to_funcptr";
        case DifferenceReason::GenericToStructPtr:      return "generic_to_structptr";
        case DifferenceReason::PointerLevelMismatch:    return "ptr_level_mismatch";
        case DifferenceReason::IntegerToPointer:        return "int_to_ptr";
        case DifferenceReason::PointerToInteger:        return "ptr_to_int";
        case DifferenceReason::FloatToInteger:          return "float_to_int";
        case DifferenceReason::ArrayDetected:           return "array_detected";
        case DifferenceReason::StructureDetected:       return "struct_detected";
        case DifferenceReason::VTableDetected:          return "vtable_detected";
        case DifferenceReason::TypeQualifierDifference: return "qualifier_diff";
        case DifferenceReason::CompletelyDifferent:     return "completely_different";
        default:                                        return "unknown";
    }
}

// ============================================================================
// Type Comparison Result
// ============================================================================

/// Result of comparing two types
struct TypeComparisonResult {
    TypeDifference difference = TypeDifference::None;
    DifferenceReason primary_reason = DifferenceReason::None;
    qvector<DifferenceReason> secondary_reasons;
    
    /// The original type (from IDA)
    tinfo_t original_type;
    
    /// The inferred type (from analysis)
    tinfo_t inferred_type;
    
    /// Confidence in the inferred type
    TypeConfidence confidence = TypeConfidence::Low;
    
    /// Human-readable description of the difference
    qstring description;
    
    /// Is this difference significant enough to warrant fixing?
    [[nodiscard]] bool is_significant() const noexcept {
        return difference >= TypeDifference::Significant;
    }
    
    /// Is this difference worth reporting but not auto-fixing?
    [[nodiscard]] bool is_notable() const noexcept {
        return difference >= TypeDifference::Moderate;
    }
};

// ============================================================================
// Type Fixer Configuration
// ============================================================================

/// Configuration for automatic type fixing
struct TypeFixerConfig {
    /// Minimum difference level to auto-fix
    TypeDifference min_auto_fix_level = TypeDifference::Significant;
    
    /// Minimum confidence to apply fixes
    TypeConfidence min_confidence = TypeConfidence::Medium;
    
    /// Whether to fix argument types
    bool fix_arguments = true;
    
    /// Whether to fix local variable types
    bool fix_locals = true;
    
    /// Whether to fix return types (experimental)
    bool fix_return_type = false;
    
    /// Whether to propagate fixed types to callers/callees
    bool propagate_fixes = true;
    
    /// Maximum propagation depth for fixed types
    int max_propagation_depth = 3;
    
    /// Whether to create synthesized structures when detected
    bool synthesize_structures = true;
    
    /// Whether to only report differences without applying
    bool dry_run = false;
    
    /// Whether to force fixes even if confidence is lower
    bool force_apply = false;
    
    /// Specific difference reasons to auto-fix (empty = all significant)
    qvector<DifferenceReason> auto_fix_reasons;
    
    /// Specific difference reasons to skip
    qvector<DifferenceReason> skip_reasons;
    
    /// Filter for which variables to analyze (by name pattern, empty = all)
    qstring variable_filter;
    
    /// Progress callback
    std::function<void(int var_idx, const char* var_name, const char* status)> 
        progress_callback;
    
    TypeFixerConfig() = default;
    
    /// Check if a specific reason should be auto-fixed
    [[nodiscard]] bool should_auto_fix(DifferenceReason reason) const {
        // Check skip list first
        for (const auto& r : skip_reasons) {
            if (r == reason) return false;
        }
        
        // If auto_fix_reasons is empty, fix all
        if (auto_fix_reasons.empty()) return true;
        
        // Otherwise check if reason is in the list
        for (const auto& r : auto_fix_reasons) {
            if (r == reason) return true;
        }
        return false;
    }
};

// ============================================================================
// Type Fix Result
// ============================================================================

/// Result of fixing a single variable's type
struct VariableTypeFix {
    int var_idx = -1;
    qstring var_name;
    bool is_argument = false;
    
    /// Comparison result
    TypeComparisonResult comparison;
    
    /// Whether the fix was applied
    bool applied = false;
    
    /// Reason if not applied
    qstring skip_reason;
    
    /// If a structure was synthesized
    tid_t synthesized_struct_tid = BADADDR;
    
    /// Propagation results (if propagation was enabled)
    PropagationResult propagation;
};

/// Result of fixing types in a function
struct TypeFixResult {
    ea_t func_ea = BADADDR;
    qstring func_name;
    
    /// All variable fixes (attempted and applied)
    qvector<VariableTypeFix> variable_fixes;
    
    /// Summary statistics
    unsigned total_variables = 0;
    unsigned analyzed = 0;
    unsigned differences_found = 0;
    unsigned fixes_applied = 0;
    unsigned fixes_skipped = 0;
    unsigned structures_synthesized = 0;
    unsigned propagated_count = 0;
    
    /// Errors encountered
    qvector<qstring> errors;
    qvector<qstring> warnings;
    qvector<qstring> diagnostics;
    
    /// Overall success
    [[nodiscard]] bool success() const noexcept {
        return errors.empty();
    }
    
    /// Get summary string
    [[nodiscard]] qstring summary() const {
        qstring s;
        s.sprnt("TypeFix: %u vars, %u analyzed, %u diffs, %u fixed, %u skipped",
                total_variables, analyzed, differences_found, 
                fixes_applied, fixes_skipped);
        if (structures_synthesized > 0) {
            s.cat_sprnt(", %u structs", structures_synthesized);
        }
        if (propagated_count > 0) {
            s.cat_sprnt(", %u propagated", propagated_count);
        }
        return s;
    }
};

// ============================================================================
// Type Comparison Utilities
// ============================================================================

/// Compare two types and determine their difference level
[[nodiscard]] inline TypeComparisonResult compare_types(
    const tinfo_t& original,
    const tinfo_t& inferred,
    TypeConfidence confidence = TypeConfidence::Medium)
{
    TypeComparisonResult result;
    result.original_type = original;
    result.inferred_type = inferred;
    result.confidence = confidence;
    
    // Handle empty types
    if (original.empty() && inferred.empty()) {
        result.difference = TypeDifference::None;
        return result;
    }
    
    if (original.empty()) {
        result.difference = TypeDifference::Significant;
        result.primary_reason = DifferenceReason::CompletelyDifferent;
        result.description = "Original type is empty";
        return result;
    }
    
    if (inferred.empty()) {
        result.difference = TypeDifference::None;
        result.description = "No inferred type available";
        return result;
    }
    
    // Compare types
    if (original.equals_to(inferred)) {
        result.difference = TypeDifference::None;
        return result;
    }
    
    // Get sizes
    size_t orig_size = original.get_size();
    size_t inf_size = inferred.get_size();
    
    // Check for void* -> typed pointer conversion
    bool orig_is_void_ptr = original.is_ptr() && 
        (original.get_pointed_object().empty() || 
         original.get_pointed_object().is_unknown() ||
         original.get_pointed_object().is_void());
    
    bool inf_is_typed_ptr = inferred.is_ptr() && 
        !inferred.get_pointed_object().empty() &&
        !inferred.get_pointed_object().is_unknown() &&
        !inferred.get_pointed_object().is_void();
    
    // void* -> struct* is significant
    if (orig_is_void_ptr && inf_is_typed_ptr) {
        tinfo_t pointed = inferred.get_pointed_object();
        
        if (pointed.is_struct()) {
            result.difference = TypeDifference::Significant;
            result.primary_reason = DifferenceReason::StructureDetected;
            qstring type_name;
            pointed.get_type_name(&type_name);
            result.description.sprnt("void* -> struct %s", type_name.c_str());
        } else if (pointed.is_funcptr() || inferred.is_funcptr()) {
            result.difference = TypeDifference::Significant;
            result.primary_reason = DifferenceReason::GenericToFuncPtr;
            result.description = "void* -> function pointer";
        } else {
            result.difference = TypeDifference::Significant;
            result.primary_reason = DifferenceReason::VoidPointerToTyped;
            result.description.sprnt("void* -> %s", inferred.dstr());
        }
        return result;
    }
    
    // Check for integer <-> pointer mismatch
    bool orig_is_integer = original.is_integral() && !original.is_ptr();
    bool inf_is_pointer = inferred.is_ptr() || inferred.is_funcptr();
    bool orig_is_pointer = original.is_ptr() || original.is_funcptr();
    bool inf_is_integer = inferred.is_integral() && !inferred.is_ptr();
    
    if (orig_is_integer && inf_is_pointer) {
        result.difference = TypeDifference::Significant;
        result.primary_reason = DifferenceReason::IntegerToPointer;
        result.description.sprnt("integer -> %s", inferred.dstr());
        return result;
    }
    
    if (orig_is_pointer && inf_is_integer) {
        // This is usually wrong - pointer used as integer
        result.difference = TypeDifference::Moderate;
        result.primary_reason = DifferenceReason::PointerToInteger;
        result.description.sprnt("%s -> integer", original.dstr());
        return result;
    }
    
    // Check pointer indirection levels
    if (orig_is_pointer && inf_is_pointer) {
        int orig_level = 0, inf_level = 0;
        tinfo_t t = original;
        while (t.is_ptr()) { orig_level++; t = t.get_pointed_object(); }
        t = inferred;
        while (t.is_ptr()) { inf_level++; t = t.get_pointed_object(); }
        
        if (orig_level != inf_level) {
            result.difference = TypeDifference::Critical;
            result.primary_reason = DifferenceReason::PointerLevelMismatch;
            result.description.sprnt("pointer level %d -> %d", orig_level, inf_level);
            return result;
        }
    }
    
    // Check signedness for integers
    if (orig_is_integer && inf_is_integer) {
        bool orig_signed = original.is_signed();
        bool inf_signed = inferred.is_signed();
        
        if (orig_signed != inf_signed) {
            result.secondary_reasons.push_back(DifferenceReason::SignednessMismatch);
        }
        
        if (orig_size != inf_size && orig_size != BADSIZE && inf_size != BADSIZE) {
            result.difference = TypeDifference::Moderate;
            result.primary_reason = DifferenceReason::SizeMismatch;
            result.description.sprnt("int%zu -> int%zu", 
                orig_size * 8, inf_size * 8);
        } else if (orig_signed != inf_signed) {
            result.difference = TypeDifference::Minor;
            result.primary_reason = DifferenceReason::SignednessMismatch;
            result.description = orig_signed ? "signed -> unsigned" : "unsigned -> signed";
        }
        return result;
    }
    
    // Check float vs integer
    bool orig_is_float = original.is_floating();
    bool inf_is_float = inferred.is_floating();
    
    if (orig_is_float != inf_is_float) {
        result.difference = TypeDifference::Moderate;
        result.primary_reason = DifferenceReason::FloatToInteger;
        result.description = orig_is_float ? "float -> integer" : "integer -> float";
        return result;
    }
    
    // Check for array detection
    if (!original.is_array() && inferred.is_array()) {
        result.difference = TypeDifference::Significant;
        result.primary_reason = DifferenceReason::ArrayDetected;
        result.description.sprnt("scalar -> %s", inferred.dstr());
        return result;
    }
    
    // Default: completely different
    result.difference = TypeDifference::Moderate;
    result.primary_reason = DifferenceReason::CompletelyDifferent;
    result.description.sprnt("%s -> %s", original.dstr(), inferred.dstr());
    
    return result;
}

/// Check if an IDA type is a "default" type (void*, __int64, etc.)
[[nodiscard]] inline bool is_default_type(const tinfo_t& type) {
    if (type.empty()) return true;
    
    // Check for void*
    if (type.is_ptr()) {
        tinfo_t pointed = type.get_pointed_object();
        if (pointed.empty() || pointed.is_void() || pointed.is_unknown()) {
            return true;
        }
    }
    
    // Check for generic integer types (often default decompiler output)
    if (type.is_integral() && !type.is_ptr()) {
        // __int64, __int32, etc. without better type info
        qstring name;
        type.get_type_name(&name);
        if (name.empty()) return true;
        if (name.find("int") != qstring::npos && 
            name.find("_") != qstring::npos) {
            // Likely __int64 or similar
            return true;
        }
    }
    
    return false;
}

namespace detail {

[[nodiscard]] inline bool types_are_compatible_for_recovery(
    const tinfo_t& lhs,
    const tinfo_t& rhs)
{
    if (lhs.empty() || rhs.empty()) {
        return false;
    }
    if (lhs.equals_to(rhs)) {
        return true;
    }

    TypeComparisonResult cmp = compare_types(lhs, rhs, TypeConfidence::Low);
    if (cmp.difference <= TypeDifference::Moderate) {
        return true;
    }

    return cmp.primary_reason == DifferenceReason::VoidPointerToTyped
        || cmp.primary_reason == DifferenceReason::StructureDetected
        || cmp.primary_reason == DifferenceReason::GenericToFuncPtr;
}

[[nodiscard]] inline bool type_matches_lvar_width(const tinfo_t& type, const lvar_t& var) {
#ifndef STRUCTOR_TESTING
    if (type.empty()) {
        return false;
    }

    if (var.width <= 0) {
        return true;
    }

    size_t size = type.get_size();
    return size != BADSIZE && size == static_cast<size_t>(var.width);
#else
    (void) type;
    (void) var;
    return false;
#endif
}

[[nodiscard]] inline bool lvars_share_exact_storage(const lvar_t& lhs, const lvar_t& rhs) {
#ifndef STRUCTOR_TESTING
    if (lhs.width <= 0 || rhs.width <= 0 || lhs.width != rhs.width) {
        return false;
    }

    if (lhs.is_stk_var() && rhs.is_stk_var()) {
        return lhs.get_stkoff() == rhs.get_stkoff();
    }

    if (lhs.is_reg1() && rhs.is_reg1()) {
        return lhs.get_reg1() == rhs.get_reg1();
    }

    if (lhs.is_reg2() && rhs.is_reg2()) {
        return lhs.get_reg1() == rhs.get_reg1()
            && lhs.get_reg2() == rhs.get_reg2();
    }

    return false;
#else
    (void) lhs;
    (void) rhs;
    return false;
#endif
}

[[nodiscard]] inline qstring describe_lvar_location(const lvar_t& var) {
    qstring loc;

#ifndef STRUCTOR_TESTING
    if (var.is_reg_var()) {
        if (get_mreg_name(&loc, var.get_reg1(), std::max(var.width, 1), nullptr) > 0 && !loc.empty()) {
            return loc;
        }
    } else if (var.is_stk_var()) {
        loc.sprnt("stack+0x%llX", static_cast<unsigned long long>(var.get_stkoff()));
        return loc;
    }

    print_vdloc(&loc, var.location, std::max(var.width, 1));
#else
    loc = "<unknown>";
    (void) var;
#endif

    return loc;
}

[[nodiscard]] inline std::string normalize_register_family(const qstring& reg_name) {
    std::string normalized;
    normalized.reserve(reg_name.length());
    for (size_t i = 0; i < reg_name.length(); ++i) {
        unsigned char ch = static_cast<unsigned char>(reg_name[i]);
        if (std::isalnum(ch)) {
            normalized.push_back(static_cast<char>(std::tolower(ch)));
        }
    }

#ifndef STRUCTOR_TESTING
    const bool is_64bit_db = inf_is_64bit();
#else
    const bool is_64bit_db = true;
#endif

    auto is_numbered_family = [](const std::string& s, char prefix) -> bool {
        return s.size() >= 2
            && s[0] == prefix
            && std::all_of(s.begin() + 1, s.end(), [](unsigned char c) { return std::isdigit(c) != 0; });
    };

    if (is_64bit_db) {
        if (normalized == "rdi" || normalized == "edi" || normalized == "di" || normalized == "dil") return "rdi";
        if (normalized == "rsi" || normalized == "esi" || normalized == "si" || normalized == "sil") return "rsi";
        if (normalized == "rcx" || normalized == "ecx" || normalized == "cx" || normalized == "cl" || normalized == "ch") return "rcx";
        if (normalized == "rdx" || normalized == "edx" || normalized == "dx" || normalized == "dl" || normalized == "dh") return "rdx";
        if (normalized.rfind("r8", 0) == 0) return "r8";
        if (normalized.rfind("r9", 0) == 0) return "r9";
    } else {
        if (normalized == "ecx" || normalized == "cx" || normalized == "cl" || normalized == "ch") return "ecx";
        if (normalized == "edx" || normalized == "dx" || normalized == "dl" || normalized == "dh") return "edx";
    }

    if (normalized.rfind("xmm", 0) == 0) {
        return normalized;
    }

    if (is_numbered_family(normalized, 'x') || is_numbered_family(normalized, 'r')) {
        return normalized;
    }

    if (is_numbered_family(normalized, 'w')) {
        return std::string("x") + normalized.substr(1);
    }

    if (is_numbered_family(normalized, 's')
     || is_numbered_family(normalized, 'd')
     || is_numbered_family(normalized, 'q')
     || is_numbered_family(normalized, 'v')) {
        return std::string("v") + normalized.substr(1);
    }

    return normalized;
}

[[nodiscard]] inline qvector<int> candidate_param_indices_for_register(const std::string& reg_family) {
    qvector<int> indices;

    auto push = [&indices](int idx) {
        if (idx < 0) {
            return;
        }
        if (std::find(indices.begin(), indices.end(), idx) == indices.end()) {
            indices.push_back(idx);
        }
    };

    if (reg_family == "rdi") {
        push(0);
    } else if (reg_family == "rsi") {
        push(1);
    } else if (reg_family == "rcx") {
        push(0);
        push(3);
    } else if (reg_family == "rdx") {
        push(1);
        push(2);
    } else if (reg_family == "r8") {
        push(2);
        push(4);
    } else if (reg_family == "r9") {
        push(3);
        push(5);
    } else if (reg_family == "ecx") {
        push(0);
    } else if (reg_family == "edx") {
        push(1);
    } else if (reg_family.rfind("xmm", 0) == 0) {
        int idx = std::atoi(reg_family.c_str() + 3);
        if (idx >= 0 && idx <= 7) {
            push(idx);
        }
    } else if (reg_family.rfind('x', 0) == 0 || reg_family.rfind('v', 0) == 0) {
        int idx = std::atoi(reg_family.c_str() + 1);
        if (idx >= 0 && idx <= 7) {
            push(idx);
        }
    } else if (reg_family.rfind('r', 0) == 0) {
        int idx = std::atoi(reg_family.c_str() + 1);
        if (idx >= 0 && idx <= 3) {
            push(idx);
        }
    }

    return indices;
}

struct RegisterHandoffSummary {
    tinfo_t type;
    TypeConfidence confidence = TypeConfidence::Low;
    int support = 0;
    int typed_support = 0;
    int conflicts = 0;
};

[[nodiscard]] inline tinfo_t make_width_fallback_type(int width) {
    tinfo_t type;
    switch (width) {
        case 1: type.create_simple_type(BTF_INT8); break;
        case 2: type.create_simple_type(BTF_INT16); break;
        case 4: type.create_simple_type(BTF_INT32); break;
        case 8: type.create_simple_type(BTF_INT64); break;
        default: break;
    }
    return type;
}

[[nodiscard]] inline bool is_likely_return_register_family(const std::string& reg_family) {
    return reg_family == "rax"
        || reg_family == "x0"
        || reg_family == "v0"
        || reg_family == "xmm0";
}

[[nodiscard]] inline std::string operand_reg_family(const op_t& op, int fallback_width = 0) {
#ifndef STRUCTOR_TESTING
    if (op.type != o_reg) {
        return std::string();
    }

    qstring reg_name;
    size_t width = get_dtype_size(op.dtype);
    if (width == 0 && fallback_width > 0) {
        width = static_cast<size_t>(fallback_width);
    }
    if (width == 0) {
        width = 1;
    }

    if (get_reg_name(&reg_name, op.reg, width) <= 0 || reg_name.empty()) {
        return std::string();
    }

    return normalize_register_family(reg_name);
#else
    (void) op;
    (void) fallback_width;
    return std::string();
#endif
}

[[nodiscard]] inline RegisterHandoffSummary collect_register_handoff_summary(
    cfunc_t* callee_cfunc,
    const lvar_t& callee_var)
{
    RegisterHandoffSummary summary;

#ifndef STRUCTOR_TESTING
    if (callee_cfunc == nullptr || !callee_var.is_reg_var()) {
        return summary;
    }

    qstring callee_reg_name = describe_lvar_location(callee_var);
    std::string target_family = normalize_register_family(callee_reg_name);
    if (target_family.empty()) {
        return summary;
    }

    xrefblk_t xref;
    for (bool ok = xref.first_to(callee_cfunc->entry_ea, XREF_ALL); ok; ok = xref.next_to()) {
        if (!xref.iscode || (xref.type != fl_CF && xref.type != fl_CN)) {
            continue;
        }

        ea_t call_ea = xref.from;
        func_t* caller_func = get_func(call_ea);
        if (caller_func == nullptr) {
            continue;
        }

        cfuncptr_t caller_cfunc = utils::get_cfunc(caller_func->start_ea);
        if (!caller_cfunc) {
            continue;
        }

        lvars_t* caller_lvars = caller_cfunc->get_lvars();
        if (caller_lvars == nullptr) {
            continue;
        }

        ea_t scan_ea = call_ea;
        bool found_write = false;
        bool rejected_write = false;

        for (int step = 0; step < 12; ++step) {
            insn_t insn;
            ea_t prev_ea = decode_prev_insn(&insn, scan_ea);
            if (prev_ea == BADADDR || prev_ea < caller_func->start_ea) {
                break;
            }
            scan_ea = prev_ea;

            uint32 feature = insn.get_canon_feature(PH);
            if ((feature & CF_CHG1) == 0 || insn.Op1.type != o_reg) {
                if ((feature & CF_STOP) != 0) {
                    break;
                }
                continue;
            }

            std::string dst_family = operand_reg_family(insn.Op1, callee_var.width);
            if (dst_family != target_family) {
                if ((feature & CF_STOP) != 0) {
                    break;
                }
                continue;
            }

            found_write = true;

            if ((feature & CF_USE2) != 0 && insn.Op2.type == o_reg) {
                int src_width = static_cast<int>(get_dtype_size(insn.Op2.dtype));
                if (src_width <= 0) {
                    src_width = callee_var.width;
                }

                std::string src_family = operand_reg_family(insn.Op2, src_width);
                if (is_likely_return_register_family(src_family)) {
                    insn_t prev_write_insn;
                    ea_t before_write_ea = decode_prev_insn(&prev_write_insn, prev_ea);
                    if (before_write_ea != BADADDR
                     && before_write_ea >= caller_func->start_ea
                     && (prev_write_insn.get_canon_feature(PH) & CF_CALL) != 0) {
                        rejected_write = true;
                        found_write = false;
                        break;
                    }
                }
            }

            ++summary.support;

            tinfo_t candidate_type;
            TypeConfidence candidate_confidence = TypeConfidence::Low;

            if ((feature & CF_USE2) != 0) {
                const op_t& src = insn.Op2;
                if (src.type == o_reg) {
                    int src_width = static_cast<int>(get_dtype_size(src.dtype));
                    if (src_width <= 0) {
                        src_width = callee_var.width;
                    }

                    int input_idx = caller_lvars->find_input_reg(reg2mreg(src.reg), std::max(src_width, 1));
                    if (input_idx >= 0 && static_cast<size_t>(input_idx) < caller_lvars->size()) {
                        const lvar_t& input_var = caller_lvars->at(static_cast<size_t>(input_idx));
                        if (!input_var.type().empty()) {
                            candidate_type = input_var.type();
                            candidate_confidence = input_var.has_user_type()
                                ? TypeConfidence::High
                                : TypeConfidence::Medium;
                        }
                    }

                    if (candidate_type.empty()) {
                        candidate_type = make_width_fallback_type(src_width);
                        candidate_confidence = TypeConfidence::Low;
                    }
                } else if (src.type == o_imm) {
                    candidate_type = make_width_fallback_type(callee_var.width);
                    candidate_confidence = TypeConfidence::Medium;
                }
            }

            if (candidate_type.empty()) {
                candidate_type = make_width_fallback_type(callee_var.width);
                candidate_confidence = TypeConfidence::Low;
            }

            if (!candidate_type.empty()) {
                if (summary.type.empty()) {
                    summary.type = candidate_type;
                    summary.confidence = candidate_confidence;
                    ++summary.typed_support;
                } else if (types_are_compatible_for_recovery(summary.type, candidate_type)) {
                    summary.type = resolve_type_conflict(summary.type, candidate_type);
                    summary.confidence = std::max(summary.confidence, candidate_confidence);
                    ++summary.typed_support;
                } else {
                    ++summary.conflicts;
                }
            }

            break;
        }

        if (!found_write || rejected_write) {
            continue;
        }
    }
#else
    (void) callee_cfunc;
    (void) callee_var;
#endif

    return summary;
}

[[nodiscard]] inline bool is_var_assigned_in_function(cfunc_t* cfunc, int var_idx) {
#ifndef STRUCTOR_TESTING
    if (!cfunc || var_idx < 0) {
        return false;
    }

    struct AssignmentFinder : public ctree_visitor_t {
        int target_var_idx;
        bool assigned = false;

        explicit AssignmentFinder(int target)
            : ctree_visitor_t(CV_FAST)
            , target_var_idx(target) {}

        static cexpr_t* peel(cexpr_t* expr) {
            while (expr != nullptr && (expr->op == cot_cast || expr->op == cot_ref)) {
                expr = expr->x;
            }
            return expr;
        }

        bool is_target(cexpr_t* expr) const {
            expr = peel(expr);
            return expr != nullptr && expr->op == cot_var && expr->v.idx == target_var_idx;
        }

        int idaapi visit_expr(cexpr_t* expr) override {
            if (expr == nullptr || assigned) {
                return 0;
            }

            switch (expr->op) {
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
                    if (is_target(expr->x)) {
                        assigned = true;
                        return 1;
                    }
                    break;
                case cot_postinc:
                case cot_postdec:
                case cot_preinc:
                case cot_predec:
                    if (is_target(expr->x)) {
                        assigned = true;
                        return 1;
                    }
                    break;
                default:
                    break;
            }

            return 0;
        }
    };

    AssignmentFinder finder(var_idx);
    finder.apply_to(&cfunc->body, nullptr);
    return finder.assigned;
#else
    (void) cfunc;
    (void) var_idx;
    return false;
#endif
}

} // namespace detail

// ============================================================================
// Type Fixer Class
// ============================================================================

/// Analyzes and fixes types for all variables in a function
class TypeFixer {
public:
    explicit TypeFixer(const TypeFixerConfig& config = TypeFixerConfig())
        : config_(config) {}
    
    /// Analyze and optionally fix types for all variables in a function
    [[nodiscard]] TypeFixResult fix_function_types(cfunc_t* cfunc);
    
    /// Analyze and optionally fix types for a function by EA
    [[nodiscard]] TypeFixResult fix_function_types(ea_t func_ea);
    
    /// Analyze a single variable (without fixing)
    [[nodiscard]] TypeComparisonResult analyze_variable(
        cfunc_t* cfunc,
        int var_idx);
    
    /// Apply a type fix to a variable
    [[nodiscard]] bool apply_fix(
        cfunc_t* cfunc,
        int var_idx,
        const tinfo_t& new_type,
        PropagationResult* out_propagation = nullptr);
    
    /// Get configuration
    [[nodiscard]] const TypeFixerConfig& config() const noexcept { return config_; }
    TypeFixerConfig& config() noexcept { return config_; }

private:
    TypeFixerConfig config_;
    qvector<qstring> diagnostics_;
    
    /// Infer type for a variable by analyzing access patterns
    [[nodiscard]] tinfo_t infer_variable_type(cfunc_t* cfunc, int var_idx, TypeConfidence& out_confidence);

    /// Directly infer a variable type from its own usage only
    [[nodiscard]] tinfo_t infer_variable_type_direct(cfunc_t* cfunc, int var_idx, TypeConfidence& out_confidence);

    /// Recover type for overlapped locals by borrowing from exact-storage peers
    [[nodiscard]] tinfo_t infer_overlapped_variable_type(cfunc_t* cfunc, int var_idx, TypeConfidence& out_confidence);

    /// Report likely missing register-backed arguments that callers already treat as parameters
    [[nodiscard]] qvector<qstring> collect_missing_argument_warnings(cfunc_t* cfunc);
    
    /// Check if variable should be analyzed based on config
    [[nodiscard]] bool should_analyze(cfunc_t* cfunc, int var_idx);
    
    /// Check if a fix should be applied based on config and comparison
    [[nodiscard]] bool should_apply_fix(const TypeComparisonResult& comparison);
    
    /// Try to synthesize a structure if the variable has pointer accesses
    [[nodiscard]] std::optional<tid_t> try_synthesize_structure(
        cfunc_t* cfunc,
        int var_idx);
    
    /// Report progress if callback is set
    void report_progress(int var_idx, const char* var_name, const char* status);
};

// ============================================================================
// Implementation
// ============================================================================

inline TypeFixResult TypeFixer::fix_function_types(ea_t func_ea) {
    TypeFixResult result;
    result.func_ea = func_ea;
    
    // Get function name
    qstring fname;
    get_func_name(&fname, func_ea);
    result.func_name = fname;
    
    // Decompile function
    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(get_func(func_ea), &hf, DECOMP_NO_WAIT);
    
    if (!cfunc) {
        result.errors.push_back(qstring("Failed to decompile function"));
        return result;
    }
    
    return fix_function_types(cfunc);
}

inline TypeFixResult TypeFixer::fix_function_types(cfunc_t* cfunc) {
    TypeFixResult result;
    diagnostics_.clear();
    
    if (!cfunc) {
        result.errors.push_back(qstring("Null cfunc pointer"));
        return result;
    }
    
    result.func_ea = cfunc->entry_ea;
    qstring fname;
    get_func_name(&fname, cfunc->entry_ea);
    result.func_name = fname;
    
    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars) {
        result.errors.push_back(qstring("Failed to get local variables"));
        return result;
    }
    
    result.total_variables = static_cast<unsigned>(lvars->size());
    
    // Process each variable
    for (size_t i = 0; i < lvars->size(); ++i) {
        int var_idx = static_cast<int>(i);
        lvar_t& var = lvars->at(i);
        
        // Check if we should analyze this variable
        if (!should_analyze(cfunc, var_idx)) {
            continue;
        }
        
        result.analyzed++;
        report_progress(var_idx, var.name.c_str(), "analyzing");
        
        VariableTypeFix fix;
        fix.var_idx = var_idx;
        fix.var_name = var.name;
        fix.is_argument = var.is_arg_var();
        
        // Infer type for this variable
        TypeConfidence confidence = TypeConfidence::Low;
        tinfo_t inferred_type = infer_variable_type(cfunc, var_idx, confidence);
        
        if (inferred_type.empty()) {
            fix.skip_reason = "No type inferred";
            result.variable_fixes.push_back(std::move(fix));
            continue;
        }
        
        // Compare types
        fix.comparison = compare_types(var.type(), inferred_type, confidence);
        
        if (fix.comparison.difference != TypeDifference::None) {
            result.differences_found++;
        }
        
        // Check if we should apply the fix
        if (!should_apply_fix(fix.comparison)) {
            if (fix.comparison.difference != TypeDifference::None) {
                fix.skip_reason.sprnt("Below threshold (%s)", 
                    type_difference_str(fix.comparison.difference));
                result.fixes_skipped++;
            }
            result.variable_fixes.push_back(std::move(fix));
            continue;
        }
        
        // Check if we should synthesize a structure
        if (config_.synthesize_structures && 
            (fix.comparison.primary_reason == DifferenceReason::VoidPointerToTyped ||
             fix.comparison.primary_reason == DifferenceReason::StructureDetected ||
             fix.comparison.primary_reason == DifferenceReason::VTableDetected ||
             fix.comparison.primary_reason == DifferenceReason::GenericToStructPtr)) {
            
            auto struct_tid = try_synthesize_structure(cfunc, var_idx);
            if (struct_tid) {
                fix.synthesized_struct_tid = *struct_tid;
                result.structures_synthesized++;
                
                // Get the struct type
                tinfo_t struct_type;
                if (struct_type.get_type_by_tid(*struct_tid)) {
                    qstring struct_name;
                    struct_type.get_type_name(&struct_name);
                    if (!struct_name.empty() && struct_name.find("_window") != qstring::npos) {
                        fix.skip_reason = "Window view kept local";
                        result.fixes_skipped++;
                        result.variable_fixes.push_back(std::move(fix));
                        continue;
                    }

                    // Create pointer to the synthesized struct
                    inferred_type.create_ptr(struct_type);
                }
            }
        }
        
        // Apply the fix if not dry run
        if (!config_.dry_run) {
            report_progress(var_idx, var.name.c_str(), "applying fix");
            
            PropagationResult prop_result;
            if (apply_fix(cfunc, var_idx, inferred_type, 
                         config_.propagate_fixes ? &prop_result : nullptr)) {
                fix.applied = true;
                fix.propagation = std::move(prop_result);
                result.fixes_applied++;
                result.propagated_count += fix.propagation.success_count;
            } else {
                fix.skip_reason = "Failed to apply type";
                result.fixes_skipped++;
            }
        } else {
            fix.skip_reason = "Dry run mode";
            result.fixes_skipped++;
        }
        
        result.variable_fixes.push_back(std::move(fix));
    }

    qvector<qstring> missing_arg_warnings = collect_missing_argument_warnings(cfunc);
    for (auto& warning : missing_arg_warnings) {
        result.warnings.push_back(std::move(warning));
    }

    for (auto& diagnostic : diagnostics_) {
        result.diagnostics.push_back(std::move(diagnostic));
    }
    diagnostics_.clear();
    
    return result;
}

inline TypeComparisonResult TypeFixer::analyze_variable(
    cfunc_t* cfunc,
    int var_idx)
{
    TypeComparisonResult result;
    
    if (!cfunc) return result;
    
    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars || var_idx < 0 || static_cast<size_t>(var_idx) >= lvars->size()) {
        return result;
    }
    
    lvar_t& var = lvars->at(var_idx);
    
    // Infer type for this variable
    TypeConfidence confidence = TypeConfidence::Low;
    tinfo_t inferred_type = infer_variable_type(cfunc, var_idx, confidence);
    
    if (inferred_type.empty()) {
        result.original_type = var.type();
        result.description = "Could not infer type";
        return result;
    }
    
    return compare_types(var.type(), inferred_type, confidence);
}

inline tinfo_t TypeFixer::infer_variable_type(cfunc_t* cfunc, int var_idx, TypeConfidence& out_confidence) {
    tinfo_t direct = infer_variable_type_direct(cfunc, var_idx, out_confidence);

#ifndef STRUCTOR_TESTING
    TypeConfidence overlap_confidence = TypeConfidence::Low;
    tinfo_t overlap = infer_overlapped_variable_type(cfunc, var_idx, overlap_confidence);

    if (overlap.empty()) {
        return direct;
    }

    if (direct.empty() || is_default_type(direct)) {
        out_confidence = overlap_confidence;
        return overlap;
    }

    if (!is_default_type(overlap)
     && overlap_confidence >= out_confidence
     && type_priority_score(overlap) > type_priority_score(direct)) {
        out_confidence = overlap_confidence;
        return overlap;
    }
#endif

    return direct;
}

inline tinfo_t TypeFixer::infer_variable_type_direct(cfunc_t* cfunc, int var_idx, TypeConfidence& out_confidence) {
    tinfo_t result;
    out_confidence = TypeConfidence::Low;
    
    if (!cfunc) return result;
    
    // Collect access patterns for this variable
    SynthOptions opts = Config::instance().options();
    opts.min_accesses = 1;  // Be more lenient for type fixing
    
    AccessCollector collector(opts);
    AccessPattern pattern = collector.collect(cfunc, var_idx);
    
    if (pattern.accesses.empty()) {
        return result;
    }
    
    // Analyze access patterns to determine type
    bool has_pointer_access = false;
    bool has_struct_access = false;
    bool has_vtable_access = false;
    
    tinfo_t best_type;
    int best_priority = 0;
    
    for (const auto& access : pattern.accesses) {
        // Check for vtable pattern
        if (access.is_vtable_access) {
            has_vtable_access = true;
        }
        
        // Check for function pointer access
        // Check for pointer dereferences (indicates this is a pointer)
        if (access.offset >= 0) {
            has_pointer_access = true;
        }
        
        // Use access inferred type if available
        if (!access.inferred_type.empty()) {
            int priority = type_priority_score(access.inferred_type);
            if (priority > best_priority) {
                best_priority = priority;
                best_type = access.inferred_type;
            }
        }
    }
    
    // Determine confidence based on access count and patterns
    if (pattern.accesses.size() >= 5) {
        out_confidence = TypeConfidence::High;
    } else if (pattern.accesses.size() >= 2) {
        out_confidence = TypeConfidence::Medium;
    } else {
        out_confidence = TypeConfidence::Low;
    }
    
    // If we have multiple field accesses, this is likely a structure pointer
    if (has_pointer_access && pattern.accesses.size() >= 2) {
        has_struct_access = true;
        out_confidence = TypeConfidence::High;
    }
    
    // Return inferred type
    if (has_struct_access || has_vtable_access) {
        // Return void* as a placeholder - actual struct will be synthesized
        tinfo_t void_type;
        void_type.create_simple_type(BTF_VOID);
        result.create_ptr(void_type);
        out_confidence = TypeConfidence::High;
    } else if (!best_type.empty()) {
        result = best_type;
    } else if (has_pointer_access) {
        // Generic pointer
        tinfo_t void_type;
        void_type.create_simple_type(BTF_VOID);
        result.create_ptr(void_type);
    }
    
    return result;
}

inline tinfo_t TypeFixer::infer_overlapped_variable_type(cfunc_t* cfunc, int var_idx, TypeConfidence& out_confidence) {
    tinfo_t best_type;
    out_confidence = TypeConfidence::Low;

#ifndef STRUCTOR_TESTING
    if (!cfunc) {
        return best_type;
    }

    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars || var_idx < 0 || static_cast<size_t>(var_idx) >= lvars->size()) {
        return best_type;
    }

    const lvar_t& target = lvars->at(static_cast<size_t>(var_idx));
    int best_score = -1;
    int best_source_idx = -1;

    for (size_t i = 0; i < lvars->size(); ++i) {
        if (static_cast<int>(i) == var_idx) {
            continue;
        }

        const lvar_t& other = lvars->at(i);
        if (!target.has_common(other)) {
            continue;
        }
        if (!detail::lvars_share_exact_storage(target, other)) {
            continue;
        }

        tinfo_t candidate_type;
        TypeConfidence candidate_confidence = TypeConfidence::Low;

        if (!other.type().empty()
         && !is_default_type(other.type())
         && detail::type_matches_lvar_width(other.type(), target)) {
            candidate_type = other.type();
            candidate_confidence = other.has_user_type() ? TypeConfidence::High
                                                         : TypeConfidence::Medium;
        }

        TypeConfidence inferred_confidence = TypeConfidence::Low;
        tinfo_t inferred_type = infer_variable_type_direct(cfunc, static_cast<int>(i), inferred_confidence);
        if (!inferred_type.empty()
         && !is_default_type(inferred_type)
         && detail::type_matches_lvar_width(inferred_type, target)
         && (candidate_type.empty()
          || inferred_confidence > candidate_confidence
          || type_priority_score(inferred_type) > type_priority_score(candidate_type))) {
            candidate_type = inferred_type;
            candidate_confidence = inferred_confidence;
        }

        if (candidate_type.empty()) {
            continue;
        }

        int score = static_cast<int>(candidate_confidence) * 100
                  + type_priority_score(candidate_type)
                  + (other.has_user_type() ? 25 : 0);
        if (score > best_score) {
            best_score = score;
            best_type = candidate_type;
            out_confidence = candidate_confidence;
            best_source_idx = static_cast<int>(i);
        }
    }

    if (!best_type.empty() && best_source_idx >= 0) {
        const lvar_t& source = lvars->at(static_cast<size_t>(best_source_idx));
        qstring func_name;
        get_func_name(&func_name, cfunc->entry_ea);

        qstring type_str;
        best_type.print(&type_str);

        qstring target_loc = detail::describe_lvar_location(target);
        qstring source_loc = detail::describe_lvar_location(source);

        qstring target_name = target.name;
        if (target_name.empty()) {
            target_name.sprnt("var#%d", var_idx);
        }

        qstring source_name = source.name;
        if (source_name.empty()) {
            source_name.sprnt("var#%d", best_source_idx);
        }

        qstring diagnostic;
        diagnostic.sprnt(
            "overlap recovery in %s selected %s for var #%d (%s @ %s) from var #%d (%s @ %s)",
            func_name.c_str(),
            type_str.c_str(),
            var_idx,
            target_name.c_str(),
            target_loc.c_str(),
            best_source_idx,
            source_name.c_str(),
            source_loc.c_str());
        diagnostics_.push_back(diagnostic);

        if (Config::instance().options().debug_mode) {
            msg("Structor: diagnostic: %s\n", diagnostic.c_str());
        }
    }
#else
    (void) cfunc;
    (void) var_idx;
#endif

    return best_type;
}

inline qvector<qstring> TypeFixer::collect_missing_argument_warnings(cfunc_t* cfunc) {
    qvector<qstring> warnings;

#ifndef STRUCTOR_TESTING
    if (!cfunc) {
        return warnings;
    }

    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars) {
        return warnings;
    }

    qstring func_name;
    get_func_name(&func_name, cfunc->entry_ea);

    struct CallerTypeSummary {
        tinfo_t type;
        TypeConfidence confidence = TypeConfidence::Low;
        int support = 0;
        int typed_callers = 0;
        int conflicts = 0;
    };

    std::unordered_map<ea_t, cfuncptr_t> cfunc_cache;
    std::unordered_map<uint64_t, std::pair<tinfo_t, TypeConfidence>> type_cache;

    auto get_cached_cfunc = [&cfunc_cache](ea_t func_ea) -> cfuncptr_t {
        auto it = cfunc_cache.find(func_ea);
        if (it != cfunc_cache.end()) {
            return it->second;
        }

        cfuncptr_t decompiled = utils::get_cfunc(func_ea);
        cfunc_cache.emplace(func_ea, decompiled);
        return decompiled;
    };

    auto get_cached_direct_type = [this, &type_cache](cfunc_t* owner, int owner_var_idx) {
        TypeConfidence confidence = TypeConfidence::Low;
        if (!owner) {
            return std::make_pair(tinfo_t(), confidence);
        }

        uint64_t key = (static_cast<uint64_t>(owner->entry_ea) << 32)
                     | static_cast<uint32_t>(owner_var_idx);
        auto it = type_cache.find(key);
        if (it != type_cache.end()) {
            return it->second;
        }

        tinfo_t inferred = infer_variable_type_direct(owner, owner_var_idx, confidence);
        auto inserted = type_cache.emplace(key, std::make_pair(inferred, confidence));
        return inserted.first->second;
    };

    CrossFunctionAnalyzer analyzer;

    for (size_t i = 0; i < lvars->size(); ++i) {
        const lvar_t& var = lvars->at(i);
        if (var.is_arg_var() || !var.is_reg_var()) {
            continue;
        }
        if (var.is_result_var() || var.is_fake_var() || var.is_spoiled_var() || var.has_regname()) {
            continue;
        }
        if (var.is_dummy_arg()) {
            continue;
        }
        if (detail::is_var_assigned_in_function(cfunc, static_cast<int>(i))) {
            continue;
        }

        qstring display_name = var.name;
        if (display_name.empty()) {
            display_name.sprnt("var#%d", static_cast<int>(i));
        }

        qstring reg_display = detail::describe_lvar_location(var);
        std::string reg_family = detail::normalize_register_family(reg_display);

        TypeConfidence local_confidence = TypeConfidence::Low;
        tinfo_t local_type = infer_variable_type_direct(cfunc, static_cast<int>(i), local_confidence);
        if (local_type.empty() && !var.type().empty()) {
            local_type = var.type();
        }
        if (local_type.empty()) {
            local_type = detail::make_width_fallback_type(var.width);
        }

        detail::RegisterHandoffSummary reg_handoff =
            detail::collect_register_handoff_summary(cfunc, var);
        bool best_is_register_handoff = false;

        qvector<int> candidate_param_indices = detail::candidate_param_indices_for_register(reg_family);

        int best_param_idx = -1;
        int best_score = 0;
        CallerTypeSummary best_summary;

        if (reg_handoff.support > 0) {
            if (!local_type.empty()) {
                if (reg_handoff.type.empty()) {
                    reg_handoff.type = local_type;
                    reg_handoff.confidence = std::max(reg_handoff.confidence, local_confidence);
                } else if (detail::types_are_compatible_for_recovery(reg_handoff.type, local_type)) {
                    reg_handoff.type = resolve_type_conflict(reg_handoff.type, local_type);
                    reg_handoff.confidence = std::max(reg_handoff.confidence, local_confidence);
                } else {
                    ++reg_handoff.conflicts;
                }
            }

            best_summary.type = reg_handoff.type;
            best_summary.confidence = reg_handoff.confidence;
            best_summary.support = reg_handoff.support;
            best_summary.typed_callers = reg_handoff.typed_support;
            best_summary.conflicts = reg_handoff.conflicts;
            best_score = reg_handoff.support * 140
                      + reg_handoff.typed_support * 40
                      + static_cast<int>(reg_handoff.confidence) * 20
                      - reg_handoff.conflicts * 60;
            best_is_register_handoff = true;
        }

        for (int param_idx : candidate_param_indices) {
            auto callers = analyzer.find_callers_with_param(cfunc->entry_ea, param_idx);
            if (callers.empty()) {
                continue;
            }

            CallerTypeSummary summary;

            for (const auto& caller : callers) {
                if (caller.caller_ea == BADADDR || caller.var_idx < 0) {
                    continue;
                }

                cfuncptr_t caller_cfunc = get_cached_cfunc(caller.caller_ea);
                if (!caller_cfunc) {
                    continue;
                }

                lvars_t* caller_lvars = caller_cfunc->get_lvars();
                if (!caller_lvars || static_cast<size_t>(caller.var_idx) >= caller_lvars->size()) {
                    continue;
                }

                const lvar_t& caller_var = caller_lvars->at(static_cast<size_t>(caller.var_idx));
                tinfo_t candidate_type = caller_var.type();
                TypeConfidence candidate_confidence = caller_var.has_user_type()
                    ? TypeConfidence::High
                    : TypeConfidence::Medium;

                if (candidate_type.empty() || is_default_type(candidate_type)) {
                    auto inferred = get_cached_direct_type(caller_cfunc, caller.var_idx);
                    candidate_type = inferred.first;
                    candidate_confidence = inferred.second;
                }

                if (candidate_type.empty() || is_default_type(candidate_type)) {
                    continue;
                }

                if (caller.by_ref && !candidate_type.is_ptr() && !candidate_type.is_funcptr()) {
                    tinfo_t ptr_type;
                    ptr_type.create_ptr(candidate_type);
                    candidate_type = ptr_type;
                    candidate_confidence = std::max(candidate_confidence, TypeConfidence::Medium);
                }

                if (!detail::type_matches_lvar_width(candidate_type, var)) {
                    continue;
                }

                if (summary.type.empty()) {
                    summary.type = candidate_type;
                    summary.confidence = candidate_confidence;
                    summary.support = 1;
                    summary.typed_callers = 1;
                    continue;
                }

                if (detail::types_are_compatible_for_recovery(summary.type, candidate_type)) {
                    summary.type = resolve_type_conflict(summary.type, candidate_type);
                    summary.confidence = std::max(summary.confidence, candidate_confidence);
                    ++summary.support;
                    ++summary.typed_callers;
                } else {
                    ++summary.conflicts;
                }
            }

            if (summary.type.empty()) {
                continue;
            }

            if (!local_type.empty()) {
                if (detail::types_are_compatible_for_recovery(summary.type, local_type)) {
                    summary.type = resolve_type_conflict(summary.type, local_type);
                    summary.confidence = std::max(summary.confidence, local_confidence);
                } else {
                    ++summary.conflicts;
                }
            }

            int score = summary.support * 100
                      + summary.typed_callers * 40
                      + static_cast<int>(summary.confidence) * 20
                      - summary.conflicts * 60;
            if (!local_type.empty()) {
                score += 20;
            }

            if (score > best_score) {
                best_score = score;
                best_param_idx = param_idx;
                best_summary = summary;
                best_is_register_handoff = false;
            }
        }

        if (best_summary.type.empty() || (!best_is_register_handoff && best_param_idx < 0)) {
            continue;
        }

        qstring type_str;
        best_summary.type.print(&type_str);

        qstring warning;
        if (best_is_register_handoff) {
            warning.sprnt(
                "possible missing argument in %s: %s (%s) is populated by %d caller%s before the call; inferred type %s",
                func_name.c_str(),
                display_name.c_str(),
                reg_display.c_str(),
                best_summary.support,
                best_summary.support == 1 ? "" : "s",
                type_str.c_str());
        } else {
            warning.sprnt(
                "possible missing argument in %s: %s (%s) looks like parameter #%d with type %s from %d caller%s",
                func_name.c_str(),
                display_name.c_str(),
                reg_display.c_str(),
                best_param_idx + 1,
                type_str.c_str(),
                best_summary.support,
                best_summary.support == 1 ? "" : "s");
        }
        if (best_summary.conflicts > 0) {
            warning.cat_sprnt(
                " (%d conflicting caller inference%s)",
                best_summary.conflicts,
                best_summary.conflicts == 1 ? "" : "s");
        }
        warnings.push_back(std::move(warning));
    }
#else
    (void) cfunc;
#endif

    return warnings;
}

inline bool TypeFixer::apply_fix(
    cfunc_t* cfunc,
    int var_idx,
    const tinfo_t& new_type,
    PropagationResult* out_propagation)
{
    if (!cfunc || new_type.empty()) return false;
    
    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars || var_idx < 0 || static_cast<size_t>(var_idx) >= lvars->size()) {
        return false;
    }
    
    lvar_t& var = lvars->at(var_idx);
    
    // Create pointer type if needed
    tinfo_t applied_type = new_type;
    if (!applied_type.is_ptr() && !applied_type.is_funcptr()) {
        // For structure types, create a pointer
        if (applied_type.is_struct()) {
            applied_type.create_ptr(new_type);
        }
    }
    
    // Apply the type
    lvar_saved_info_t lsi;
    lsi.ll = var;
    lsi.type = applied_type;
    
    if (!modify_user_lvar_info(cfunc->entry_ea, MLI_TYPE, lsi)) {
        return false;
    }
    
    // Update local copy
    var.set_lvar_type(applied_type);
    
    // Propagate if requested
    bool allow_propagation = config_.propagate_fixes;
    if (allow_propagation && applied_type.is_ptr()) {
        tinfo_t pointed = applied_type.get_pointed_object();
        qstring pointed_name;
        pointed.get_type_name(&pointed_name);
        if (!pointed_name.empty() && pointed_name.find("_window") != qstring::npos) {
            allow_propagation = false;
        }
    }

    if (out_propagation && allow_propagation) {
        SynthOptions opts = Config::instance().options();
        opts.max_propagation_depth = config_.max_propagation_depth;
        TypePropagator propagator(opts);
        *out_propagation = propagator.propagate(
            cfunc->entry_ea,
            var_idx,
            applied_type,
            PropagationDirection::Both);
    }
    
    return true;
}

inline bool TypeFixer::should_analyze(cfunc_t* cfunc, int var_idx) {
    if (!cfunc) return false;
    
    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars || var_idx < 0 || static_cast<size_t>(var_idx) >= lvars->size()) {
        return false;
    }
    
    lvar_t& var = lvars->at(var_idx);
    
    // Check argument/local filter
    if (var.is_arg_var() && !config_.fix_arguments) {
        return false;
    }
    if (!var.is_arg_var() && !config_.fix_locals) {
        return false;
    }
    
    // Check variable name filter
    if (!config_.variable_filter.empty()) {
        if (var.name.find(config_.variable_filter.c_str()) == qstring::npos) {
            return false;
        }
    }
    
    return true;
}

inline bool TypeFixer::should_apply_fix(const TypeComparisonResult& comparison) {
    // Check difference level
    if (comparison.difference < config_.min_auto_fix_level) {
        return false;
    }
    
    // Check confidence
    if (comparison.confidence < config_.min_confidence && !config_.force_apply) {
        return false;
    }
    
    // Check reason filters
    if (!config_.should_auto_fix(comparison.primary_reason)) {
        return false;
    }
    
    return true;
}

inline std::optional<tid_t> TypeFixer::try_synthesize_structure(
    cfunc_t* cfunc,
    int var_idx)
{
    if (!cfunc) return std::nullopt;
    
    // Use the existing synthesis infrastructure
    SynthOptions opts = Config::instance().options();
    opts.interactive_mode = false;
    opts.auto_open_struct = false;
    opts.highlight_changes = false;
    
    AccessCollector collector(opts);
    AccessPattern pattern = collector.collect(cfunc, var_idx);
    
    if (pattern.accesses.empty() || 
        static_cast<int>(pattern.access_count()) < opts.min_accesses) {
        return std::nullopt;
    }
    
    // Synthesize structure
    LayoutSynthesizer synthesizer(opts);
    SynthesisResult synth_result = synthesizer.synthesize(pattern, opts);
    
    if (synth_result.structure.fields.empty()) {
        return std::nullopt;
    }
    
    // Persist to IDB
    StructurePersistence persistence(opts);
    tid_t struct_tid = persistence.create_struct(synth_result.structure);
    
    return struct_tid != BADADDR ? std::optional<tid_t>(struct_tid) : std::nullopt;
}

inline void TypeFixer::report_progress(int var_idx, const char* var_name, const char* status) {
    if (config_.progress_callback) {
        config_.progress_callback(var_idx, var_name, status);
    }
}

} // namespace structor
