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

#include <functional>

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
    
    /// Infer type for a variable by analyzing access patterns
    [[nodiscard]] tinfo_t infer_variable_type(cfunc_t* cfunc, int var_idx, TypeConfidence& out_confidence);
    
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
    bool has_funcptr_access = false;
    
    tinfo_t best_type;
    int best_priority = 0;
    
    for (const auto& access : pattern.accesses) {
        // Check for vtable pattern
        if (access.is_vtable_access) {
            has_vtable_access = true;
        }
        
        // Check for function pointer access
        if (access.semantic_type == SemanticType::FunctionPointer ||
            access.access_type == AccessType::Call) {
            has_funcptr_access = true;
        }
        
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
