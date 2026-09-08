#include "structor/z3/type_applicator.hpp"
#include "structor/utils.hpp"

#ifndef STRUCTOR_TESTING
#include <pro.h>
#include <kernwin.hpp>
#include <funcs.hpp>
#include <name.hpp>
#endif

namespace structor::z3 {

namespace {

[[nodiscard]] std::optional<int> resolve_lvar_locator(
    cfunc_t* cfunc,
    const lvar_locator_t& locator)
{
    if (cfunc == nullptr) {
        return std::nullopt;
    }
    lvars_t* lvars = cfunc->get_lvars();
    if (lvars == nullptr || lvars->find(locator) == nullptr) {
        return std::nullopt;
    }
    for (size_t i = 0; i < lvars->size(); ++i) {
        if (static_cast<const lvar_locator_t&>(lvars->at(i)) == locator) {
            return static_cast<int>(i);
        }
    }
    return std::nullopt;
}

} // namespace

// ============================================================================
// TypeApplicationResult implementation
// ============================================================================

qstring TypeApplicationResult::summary() const {
    qstring result;
    result.sprnt("Type Application Results:\n");
    if (!error_message.empty()) {
        result.cat_sprnt("  Error: %s\n", error_message.c_str());
    }
    result.cat_sprnt("  Total variables: %u\n", total_variables);
    result.cat_sprnt("  Applied: %u\n", applied_count);
    result.cat_sprnt("  Failed: %u\n", failed_count);
    result.cat_sprnt("  Skipped: %u\n", skipped_count);
    
    if (propagated_count > 0) {
        result.cat_sprnt("  Propagated: %u\n", propagated_count);
    }
    
    if (!applied.empty()) {
        result.cat_sprnt("\nApplied types:\n");
        for (const auto& a : applied) {
            qstring type_str = a.inferred.to_string();
            result.cat_sprnt("  %s (var %d): %s\n", 
                            a.var_name.c_str(), a.var_idx, type_str.c_str());
        }
    }
    
    if (!failed.empty()) {
        result.cat_sprnt("\nFailed types:\n");
        for (const auto& f : failed) {
            result.cat_sprnt("  %s (var %d): %s\n",
                            f.var_name.c_str(), f.var_idx, f.reason.c_str());
        }
    }
    
    if (!skipped.empty() && skipped.size() <= 10) {
        result.cat_sprnt("\nSkipped:\n");
        for (const auto& s : skipped) {
            result.cat_sprnt("  %s (var %d): %s\n",
                            s.var_name.c_str(), s.var_idx, s.reason.c_str());
        }
    } else if (!skipped.empty()) {
        result.cat_sprnt("\nSkipped: %zu variables (too many to list)\n", skipped.size());
    }
    
    return result;
}

// ============================================================================
// TypeApplicator implementation
// ============================================================================

TypeApplicator::TypeApplicator(const TypeApplicationConfig& config)
    : config_(config)
    , propagator_(Config::instance().options())
{
}

TypeApplicationResult TypeApplicator::apply(
    cfunc_t* cfunc,
    const FunctionTypeInferenceResult& inference_result)
{
    TypeApplicationResult result;
    last_signature_rollback_failed_ = false;

    if (!inference_result.success) {
        result.func_ea = cfunc ? cfunc->entry_ea : BADADDR;
        if (inference_result.error_message.empty()) {
            result.error_message = "type inference result is not successful";
        } else {
            result.error_message = inference_result.error_message;
        }
        return result;
    }

    if (!cfunc) {
        result.error_message = "null cfunc";
        return result;
    }
    
    result.func_ea = cfunc->entry_ea;
    if (result.func_ea == BADADDR ||
        inference_result.func_ea != result.func_ea) {
        result.error_message = "type inference result belongs to a different or unknown function";
        return result;
    }
    
    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars) {
        return result;
    }
    
    result.total_variables = static_cast<unsigned>(inference_result.local_types.size());
    result.applied.reserve(inference_result.local_types.size());
    result.failed.reserve(inference_result.local_types.size());
    result.skipped.reserve(inference_result.local_types.size());

    std::vector<TypeApplicationResult::AppliedType> prepared_applied;
    std::vector<std::optional<lvar_locator_t>> stable_locators;
    prepared_applied.reserve(inference_result.local_types.size());
    stable_locators.reserve(inference_result.local_types.size());
    for (const auto& ivt : inference_result.local_types) {
        TypeApplicationResult::AppliedType prepared;
        prepared.var_idx = ivt.var_idx;
        prepared.var_name = ivt.var_name;
        prepared.inferred = ivt.type;
        if (ivt.may_apply_model_value(config_.allow_model_candidates))
            prepared.applied = ivt.type.to_tinfo();
        prepared.confidence = ivt.confidence;
        prepared_applied.push_back(std::move(prepared));
        if (ivt.var_idx >= 0 &&
            static_cast<size_t>(ivt.var_idx) < lvars->size()) {
            stable_locators.emplace_back(
                static_cast<const lvar_locator_t&>(
                    lvars->at(static_cast<size_t>(ivt.var_idx))));
        } else {
            stable_locators.emplace_back(std::nullopt);
        }
    }

    // Apply each inferred type
    std::size_t inference_index = 0;
    try {
    for (const auto& ivt : inference_result.local_types) {
        qstring reason;
        if (!ivt.may_apply_model_value(config_.allow_model_candidates)) {
            TypeApplicationResult::SkippedType skipped;
            skipped.var_idx = ivt.var_idx;
            skipped.var_name = ivt.var_name;
            skipped.reason = ivt.evidence_query_bounds
                ? "selected type has only bounded-domain model evidence"
                : "selected type is not determined by the hard constraints";
            result.skipped.push_back(std::move(skipped));
            ++result.skipped_count;
            ++inference_index;
            continue;
        }
        cfuncptr_t current_cfunc = utils::get_cfunc(result.func_ea);
        const auto current_var_idx = stable_locators[inference_index].has_value()
            ? resolve_lvar_locator(
                current_cfunc, *stable_locators[inference_index])
            : std::nullopt;

        // Check if we should apply this type
        if (!current_cfunc || !current_var_idx.has_value()) {
            reason = "stable variable locator no longer resolves";
            TypeApplicationResult::FailedType failed;
            failed.var_idx = ivt.var_idx;
            failed.var_name = ivt.var_name;
            failed.inferred = ivt.type;
            failed.reason = reason;
            result.failed.push_back(std::move(failed));
            ++result.failed_count;
            result.incomplete = result.incomplete ||
                stable_locators[inference_index].has_value();
            ++inference_index;
            continue;
        }
        if (!should_apply(
                current_cfunc, *current_var_idx,
                ivt.type, ivt.confidence, &reason)) {
            TypeApplicationResult::SkippedType skipped;
            skipped.var_idx = ivt.var_idx;
            skipped.var_name = ivt.var_name;
            skipped.reason = reason;
            result.skipped.push_back(std::move(skipped));
            result.skipped_count++;
            ++inference_index;
            continue;
        }
        
        // Try to apply the type
        bool success = apply_variable(
            current_cfunc, *current_var_idx,
            ivt.type, ivt.confidence, &reason);
        
        if (success) {
            result.applied.push_back(
                std::move(prepared_applied[inference_index]));
            result.applied_count++;
            
            report_application(ivt.var_idx, ivt.var_name.c_str(), true, "applied");
        } else {
            TypeApplicationResult::FailedType failed;
            failed.var_idx = ivt.var_idx;
            failed.var_name = ivt.var_name;
            failed.inferred = ivt.type;
            failed.reason = reason;
            result.failed.push_back(std::move(failed));
            result.failed_count++;
            
            report_application(ivt.var_idx, ivt.var_name.c_str(), false, reason.c_str());
        }
        ++inference_index;
    }
    } catch (...) {
        result.incomplete = true;
        try {
            result.error_message =
                "type application stopped after an internal exception";
        } catch (...) {}
    }
    
    // Apply function signature if configured
    const bool has_signature_inference =
        inference_result.return_type.has_value() ||
        !inference_result.param_types.empty();
    cfuncptr_t post_apply_cfunc = utils::get_cfunc(result.func_ea);
    if (!result.incomplete && config_.apply_signatures &&
        has_signature_inference) {
        result.signature_requested = true;
        result.signature_applied = post_apply_cfunc &&
            apply_signature(post_apply_cfunc, inference_result);
        result.signature_failed = !result.signature_applied;
        result.signature_rollback_failed =
            last_signature_rollback_failed_;
        if (result.signature_failed) {
            result.error_message = "failed to apply inferred function signature";
        }
    }
    
    // Refresh decompiler if configured
    if (config_.force_refresh &&
        (result.applied_count > 0 || result.signature_applied) &&
        post_apply_cfunc) {
        refresh_decompiler(post_apply_cfunc);
    }
    
    return result;
}

bool TypeApplicator::apply_variable(
    cfunc_t* cfunc,
    int var_idx,
    const InferredType& type,
    TypeConfidence confidence,
    qstring* out_reason)
{
    if (!cfunc) {
        if (out_reason) *out_reason = "null cfunc";
        return false;
    }
    
    // Check variable bounds
    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars || var_idx < 0 || static_cast<size_t>(var_idx) >= lvars->size()) {
        if (out_reason) *out_reason = "invalid variable index";
        return false;
    }
    
    // Convert to tinfo_t
    tinfo_t ida_type = prepare_type(type, cfunc, var_idx);
    if (ida_type.empty()) {
        if (out_reason) *out_reason = "failed to convert type to tinfo_t";
        return false;
    }
    
    // Apply the type
    return apply_tinfo(cfunc, var_idx, ida_type, out_reason);
}

TypeApplicationResult TypeApplicator::apply_and_propagate(
    cfunc_t* cfunc,
    const FunctionTypeInferenceResult& inference_result)
{
    const ea_t entry_ea = cfunc ? cfunc->entry_ea : BADADDR;
    std::vector<std::pair<int, lvar_locator_t>> stable_locators;
    if (cfunc != nullptr) {
        lvars_t* lvars = cfunc->get_lvars();
        if (lvars != nullptr) {
            stable_locators.reserve(inference_result.local_types.size());
            for (const auto& inferred : inference_result.local_types) {
                if (inferred.var_idx >= 0 &&
                    static_cast<size_t>(inferred.var_idx) < lvars->size()) {
                    stable_locators.emplace_back(
                        inferred.var_idx,
                        static_cast<const lvar_locator_t&>(
                            lvars->at(static_cast<size_t>(inferred.var_idx))));
                }
            }
        }
    }
    PropagationResult combined_propagation;
    combined_propagation.sites.reserve(MAX_FIELDS);

    // First apply types locally
    TypeApplicationResult result = apply(cfunc, inference_result);
    
    if (!config_.propagate_types || result.applied_count == 0) {
        return result;
    }
    
    // Propagate each applied type
    try {
    for (const auto& applied : result.applied) {
        const auto locator_it = std::find_if(
            stable_locators.begin(), stable_locators.end(),
            [&](const auto& item) { return item.first == applied.var_idx; });
        cfuncptr_t current_cfunc = utils::get_cfunc(entry_ea);
        const auto current_var_idx =
            locator_it != stable_locators.end()
            ? resolve_lvar_locator(current_cfunc, locator_it->second)
            : std::nullopt;
        if (!current_cfunc || !current_var_idx.has_value()) {
            ++combined_propagation.failure_count;
            combined_propagation.mark_incomplete(
                "applied-variable locator no longer resolves");
            result.incomplete = true;
            continue;
        }
        PropagationResult prop = propagator_.propagate(
            entry_ea, *current_var_idx, applied.applied,
            PropagationDirection::Both);
        
        // Merge propagation results
        for (auto& site : prop.sites) {
            if (!combined_propagation.can_record_site()) {
                combined_propagation.mark_incomplete(
                    "combined propagation site limit exceeded");
                result.incomplete = true;
                break;
            }
            combined_propagation.sites.push_back(std::move(site));
        }
        combined_propagation.success_count += prop.success_count;
        combined_propagation.failure_count += prop.failure_count;
        result.propagated_count += prop.success_count;
        if (prop.incomplete) {
            result.incomplete = true;
            combined_propagation.mark_incomplete(
                prop.error_message.empty()
                    ? "nested propagation incomplete"
                    : prop.error_message.c_str());
        }
    }
    } catch (...) {
        result.incomplete = true;
        ++combined_propagation.failure_count;
        combined_propagation.mark_incomplete(
            "combined propagation raised an unexpected exception");
    }
    result.propagation = std::move(combined_propagation);
    
    return result;
}

TypeApplicationResult TypeApplicator::infer_and_apply(
    Z3Context& ctx,
    cfunc_t* cfunc,
    const TypeInferenceConfig& inference_config)
{
    TypeInferenceEngine engine(ctx, inference_config);
    FunctionTypeInferenceResult inference_result = engine.infer_function(cfunc);
    
    if (!inference_result.success) {
        TypeApplicationResult result;
        result.func_ea = cfunc ? cfunc->entry_ea : BADADDR;
        result.error_message = inference_result.error_message;
        return result;
    }
    
    if (config_.propagate_types) {
        return apply_and_propagate(cfunc, inference_result);
    } else {
        return apply(cfunc, inference_result);
    }
}

bool TypeApplicator::apply_signature(
    cfunc_t* cfunc,
    const FunctionTypeInferenceResult& inference_result)
{
    last_signature_rollback_failed_ = false;
    if (!cfunc || cfunc->entry_ea == BADADDR ||
        !inference_result.success ||
        inference_result.func_ea != cfunc->entry_ea) {
        return false;
    }
    
    // Build new function type
    tinfo_t func_type;
    if (!cfunc->get_func_type(&func_type)) {
        return false;
    }
    
    func_type_data_t ftd;
    if (!func_type.get_func_details(&ftd)) {
        return false;
    }
    
    bool modified = false;
    
    // Apply return type if inferred
    if (inference_result.return_type.has_value()) {
        tinfo_t ret = inference_result.return_type->to_tinfo();
        if (!ret.empty() && ret != ftd.rettype) {
            ftd.rettype = ret;
            modified = true;
        }
    }
    
    // Apply parameter types
    for (size_t i = 0; i < inference_result.param_types.size() && i < ftd.size(); ++i) {
        tinfo_t param = inference_result.param_types[i].to_tinfo();
        if (!param.empty() && param != ftd[i].type) {
            ftd[i].type = param;
            modified = true;
        }
    }
    
    if (!modified) {
        return true;  // Nothing to change
    }
    
    // Create new function type and apply
    tinfo_t new_func_type;
    if (!new_func_type.create_func(ftd)) {
        return false;
    }
    
    const ea_t entry_ea = cfunc->entry_ea;
    tinfo_t stored_before;
    bool had_stored_type = false;
    bool write_attempted = false;
    const auto rollback = [&]() noexcept {
        try {
            if (!had_stored_type) {
                del_tinfo(entry_ea);
                tinfo_t residual;
                const bool restored = !get_tinfo(&residual, entry_ea);
                (void)mark_cfunc_dirty(entry_ea, false);
                return restored;
            }
            if (!set_tinfo(entry_ea, &stored_before)) {
                return false;
            }
            tinfo_t restored;
            const bool restored_ok = get_tinfo(&restored, entry_ea) &&
                restored.equals_to(stored_before);
            (void)mark_cfunc_dirty(entry_ea, false);
            return restored_ok;
        } catch (...) {
            return false;
        }
    };
    const auto rollback_or_report = [&]() noexcept {
        const bool restored = rollback();
        if (!restored) {
            last_signature_rollback_failed_ = true;
            msg("Structor: CRITICAL: failed to restore function signature at 0x%llX\n",
                static_cast<unsigned long long>(entry_ea));
        }
        return restored;
    };

    try {
        had_stored_type = get_tinfo(&stored_before, entry_ea);
        write_attempted = true;
        if (!set_tinfo(entry_ea, &new_func_type)) {
            (void)rollback_or_report();
            return false;
        }
        tinfo_t observed;
        if (!get_tinfo(&observed, entry_ea) ||
            !observed.equals_to(new_func_type)) {
            (void)rollback_or_report();
            return false;
        }
        (void)mark_cfunc_dirty(entry_ea, false);
        return true;
    } catch (...) {
        if (write_attempted) {
            (void)rollback_or_report();
        }
        return false;
    }
}

void TypeApplicator::refresh_decompiler(cfunc_t* cfunc) {
    if (!cfunc) return;
    
#ifndef STRUCTOR_TESTING
    // Mark for regeneration
    mark_cfunc_dirty(cfunc->entry_ea);
    
    // If there's an active pseudocode view, refresh it
    vdui_t* vu = get_widget_vdui(find_widget("Pseudocode-A"));
    if (vu && vu->cfunc && vu->cfunc->entry_ea == cfunc->entry_ea) {
        vu->refresh_view(true);
    }
#endif
}

bool TypeApplicator::should_apply(
    cfunc_t* cfunc,
    int var_idx,
    const InferredType& type,
    TypeConfidence confidence,
    qstring* out_reason)
{
    // Check confidence threshold
    if (static_cast<int>(confidence) < static_cast<int>(config_.min_confidence)) {
        if (out_reason) {
            out_reason->sprnt("confidence too low (%d < %d)",
                            static_cast<int>(confidence),
                            static_cast<int>(config_.min_confidence));
        }
        return false;
    }
    
    // Check type categories
    if (type.is_pointer() && !config_.apply_pointer_types) {
        if (out_reason) *out_reason = "pointer types disabled";
        return false;
    }
    
    if (type.is_base() && !config_.apply_scalar_types) {
        if (out_reason) *out_reason = "scalar types disabled";
        return false;
    }
    
    // Check if unknown/bottom type
    if (type.is_unknown() || type.is_bottom()) {
        if (out_reason) *out_reason = "unknown or bottom type";
        return false;
    }
    
    // Check if variable already has a meaningful type
    if (!config_.overwrite_existing && has_meaningful_type(cfunc, var_idx)) {
        if (out_reason) *out_reason = "variable already has meaningful type";
        return false;
    }
    
    return true;
}

tinfo_t TypeApplicator::prepare_type(
    const InferredType& type,
    cfunc_t* cfunc,
    int var_idx)
{
    tinfo_t result = type.to_tinfo();
    
    // For pointer types, we don't need to wrap again
    // The to_tinfo() already produces the correct pointer type
    
    return result;
}

bool TypeApplicator::apply_tinfo(
    cfunc_t* cfunc,
    int var_idx,
    const tinfo_t& type,
    qstring* out_reason)
{
    if (!cfunc || type.empty()) {
        if (out_reason) *out_reason = "invalid cfunc or empty type";
        return false;
    }
    
    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars || var_idx < 0 || static_cast<size_t>(var_idx) >= lvars->size()) {
        if (out_reason) *out_reason = "invalid variable index";
        return false;
    }

    // Use the shared rollback-verified path. It snapshots saved-lvar state,
    // updates the cached lvar only when Hex-Rays accepts the type, synchronizes
    // affected function signatures, and restores every attempted mutation on
    // failure.
    if (!propagator_.apply_exact_type(cfunc, var_idx, type)) {
        if (out_reason) {
            *out_reason = propagator_.last_application_rollback_failed()
                ? "type application failed and rollback failed"
                : "type application failed and was rolled back";
        }
        return false;
    }

    return true;
}

bool TypeApplicator::has_meaningful_type(cfunc_t* cfunc, int var_idx) {
    if (!cfunc) return false;
    
    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars || var_idx < 0 || static_cast<size_t>(var_idx) >= lvars->size()) {
        return false;
    }
    
    const lvar_t& var = lvars->at(var_idx);
    tinfo_t type = var.type();
    
    if (type.empty()) return false;
    
    // Check if it's a generic type (void*, int, __int64, etc.)
    // These are often defaults and can be overwritten
    
    // Pointer to void is often a placeholder
    if (type.is_ptr()) {
        tinfo_t pointed = type.get_pointed_object();
        if (pointed.is_void()) {
            return false;  // void* is a placeholder
        }
    }
    
    // Check for user-defined flag
    if (var.has_user_type()) {
        return true;  // User explicitly set this type
    }
    
    // Simple integer types are often defaults
    if (type.is_scalar()) {
        // Check if it's just the default int/long type
        qstring type_str;
        type.print(&type_str);
        if (type_str == "__int64" || type_str == "int" || 
            type_str == "unsigned int" || type_str == "unsigned __int64") {
            return false;  // Likely default
        }
    }
    
    return true;  // Has a meaningful type
}

void TypeApplicator::report_application(
    int var_idx,
    const char* var_name,
    bool success,
    const char* reason)
{
    if (config_.application_callback) {
        try {
            config_.application_callback(var_idx, var_name, success, reason);
        } catch (...) {
            // Observability callbacks are not part of the mutation contract.
            // A client exception cannot invalidate already-applied types.
        }
    }
}

// ============================================================================
// Convenience functions
// ============================================================================

TypeApplicationResult infer_and_apply_types(
    cfunc_t* cfunc,
    const TypeInferenceConfig& inference_config,
    const TypeApplicationConfig& application_config)
{
    if (!cfunc) {
        return TypeApplicationResult();
    }
    
    // Create Z3 context
    Z3Context ctx;
    
    // Create applicator and run
    TypeApplicator applicator(application_config);
    return applicator.infer_and_apply(ctx, cfunc, inference_config);
}

TypeApplicationResult apply_inferred_types(
    cfunc_t* cfunc,
    const FunctionTypeInferenceResult& result,
    const TypeApplicationConfig& config)
{
    TypeApplicator applicator(config);
    return applicator.apply(cfunc, result);
}

} // namespace structor::z3
