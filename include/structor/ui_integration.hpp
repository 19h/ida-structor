#pragma once

#include "synth_types.hpp"
#include "config.hpp"
#include "utils.hpp"
#include "access_collector.hpp"
#include "layout_synthesizer.hpp"
#include "vtable_detector.hpp"
#include "type_propagator.hpp"
#include "pseudocode_rewriter.hpp"
#include "structure_persistence.hpp"

namespace structor {

/// Main action handler for structure synthesis
class SynthActionHandler : public action_handler_t {
public:
    int idaapi activate(action_activation_ctx_t* ctx) override;
    action_state_t idaapi update(action_update_ctx_t* ctx) override;
};

/// Hex-Rays callback handler
struct HexRaysHooks {
    static ssize_t idaapi callback(void* ud, hexrays_event_t event, va_list va);
};

/// UI integration - stateless functions, no singleton
namespace ui {

inline bool g_initialized = false;

/// Execute synthesis on selected variable
inline SynthResult do_synthesis(cfunc_t* cfunc, int var_idx, const SynthOptions& opts) {
    SynthResult result;

    // Step 1: Collect access patterns
    AccessCollector collector(opts);
    AccessPattern pattern = collector.collect(cfunc, var_idx);

    if (pattern.accesses.empty()) {
        return SynthResult::make_error(SynthError::NoAccessesFound,
            "No dereferences found for variable");
    }

    if (static_cast<int>(pattern.access_count()) < opts.min_accesses) {
        qstring msg;
        msg.sprnt("Only %zu accesses found (minimum: %d)", pattern.access_count(), opts.min_accesses);
        return SynthResult::make_error(SynthError::InsufficientAccesses, msg);
    }

    // Step 2: Synthesize structure layout
    LayoutSynthesizer synthesizer(opts);
    SynthesisResult synth_result = synthesizer.synthesize(pattern);
    SynthStruct synth_struct = std::move(synth_result.structure);

    result.conflicts = synth_result.conflicts;

    if (synth_struct.fields.empty()) {
        return SynthResult::make_error(SynthError::TypeCreationFailed,
            "Failed to synthesize structure fields");
    }

    // Step 3: Detect vtable if enabled
    if (opts.vtable_detection && pattern.has_vtable) {
        VTableDetector vtable_detector(opts);
        auto vtable = vtable_detector.detect(pattern, cfunc);
        if (vtable) {
            synth_struct.vtable = std::move(vtable);
        }
    }

    // Step 4: Persist structure to IDB
    StructurePersistence persistence(opts);
    tid_t struct_tid = persistence.create_struct(synth_struct);

    if (struct_tid == BADADDR) {
        return SynthResult::make_error(SynthError::TypeCreationFailed,
            "Failed to create structure in IDB");
    }

    result.struct_tid = struct_tid;
    result.fields_created = synth_struct.field_count();

    if (synth_struct.has_vtable()) {
        result.vtable_tid = synth_struct.vtable->tid;
        result.vtable_slots = synth_struct.vtable->slot_count();
    }

    // Step 5: Apply type to variable and propagate
    tinfo_t struct_type;
    if (struct_type.get_type_by_tid(struct_tid)) {
        TypePropagator propagator(opts);

        // Apply locally first
        if (propagator.apply_type(cfunc, var_idx, struct_type)) {
            result.propagated_to.push_back(cfunc->entry_ea);
        }

        // Propagate if enabled
        if (opts.auto_propagate) {
            PropagationResult prop_result = propagator.propagate(
                cfunc->entry_ea,
                var_idx,
                struct_type,
                PropagationDirection::Both);

            for (const auto& site : prop_result.sites) {
                if (site.success) {
                    result.propagated_to.push_back(site.func_ea);
                } else {
                    result.failed_sites.push_back(site.func_ea);
                }
            }
        }
    }

    // Step 6: Store synthesized struct in result
    result.synthesized_struct = std::make_unique<SynthStruct>(std::move(synth_struct));
    result.error = SynthError::Success;

    return result;
}

/// Show conflict resolution dialog
inline bool show_conflict_dialog(const qvector<AccessConflict>& conflicts) {
    qstring msg_text;
    msg_text = "The following access conflicts were detected:\n\n";

    for (const auto& conflict : conflicts) {
        msg_text.cat_sprnt("Offset 0x%X: %s\n", static_cast<unsigned>(conflict.offset), conflict.description.c_str());
        for (const auto& acc : conflict.conflicting_accesses) {
            msg_text.cat_sprnt("  - Size %u at EA 0x%llX\n", acc.size, static_cast<unsigned long long>(acc.insn_ea));
        }
        msg_text.append("\n");
    }

    msg_text.append("These will be marked as union candidates.\nContinue with synthesis?");

    return ask_yn(ASKBTN_YES, "%s", msg_text.c_str()) == ASKBTN_YES;
}

/// Show synthesis result summary
inline void show_result_dialog(const SynthResult& result) {
    qstring msg_text;

    if (result.success()) {
        msg_text.sprnt("Structure synthesis completed successfully.\n\n");
        msg_text.cat_sprnt("Structure TID: 0x%llX\n", static_cast<unsigned long long>(result.struct_tid));
        msg_text.cat_sprnt("Fields created: %d\n", result.fields_created);

        if (result.vtable_tid != BADADDR) {
            msg_text.cat_sprnt("VTable TID: 0x%llX\n", static_cast<unsigned long long>(result.vtable_tid));
            msg_text.cat_sprnt("VTable slots: %d\n", result.vtable_slots);
        }

        if (!result.propagated_to.empty()) {
            msg_text.cat_sprnt("\nType propagated to %zu functions.\n", result.propagated_to.size());
        }
    } else {
        msg_text.sprnt("Structure synthesis failed.\n\n");
        msg_text.cat_sprnt("Error: %s\n", synth_error_str(result.error));
        if (!result.error_message.empty()) {
            msg_text.cat_sprnt("Details: %s\n", result.error_message.c_str());
        }
    }

    info("%s", msg_text.c_str());
}

/// Open structure view for synthesized type
inline void open_struct_view(tid_t tid) {
    open_loctypes_window(static_cast<int>(tid));
}

/// Execute synthesis on selected variable in vdui
inline SynthResult execute_synthesis(vdui_t* vdui) {
    if (!vdui || !vdui->cfunc) {
        return SynthResult::make_error(SynthError::InternalError, "No decompilation available");
    }

    // Get variable at cursor
    auto [var, var_idx] = utils::get_var_at_cursor(vdui);
    if (!var || var_idx < 0) {
        return SynthResult::make_error(SynthError::NoVariableSelected, "No variable at cursor position");
    }

    // Check if variable already has a structure type
    const SynthOptions& opts = Config::instance().options();
    tinfo_t var_type = var->type();

    if (!var_type.empty() && var_type.is_ptr()) {
        tinfo_t pointed = var_type.get_pointed_object();
        if (!pointed.empty() && pointed.is_struct()) {
            if (opts.interactive_mode) {
                if (!utils::ask_yes_no("Variable already has a structure type. Retype?")) {
                    return SynthResult::make_error(SynthError::InvalidVariable, "User cancelled retype");
                }
            }
        }
    }

    // Perform synthesis
    SynthResult result = do_synthesis(vdui->cfunc, var_idx, opts);

    // Handle conflicts
    if (result.has_conflicts() && opts.interactive_mode) {
        if (!show_conflict_dialog(result.conflicts)) {
            return SynthResult::make_error(SynthError::ConflictingAccesses, "User cancelled due to conflicts");
        }
    }

    // Show result in interactive mode
    if (result.success()) {
        if (opts.auto_open_struct && result.struct_tid != BADADDR) {
            open_struct_view(result.struct_tid);
        }

        // Refresh pseudocode view
        vdui->refresh_view(true);

        if (opts.highlight_changes && result.synthesized_struct) {
            PseudocodeRewriter rewriter(opts);
            RewriteResult rw_result = rewriter.rewrite(vdui->cfunc, var_idx, *result.synthesized_struct);
            rewriter.highlight_transforms(vdui, rw_result);
        }

        msg("Structor: Created %s with %d fields",
            result.synthesized_struct ? result.synthesized_struct->name.c_str() : "<unknown>",
            result.fields_created);

        if (result.vtable_slots > 0) {
            msg(", %d vtable slots", result.vtable_slots);
        }

        msg("\n");
    }

    return result;
}

/// Initialize UI hooks and register actions
inline bool initialize(SynthActionHandler* handler) {
    if (g_initialized) return true;

    // Register action
    const action_desc_t action_desc = ACTION_DESC_LITERAL(
        ACTION_NAME,
        ACTION_LABEL,
        handler,
        Config::instance().hotkey(),
        "Create structure from access patterns",
        -1
    );

    if (!register_action(action_desc)) {
        msg("Structor: Failed to register action\n");
        return false;
    }

    // Install Hex-Rays callback
    if (!install_hexrays_callback(HexRaysHooks::callback, nullptr)) {
        msg("Structor: Failed to install Hex-Rays callback\n");
        unregister_action(ACTION_NAME);
        return false;
    }

    g_initialized = true;
    return true;
}

/// Cleanup UI hooks and unregister actions
inline void shutdown() {
    if (!g_initialized) return;

    remove_hexrays_callback(HexRaysHooks::callback, nullptr);
    unregister_action(ACTION_NAME);

    g_initialized = false;
}

} // namespace ui

// ============================================================================
// SynthActionHandler Implementation
// ============================================================================

inline int SynthActionHandler::activate(action_activation_ctx_t* ctx) {
    vdui_t* vdui = get_widget_vdui(ctx->widget);
    if (!vdui) {
        msg("Structor: No pseudocode view active\n");
        return 0;
    }

    SynthResult result = ui::execute_synthesis(vdui);

    if (!result.success()) {
        msg("Structor: %s\n", synth_error_str(result.error));
        if (!result.error_message.empty()) {
            msg("  Details: %s\n", result.error_message.c_str());
        }
    }

    return 1;
}

inline action_state_t SynthActionHandler::update(action_update_ctx_t* ctx) {
    vdui_t* vdui = get_widget_vdui(ctx->widget);
    if (!vdui || !vdui->cfunc) {
        return AST_DISABLE;
    }

    if (!vdui->item.is_citem()) {
        return AST_DISABLE;
    }

    const citem_t* item = vdui->item.it;
    if (!item) {
        return AST_DISABLE;
    }

    const cexpr_t* expr = nullptr;
    if (item->is_expr()) {
        expr = static_cast<const cexpr_t*>(item);
    }

    while (expr) {
        if (expr->op == cot_var) {
            return AST_ENABLE;
        }
        if (expr->op == cot_cast || expr->op == cot_ref ||
            expr->op == cot_ptr || expr->op == cot_memptr ||
            expr->op == cot_idx) {
            expr = expr->x;
        } else {
            break;
        }
    }

    return AST_DISABLE;
}

// ============================================================================
// HexRaysHooks Implementation
// ============================================================================

inline ssize_t HexRaysHooks::callback(void* ud, hexrays_event_t event, va_list va) {
    switch (event) {
        case hxe_populating_popup: {
            TWidget* widget = va_arg(va, TWidget*);
            TPopupMenu* popup = va_arg(va, TPopupMenu*);
            vdui_t* vdui = va_arg(va, vdui_t*);

            if (vdui && vdui->cfunc) {
                auto [var, var_idx] = utils::get_var_at_cursor(vdui);
                if (var && var_idx >= 0) {
                    attach_action_to_popup(widget, popup, ACTION_NAME);
                }
            }
            break;
        }

        case hxe_double_click:
            break;

        default:
            break;
    }

    return 0;
}

} // namespace structor
