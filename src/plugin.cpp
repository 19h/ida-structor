/// @file plugin.cpp
/// @brief Main plugin entry point for Structor

#include <structor/synth_types.hpp>
#include <structor/config.hpp>
#include <structor/ui_integration.hpp>
#include <structor/api.hpp>
#include <expr.hpp>
#include <auto.hpp>

namespace structor {

// Thread-local storage for last result info (must be defined before use)
static thread_local qstring g_last_error;
static thread_local int g_last_field_count = 0;
static thread_local tid_t g_last_vtable_tid = BADADDR;

// IDC function: structor_synthesize(func_ea, var_idx) -> tid_t
static error_t idaapi idc_structor_synthesize(idc_value_t* argv, idc_value_t* res) {
    ea_t func_ea = argv[0].vtype == VT_INT64 ? argv[0].i64 : static_cast<ea_t>(argv[0].num);
    int var_idx = static_cast<int>(argv[1].num);

    // Use non-interactive options for IDC calls
    SynthOptions opts = Config::instance().options();
    opts.interactive_mode = false;
    opts.auto_open_struct = false;
    opts.highlight_changes = false;

    SynthResult result = StructorAPI::instance().synthesize_structure(func_ea, var_idx, &opts);

    // Store results for helper functions
    g_last_error = result.error_message;
    g_last_field_count = result.fields_created;
    g_last_vtable_tid = result.vtable_tid;

    if (result.success()) {
        res->set_int64(result.struct_tid);
    } else {
        if (g_last_error.empty()) {
            g_last_error = synth_error_str(result.error);
        }
        res->set_int64(BADADDR);
    }
    return eOk;
}

// IDC function: structor_synthesize_by_name(func_ea, var_name) -> tid_t
static error_t idaapi idc_structor_synthesize_by_name(idc_value_t* argv, idc_value_t* res) {
    ea_t func_ea = argv[0].vtype == VT_INT64 ? argv[0].i64 : static_cast<ea_t>(argv[0].num);
    const char* var_name = argv[1].c_str();

    SynthResult result = StructorAPI::instance().synthesize_structure(func_ea, var_name);

    // Store results for helper functions
    g_last_error = result.error_message;
    g_last_field_count = result.fields_created;
    g_last_vtable_tid = result.vtable_tid;

    if (result.success()) {
        res->set_int64(result.struct_tid);
    } else {
        if (g_last_error.empty()) {
            g_last_error = synth_error_str(result.error);
        }
        res->set_int64(BADADDR);
    }
    return eOk;
}

// IDC function: structor_get_error() -> string
static error_t idaapi idc_structor_get_error(idc_value_t* /*argv*/, idc_value_t* res) {
    res->set_string(g_last_error);
    return eOk;
}

// IDC function: structor_get_field_count() -> long
static error_t idaapi idc_structor_get_field_count(idc_value_t* /*argv*/, idc_value_t* res) {
    res->set_long(g_last_field_count);
    return eOk;
}

// IDC function: structor_get_vtable_tid() -> tid_t
static error_t idaapi idc_structor_get_vtable_tid(idc_value_t* /*argv*/, idc_value_t* res) {
    res->set_int64(g_last_vtable_tid);
    return eOk;
}

// Argument type arrays for IDC functions
static const char args_synthesize[] = { VT_INT64, VT_LONG, 0 };
static const char args_synthesize_by_name[] = { VT_INT64, VT_STR, 0 };
static const char args_no_args[] = { 0 };

static const ext_idcfunc_t idc_funcs[] = {
    { "structor_synthesize", idc_structor_synthesize, args_synthesize, nullptr, 0, EXTFUN_BASE },
    { "structor_synthesize_by_name", idc_structor_synthesize_by_name, args_synthesize_by_name, nullptr, 0, EXTFUN_BASE },
    { "structor_get_error", idc_structor_get_error, args_no_args, nullptr, 0, EXTFUN_BASE },
    { "structor_get_field_count", idc_structor_get_field_count, args_no_args, nullptr, 0, EXTFUN_BASE },
    { "structor_get_vtable_tid", idc_structor_get_vtable_tid, args_no_args, nullptr, 0, EXTFUN_BASE },
};

static void register_idc_funcs() {
    for (const auto& f : idc_funcs) {
        add_idc_func(f);
    }
}

static void unregister_idc_funcs() {
    for (const auto& f : idc_funcs) {
        del_idc_func(f.name);
    }
}

/// Plugin descriptor - owns the action handler to ensure proper lifetime
class StructorPlugin : public plugmod_t, public event_listener_t {
public:
    StructorPlugin();
    ~StructorPlugin() override;

    bool idaapi run(size_t arg) override;
    ssize_t idaapi on_event(ssize_t code, va_list va) override;

private:
    void cleanup();
    void run_pending_auto_synth();

    SynthActionHandler action_handler_;  // Owned by plugin, passed to IDA
    bool initialized_ = false;
    bool cleaned_up_ = false;

    // Pending auto-synthesis from env var
    ea_t pending_synth_ea_ = BADADDR;
    int pending_synth_var_idx_ = 0;
    bool auto_synth_done_ = false;
};

StructorPlugin::StructorPlugin() {
    // Load configuration
    Config::instance().load();

    // Register IDC functions
    register_idc_funcs();

    // Hook UI notifications to cleanup before widget destruction
    hook_event_listener(HT_UI, this);

    // Initialize UI - pass our action handler which we own
    if (ui::initialize(&action_handler_)) {
        initialized_ = true;
        msg("Structor %s: Plugin initialized (hotkey: %s)\n",
            PLUGIN_VERSION, Config::instance().hotkey());
    } else {
        msg("Structor: Failed to initialize UI\n");
    }

    // Check for auto-synthesis env var: STRUCTOR_AUTO_SYNTH=func_ea or func_ea:var_idx
    const char* env = getenv("STRUCTOR_AUTO_SYNTH");
    if (env) {
        char* endptr = nullptr;
        pending_synth_ea_ = strtoull(env, &endptr, 0);
        if (endptr && *endptr == ':') {
            pending_synth_var_idx_ = static_cast<int>(strtol(endptr + 1, nullptr, 0));
        }
        if (pending_synth_ea_ != BADADDR) {
            // Run synthesis immediately (auto_wait() is called internally)
            run_pending_auto_synth();
        }
    }
}

void StructorPlugin::run_pending_auto_synth() {
    if (auto_synth_done_ || pending_synth_ea_ == BADADDR) return;
    auto_synth_done_ = true;

    // Wait for auto-analysis to complete
    auto_wait();

    msg("Structor: Running auto-synthesis for func=0x%llx var_idx=%d\n",
        (unsigned long long)pending_synth_ea_, pending_synth_var_idx_);

    SynthOptions opts = Config::instance().options();
    opts.interactive_mode = false;
    opts.auto_open_struct = false;
    opts.highlight_changes = false;

    SynthResult result = StructorAPI::instance().synthesize_structure(
        pending_synth_ea_, pending_synth_var_idx_, &opts);

    g_last_error = result.error_message;
    g_last_field_count = result.fields_created;
    g_last_vtable_tid = result.vtable_tid;

    if (result.success()) {
        msg("Structor: Auto-synthesis OK - tid=0x%llx fields=%d\n",
            (unsigned long long)result.struct_tid, result.fields_created);
    } else {
        msg("Structor: Auto-synthesis FAILED - %s\n",
            result.error_message.empty() ? synth_error_str(result.error) : result.error_message.c_str());
    }
}

StructorPlugin::~StructorPlugin() {
    unhook_event_listener(HT_UI, this);
    cleanup();
}

void StructorPlugin::cleanup() {
    if (cleaned_up_) return;
    cleaned_up_ = true;

    // Unregister IDC functions
    unregister_idc_funcs();

    if (initialized_) {
        ui::shutdown();

        // Save configuration if dirty
        if (Config::instance().is_dirty()) {
            Config::instance().save();
        }
        initialized_ = false;
    }
}

ssize_t StructorPlugin::on_event(ssize_t code, va_list /*va*/) {
    switch (code) {
        case ui_database_closed:
            // Database closed - cleanup before Qt widgets are destroyed
            cleanup();
            break;
        default:
            break;
    }
    return 0;
}

bool StructorPlugin::run(size_t arg) {
    if (!initialized_) {
        warning("Structor plugin not properly initialized");
        return false;
    }

    // Get current vdui if in pseudocode view
    TWidget* widget = get_current_widget();
    vdui_t* vdui = get_widget_vdui(widget);

    if (!vdui) {
        info("Structor: Please place cursor on a variable in the pseudocode view\n"
             "and use %s or right-click -> '%s'",
             Config::instance().hotkey(), ACTION_LABEL);
        return true;
    }

    // Execute synthesis
    SynthResult result = ui::execute_synthesis(vdui);

    if (result.success()) {
        if (Config::instance().interactive_mode()) {
            ui::show_result_dialog(result);
        }
    } else {
        qstring errmsg;
        errmsg.sprnt("Structure synthesis failed: %s", synth_error_str(result.error));
        if (!result.error_message.empty()) {
            errmsg.cat_sprnt("\n%s", result.error_message.c_str());
        }
        warning("%s", errmsg.c_str());
    }

    return true;
}

// Plugin information
static plugmod_t* idaapi init() {
    // Check for Hex-Rays decompiler
    if (!init_hexrays_plugin()) {
        msg("Structor: Hex-Rays decompiler not found\n");
        return nullptr;
    }

    return new StructorPlugin();
}

} // namespace structor

// Plugin export
plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI,                           // Plugin flags
    structor::init,                         // Initialize
    nullptr,                                // Terminate (handled by destructor)
    nullptr,                                // Run (handled by plugmod_t::run)
    structor::PLUGIN_NAME,                  // Comment
    "Structure synthesis from access patterns",  // Help
    structor::PLUGIN_NAME,                  // Wanted name
    structor::DEFAULT_HOTKEY                // Wanted hotkey
};
