/// @file plugin.cpp
/// @brief Main plugin entry point for Structor

#include <structor/synth_types.hpp>
#include <structor/config.hpp>
#include <structor/ui_integration.hpp>
#include <structor/api.hpp>
#include <structor/type_fixer.hpp>
#include <expr.hpp>
#include <auto.hpp>
#include <name.hpp>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_set>

namespace structor {

namespace {

constexpr const char* kResultExportEnv = "STRUCTOR_EXPORT_LAST_RESULT";

static std::string json_escape(const char* text) {
    if (!text) {
        return std::string();
    }

    std::string escaped;
    for (const unsigned char ch : std::string(text)) {
        switch (ch) {
            case '\\': escaped += "\\\\"; break;
            case '"':  escaped += "\\\""; break;
            case '\b': escaped += "\\b"; break;
            case '\f': escaped += "\\f"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default:
                if (ch < 0x20) {
                    char buf[7] = {0};
                    std::snprintf(buf, sizeof(buf), "\\u%04x", ch);
                    escaped += buf;
                } else {
                    escaped += static_cast<char>(ch);
                }
                break;
        }
    }

    return escaped;
}

static void append_json_string(std::string& out, const char* text) {
    out += '"';
    out += json_escape(text);
    out += '"';
}

static void append_json_string(std::string& out, const qstring& text) {
    append_json_string(out, text.c_str());
}

static void append_json_bool(std::string& out, bool value) {
    out += value ? "true" : "false";
}

static qstring render_type_decl(const tinfo_t& type) {
    qstring decl;
    if (!type.empty()) {
        type.print(&decl);
    }
    return decl;
}

static qstring render_func_name(ea_t ea) {
    qstring name;
    if (ea != BADADDR) {
        get_func_name(&name, ea);
    }
    return name;
}

static void append_field_json(std::string& out, const SynthField& field) {
    out += '{';

    out += "\"name\":";
    append_json_string(out, field.name);
    out += ",\"offset\":" + std::to_string(static_cast<long long>(field.offset));
    out += ",\"size\":" + std::to_string(field.size);
    out += ",\"semantic\":";
    append_json_string(out, semantic_type_str(field.semantic));
    out += ",\"type\":";
    append_json_string(out, render_type_decl(field.type));
    out += ",\"confidence\":";
    append_json_string(out, type_confidence_str(field.confidence));
    out += ",\"is_padding\":";
    append_json_bool(out, field.is_padding);
    out += ",\"is_array\":";
    append_json_bool(out, field.is_array);
    out += ",\"array_count\":" + std::to_string(field.array_count);
    out += ",\"is_union_candidate\":";
    append_json_bool(out, field.is_union_candidate);
    out += ",\"is_bitfield\":";
    append_json_bool(out, field.is_bitfield);
    out += ",\"bit_offset\":" + std::to_string(field.bit_offset);
    out += ",\"bit_size\":" + std::to_string(field.bit_size);

    out += ",\"union_members\":[";
    for (size_t i = 0; i < field.union_members.size(); ++i) {
        if (i != 0) {
            out += ',';
        }

        const auto& member = field.union_members[i];
        out += '{';
        out += "\"name\":";
        append_json_string(out, member.name);
        out += ",\"offset\":" + std::to_string(static_cast<long long>(member.offset));
        out += ",\"size\":" + std::to_string(member.size);
        out += ",\"type\":";
        append_json_string(out, render_type_decl(member.type));
        out += '}';
    }
    out += ']';

    out += '}';
}

static void append_ea_list_json(std::string& out, const qvector<ea_t>& addrs) {
    out += '[';
    for (size_t i = 0; i < addrs.size(); ++i) {
        if (i != 0) {
            out += ',';
        }

        const ea_t ea = addrs[i];
        out += '{';
        out += "\"ea\":" + std::to_string(static_cast<unsigned long long>(ea));
        out += ",\"name\":";
        append_json_string(out, render_func_name(ea));
        out += '}';
    }
    out += ']';
}

static void maybe_export_last_result(const SynthResult& result, const char* mode) {
    const char* path = std::getenv(kResultExportEnv);
    if (!path || !*path) {
        return;
    }

    std::string json;
    json.reserve(4096);
    json += '{';
    json += "\"version\":1";
    json += ",\"mode\":";
    append_json_string(json, mode ? mode : "unknown");
    json += ",\"success\":";
    append_json_bool(json, result.success());
    json += ",\"error\":";
    append_json_string(json, synth_error_str(result.error));
    json += ",\"error_message\":";
    append_json_string(json, result.error_message);
    json += ",\"struct_tid\":" + std::to_string(static_cast<unsigned long long>(result.struct_tid));
    json += ",\"vtable_tid\":" + std::to_string(static_cast<unsigned long long>(result.vtable_tid));
    json += ",\"fields_created\":" + std::to_string(result.fields_created);
    json += ",\"vtable_slots\":" + std::to_string(result.vtable_slots);

    json += ",\"z3\":{";
    json += "\"status\":";
    append_json_string(json, z3_status_str(result.z3_info.status));
    json += ",\"used_z3\":";
    append_json_bool(json, result.z3_info.used_z3());
    json += ",\"used_fallback\":";
    append_json_bool(json, result.z3_info.used_fallback());
    json += ",\"solve_time_ms\":" + std::to_string(result.z3_info.solve_time_ms);
    json += ",\"candidates_generated\":" + std::to_string(result.z3_info.candidates_generated);
    json += ",\"candidates_selected\":" + std::to_string(result.z3_info.candidates_selected);
    json += ",\"constraints_hard\":" + std::to_string(result.z3_info.constraints_hard);
    json += ",\"constraints_soft\":" + std::to_string(result.z3_info.constraints_soft);
    json += ",\"constraints_relaxed\":" + std::to_string(result.z3_info.constraints_relaxed);
    json += ",\"arrays_detected\":" + std::to_string(result.z3_info.arrays_detected);
    json += ",\"unions_created\":" + std::to_string(result.z3_info.unions_created);
    json += ",\"cross_func_merged\":" + std::to_string(result.z3_info.cross_func_merged);
    json += '}';

    json += ",\"propagated_to\":";
    append_ea_list_json(json, result.propagated_to);
    json += ",\"failed_sites\":";
    append_ea_list_json(json, result.failed_sites);

    json += ",\"structure\":";
    if (!result.synthesized_struct) {
        json += "null";
    } else {
        const SynthStruct& synth = *result.synthesized_struct;
        json += '{';
        json += "\"name\":";
        append_json_string(json, synth.name);
        json += ",\"size\":" + std::to_string(synth.size);
        json += ",\"alignment\":" + std::to_string(synth.alignment);
        json += ",\"source_func_ea\":" + std::to_string(static_cast<unsigned long long>(synth.source_func));
        json += ",\"source_func_name\":";
        append_json_string(json, render_func_name(synth.source_func));
        json += ",\"source_var\":";
        append_json_string(json, synth.source_var);
        json += ",\"provenance\":";
        append_ea_list_json(json, synth.provenance);

        size_t non_padding_count = 0;
        for (const auto& field : synth.fields) {
            if (!field.is_padding) {
                ++non_padding_count;
            }
        }
        json += ",\"field_count\":" + std::to_string(synth.fields.size());
        json += ",\"non_padding_field_count\":" + std::to_string(non_padding_count);

        json += ",\"fields\":[";
        for (size_t i = 0; i < synth.fields.size(); ++i) {
            if (i != 0) {
                json += ',';
            }
            append_field_json(json, synth.fields[i]);
        }
        json += ']';

        json += ",\"vtable\":";
        if (!synth.vtable.has_value()) {
            json += "null";
        } else {
            const SynthVTable& vtable = *synth.vtable;
            json += '{';
            json += "\"name\":";
            append_json_string(json, vtable.name);
            json += ",\"tid\":" + std::to_string(static_cast<unsigned long long>(vtable.tid));
            json += ",\"slot_count\":" + std::to_string(vtable.slot_count());
            json += ",\"slots\":[";
            for (size_t i = 0; i < vtable.slots.size(); ++i) {
                if (i != 0) {
                    json += ',';
                }

                const auto& slot = vtable.slots[i];
                json += '{';
                json += "\"index\":" + std::to_string(slot.index);
                json += ",\"offset\":" + std::to_string(static_cast<long long>(slot.offset));
                json += ",\"name\":";
                append_json_string(json, slot.name);
                json += ",\"signature_hint\":";
                append_json_string(json, slot.signature_hint);
                json += ",\"type\":";
                append_json_string(json, render_type_decl(slot.func_type));
                json += '}';
            }
            json += ']';
            json += '}';
        }

        json += '}';
    }

    json += '}';
    json += '\n';

    std::FILE* fp = std::fopen(path, "wb");
    if (!fp) {
        msg("Structor: Failed to open result export path: %s\n", path);
        return;
    }

    const size_t written = std::fwrite(json.data(), 1, json.size(), fp);
    std::fclose(fp);
    if (written != json.size()) {
        msg("Structor: Failed to write full result export: %s\n", path);
    }
}

static bool resolve_function_target(const qstring& requested_name, ea_t& resolved_ea) {
    resolved_ea = BADADDR;
    if (requested_name.empty()) {
        return false;
    }

    resolved_ea = get_name_ea(BADADDR, requested_name.c_str());
    if (resolved_ea != BADADDR) {
        return true;
    }

    if (requested_name[0] != '_') {
        qstring alt_name("_");
        alt_name.append(requested_name);
        resolved_ea = get_name_ea(BADADDR, alt_name.c_str());
        if (resolved_ea != BADADDR) {
            return true;
        }
    }

    return false;
}

} // namespace

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

// IDC function: structor_synthesize_global(global_ea) -> tid_t
static error_t idaapi idc_structor_synthesize_global(idc_value_t* argv, idc_value_t* res) {
    ea_t global_ea = argv[0].vtype == VT_INT64 ? argv[0].i64 : static_cast<ea_t>(argv[0].num);

    SynthOptions opts = Config::instance().options();
    opts.interactive_mode = false;
    opts.auto_open_struct = false;
    opts.highlight_changes = false;

    SynthResult result = StructorAPI::instance().synthesize_global_structure(global_ea, &opts);

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

// IDC function: structor_synthesize_global_by_name(global_name) -> tid_t
static error_t idaapi idc_structor_synthesize_global_by_name(idc_value_t* argv, idc_value_t* res) {
    const char* global_name = argv[0].c_str();

    SynthOptions opts = Config::instance().options();
    opts.interactive_mode = false;
    opts.auto_open_struct = false;
    opts.highlight_changes = false;

    SynthResult result = StructorAPI::instance().synthesize_global_structure(global_name, &opts);

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

// Thread-local storage for type fix results
static thread_local int g_last_fix_count = 0;
static thread_local int g_last_fix_applied = 0;
static thread_local int g_last_fix_skipped = 0;
static thread_local qvector<qstring> g_last_fix_warnings;
static thread_local qvector<qstring> g_last_fix_diagnostics;

static void print_type_fix_messages(const TypeFixResult& result, bool include_diagnostics) {
    for (const auto& warning : result.warnings) {
        msg("Structor: %s\n", warning.c_str());
    }

    if (!include_diagnostics) {
        return;
    }

    for (const auto& diagnostic : result.diagnostics) {
        msg("Structor: diagnostic: %s\n", diagnostic.c_str());
    }
}

static void store_last_type_fix_result(const TypeFixResult& result, int applied_value, int skipped_value) {
    g_last_error = result.errors.empty() ? qstring() : result.errors[0];
    g_last_fix_count = result.analyzed;
    g_last_fix_applied = applied_value;
    g_last_fix_skipped = skipped_value;
    g_last_fix_warnings = result.warnings;
    g_last_fix_diagnostics = result.diagnostics;
}

static error_t idaapi idc_structor_get_fix_warning_count(idc_value_t* /*argv*/, idc_value_t* res) {
    res->set_long(static_cast<long>(g_last_fix_warnings.size()));
    return eOk;
}

static error_t idaapi idc_structor_get_fix_warning(idc_value_t* argv, idc_value_t* res) {
    int idx = static_cast<int>(argv[0].num);
    if (idx < 0 || static_cast<size_t>(idx) >= g_last_fix_warnings.size()) {
        res->set_string(qstring());
        return eOk;
    }

    res->set_string(g_last_fix_warnings[static_cast<size_t>(idx)]);
    return eOk;
}

static error_t idaapi idc_structor_get_fix_diagnostic_count(idc_value_t* /*argv*/, idc_value_t* res) {
    res->set_long(static_cast<long>(g_last_fix_diagnostics.size()));
    return eOk;
}

static error_t idaapi idc_structor_get_fix_diagnostic(idc_value_t* argv, idc_value_t* res) {
    int idx = static_cast<int>(argv[0].num);
    if (idx < 0 || static_cast<size_t>(idx) >= g_last_fix_diagnostics.size()) {
        res->set_string(qstring());
        return eOk;
    }

    res->set_string(g_last_fix_diagnostics[static_cast<size_t>(idx)]);
    return eOk;
}

// IDC function: structor_fix_function_types(func_ea) -> long (number of fixes applied)
static error_t idaapi idc_structor_fix_function_types(idc_value_t* argv, idc_value_t* res) {
    ea_t func_ea = argv[0].vtype == VT_INT64 ? argv[0].i64 : static_cast<ea_t>(argv[0].num);

    TypeFixResult result = StructorAPI::instance().fix_function_types(func_ea);

    print_type_fix_messages(result, true);

    store_last_type_fix_result(result, result.fixes_applied, result.fixes_skipped);

    res->set_long(result.fixes_applied);
    return eOk;
}

// IDC function: structor_fix_variable_type(func_ea, var_idx) -> long (1 if fixed, 0 otherwise)
static error_t idaapi idc_structor_fix_variable_type(idc_value_t* argv, idc_value_t* res) {
    ea_t func_ea = argv[0].vtype == VT_INT64 ? argv[0].i64 : static_cast<ea_t>(argv[0].num);
    int var_idx = static_cast<int>(argv[1].num);

    VariableTypeFix result = StructorAPI::instance().fix_variable_type(func_ea, var_idx);

    g_last_error = result.skip_reason;
    res->set_long(result.applied ? 1 : 0);
    return eOk;
}

// IDC function: structor_fix_variable_by_name(func_ea, var_name) -> long (1 if fixed, 0 otherwise)
static error_t idaapi idc_structor_fix_variable_by_name(idc_value_t* argv, idc_value_t* res) {
    ea_t func_ea = argv[0].vtype == VT_INT64 ? argv[0].i64 : static_cast<ea_t>(argv[0].num);
    const char* var_name = argv[1].c_str();

    VariableTypeFix result = StructorAPI::instance().fix_variable_type(func_ea, var_name);

    g_last_error = result.skip_reason;
    res->set_long(result.applied ? 1 : 0);
    return eOk;
}

// IDC function: structor_analyze_function_types(func_ea) -> long (number of differences found)
static error_t idaapi idc_structor_analyze_function_types(idc_value_t* argv, idc_value_t* res) {
    ea_t func_ea = argv[0].vtype == VT_INT64 ? argv[0].i64 : static_cast<ea_t>(argv[0].num);

    TypeFixResult result = StructorAPI::instance().analyze_function_types(func_ea);

    print_type_fix_messages(result, true);

    store_last_type_fix_result(result, result.differences_found, 0);

    res->set_long(result.differences_found);
    return eOk;
}

// IDC function: structor_get_fix_count() -> long
static error_t idaapi idc_structor_get_fix_count(idc_value_t* /*argv*/, idc_value_t* res) {
    res->set_long(g_last_fix_count);
    return eOk;
}

// IDC function: structor_get_fixes_applied() -> long
static error_t idaapi idc_structor_get_fixes_applied(idc_value_t* /*argv*/, idc_value_t* res) {
    res->set_long(g_last_fix_applied);
    return eOk;
}

// IDC function: structor_get_fixes_skipped() -> long
static error_t idaapi idc_structor_get_fixes_skipped(idc_value_t* /*argv*/, idc_value_t* res) {
    res->set_long(g_last_fix_skipped);
    return eOk;
}

// Argument type arrays for IDC functions
static const char args_synthesize[] = { VT_INT64, VT_LONG, 0 };
static const char args_synthesize_by_name[] = { VT_INT64, VT_STR, 0 };
static const char args_global_synthesize[] = { VT_INT64, 0 };
static const char args_global_synthesize_by_name[] = { VT_STR, 0 };
static const char args_no_args[] = { 0 };
static const char args_func_ea[] = { VT_INT64, 0 };
static const char args_index[] = { VT_LONG, 0 };

static const ext_idcfunc_t idc_funcs[] = {
    { "structor_synthesize", idc_structor_synthesize, args_synthesize, nullptr, 0, EXTFUN_BASE },
    { "structor_synthesize_by_name", idc_structor_synthesize_by_name, args_synthesize_by_name, nullptr, 0, EXTFUN_BASE },
    { "structor_synthesize_global", idc_structor_synthesize_global, args_global_synthesize, nullptr, 0, EXTFUN_BASE },
    { "structor_synthesize_global_by_name", idc_structor_synthesize_global_by_name, args_global_synthesize_by_name, nullptr, 0, EXTFUN_BASE },
    { "structor_get_error", idc_structor_get_error, args_no_args, nullptr, 0, EXTFUN_BASE },
    { "structor_get_field_count", idc_structor_get_field_count, args_no_args, nullptr, 0, EXTFUN_BASE },
    { "structor_get_vtable_tid", idc_structor_get_vtable_tid, args_no_args, nullptr, 0, EXTFUN_BASE },
    // Type fixing functions
    { "structor_fix_function_types", idc_structor_fix_function_types, args_func_ea, nullptr, 0, EXTFUN_BASE },
    { "structor_fix_variable_type", idc_structor_fix_variable_type, args_synthesize, nullptr, 0, EXTFUN_BASE },
    { "structor_fix_variable_by_name", idc_structor_fix_variable_by_name, args_synthesize_by_name, nullptr, 0, EXTFUN_BASE },
    { "structor_analyze_function_types", idc_structor_analyze_function_types, args_func_ea, nullptr, 0, EXTFUN_BASE },
    { "structor_get_fix_count", idc_structor_get_fix_count, args_no_args, nullptr, 0, EXTFUN_BASE },
    { "structor_get_fixes_applied", idc_structor_get_fixes_applied, args_no_args, nullptr, 0, EXTFUN_BASE },
    { "structor_get_fixes_skipped", idc_structor_get_fixes_skipped, args_no_args, nullptr, 0, EXTFUN_BASE },
    { "structor_get_fix_warning_count", idc_structor_get_fix_warning_count, args_no_args, nullptr, 0, EXTFUN_BASE },
    { "structor_get_fix_warning", idc_structor_get_fix_warning, args_index, nullptr, 0, EXTFUN_BASE },
    { "structor_get_fix_diagnostic_count", idc_structor_get_fix_diagnostic_count, args_no_args, nullptr, 0, EXTFUN_BASE },
    { "structor_get_fix_diagnostic", idc_structor_get_fix_diagnostic, args_index, nullptr, 0, EXTFUN_BASE },
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

// Hex-Rays callback for automatic type fixing
static ssize_t idaapi hexrays_callback(void* ud, hexrays_event_t event, va_list va);

/// Plugin descriptor - owns the action handler to ensure proper lifetime
class StructorPlugin : public plugmod_t, public event_listener_t {
public:
    StructorPlugin();
    ~StructorPlugin() override;

    bool idaapi run(size_t arg) override;
    ssize_t idaapi on_event(ssize_t code, va_list va) override;

    /// Called when decompilation completes - fix types automatically
    void on_decompilation_complete(cfunc_t* cfunc);

private:
    void cleanup();
    void run_pending_auto_synth();

    SynthActionHandler action_handler_;  // Owned by plugin, passed to IDA
    bool initialized_ = false;
    bool cleaned_up_ = false;
    bool hexrays_hooked_ = false;

    // Track which functions we've already processed to avoid re-fixing
    std::unordered_set<ea_t> processed_functions_;

    // Pending auto-synthesis from env var
    ea_t pending_synth_ea_ = BADADDR;
    qstring pending_synth_func_name_;
    int pending_synth_var_idx_ = 0;
    qstring pending_synth_var_name_;
    ea_t pending_global_synth_ea_ = BADADDR;
    qstring pending_global_synth_name_;
    bool auto_synth_done_ = false;
};

// Global plugin instance for callback access
static StructorPlugin* g_plugin = nullptr;

// Hex-Rays callback implementation
static ssize_t idaapi hexrays_callback(void* /*ud*/, hexrays_event_t event, va_list va) {
    if (!g_plugin) return 0;
    
    switch (event) {
        case hxe_maturity: {
            cfunc_t* cfunc = va_arg(va, cfunc_t*);
            ctree_maturity_t maturity = va_argi(va, ctree_maturity_t);
            if (cfunc && maturity == CMAT_FINAL) {
                if (Config::instance().options().debug_mode) {
                    qstring func_name;
                    get_func_name(&func_name, cfunc->entry_ea);
                    msg("Structor: hxe_maturity final for %s\n", func_name.c_str());
                }
                (void)rewrite_registered_global_uses(cfunc);
            }
            break;
        }
        case hxe_func_printed: {
            // Called after the function pseudocode is generated
            cfunc_t* cfunc = va_arg(va, cfunc_t*);
            if (cfunc && Config::instance().options().auto_fix_types) {
                g_plugin->on_decompilation_complete(cfunc);
            }
            break;
        }
        default:
            break;
    }
    
    return 0;
}

StructorPlugin::StructorPlugin() {
    // Set global plugin pointer for callback access
    g_plugin = this;

    // Load configuration
    Config::instance().load();

    // Register IDC functions
    register_idc_funcs();

    // Hook UI notifications to cleanup before widget destruction
    hook_event_listener(HT_UI, this);

    // Install Hex-Rays callback for automatic type fixing
    if (install_hexrays_callback(hexrays_callback, nullptr)) {
        hexrays_hooked_ = true;
        msg("Structor: Hex-Rays callback installed (auto_fix_types=%s)\n",
            Config::instance().options().auto_fix_types ? "true" : "false");
    } else {
        msg("Structor: Failed to install Hex-Rays callback\n");
    }

    // Initialize UI - pass our action handler which we own
    if (ui::initialize(&action_handler_)) {
        initialized_ = true;
        msg("Structor %s: Plugin initialized (hotkey: %s)\n",
            PLUGIN_VERSION, Config::instance().hotkey());
    } else {
        msg("Structor: Failed to initialize UI\n");
    }

    // Check for auto-synthesis env var:
    // STRUCTOR_AUTO_SYNTH=func_ea or func_ea:var_idx or func_ea:var_name
    // STRUCTOR_AUTO_SYNTH=func_name or func_name:var_idx or func_name:var_name
    const char* env = getenv("STRUCTOR_AUTO_SYNTH");
    if (env && *env) {
        qstring requested = env;
        qstring target = requested;
        const char* selector = nullptr;

        char* endptr = nullptr;
        pending_synth_ea_ = BADADDR;
        pending_synth_func_name_.clear();
        pending_synth_var_name_.clear();
        pending_synth_var_idx_ = 0;

        const char* colon = std::strchr(env, ':');
        if (colon) {
            target = qstring(env, static_cast<size_t>(colon - env));
            selector = colon + 1;
        }

        unsigned long long parsed = std::strtoull(target.c_str(), &endptr, 0);
        if (endptr && *endptr == '\0') {
            pending_synth_ea_ = static_cast<ea_t>(parsed);
        } else {
            pending_synth_func_name_ = target;
        }

        if (selector && *selector) {
            char* idx_end = nullptr;
            long idx = std::strtol(selector, &idx_end, 0);
            if (idx_end && *idx_end == '\0') {
                pending_synth_var_idx_ = static_cast<int>(idx);
            } else {
                pending_synth_var_name_ = selector;
            }
        }

        if (pending_synth_ea_ != BADADDR || !pending_synth_func_name_.empty()) {
            // Run synthesis immediately (auto_wait() is called internally)
            run_pending_auto_synth();
        }
    }

    // Check for global/static auto-synthesis env var: STRUCTOR_AUTO_SYNTH_GLOBAL=ea_or_name
    const char* global_env = getenv("STRUCTOR_AUTO_SYNTH_GLOBAL");
    if (global_env && *global_env) {
        char* endptr = nullptr;
        pending_global_synth_ea_ = strtoull(global_env, &endptr, 0);
        if (!endptr || *endptr != '\0') {
            pending_global_synth_ea_ = BADADDR;
            pending_global_synth_name_ = global_env;
        }
        run_pending_auto_synth();
    }
}

void StructorPlugin::run_pending_auto_synth() {
    if (auto_synth_done_) return;
    if (pending_synth_ea_ == BADADDR
        && pending_synth_func_name_.empty()
        && pending_global_synth_ea_ == BADADDR
        && pending_global_synth_name_.empty()) {
        return;
    }
    auto_synth_done_ = true;

    // Wait for auto-analysis to complete
    auto_wait();

    if (!pending_global_synth_name_.empty()) {
        msg("Structor: Running auto global synthesis for name=%s\n",
            pending_global_synth_name_.c_str());
    } else if (pending_global_synth_ea_ != BADADDR) {
        msg("Structor: Running auto global synthesis for ea=0x%llx\n",
            (unsigned long long)pending_global_synth_ea_);
    } else if (!pending_synth_func_name_.empty() && !pending_synth_var_name_.empty()) {
        msg("Structor: Running auto-synthesis for func=%s var_name=%s\n",
            pending_synth_func_name_.c_str(), pending_synth_var_name_.c_str());
    } else if (!pending_synth_func_name_.empty()) {
        msg("Structor: Running auto-synthesis for func=%s var_idx=%d\n",
            pending_synth_func_name_.c_str(), pending_synth_var_idx_);
    } else if (!pending_synth_var_name_.empty()) {
        msg("Structor: Running auto-synthesis for func=0x%llx var_name=%s\n",
            (unsigned long long)pending_synth_ea_, pending_synth_var_name_.c_str());
    } else {
        msg("Structor: Running auto-synthesis for func=0x%llx var_idx=%d\n",
            (unsigned long long)pending_synth_ea_, pending_synth_var_idx_);
    }

    SynthOptions opts = Config::instance().options();
    opts.interactive_mode = false;
    opts.auto_open_struct = false;
    opts.highlight_changes = false;

    SynthResult result;
    ea_t synth_ea = pending_synth_ea_;
    if (synth_ea == BADADDR && !pending_synth_func_name_.empty()) {
        if (!resolve_function_target(pending_synth_func_name_, synth_ea)) {
            qstring err;
            err.sprnt("Function '%s' not found", pending_synth_func_name_.c_str());
            result = SynthResult::make_error(SynthError::InternalError, err);
            g_last_error = result.error_message;
            g_last_field_count = 0;
            g_last_vtable_tid = BADADDR;
            maybe_export_last_result(result, "auto");
            msg("Structor: Auto-synthesis FAILED - %s\n", result.error_message.c_str());
            return;
        }
    }

    if (!pending_global_synth_name_.empty()) {
        result = StructorAPI::instance().synthesize_global_structure(
            pending_global_synth_name_.c_str(), &opts);
    } else if (pending_global_synth_ea_ != BADADDR) {
        result = StructorAPI::instance().synthesize_global_structure(
            pending_global_synth_ea_, &opts);
    } else if (pending_synth_var_name_.empty()) {
        result = StructorAPI::instance().synthesize_structure(
            synth_ea, pending_synth_var_idx_, &opts);
    } else {
        result = StructorAPI::instance().synthesize_structure(
            synth_ea, pending_synth_var_name_.c_str(), &opts);
    }

    g_last_error = result.error_message;
    g_last_field_count = result.fields_created;
    g_last_vtable_tid = result.vtable_tid;
    maybe_export_last_result(result, "auto");

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

    // Remove Hex-Rays callback
    if (hexrays_hooked_) {
        remove_hexrays_callback(hexrays_callback, nullptr);
        hexrays_hooked_ = false;
    }

    // Clear global plugin pointer
    g_plugin = nullptr;
    clear_registered_global_rewrite_info();

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

void StructorPlugin::on_decompilation_complete(cfunc_t* cfunc) {
    if (!cfunc) return;

    // When running an explicit non-interactive auto-synthesis session
    // (used by idump verification), do not let the background type fixer
    // mutate the database at the same time.
    if (pending_synth_ea_ != BADADDR
        || !pending_synth_func_name_.empty()
        || pending_global_synth_ea_ != BADADDR
        || !pending_global_synth_name_.empty()) {
        return;
    }

    ea_t func_ea = cfunc->entry_ea;

    // Check if we've already processed this function
    if (processed_functions_.count(func_ea) > 0) {
        return;
    }

    // Mark as processed to avoid re-processing
    processed_functions_.insert(func_ea);

    // Debug: always log that we're processing
    if (Config::instance().options().debug_mode) {
        qstring func_name;
        get_func_name(&func_name, func_ea);
        msg("Structor: Processing function %s (0x%llx)\n", 
            func_name.c_str(), (unsigned long long)func_ea);
    }

    // Run type fixer
    TypeFixerConfig fix_config;
    fix_config.dry_run = false;
    fix_config.synthesize_structures = true;
    fix_config.propagate_fixes = Config::instance().options().auto_propagate;
    fix_config.max_propagation_depth = Config::instance().options().max_propagation_depth;

    TypeFixer fixer(fix_config);
    TypeFixResult result = fixer.fix_function_types(cfunc);

    // Report results
    bool verbose = Config::instance().options().auto_fix_verbose;
    bool debug = Config::instance().options().debug_mode;
    
    if (debug) {
        msg("Structor: %s - analyzed %u vars, %u differences, %u fixed\n",
            result.func_name.c_str(),
            result.analyzed,
            result.differences_found,
            result.fixes_applied);
    }

    print_type_fix_messages(result, debug);
    
    if (verbose && result.fixes_applied > 0) {
        msg("Structor: Auto-fixed %u types in %s\n",
            result.fixes_applied, 
            result.func_name.c_str());

        // Report individual fixes
        for (const auto& fix : result.variable_fixes) {
            if (fix.applied) {
                msg("  - %s: %s\n", 
                    fix.var_name.c_str(),
                    fix.comparison.description.c_str());
            }
        }
    }
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
