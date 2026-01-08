/// @file api.cpp
/// @brief Public API implementation

#include <structor/api.hpp>

namespace structor {

// C API implementations (extern "C" wrappers)

extern "C" {

IDAAPI tid_t structor_synthesize(ea_t func_ea, int var_idx) {
    SynthResult result = StructorAPI::instance().synthesize_structure(func_ea, var_idx);

    extern thread_local qstring g_last_error;
    extern thread_local int g_last_field_count;
    extern thread_local tid_t g_last_vtable_tid;

    g_last_error = result.error_message;
    g_last_field_count = result.fields_created;
    g_last_vtable_tid = result.vtable_tid;

    if (!result.success()) {
        if (g_last_error.empty()) {
            g_last_error = synth_error_str(result.error);
        }
        return BADADDR;
    }

    return result.struct_tid;
}

IDAAPI tid_t structor_synthesize_by_name(ea_t func_ea, const char* var_name) {
    SynthResult result = StructorAPI::instance().synthesize_structure(func_ea, var_name);

    extern thread_local qstring g_last_error;
    extern thread_local int g_last_field_count;
    extern thread_local tid_t g_last_vtable_tid;

    g_last_error = result.error_message;
    g_last_field_count = result.fields_created;
    g_last_vtable_tid = result.vtable_tid;

    if (!result.success()) {
        if (g_last_error.empty()) {
            g_last_error = synth_error_str(result.error);
        }
        return BADADDR;
    }

    return result.struct_tid;
}

IDAAPI const char* structor_get_error() {
    extern thread_local qstring g_last_error;
    return g_last_error.c_str();
}

IDAAPI int structor_get_field_count() {
    extern thread_local int g_last_field_count;
    return g_last_field_count;
}

IDAAPI tid_t structor_get_vtable_tid() {
    extern thread_local tid_t g_last_vtable_tid;
    return g_last_vtable_tid;
}

} // extern "C"

// Thread-local storage for C API
thread_local qstring g_last_error;
thread_local int g_last_field_count = 0;
thread_local tid_t g_last_vtable_tid = BADADDR;

} // namespace structor
