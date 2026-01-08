/// @file python_bindings.cpp
/// @brief IDAPython bindings for Structor

#include <structor/api.hpp>
#include <structor/synth_types.hpp>
#include <structor/config.hpp>

// IDA Python integration
#include <expr.hpp>

namespace structor {
namespace python {

/// IDAPython function: synth_struct_for_var(ea, varname) -> dict
/// Synthesizes a structure for the given variable in the function
static error_t idaapi py_synth_struct_for_var(idc_value_t* argv, idc_value_t* res) {
    // Validate arguments
    if (argv[0].vtype != VT_INT64 && argv[0].vtype != VT_LONG) {
        return set_qerrno(eTypeConflict);
    }

    ea_t func_ea = argv[0].vtype == VT_INT64 ? argv[0].i64 : argv[0].num;
    const char* var_name = argv[1].c_str();

    // Perform synthesis
    SynthResult result = StructorAPI::instance().synthesize_structure(func_ea, var_name);

    // Build result dictionary
    res->vtype = VT_OBJ;
    res->obj = nullptr;

    // Create Python dict using IDC-compatible object
    idc_value_t dict;
    dict.vtype = VT_OBJ;

    // Set success field
    idc_value_t success_key, success_val;
    success_key.set_string("success");
    success_val.set_long(result.success() ? 1 : 0);
    VarSetAttr(&dict, &success_key, &success_val);

    // Set error field
    idc_value_t error_key, error_val;
    error_key.set_string("error");
    error_val.set_string(synth_error_str(result.error));
    VarSetAttr(&dict, &error_key, &error_val);

    // Set error_message field
    idc_value_t errmsg_key, errmsg_val;
    errmsg_key.set_string("error_message");
    errmsg_val.set_string(result.error_message.c_str());
    VarSetAttr(&dict, &errmsg_key, &errmsg_val);

    // Set struct_tid field
    idc_value_t tid_key, tid_val;
    tid_key.set_string("struct_tid");
    tid_val.set_int64(result.struct_tid);
    VarSetAttr(&dict, &tid_key, &tid_val);

    // Set vtable_tid field
    idc_value_t vtid_key, vtid_val;
    vtid_key.set_string("vtable_tid");
    vtid_val.set_int64(result.vtable_tid);
    VarSetAttr(&dict, &vtid_key, &vtid_val);

    // Set fields_created field
    idc_value_t fields_key, fields_val;
    fields_key.set_string("fields_created");
    fields_val.set_long(result.fields_created);
    VarSetAttr(&dict, &fields_key, &fields_val);

    // Set vtable_slots field
    idc_value_t slots_key, slots_val;
    slots_key.set_string("vtable_slots");
    slots_val.set_long(result.vtable_slots);
    VarSetAttr(&dict, &slots_key, &slots_val);

    // Set struct_name if available
    if (result.synthesized_struct) {
        idc_value_t name_key, name_val;
        name_key.set_string("struct_name");
        name_val.set_string(result.synthesized_struct->name.c_str());
        VarSetAttr(&dict, &name_key, &name_val);

        // Set struct_size
        idc_value_t size_key, size_val;
        size_key.set_string("struct_size");
        size_val.set_long(result.synthesized_struct->size);
        VarSetAttr(&dict, &size_key, &size_val);
    }

    // Set propagated_count field
    idc_value_t prop_key, prop_val;
    prop_key.set_string("propagated_count");
    prop_val.set_long(result.propagated_to.size());
    VarSetAttr(&dict, &prop_key, &prop_val);

    *res = dict;
    return eOk;
}

/// IDAPython function: synth_struct_for_var_idx(ea, idx) -> dict
static error_t idaapi py_synth_struct_for_var_idx(idc_value_t* argv, idc_value_t* res) {
    ea_t func_ea = argv[0].vtype == VT_INT64 ? argv[0].i64 : argv[0].num;
    int var_idx = static_cast<int>(argv[1].num);

    SynthResult result = StructorAPI::instance().synthesize_structure(func_ea, var_idx);

    // Build result (same as above)
    res->vtype = VT_OBJ;

    idc_value_t dict;
    dict.vtype = VT_OBJ;

    idc_value_t success_key, success_val;
    success_key.set_string("success");
    success_val.set_long(result.success() ? 1 : 0);
    VarSetAttr(&dict, &success_key, &success_val);

    idc_value_t error_key, error_val;
    error_key.set_string("error");
    error_val.set_string(synth_error_str(result.error));
    VarSetAttr(&dict, &error_key, &error_val);

    idc_value_t tid_key, tid_val;
    tid_key.set_string("struct_tid");
    tid_val.set_int64(result.struct_tid);
    VarSetAttr(&dict, &tid_key, &tid_val);

    idc_value_t vtid_key, vtid_val;
    vtid_key.set_string("vtable_tid");
    vtid_val.set_int64(result.vtable_tid);
    VarSetAttr(&dict, &vtid_key, &vtid_val);

    idc_value_t fields_key, fields_val;
    fields_key.set_string("fields_created");
    fields_val.set_long(result.fields_created);
    VarSetAttr(&dict, &fields_key, &fields_val);

    idc_value_t slots_key, slots_val;
    slots_key.set_string("vtable_slots");
    slots_val.set_long(result.vtable_slots);
    VarSetAttr(&dict, &slots_key, &slots_val);

    if (result.synthesized_struct) {
        idc_value_t name_key, name_val;
        name_key.set_string("struct_name");
        name_val.set_string(result.synthesized_struct->name.c_str());
        VarSetAttr(&dict, &name_key, &name_val);

        idc_value_t size_key, size_val;
        size_key.set_string("struct_size");
        size_val.set_long(result.synthesized_struct->size);
        VarSetAttr(&dict, &size_key, &size_val);
    }

    *res = dict;
    return eOk;
}

/// IDAPython function: structor_get_accesses(ea, idx) -> list
static error_t idaapi py_get_accesses(idc_value_t* argv, idc_value_t* res) {
    ea_t func_ea = argv[0].vtype == VT_INT64 ? argv[0].i64 : argv[0].num;
    int var_idx = static_cast<int>(argv[1].num);

    AccessPattern pattern = StructorAPI::instance().collect_accesses(func_ea, var_idx);

    // Create array of access info
    res->vtype = VT_OBJ;

    idc_value_t arr;
    arr.vtype = VT_OBJ;
    arr.obj = nullptr;

    for (size_t i = 0; i < pattern.accesses.size(); ++i) {
        const FieldAccess& acc = pattern.accesses[i];

        idc_value_t access_dict;
        access_dict.vtype = VT_OBJ;

        idc_value_t offset_key, offset_val;
        offset_key.set_string("offset");
        offset_val.set_int64(acc.offset);
        VarSetAttr(&access_dict, &offset_key, &offset_val);

        idc_value_t size_key, size_val;
        size_key.set_string("size");
        size_val.set_long(acc.size);
        VarSetAttr(&access_dict, &size_key, &size_val);

        idc_value_t ea_key, ea_val;
        ea_key.set_string("ea");
        ea_val.set_int64(acc.insn_ea);
        VarSetAttr(&access_dict, &ea_key, &ea_val);

        idc_value_t type_key, type_val;
        type_key.set_string("access_type");
        type_val.set_string(access_type_str(acc.access_type));
        VarSetAttr(&access_dict, &type_key, &type_val);

        idc_value_t sem_key, sem_val;
        sem_key.set_string("semantic_type");
        sem_val.set_string(semantic_type_str(acc.semantic_type));
        VarSetAttr(&access_dict, &sem_key, &sem_val);

        idc_value_t vtbl_key, vtbl_val;
        vtbl_key.set_string("is_vtable_access");
        vtbl_val.set_long(acc.is_vtable_access ? 1 : 0);
        VarSetAttr(&access_dict, &vtbl_key, &vtbl_val);

        idc_value_t idx_val;
        idx_val.set_long(i);
        VarSetAttr(&arr, &idx_val, &access_dict);
    }

    *res = arr;
    return eOk;
}

/// IDAPython function: structor_set_option(name, value) -> bool
static error_t idaapi py_set_option(idc_value_t* argv, idc_value_t* res) {
    const char* opt_name = argv[0].c_str();
    SynthOptions& opts = Config::instance().mutable_options();

    bool success = true;

    if (qstrcmp(opt_name, "auto_propagate") == 0) {
        opts.auto_propagate = argv[1].num != 0;
    } else if (qstrcmp(opt_name, "vtable_detection") == 0) {
        opts.vtable_detection = argv[1].num != 0;
    } else if (qstrcmp(opt_name, "min_accesses") == 0) {
        opts.min_accesses = static_cast<int>(argv[1].num);
    } else if (qstrcmp(opt_name, "alignment") == 0) {
        opts.alignment = static_cast<int>(argv[1].num);
    } else if (qstrcmp(opt_name, "interactive_mode") == 0) {
        opts.interactive_mode = argv[1].num != 0;
    } else if (qstrcmp(opt_name, "max_propagation_depth") == 0) {
        opts.max_propagation_depth = static_cast<int>(argv[1].num);
    } else if (qstrcmp(opt_name, "hotkey") == 0) {
        opts.hotkey = argv[1].c_str();
    } else {
        success = false;
    }

    res->set_long(success ? 1 : 0);
    return eOk;
}

/// IDAPython function: structor_get_option(name) -> value
static error_t idaapi py_get_option(idc_value_t* argv, idc_value_t* res) {
    const char* opt_name = argv[0].c_str();
    const SynthOptions& opts = Config::instance().options();

    if (qstrcmp(opt_name, "auto_propagate") == 0) {
        res->set_long(opts.auto_propagate ? 1 : 0);
    } else if (qstrcmp(opt_name, "vtable_detection") == 0) {
        res->set_long(opts.vtable_detection ? 1 : 0);
    } else if (qstrcmp(opt_name, "min_accesses") == 0) {
        res->set_long(opts.min_accesses);
    } else if (qstrcmp(opt_name, "alignment") == 0) {
        res->set_long(opts.alignment);
    } else if (qstrcmp(opt_name, "interactive_mode") == 0) {
        res->set_long(opts.interactive_mode ? 1 : 0);
    } else if (qstrcmp(opt_name, "max_propagation_depth") == 0) {
        res->set_long(opts.max_propagation_depth);
    } else if (qstrcmp(opt_name, "hotkey") == 0) {
        res->set_string(opts.hotkey.c_str());
    } else {
        res->set_long(-1);
    }

    return eOk;
}

// IDC function descriptors
static const ext_idcfunc_t funcs[] = {
    {
        "synth_struct_for_var",
        py_synth_struct_for_var,
        "synth_struct_for_var(ea, varname)\n"
        "Synthesize a structure from access patterns for a variable.\n"
        "\n"
        "Args:\n"
        "    ea: Function address\n"
        "    varname: Variable name in the function\n"
        "\n"
        "Returns:\n"
        "    dict: Result with keys:\n"
        "        success: bool\n"
        "        error: str\n"
        "        struct_tid: int (BADADDR if failed)\n"
        "        vtable_tid: int (BADADDR if no vtable)\n"
        "        fields_created: int\n"
        "        vtable_slots: int\n"
        "        struct_name: str\n"
        "        struct_size: int\n",
        "ll",  // long, string
        0
    },
    {
        "synth_struct_for_var_idx",
        py_synth_struct_for_var_idx,
        "synth_struct_for_var_idx(ea, idx)\n"
        "Synthesize a structure for a variable by index.\n"
        "\n"
        "Args:\n"
        "    ea: Function address\n"
        "    idx: Variable index in local variables\n"
        "\n"
        "Returns:\n"
        "    dict: Same as synth_struct_for_var\n",
        "ll",  // long, long
        0
    },
    {
        "structor_get_accesses",
        py_get_accesses,
        "structor_get_accesses(ea, idx)\n"
        "Get all access patterns for a variable.\n"
        "\n"
        "Args:\n"
        "    ea: Function address\n"
        "    idx: Variable index\n"
        "\n"
        "Returns:\n"
        "    list: List of access info dicts with keys:\n"
        "        offset: int\n"
        "        size: int\n"
        "        ea: int (instruction address)\n"
        "        access_type: str\n"
        "        semantic_type: str\n"
        "        is_vtable_access: bool\n",
        "ll",
        0
    },
    {
        "structor_set_option",
        py_set_option,
        "structor_set_option(name, value)\n"
        "Set a Structor configuration option.\n"
        "\n"
        "Options:\n"
        "    auto_propagate: bool\n"
        "    vtable_detection: bool\n"
        "    min_accesses: int\n"
        "    alignment: int\n"
        "    interactive_mode: bool\n"
        "    max_propagation_depth: int\n"
        "    hotkey: str\n"
        "\n"
        "Returns:\n"
        "    bool: True if option was set successfully\n",
        "sl",  // string, long
        0
    },
    {
        "structor_get_option",
        py_get_option,
        "structor_get_option(name)\n"
        "Get a Structor configuration option value.\n"
        "\n"
        "Returns:\n"
        "    The option value, or -1 if not found\n",
        "s",
        0
    }
};

/// Register IDAPython functions
void register_python_functions() {
    for (const auto& func : funcs) {
        add_idc_func(func);
    }
}

/// Unregister IDAPython functions
void unregister_python_functions() {
    for (const auto& func : funcs) {
        del_idc_func(func.name);
    }
}

} // namespace python
} // namespace structor
