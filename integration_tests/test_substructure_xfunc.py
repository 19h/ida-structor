"""
Test cross-function analysis with complex call graph and substructure.

Call graph:
  main (A) -> setup_links (B) -> process_node_d (D) -> process_data (C)
  main (A) -> process_data (C)  [direct, with substructure ptr+0x10]

Expected behavior:
  When structor is invoked on process_data's parameter (which receives
  struct+0x10), it should:
  1. Trace backward to main (and process_node_d)
  2. From main, trace forward to discover setup_links
  3. Collect access patterns from ALL functions
  4. Synthesize the FULL struct layout

Expected struct:
  offset 0x00: pointer (next) - from main, setup_links, process_node_d
  offset 0x08: pointer (prev) - from main, setup_links
  offset 0x10: int (data) - from main, process_data, process_node_d
  offset 0x14: int (flags) - from main, process_data

Usage: idat -A -Stest_substructure_xfunc.py /path/to/test_substructure
"""

import idc
import ida_name
import ida_auto
import ida_hexrays
import ida_expr
import ida_funcs
import idautils

LOG_FILE = "/tmp/structor_substructure_test.log"
log_file = open(LOG_FILE, "w")


def log(msg):
    log_file.write(f"[SUBST] {msg}\n")
    log_file.flush()
    print(f"[SUBST] {msg}")


def get_function_ea(name):
    ea = ida_name.get_name_ea(idc.BADADDR, f"_{name}")
    if ea == idc.BADADDR:
        ea = ida_name.get_name_ea(idc.BADADDR, name)
    return ea


def get_decompiled_var_types(func_ea):
    """Get all variable types from a decompiled function."""
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc:
            return []

        result = []
        for i, lvar in enumerate(cfunc.lvars):
            lvar_type = lvar.type()
            type_str = str(lvar_type)

            # Check if it's a synthesized struct pointer
            if lvar_type.is_ptr():
                pointed = lvar_type.get_pointed_object()
                if pointed.is_struct():
                    type_str = f"{pointed.get_type_name()}*"

            result.append((i, lvar.name, type_str, lvar.is_arg_var()))

        return result
    except Exception as e:
        log(f"Error decompiling: {e}")
        return []


def call_structor_synthesize(func_ea, var_idx):
    """Call structor_synthesize."""
    result = ida_expr.idc_value_t()
    expr = f"structor_synthesize(0x{func_ea:x}, {var_idx})"
    err = ida_expr.eval_idc_expr(result, idc.BADADDR, expr)

    if err:
        log(f"Error: {err}")
        return None

    tid = result.i64 if hasattr(result, "i64") else result.num

    # Get field count
    fc = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(fc, idc.BADADDR, "structor_get_field_count()")
    fields = fc.i64 if hasattr(fc, "i64") else (fc.num if hasattr(fc, "num") else 0)

    # Get struct size
    sz = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(sz, idc.BADADDR, "structor_get_struct_size()")
    size = sz.i64 if hasattr(sz, "i64") else (sz.num if hasattr(sz, "num") else 0)

    return {"tid": tid, "fields": fields, "size": size}


def main():
    log("=" * 70)
    log("SUBSTRUCTURE CROSS-FUNCTION ANALYSIS TEST")
    log("=" * 70)
    log("")
    log("Testing that struct reconstruction considers ALL xref callees")
    log("even when starting from a function that receives a substructure.")
    log("")

    ida_auto.auto_wait()

    if not ida_hexrays.init_hexrays_plugin():
        log("ERROR: Hex-Rays not available")
        idc.qexit(1)

    # List functions
    funcs = ["main", "setup_links", "process_node_d", "process_data"]

    log("Functions in binary:")
    for name in funcs:
        ea = get_function_ea(name)
        if ea != idc.BADADDR:
            log(f"  {name}: 0x{ea:x}")
            vars = get_decompiled_var_types(ea)
            for idx, vname, vtype, is_arg in vars:
                if is_arg:
                    log(f"    param {idx}: {vname} : {vtype}")
        else:
            log(f"  {name}: NOT FOUND")

    # Test: Invoke structor on process_data (C), which receives substructure
    log("")
    log("=" * 70)
    log("TEST: Invoke structor on process_data's parameter")
    log("=" * 70)

    process_data_ea = get_function_ea("process_data")
    if process_data_ea == idc.BADADDR:
        log("ERROR: process_data not found")
        idc.qexit(1)

    log(f"Calling structor_synthesize(0x{process_data_ea:x}, 0)...")
    result = call_structor_synthesize(process_data_ea, 0)

    if result:
        log(f"Result: TID=0x{result['tid'] & 0xFFFFFFFFFFFFFFFF:x}, fields={result['fields']}, size={result['size']}")
    else:
        log("ERROR: Synthesis failed")

    # Check types after synthesis
    log("")
    log("Variable types AFTER synthesis:")
    for name in funcs:
        ea = get_function_ea(name)
        if ea != idc.BADADDR:
            vars = get_decompiled_var_types(ea)
            log(f"  {name}:")
            for idx, vname, vtype, is_arg in vars:
                if is_arg:
                    log(f"    param {idx}: {vname} : {vtype}")

    log("")
    log("=" * 70)
    log("EXPECTED OUTCOME:")
    log("  - All four functions should have synth_struct* types")
    log("  - Struct should have fields at 0x00, 0x08, 0x10, 0x14")
    log("  - This proves cross-function analysis discovered ALL callees")
    log("=" * 70)

    log_file.close()
    idc.qexit(0)


main()
