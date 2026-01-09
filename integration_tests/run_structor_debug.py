"""
IDA Python script to invoke structor synthesis with debug output.
Run with: idat -A -S"run_structor_debug.py" test_substructure
"""

import idc
import ida_name
import ida_auto
import ida_hexrays
import ida_expr
import ida_loader
import ida_struct
import ida_typeinf

LOG_FILE = "/tmp/structor_debug.log"

def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"{msg}\n")
    print(msg)

def get_function_ea(name):
    ea = ida_name.get_name_ea(idc.BADADDR, f"_{name}")
    if ea == idc.BADADDR:
        ea = ida_name.get_name_ea(idc.BADADDR, name)
    return ea

def dump_struct_by_tid(tid):
    """Dump structure fields by TID."""
    sptr = ida_struct.get_struc(tid)
    if not sptr:
        return "Could not get struct"

    name = ida_struct.get_struc_name(tid)
    size = ida_struct.get_struc_size(sptr)
    result = f"struct {name} (size={size}):\n"

    # Iterate members
    offset = 0
    while offset < size:
        mptr = ida_struct.get_member(sptr, offset)
        if mptr:
            mname = ida_struct.get_member_name(mptr.id)
            msize = ida_struct.get_member_size(mptr)
            moffset = mptr.soff

            # Get member type
            tif = ida_typeinf.tinfo_t()
            if ida_struct.get_member_tinfo(tif, mptr):
                mtype = str(tif)
            else:
                mtype = f"(size {msize})"

            result += f"  +0x{moffset:02x}: {mname} : {mtype}\n"
            offset = moffset + msize
        else:
            offset += 1

    return result

def main():
    # Clear log
    with open(LOG_FILE, "w") as f:
        f.write("")

    log("=== STRUCTOR DEBUG TEST ===")
    log("")

    ida_auto.auto_wait()

    if not ida_hexrays.init_hexrays_plugin():
        log("ERROR: Hex-Rays not available")
        idc.qexit(1)

    # List functions
    funcs = ["main", "setup_links", "process_node_d", "process_data"]
    log("Functions:")
    for name in funcs:
        ea = get_function_ea(name)
        log(f"  {name}: 0x{ea:x}")

    # Find process_data function
    process_data_ea = get_function_ea("process_data")
    if process_data_ea == idc.BADADDR:
        log("ERROR: process_data not found")
        idc.qexit(1)

    log("")
    log(f"=== Invoking structor on process_data (0x{process_data_ea:x}) param 0 ===")
    log("")

    # Enable debug mode via IDC if available
    debug_result = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(debug_result, idc.BADADDR, "structor_set_debug(1)")

    # Call structor_synthesize
    result = ida_expr.idc_value_t()
    expr = f"structor_synthesize(0x{process_data_ea:x}, 0)"
    err = ida_expr.eval_idc_expr(result, idc.BADADDR, expr)

    if err:
        log(f"IDC Error: {err}")
    else:
        tid = result.i64 if hasattr(result, "i64") else result.num
        # Handle negative values (BADADDR)
        if tid < 0:
            tid = tid & 0xFFFFFFFFFFFFFFFF
        log(f"Result TID: 0x{tid:x}")

        if tid != 0xFFFFFFFFFFFFFFFF:
            # Try to dump the struct
            struct_info = dump_struct_by_tid(tid)
            log(struct_info)

    # Get error message if any
    err_result = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(err_result, idc.BADADDR, "structor_get_error()")
    if hasattr(err_result, "c_str"):
        error = err_result.c_str()
        if error:
            log(f"Error message: {error}")

    # Get field count
    fc = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(fc, idc.BADADDR, "structor_get_field_count()")
    fields = fc.i64 if hasattr(fc, "i64") else (fc.num if hasattr(fc, "num") else 0)
    log(f"Field count: {fields}")

    # Get struct size
    sz = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(sz, idc.BADADDR, "structor_get_struct_size()")
    size = sz.i64 if hasattr(sz, "i64") else (sz.num if hasattr(sz, "num") else 0)
    log(f"Struct size: {size}")

    # Save database
    log("")
    log("Saving database...")
    ida_loader.save_database(idc.get_idb_path(), 0)
    log(f"Saved to: {idc.get_idb_path()}")

    log("")
    log("=== EXPECTED RESULT ===")
    log("If cross-function analysis works, we should see:")
    log("  - Fields at 0x00, 0x08, 0x10, 0x14")
    log("  - Multiple functions analyzed")
    log("")
    log("If ONLY process_data was analyzed:")
    log("  - Fields only at 0x00, 0x04 (local offsets)")
    log("")

    log("=== TEST COMPLETE ===")
    idc.qexit(0)

main()
