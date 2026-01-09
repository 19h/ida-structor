"""Run structor synthesis and save database."""

import idc
import ida_auto
import ida_hexrays
import ida_expr
import ida_name
import ida_loader

LOG = "/tmp/structor_synthesis.log"

def log(msg):
    with open(LOG, "a") as f:
        f.write(f"{msg}\n")

with open(LOG, "w") as f:
    f.write("=== STRUCTOR SYNTHESIS ===\n")

try:
    log("Waiting for auto analysis...")
    ida_auto.auto_wait()
    log("Done")

    log("Initializing Hex-Rays...")
    if not ida_hexrays.init_hexrays_plugin():
        log("ERROR: No Hex-Rays")
        idc.qexit(1)
    log("Hex-Rays OK")

    # Find process_data
    ea = ida_name.get_name_ea(idc.BADADDR, "_process_data")
    if ea == idc.BADADDR:
        ea = ida_name.get_name_ea(idc.BADADDR, "process_data")
    log(f"process_data at 0x{ea:x}")

    # Call structor_synthesize
    log("Calling structor_synthesize...")
    result = ida_expr.idc_value_t()
    # Pass flag=1 to enable cross-function analysis
    err = ida_expr.eval_idc_expr(result, idc.BADADDR, f"structor_synthesize(0x{ea:x}, 1)")
    
    if err:
        log(f"IDC error: {err}")
    else:
        tid = result.i64 if hasattr(result, "i64") else result.num
        log(f"TID: 0x{tid & 0xFFFFFFFFFFFFFFFF:x}")

    # Get field count  
    fc = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(fc, idc.BADADDR, "structor_get_field_count()")
    fields = fc.num if hasattr(fc, "num") else 0
    log(f"Field count: {fields}")

    # Get struct size
    sz = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(sz, idc.BADADDR, "structor_get_struct_size()")
    size = sz.num if hasattr(sz, "num") else 0
    log(f"Struct size: {size}")

    # Save the database
    log("Saving database...")
    idb_path = "/tmp/test_substructure_synth.i64"
    ida_loader.save_database(idb_path, 0)
    log(f"Database saved to: {idb_path}")

    log("=== DONE ===")
except Exception as e:
    import traceback
    log(f"Exception: {e}")
    log(traceback.format_exc())

idc.qexit(0)
