import idc
import ida_auto
import ida_hexrays
import ida_expr
import ida_name

LOG = "/tmp/structor_test.log"

def log(msg):
    with open(LOG, "a") as f:
        f.write(f"{msg}\n")

with open(LOG, "w") as f:
    f.write("=== STRUCTOR TEST ===\n")

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
    err = ida_expr.eval_idc_expr(result, idc.BADADDR, f"structor_synthesize(0x{ea:x}, 0)")
    
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

    log("=== DONE ===")
except Exception as e:
    log(f"Exception: {e}")

idc.qexit(0)
