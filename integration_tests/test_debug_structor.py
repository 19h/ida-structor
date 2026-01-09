"""Debug script to check structor plugin status."""

import sys

LOG_FILE = "/tmp/structor_debug.log"
log_file = open(LOG_FILE, "w")


def log(msg):
    log_file.write(f"{msg}\n")
    log_file.flush()


try:
    import idc
    import ida_name
    import ida_auto
    import ida_hexrays
    import ida_expr
    import idautils

    log("Imports OK")
except Exception as e:
    log(f"Import error: {e}")
    raise

ida_auto.auto_wait()
log("Auto-analysis complete")

# Check if Hex-Rays is available
if ida_hexrays.init_hexrays_plugin():
    log("Hex-Rays: OK")
else:
    log("Hex-Rays: FAILED")

# List functions
log("\nFunctions found:")
for ea in idautils.Functions():
    name = ida_name.get_name(ea)
    log(f"  0x{ea:x}: {name}")

# Try to find init_simple
func_ea = ida_name.get_name_ea(idc.BADADDR, "_init_simple")
if func_ea == idc.BADADDR:
    func_ea = ida_name.get_name_ea(idc.BADADDR, "init_simple")
log(f"\ninit_simple EA: 0x{func_ea:x}")

# Try to decompile
if func_ea != idc.BADADDR:
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        if cfunc:
            log(f"Decompiled OK, {len(cfunc.lvars)} local vars")
            for i, lvar in enumerate(cfunc.lvars):
                log(f"  [{i}] {lvar.name}: {lvar.type()}")
        else:
            log("Decompile returned None")
    except Exception as e:
        log(f"Decompile error: {e}")

# Check if structor IDC functions are available
log("\nTesting structor IDC functions:")

# Test calling structor_synthesize
if func_ea != idc.BADADDR:
    result = ida_expr.idc_value_t()
    expr = f"structor_synthesize(0x{func_ea:x}, 0)"
    log(f"Calling: {expr}")

    err = ida_expr.eval_idc_expr(result, idc.BADADDR, expr)

    if err:
        log(f"IDC eval error: {err}")
    else:
        # Get result value
        tid = -1
        if hasattr(result, "i64"):
            tid = result.i64
        elif hasattr(result, "num"):
            tid = result.num
        log(f"Result TID: 0x{tid & 0xFFFFFFFFFFFFFFFF:x} (vtype={result.vtype})")

        # Get field count
        fc = ida_expr.idc_value_t()
        ida_expr.eval_idc_expr(fc, idc.BADADDR, "structor_get_field_count()")
        fields = fc.num if hasattr(fc, "num") else -1
        log(f"Field count: {fields}")

        # Get error message
        err_val = ida_expr.idc_value_t()
        ida_expr.eval_idc_expr(err_val, idc.BADADDR, "structor_get_error()")
        if hasattr(err_val, "c_str"):
            error = err_val.c_str()
        elif hasattr(err_val, "str"):
            error = err_val.str
        else:
            error = str(err_val)
        log(f"Error message: '{error}'")

log("\nDone")
log_file.close()
idc.qexit(0)
