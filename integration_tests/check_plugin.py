"""
Check if structor plugin is loaded.
"""

import idc
import ida_auto
import ida_expr

LOG_FILE = "/tmp/structor_check.log"
log_file = open(LOG_FILE, "w")


def log(msg):
    log_file.write(f"{msg}\n")
    log_file.flush()
    print(msg)


def main():
    log("=== Plugin Check ===")

    ida_auto.auto_wait()

    # Try to call structor_get_error to see if plugin is loaded
    result = ida_expr.idc_value_t()
    err = ida_expr.eval_idc_expr(result, idc.BADADDR, "structor_get_error()")

    if err:
        log(f"ERROR: structor_get_error() failed: {err}")
        log("Plugin is NOT loaded or IDC functions not registered")
    else:
        log(
            f"structor_get_error() returned: '{result.c_str() if hasattr(result, 'c_str') else result}'"
        )
        log("Plugin IS loaded")

    # Try synthesize
    log("\nTrying synthesize...")
    result2 = ida_expr.idc_value_t()
    err2 = ida_expr.eval_idc_expr(
        result2, idc.BADADDR, "structor_synthesize(0x100000494, 0)"
    )

    if err2:
        log(f"ERROR: structor_synthesize() failed: {err2}")
    else:
        tid = result2.i64 if hasattr(result2, "i64") else result2.num
        log(f"structor_synthesize() returned TID: 0x{tid & 0xFFFFFFFFFFFFFFFF:x}")

        # Check field count
        fc = ida_expr.idc_value_t()
        ida_expr.eval_idc_expr(fc, idc.BADADDR, "structor_get_field_count()")
        fields = fc.num if hasattr(fc, "num") else 0
        log(f"Field count: {fields}")

        # Check error
        err_val = ida_expr.idc_value_t()
        ida_expr.eval_idc_expr(err_val, idc.BADADDR, "structor_get_error()")
        error = err_val.c_str() if hasattr(err_val, "c_str") else str(err_val)
        log(f"Error message: '{error}'")

    log("\n=== Done ===")
    log_file.close()
    idc.qexit(0)


main()
