"""Simple test - just print to console."""

import idc
import ida_name
import ida_auto
import ida_hexrays
import ida_expr

print("=== SIMPLE TEST ===")

ida_auto.auto_wait()
print("Auto-wait done")

if not ida_hexrays.init_hexrays_plugin():
    print("ERROR: No Hex-Rays")
    idc.qexit(1)

print("Hex-Rays OK")

# Find process_data
ea = ida_name.get_name_ea(idc.BADADDR, "_process_data")
if ea == idc.BADADDR:
    ea = ida_name.get_name_ea(idc.BADADDR, "process_data")

print(f"process_data: 0x{ea:x}")

# Try to call structor_synthesize
print("Calling structor_synthesize...")
result = ida_expr.idc_value_t()
err = ida_expr.eval_idc_expr(result, idc.BADADDR, f"structor_synthesize(0x{ea:x}, 0)")
print(f"Error: {err}")
if not err:
    tid = result.i64 if hasattr(result, "i64") else result.num
    print(f"TID: 0x{tid & 0xFFFFFFFFFFFFFFFF:x}")

# Get field count
fc = ida_expr.idc_value_t()
ida_expr.eval_idc_expr(fc, idc.BADADDR, "structor_get_field_count()")
fields = fc.i64 if hasattr(fc, "i64") else fc.num
print(f"Fields: {fields}")

print("=== DONE ===")
idc.qexit(0)
