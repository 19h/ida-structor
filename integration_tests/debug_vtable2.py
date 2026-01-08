"""Debug vtable synthesis - test access_value function"""
import idc
import ida_name
import ida_auto
import ida_hexrays
import ida_expr
import idautils

ida_auto.auto_wait()

if not ida_hexrays.init_hexrays_plugin():
    print("ERROR: No Hex-Rays")
    idc.qexit(1)

# Test access_value function (has direct field access at offset 8)
func_ea = ida_name.get_name_ea(idc.BADADDR, "__Z12access_valuePv")
print(f"access_value function: 0x{func_ea:x}")

if func_ea == idc.BADADDR:
    print("ERROR: Function not found")
    idc.qexit(1)

# Decompile
print("Decompiling...")
cfunc = ida_hexrays.decompile(func_ea)
if not cfunc:
    print("ERROR: Could not decompile")
    idc.qexit(1)

print(f"Decompiled OK, lvars count: {cfunc.lvars.size()}")

# Print variables
print("\n=== LOCAL VARIABLES ===")
for i, v in enumerate(cfunc.lvars):
    print(f"  [{i}] {v.name}: {v.type()}")

# Call synthesis
print("\nCalling structor_synthesize on access_value...")
result_val = ida_expr.idc_value_t()
expr = f"structor_synthesize(0x{func_ea:x}, 0)"
err = ida_expr.eval_idc_expr(result_val, idc.BADADDR, expr)

if err:
    print(f"  IDC error: {err}")
else:
    tid = result_val.i64 if hasattr(result_val, 'i64') else result_val.num
    print(f"  Result TID: 0x{tid & 0xFFFFFFFFFFFFFFFF:x}")

    # Get error
    err_val = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(err_val, idc.BADADDR, "structor_get_error()")
    error_str = err_val.c_str() if hasattr(err_val, 'c_str') else "N/A"
    print(f"  Error string: {error_str}")

    # Get field count
    fc_val = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(fc_val, idc.BADADDR, "structor_get_field_count()")
    fc = fc_val.num if hasattr(fc_val, 'num') else 0
    print(f"  Field count: {fc}")

# Now test call_through_vtable but with different var index
print("\n\nTesting call_through_vtable with var index 1...")
func_ea2 = ida_name.get_name_ea(idc.BADADDR, "__Z19call_through_vtablePv")
cfunc2 = ida_hexrays.decompile(func_ea2)
print(f"Variables in call_through_vtable:")
for i, v in enumerate(cfunc2.lvars):
    print(f"  [{i}] {v.name}: {v.type()}")

# Try different variable indices
for idx in range(min(4, cfunc2.lvars.size())):
    result_val = ida_expr.idc_value_t()
    err = ida_expr.eval_idc_expr(result_val, idc.BADADDR, f"structor_synthesize(0x{func_ea2:x}, {idx})")
    if not err:
        tid = result_val.i64 if hasattr(result_val, 'i64') else result_val.num
        fc_val = ida_expr.idc_value_t()
        ida_expr.eval_idc_expr(fc_val, idc.BADADDR, "structor_get_field_count()")
        fc = fc_val.num if hasattr(fc_val, 'num') else 0
        err_val = ida_expr.idc_value_t()
        ida_expr.eval_idc_expr(err_val, idc.BADADDR, "structor_get_error()")
        err_str = err_val.c_str() if hasattr(err_val, 'c_str') else ""
        status = "OK" if tid != -1 and tid != idc.BADADDR else f"FAIL: {err_str}"
        print(f"  var[{idx}]: TID=0x{tid & 0xFFFFFFFFFFFFFFFF:x}, fields={fc} - {status}")

print("\nDone")
idc.qexit(0)
