"""Debug nested struct synthesis"""
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

# List all functions
print("=== FUNCTIONS ===")
for func_ea in idautils.Functions():
    name = ida_name.get_name(func_ea)
    print(f"  0x{func_ea:x}: {name}")

# Test access_nested function (has many field accesses)
func_ea = ida_name.get_name_ea(idc.BADADDR, "_access_nested")
if func_ea == idc.BADADDR:
    func_ea = ida_name.get_name_ea(idc.BADADDR, "access_nested")
print(f"\naccess_nested function: 0x{func_ea:x}")

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

# Call synthesis on first variable (ptr)
print("\nCalling structor_synthesize on access_nested var 0...")
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

    if tid != -1 and tid != idc.BADADDR:
        print(f"\n[PASS] Structure created successfully with {fc} fields")
    else:
        print(f"\n[FAIL] Synthesis failed: {error_str}")

# Also test modify_array
print("\n\n=== Testing modify_array function ===")
func_ea2 = ida_name.get_name_ea(idc.BADADDR, "_modify_array")
if func_ea2 == idc.BADADDR:
    func_ea2 = ida_name.get_name_ea(idc.BADADDR, "modify_array")
if func_ea2 != idc.BADADDR:
    cfunc2 = ida_hexrays.decompile(func_ea2)
    print(f"Variables in modify_array:")
    for i, v in enumerate(cfunc2.lvars):
        print(f"  [{i}] {v.name}: {v.type()}")

    result_val = ida_expr.idc_value_t()
    err = ida_expr.eval_idc_expr(result_val, idc.BADADDR, f"structor_synthesize(0x{func_ea2:x}, 0)")
    if not err:
        tid = result_val.i64 if hasattr(result_val, 'i64') else result_val.num
        fc_val = ida_expr.idc_value_t()
        ida_expr.eval_idc_expr(fc_val, idc.BADADDR, "structor_get_field_count()")
        fc = fc_val.num if hasattr(fc_val, 'num') else 0
        err_val = ida_expr.idc_value_t()
        ida_expr.eval_idc_expr(err_val, idc.BADADDR, "structor_get_error()")
        err_str = err_val.c_str() if hasattr(err_val, 'c_str') else ""
        if tid != -1 and tid != idc.BADADDR:
            print(f"  [PASS] TID=0x{tid & 0xFFFFFFFFFFFFFFFF:x}, fields={fc}")
        else:
            print(f"  [FAIL] {err_str}")

print("\nDone")
idc.qexit(0)
