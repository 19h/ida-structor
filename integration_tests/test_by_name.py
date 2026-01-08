"""Test structor_synthesize_by_name variant"""
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

# Find process_simple function
func_ea = ida_name.get_name_ea(idc.BADADDR, "_process_simple")
if func_ea == idc.BADADDR:
    func_ea = ida_name.get_name_ea(idc.BADADDR, "process_simple")

print(f"Function: 0x{func_ea:x}")

if func_ea == idc.BADADDR:
    print("ERROR: Function not found")
    idc.qexit(1)

# Decompile
cfunc = ida_hexrays.decompile(func_ea)
if not cfunc:
    print("ERROR: Could not decompile")
    idc.qexit(1)

# Show variables
print("\n=== LOCAL VARIABLES ===")
var_names = []
for i, v in enumerate(cfunc.lvars):
    print(f"  [{i}] {v.name}: {v.type()}")
    var_names.append(v.name)

print("\n=== Testing structor_synthesize_by_name ===")

# Test with actual variable names
for name in var_names[:3]:  # First 3 vars
    print(f"\nTesting with variable name: '{name}'")
    result_val = ida_expr.idc_value_t()
    expr = f'structor_synthesize_by_name(0x{func_ea:x}, "{name}")'
    print(f"  Expression: {expr}")
    err = ida_expr.eval_idc_expr(result_val, idc.BADADDR, expr)

    if err:
        print(f"  [ERROR] IDC error: {err}")
        continue

    tid = result_val.i64 if hasattr(result_val, 'i64') else result_val.num

    # Get results
    fc_val = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(fc_val, idc.BADADDR, "structor_get_field_count()")
    fc = fc_val.num if hasattr(fc_val, 'num') else 0

    err_val = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(err_val, idc.BADADDR, "structor_get_error()")
    err_str = err_val.c_str() if hasattr(err_val, 'c_str') else ""

    if tid != -1 and tid != idc.BADADDR:
        print(f"  [PASS] TID=0x{tid & 0xFFFFFFFFFFFFFFFF:x}, fields={fc}")
    else:
        print(f"  [INFO] Not synthesized: {err_str}")

# Test with non-existent variable name
print("\n\nTesting with non-existent variable name...")
result_val = ida_expr.idc_value_t()
err = ida_expr.eval_idc_expr(result_val, idc.BADADDR, f'structor_synthesize_by_name(0x{func_ea:x}, "nonexistent_xyz_123")')
if not err:
    tid = result_val.i64 if hasattr(result_val, 'i64') else result_val.num
    err_val = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(err_val, idc.BADADDR, "structor_get_error()")
    err_str = err_val.c_str() if hasattr(err_val, 'c_str') else ""
    if tid == -1 or tid == idc.BADADDR:
        print(f"  [PASS] Correctly rejected non-existent variable: {err_str}")
    else:
        print(f"  [FAIL] Should have rejected non-existent variable")

print("\nDone")
idc.qexit(0)
