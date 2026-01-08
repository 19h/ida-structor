"""Debug vtable synthesis"""
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

# Find the vtable function
func_ea = ida_name.get_name_ea(idc.BADADDR, "__Z19call_through_vtablePv")
print(f"\nTarget function: 0x{func_ea:x}")

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
print("\nCalling structor_synthesize...")
result_val = ida_expr.idc_value_t()
expr = f"structor_synthesize(0x{func_ea:x}, 0)"
print(f"  Expression: {expr}")
err = ida_expr.eval_idc_expr(result_val, idc.BADADDR, expr)

if err:
    print(f"  IDC error: {err}")
else:
    tid = result_val.i64 if hasattr(result_val, 'i64') else result_val.num
    print(f"  Result TID: 0x{tid:x}")

    # Get error
    err_val = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(err_val, idc.BADADDR, "structor_get_error()")
    if hasattr(err_val, 'c_str'):
        error_str = err_val.c_str()
    else:
        error_str = "N/A"
    print(f"  Error string: {error_str}")

    # Get field count
    fc_val = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(fc_val, idc.BADADDR, "structor_get_field_count()")
    fc = fc_val.num if hasattr(fc_val, 'num') else 0
    print(f"  Field count: {fc}")

print("\nDone")
idc.qexit(0)
