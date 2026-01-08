"""Simple test to call structor_synthesize"""
import idc
import ida_name
import ida_auto
import ida_hexrays
import ida_expr

ida_auto.auto_wait()

if not ida_hexrays.init_hexrays_plugin():
    print("ERROR: No Hex-Rays")
    idc.qexit(1)

func_ea = ida_name.get_name_ea(idc.BADADDR, "_process_simple")
if func_ea == idc.BADADDR:
    func_ea = ida_name.get_name_ea(idc.BADADDR, "process_simple")

print(f"func_ea = 0x{func_ea:x}")

# Decompile first to ensure ctree is available
cfunc = ida_hexrays.decompile(func_ea)
print(f"Decompiled: {cfunc is not None}")

# Call the IDC function using ida_expr
print("Calling structor_synthesize...")
try:
    # Create result holder
    result_val = ida_expr.idc_value_t()

    # Call the IDC function
    idc_expr_str = f"structor_synthesize(0x{func_ea:x}, 0)"
    err = ida_expr.eval_idc_expr(result_val, idc.BADADDR, idc_expr_str)

    if err:
        print(f"IDC Error: {err}")
    else:
        # Try to get the value - check different attributes
        result = result_val.int64 if hasattr(result_val, 'int64') else (
            result_val.i64 if hasattr(result_val, 'i64') else result_val.num)
        print(f"Result TID: 0x{result:x} (vtype={result_val.vtype})")

        if result != idc.BADADDR and result != -1:
            print("SUCCESS: Structure created!")

            # Get field count - try different ways
            field_result = ida_expr.idc_value_t()
            ida_expr.eval_idc_expr(field_result, idc.BADADDR, "structor_get_field_count()")
            print(f"  Field result vtype={field_result.vtype}")

            # Try multiple attributes
            if hasattr(field_result, 'num'):
                print(f"    .num = {field_result.num}")
            if hasattr(field_result, 'i64'):
                print(f"    .i64 = {field_result.i64}")
            if hasattr(field_result, 'int64'):
                print(f"    .int64 = {field_result.int64}")

            # Get vtable tid
            vtable_result = ida_expr.idc_value_t()
            ida_expr.eval_idc_expr(vtable_result, idc.BADADDR, "structor_get_vtable_tid()")
            vtable_tid = vtable_result.i64 if hasattr(vtable_result, 'i64') else vtable_result.num
            if vtable_tid != idc.BADADDR and vtable_tid != -1:
                print(f"  VTable TID: 0x{vtable_tid:x}")
        else:
            # Get error message
            err_result = ida_expr.idc_value_t()
            ida_expr.eval_idc_expr(err_result, idc.BADADDR, "structor_get_error()")
            error = str(err_result) if err_result else "Unknown error"
            print(f"FAILED: {error}")

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()

print("Done")
idc.qexit(0)
