"""Analyze why specific tests failed"""
import idc
import ida_name
import ida_auto
import ida_hexrays
import ida_expr
import idautils

ida_auto.auto_wait()

if not ida_hexrays.init_hexrays_plugin():
    print("[FATAL] No Hex-Rays")
    idc.qexit(1)

def find_func(*names):
    for name in names:
        ea = ida_name.get_name_ea(idc.BADADDR, name)
        if ea != idc.BADADDR:
            return ea, name
    return idc.BADADDR, None

def analyze_function(func_names, description):
    """Analyze a function to understand why synthesis might fail"""
    print(f"\n{'=' * 60}")
    print(f"ANALYZING: {description}")
    print("=" * 60)

    func_ea, name = find_func(*func_names)
    if func_ea == idc.BADADDR:
        print("[SKIP] Function not found")
        return

    print(f"Function: {name} at 0x{func_ea:x}")

    # Decompile
    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        print("[ERROR] Could not decompile")
        return

    # Print variables
    print(f"\nLocal Variables ({cfunc.lvars.size()}):")
    for i, v in enumerate(cfunc.lvars):
        print(f"  [{i}] {v.name}: {v.type()}, is_arg={v.is_arg_var}")

    # Print pseudocode
    print(f"\nPseudocode:")
    lines = str(cfunc).split('\n')
    for line in lines[:20]:  # First 20 lines
        print(f"  {line}")

    # Try synthesis on each variable
    print(f"\nSynthesis attempts:")
    for i in range(min(5, cfunc.lvars.size())):
        v = cfunc.lvars[i]
        result = ida_expr.idc_value_t()
        err = ida_expr.eval_idc_expr(result, idc.BADADDR, f"structor_synthesize(0x{func_ea:x}, {i})")
        if err:
            print(f"  var[{i}] ({v.name}): IDC error")
            continue

        tid = result.i64 if hasattr(result, 'i64') else result.num

        err_val = ida_expr.idc_value_t()
        ida_expr.eval_idc_expr(err_val, idc.BADADDR, "structor_get_error()")
        err_str = err_val.c_str() if hasattr(err_val, 'c_str') else ""

        fc_val = ida_expr.idc_value_t()
        ida_expr.eval_idc_expr(fc_val, idc.BADADDR, "structor_get_field_count()")
        fc = fc_val.num if hasattr(fc_val, 'num') else 0

        if tid != -1 and tid != idc.BADADDR:
            print(f"  var[{i}] ({v.name}): SUCCESS - {fc} fields")
        else:
            print(f"  var[{i}] ({v.name}): FAILED - {err_str}")

# Analyze each failed test function
analyze_function(["_traverse_list", "traverse_list"], "traverse_list (linked list)")
analyze_function(["_insert_after", "insert_after"], "insert_after (linked list)")
analyze_function(["_update_and_invoke", "update_and_invoke"], "update_and_invoke (function ptr)")

print("\n\nDone")
idc.qexit(0)
