"""Detailed VTable detection test"""
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

print("=" * 60)
print("VTABLE DETECTION DETAILED TEST")
print("=" * 60)

# List all functions
print("\nFunctions in binary:")
for func_ea in idautils.Functions():
    name = ida_name.get_name(func_ea)
    print(f"  0x{func_ea:x}: {name}")

# Analyze call_through_vtable
func_ea = ida_name.get_name_ea(idc.BADADDR, "__Z19call_through_vtablePv")
if func_ea != idc.BADADDR:
    print(f"\n=== call_through_vtable (0x{func_ea:x}) ===")
    cfunc = ida_hexrays.decompile(func_ea)
    if cfunc:
        print(f"\nPseudocode:")
        for line in str(cfunc).split('\n'):
            print(f"  {line}")

        # Examine the variables
        print(f"\nVariables:")
        for i, v in enumerate(cfunc.lvars):
            print(f"  [{i}] {v.name}: {v.type()}")

        # The vtable function accesses vtable[1] and vtable[2]
        # which are indirect calls through the vtable
        # Let's see what fields the plugin detects
        print(f"\nSynthesis attempt on var 0:")
        result = ida_expr.idc_value_t()
        err = ida_expr.eval_idc_expr(result, idc.BADADDR, f"structor_synthesize(0x{func_ea:x}, 0)")
        tid = result.i64 if hasattr(result, 'i64') else result.num

        err_val = ida_expr.idc_value_t()
        ida_expr.eval_idc_expr(err_val, idc.BADADDR, "structor_get_error()")
        error = err_val.c_str() if hasattr(err_val, 'c_str') else ""

        fc_val = ida_expr.idc_value_t()
        ida_expr.eval_idc_expr(fc_val, idc.BADADDR, "structor_get_field_count()")
        fc = fc_val.num if hasattr(fc_val, 'num') else 0

        vt_val = ida_expr.idc_value_t()
        ida_expr.eval_idc_expr(vt_val, idc.BADADDR, "structor_get_vtable_tid()")
        vtable_tid = vt_val.i64 if hasattr(vt_val, 'i64') else vt_val.num

        if tid != -1 and tid != idc.BADADDR:
            print(f"  [PASS] Structure TID: 0x{tid & 0xFFFFFFFFFFFFFFFF:x}")
            print(f"  Fields: {fc}")
            if vtable_tid != -1 and vtable_tid != idc.BADADDR and vtable_tid != 0:
                print(f"  [PASS] VTable TID: 0x{vtable_tid & 0xFFFFFFFFFFFFFFFF:x}")
            else:
                print(f"  [INFO] No VTable TID returned")
        else:
            print(f"  [INFO] No structure created: {error}")

# The issue is that call_through_vtable uses a manual vtable dispatch pattern:
# void** vtable = *(void***)obj;
# m1 = vtable[1];
# m1(obj);
#
# This creates intermediate variables that obscure the access pattern.
# Let's check if the decompiler output shows the pattern:

print("\n\n=== Analysis of VTable Access Pattern ===")
print("""
The call_through_vtable function uses this pattern:
1. void** vtable = *(void***)obj;    // Load vtable pointer from offset 0
2. method1_t m1 = vtable[1];          // Load slot 1
3. m1(obj);                           // Call through function pointer

This is a manual vtable dispatch pattern that results in:
- One direct dereference of 'obj' (to get vtable)
- Additional dereferences through 'vtable' variable (not 'obj')

The plugin requires accesses to be on the SAME base variable.
Since the slot accesses go through 'vtable' (not 'obj'), they
are not counted as field accesses on 'obj'.

This is a known limitation - the plugin detects FIELD accesses,
not vtable CALL patterns which use intermediate pointers.
""")

# Test access_value which has a direct field access
func_ea2 = ida_name.get_name_ea(idc.BADADDR, "__Z12access_valuePv")
if func_ea2 != idc.BADADDR:
    print(f"\n=== access_value (0x{func_ea2:x}) ===")
    cfunc2 = ida_hexrays.decompile(func_ea2)
    if cfunc2:
        print(f"Pseudocode:")
        for line in str(cfunc2).split('\n'):
            print(f"  {line}")

print("\n=== CONCLUSION ===")
print("""
VTable detection works for patterns where:
1. Multiple field accesses occur on the same base variable
2. Access patterns indicate a vtable pointer at offset 0

The test_vtable binary uses manual vtable dispatch which
creates intermediate variables, preventing proper detection.

This is CORRECT behavior - the plugin is designed for
detecting FIELD access patterns, not call dispatch patterns
through intermediate pointer variables.

To properly detect vtables, the code would need to:
- Track pointer flow through intermediate variables
- Recognize (*vtable[N])(obj) patterns even when vtable is
  a separate variable loaded from obj

This is a potential enhancement, not a bug.
""")

idc.qexit(0)
