"""Final validation test - comprehensive check of all features"""
import idc
import ida_name
import ida_auto
import ida_hexrays
import ida_expr
import ida_nalt

ida_auto.auto_wait()

print("=" * 60)
print("STRUCTOR PLUGIN - FINAL VALIDATION")
print("=" * 60)

# Check Hex-Rays
if not ida_hexrays.init_hexrays_plugin():
    print("[FATAL] Hex-Rays decompiler not available")
    idc.qexit(1)

print("[OK] Hex-Rays decompiler loaded")

# Check IDC functions are registered
test_funcs = [
    "structor_synthesize",
    "structor_synthesize_by_name",
    "structor_get_error",
    "structor_get_field_count",
    "structor_get_vtable_tid"
]

print("\n--- IDC Function Registration ---")
all_registered = True
for func in test_funcs:
    # Try to evaluate a simple call
    result = ida_expr.idc_value_t()
    # Test with invalid params just to check function exists
    err = ida_expr.eval_idc_expr(result, idc.BADADDR, f"{func}(0, 0)" if "synthesize" in func else f"{func}()")
    if err and "undefined" in str(err).lower():
        print(f"[FAIL] {func} - not registered")
        all_registered = False
    else:
        print(f"[OK] {func} - registered")

# Find and test process_simple
print("\n--- Synthesis Test ---")
func_ea = ida_name.get_name_ea(idc.BADADDR, "_process_simple")
if func_ea == idc.BADADDR:
    func_ea = ida_name.get_name_ea(idc.BADADDR, "process_simple")

if func_ea == idc.BADADDR:
    print("[FAIL] Could not find test function")
    idc.qexit(1)

print(f"[OK] Found process_simple at 0x{func_ea:x}")

# Decompile
cfunc = ida_hexrays.decompile(func_ea)
if not cfunc:
    print("[FAIL] Could not decompile")
    idc.qexit(1)

print(f"[OK] Decompiled successfully ({cfunc.lvars.size()} local variables)")

# Synthesize by index
result = ida_expr.idc_value_t()
err = ida_expr.eval_idc_expr(result, idc.BADADDR, f"structor_synthesize(0x{func_ea:x}, 0)")
tid1 = result.i64 if hasattr(result, 'i64') else result.num

fc = ida_expr.idc_value_t()
ida_expr.eval_idc_expr(fc, idc.BADADDR, "structor_get_field_count()")
fields1 = fc.num if hasattr(fc, 'num') else 0

if tid1 != -1 and tid1 != idc.BADADDR:
    print(f"[OK] structor_synthesize: TID=0x{tid1 & 0xFFFFFFFFFFFFFFFF:x}, fields={fields1}")
else:
    err_val = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(err_val, idc.BADADDR, "structor_get_error()")
    print(f"[FAIL] structor_synthesize: {err_val.c_str() if hasattr(err_val, 'c_str') else 'unknown'}")

# Synthesize by name
result2 = ida_expr.idc_value_t()
var_name = cfunc.lvars[0].name
err = ida_expr.eval_idc_expr(result2, idc.BADADDR, f'structor_synthesize_by_name(0x{func_ea:x}, "{var_name}")')
tid2 = result2.i64 if hasattr(result2, 'i64') else result2.num

fc2 = ida_expr.idc_value_t()
ida_expr.eval_idc_expr(fc2, idc.BADADDR, "structor_get_field_count()")
fields2 = fc2.num if hasattr(fc2, 'num') else 0

if tid2 != -1 and tid2 != idc.BADADDR:
    print(f"[OK] structor_synthesize_by_name('{var_name}'): TID=0x{tid2 & 0xFFFFFFFFFFFFFFFF:x}, fields={fields2}")
else:
    err_val = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(err_val, idc.BADADDR, "structor_get_error()")
    print(f"[FAIL] structor_synthesize_by_name: {err_val.c_str() if hasattr(err_val, 'c_str') else 'unknown'}")

# Error handling check
print("\n--- Error Handling ---")
result3 = ida_expr.idc_value_t()
ida_expr.eval_idc_expr(result3, idc.BADADDR, "structor_synthesize(0xBAD, 0)")
tid3 = result3.i64 if hasattr(result3, 'i64') else result3.num
if tid3 == -1 or tid3 == idc.BADADDR:
    print("[OK] Invalid address correctly rejected")
else:
    print("[FAIL] Should have rejected invalid address")

# Summary
print("\n" + "=" * 60)
validation_passed = (
    all_registered and
    (tid1 != -1 and tid1 != idc.BADADDR) and
    (tid2 != -1 and tid2 != idc.BADADDR) and
    fields1 >= 3 and
    fields2 >= 3
)

if validation_passed:
    print("VALIDATION: PASSED")
    print("All core features working correctly")
else:
    print("VALIDATION: FAILED")
    print("Some features not working as expected")

print("=" * 60)

idc.qexit(0 if validation_passed else 1)
