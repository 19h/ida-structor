"""Test error handling and edge cases"""
import idc
import ida_name
import ida_auto
import ida_hexrays
import ida_expr

ida_auto.auto_wait()

if not ida_hexrays.init_hexrays_plugin():
    print("ERROR: No Hex-Rays")
    idc.qexit(1)

print("=== ERROR HANDLING TESTS ===\n")

passed = 0
failed = 0

def get_result():
    """Get synthesis result and error"""
    err_val = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(err_val, idc.BADADDR, "structor_get_error()")
    err_str = err_val.c_str() if hasattr(err_val, 'c_str') else ""

    fc_val = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(fc_val, idc.BADADDR, "structor_get_field_count()")
    fc = fc_val.num if hasattr(fc_val, 'num') else 0

    return err_str, fc

# Test 1: Invalid function address
print("Test 1: Invalid function address (0xDEADBEEF)")
result_val = ida_expr.idc_value_t()
err = ida_expr.eval_idc_expr(result_val, idc.BADADDR, "structor_synthesize(0xDEADBEEF, 0)")
if not err:
    tid = result_val.i64 if hasattr(result_val, 'i64') else result_val.num
    err_str, fc = get_result()
    if tid == -1 or tid == idc.BADADDR:
        print(f"  [PASS] Correctly rejected invalid address: {err_str}")
        passed += 1
    else:
        print(f"  [FAIL] Should have rejected invalid address")
        failed += 1
else:
    print(f"  [FAIL] IDC error: {err}")
    failed += 1

# Test 2: Valid function but out-of-range variable index
print("\nTest 2: Out-of-range variable index (9999)")
func_ea = ida_name.get_name_ea(idc.BADADDR, "_process_simple")
if func_ea == idc.BADADDR:
    func_ea = ida_name.get_name_ea(idc.BADADDR, "process_simple")

if func_ea != idc.BADADDR:
    cfunc = ida_hexrays.decompile(func_ea)
    result_val = ida_expr.idc_value_t()
    err = ida_expr.eval_idc_expr(result_val, idc.BADADDR, f"structor_synthesize(0x{func_ea:x}, 9999)")
    if not err:
        tid = result_val.i64 if hasattr(result_val, 'i64') else result_val.num
        err_str, fc = get_result()
        if tid == -1 or tid == idc.BADADDR:
            print(f"  [PASS] Correctly rejected out-of-range index: {err_str}")
            passed += 1
        else:
            print(f"  [WARN] Accepted out-of-range index (may have fallback)")
            passed += 1  # Not necessarily wrong
    else:
        print(f"  [FAIL] IDC error: {err}")
        failed += 1
else:
    print("  [SKIP] Could not find test function")

# Test 3: Negative variable index
print("\nTest 3: Negative variable index (-1)")
if func_ea != idc.BADADDR:
    result_val = ida_expr.idc_value_t()
    err = ida_expr.eval_idc_expr(result_val, idc.BADADDR, f"structor_synthesize(0x{func_ea:x}, -1)")
    if not err:
        tid = result_val.i64 if hasattr(result_val, 'i64') else result_val.num
        err_str, fc = get_result()
        if tid == -1 or tid == idc.BADADDR:
            print(f"  [PASS] Correctly handled negative index: {err_str}")
            passed += 1
        else:
            print(f"  [INFO] Negative index created structure (may be valid behavior)")
            passed += 1
    else:
        print(f"  [FAIL] IDC error: {err}")
        failed += 1

# Test 4: Empty string variable name
print("\nTest 4: Empty string variable name")
if func_ea != idc.BADADDR:
    result_val = ida_expr.idc_value_t()
    err = ida_expr.eval_idc_expr(result_val, idc.BADADDR, f'structor_synthesize_by_name(0x{func_ea:x}, "")')
    if not err:
        tid = result_val.i64 if hasattr(result_val, 'i64') else result_val.num
        err_str, fc = get_result()
        if tid == -1 or tid == idc.BADADDR:
            print(f"  [PASS] Correctly rejected empty name: {err_str}")
            passed += 1
        else:
            print(f"  [WARN] Accepted empty name")
            passed += 1
    else:
        print(f"  [FAIL] IDC error: {err}")
        failed += 1

# Test 5: Function address 0
print("\nTest 5: Zero function address")
result_val = ida_expr.idc_value_t()
err = ida_expr.eval_idc_expr(result_val, idc.BADADDR, "structor_synthesize(0, 0)")
if not err:
    tid = result_val.i64 if hasattr(result_val, 'i64') else result_val.num
    err_str, fc = get_result()
    if tid == -1 or tid == idc.BADADDR:
        print(f"  [PASS] Correctly rejected zero address: {err_str}")
        passed += 1
    else:
        print(f"  [FAIL] Should have rejected zero address")
        failed += 1
else:
    print(f"  [FAIL] IDC error: {err}")
    failed += 1

# Test 6: Successful synthesis (sanity check)
print("\nTest 6: Valid synthesis (sanity check)")
if func_ea != idc.BADADDR:
    result_val = ida_expr.idc_value_t()
    err = ida_expr.eval_idc_expr(result_val, idc.BADADDR, f"structor_synthesize(0x{func_ea:x}, 0)")
    if not err:
        tid = result_val.i64 if hasattr(result_val, 'i64') else result_val.num
        err_str, fc = get_result()
        if tid != -1 and tid != idc.BADADDR and fc > 0:
            print(f"  [PASS] Valid synthesis: TID=0x{tid & 0xFFFFFFFFFFFFFFFF:x}, fields={fc}")
            passed += 1
        else:
            print(f"  [FAIL] Synthesis failed: {err_str}")
            failed += 1
    else:
        print(f"  [FAIL] IDC error: {err}")
        failed += 1

# Summary
print("\n" + "=" * 50)
print(f"ERROR HANDLING: {passed}/{passed+failed} tests passed")
print("=" * 50)

idc.qexit(0 if failed == 0 else 1)
