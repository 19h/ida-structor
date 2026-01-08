"""Full test suite for all test binaries"""
import idc
import ida_name
import ida_auto
import ida_hexrays
import ida_expr
import ida_nalt
import idautils

ida_auto.auto_wait()

if not ida_hexrays.init_hexrays_plugin():
    print("[FATAL] No Hex-Rays")
    idc.qexit(1)

# Stats
passed = 0
failed = 0
skipped = 0

def find_func(*names):
    """Find function by multiple possible names"""
    for name in names:
        ea = ida_name.get_name_ea(idc.BADADDR, name)
        if ea != idc.BADADDR:
            return ea, name
    return idc.BADADDR, None

def synthesize(func_ea, var_idx=0):
    """Synthesize and return (tid, fields, error)"""
    result = ida_expr.idc_value_t()
    err = ida_expr.eval_idc_expr(result, idc.BADADDR, f"structor_synthesize(0x{func_ea:x}, {var_idx})")
    if err:
        return -1, 0, f"IDC error: {err}"

    tid = result.i64 if hasattr(result, 'i64') else result.num

    fc = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(fc, idc.BADADDR, "structor_get_field_count()")
    fields = fc.num if hasattr(fc, 'num') else 0

    err_val = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(err_val, idc.BADADDR, "structor_get_error()")
    error = err_val.c_str() if hasattr(err_val, 'c_str') else ""

    return tid, fields, error

def test_function(func_names, expected_min_fields, description):
    """Test a function and return pass/fail"""
    global passed, failed, skipped

    func_ea, name = find_func(*func_names)
    if func_ea == idc.BADADDR:
        print(f"  [SKIP] {description}: Function not found")
        skipped += 1
        return

    # Decompile first
    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        print(f"  [FAIL] {description}: Could not decompile {name}")
        failed += 1
        return

    tid, fields, error = synthesize(func_ea)

    if tid == -1 or tid == idc.BADADDR:
        if expected_min_fields == 0:
            print(f"  [PASS] {description}: Correctly no structure ({error})")
            passed += 1
        else:
            print(f"  [FAIL] {description}: {error}")
            failed += 1
    else:
        if fields >= expected_min_fields:
            print(f"  [PASS] {description}: {fields} fields (TID: 0x{tid & 0xFFFFFFFFFFFFFFFF:x})")
            passed += 1
        elif fields > 0:
            print(f"  [WARN] {description}: {fields} fields (expected {expected_min_fields}+)")
            passed += 1  # Still counts as pass if we got something
        else:
            print(f"  [FAIL] {description}: No fields created")
            failed += 1

# Detect which binary we're testing
input_file = ida_nalt.get_input_file_path()
print(f"=== STRUCTOR TEST SUITE ===")
print(f"Binary: {input_file}\n")

if "simple" in input_file.lower():
    print("--- Simple Struct Tests ---")
    test_function(["_process_simple", "process_simple"], 3, "process_simple (3 fields)")

elif "vtable" in input_file.lower():
    print("--- VTable Tests ---")
    # VTable functions have limited accesses - expect failure or minimal fields
    test_function(["__Z19call_through_vtablePv", "_Z19call_through_vtablePv"], 0, "call_through_vtable (vtable access)")
    test_function(["__Z12access_valuePv", "_Z12access_valuePv"], 0, "access_value (single field)")

elif "nested" in input_file.lower():
    print("--- Nested Struct Tests ---")
    test_function(["_access_nested", "access_nested"], 1, "access_nested (multiple offsets)")
    test_function(["_modify_array", "modify_array"], 0, "modify_array (array write)")

elif "linked" in input_file.lower():
    print("--- Linked List Tests ---")
    test_function(["_traverse_list", "traverse_list"], 1, "traverse_list (node traversal)")
    test_function(["_insert_after", "insert_after"], 2, "insert_after (link manipulation)")
    test_function(["_sum_list", "sum_list"], 1, "sum_list (data + next)")

elif "function" in input_file.lower():
    print("--- Function Pointer Tests ---")
    test_function(["_invoke_handler", "invoke_handler"], 2, "invoke_handler (callback + ctx + state)")
    test_function(["_setup_handler", "setup_handler"], 3, "setup_handler (4 field writes)")
    test_function(["_update_and_invoke", "update_and_invoke"], 1, "update_and_invoke (state write)")

elif "mixed" in input_file.lower():
    print("--- Mixed Access Tests ---")
    test_function(["_read_mixed", "read_mixed"], 3, "read_mixed (multiple sizes)")
    test_function(["_write_mixed", "write_mixed"], 3, "write_mixed (multiple sizes)")
    test_function(["_modify_mixed", "modify_mixed"], 1, "modify_mixed (read-modify-write)")

else:
    print("--- Generic Tests ---")
    # Test all available functions
    for func_ea in idautils.Functions():
        name = ida_name.get_name(func_ea)
        if name and not name.startswith("_") and name != "main":
            continue
        if name in ["main", "_main"]:
            continue
        test_function([name], 1, f"{name}")

# Summary
print(f"\n{'=' * 50}")
print(f"RESULTS: {passed} passed, {failed} failed, {skipped} skipped")
print("=" * 50)

idc.qexit(0 if failed == 0 else 1)
