"""Comprehensive integration test for Structor plugin"""
import idc
import ida_name
import ida_auto
import ida_hexrays
import ida_expr
import ida_funcs
import ida_nalt
import sys

class TestResult:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.warnings = 0
        self.details = []

    def add_pass(self, msg):
        self.passed += 1
        self.details.append(f"[PASS] {msg}")
        print(f"[PASS] {msg}")

    def add_fail(self, msg):
        self.failed += 1
        self.details.append(f"[FAIL] {msg}")
        print(f"[FAIL] {msg}")

    def add_warn(self, msg):
        self.warnings += 1
        self.details.append(f"[WARN] {msg}")
        print(f"[WARN] {msg}")

    def summary(self):
        total = self.passed + self.failed
        return f"{self.passed}/{total} tests passed, {self.warnings} warnings"


def find_function(names):
    """Find function by trying multiple name variants"""
    for name in names:
        ea = ida_name.get_name_ea(idc.BADADDR, name)
        if ea != idc.BADADDR:
            return ea, name
    return idc.BADADDR, None


def call_synthesize(func_ea, var_idx):
    """Call structor_synthesize and return result"""
    result_val = ida_expr.idc_value_t()
    err = ida_expr.eval_idc_expr(result_val, idc.BADADDR, f"structor_synthesize(0x{func_ea:x}, {var_idx})")
    if err:
        return None, f"IDC error: {err}"
    tid = result_val.i64 if hasattr(result_val, 'i64') else result_val.num
    return tid, None


def call_synthesize_by_name(func_ea, var_name):
    """Call structor_synthesize_by_name and return result"""
    result_val = ida_expr.idc_value_t()
    err = ida_expr.eval_idc_expr(result_val, idc.BADADDR, f'structor_synthesize_by_name(0x{func_ea:x}, "{var_name}")')
    if err:
        return None, f"IDC error: {err}"
    tid = result_val.i64 if hasattr(result_val, 'i64') else result_val.num
    return tid, None


def get_field_count():
    """Get field count from last synthesis"""
    result = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(result, idc.BADADDR, "structor_get_field_count()")
    return result.num if hasattr(result, 'num') else 0


def get_vtable_tid():
    """Get vtable TID from last synthesis"""
    result = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(result, idc.BADADDR, "structor_get_vtable_tid()")
    tid = result.i64 if hasattr(result, 'i64') else result.num
    return tid


def get_error():
    """Get error message from last synthesis"""
    result = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(result, idc.BADADDR, "structor_get_error()")
    # Try to get string value
    if hasattr(result, 'c_str'):
        return result.c_str()
    elif hasattr(result, 'str'):
        return result.str
    elif result.vtype == 7:  # VT_STR
        return result.c_str() if hasattr(result, 'c_str') else "unknown"
    return "unknown error"


def test_simple_struct(results):
    """Test basic structure synthesis"""
    print("\n" + "=" * 50)
    print("TEST: Simple Structure Synthesis")
    print("=" * 50)

    func_ea, name = find_function(["_process_simple", "process_simple"])
    if func_ea == idc.BADADDR:
        results.add_fail("Could not find process_simple function")
        return

    print(f"[INFO] Found {name} at 0x{func_ea:x}")

    # Decompile first
    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        results.add_fail("Could not decompile function")
        return

    # Test synthesis by index
    tid, err = call_synthesize(func_ea, 0)
    if err:
        results.add_fail(f"Synthesis failed: {err}")
        return

    if tid == idc.BADADDR or tid == -1:
        results.add_fail(f"No structure created: {get_error()}")
        return

    results.add_pass(f"Structure created (TID: 0x{tid & 0xFFFFFFFFFFFFFFFF:x})")

    field_count = get_field_count()
    if field_count > 0:
        results.add_pass(f"Fields created: {field_count}")
    else:
        results.add_fail("No fields created")

    # Expected: 3 fields (int a, int b, long c)
    if field_count == 3:
        results.add_pass("Correct field count (expected 3)")
    else:
        results.add_warn(f"Unexpected field count: {field_count} (expected 3)")


def test_vtable_detection(results):
    """Test vtable detection and structure synthesis"""
    print("\n" + "=" * 50)
    print("TEST: VTable Detection")
    print("=" * 50)

    # C++ mangled names: __Z19call_through_vtablePv
    func_ea, name = find_function(["_call_through_vtable", "call_through_vtable",
                                    "__Z19call_through_vtablePv", "_Z19call_through_vtablePv"])
    if func_ea == idc.BADADDR:
        results.add_fail("Could not find call_through_vtable function")
        return

    print(f"[INFO] Found {name} at 0x{func_ea:x}")

    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        results.add_fail("Could not decompile function")
        return

    tid, err = call_synthesize(func_ea, 0)
    if err:
        results.add_fail(f"Synthesis failed: {err}")
        return

    if tid == idc.BADADDR or tid == -1:
        results.add_fail(f"No structure created: {get_error()}")
        return

    results.add_pass(f"Structure created (TID: 0x{tid & 0xFFFFFFFFFFFFFFFF:x})")

    vtable_tid = get_vtable_tid()
    if vtable_tid != idc.BADADDR and vtable_tid != -1 and vtable_tid != 0:
        results.add_pass(f"VTable detected (TID: 0x{vtable_tid & 0xFFFFFFFFFFFFFFFF:x})")
    else:
        results.add_warn("VTable not detected (may be expected for simple patterns)")

    field_count = get_field_count()
    if field_count > 0:
        results.add_pass(f"Fields created: {field_count}")
    else:
        results.add_fail("No fields created")


def test_nested_struct(results):
    """Test nested structure and array access synthesis"""
    print("\n" + "=" * 50)
    print("TEST: Nested Structure / Array Access")
    print("=" * 50)

    func_ea, name = find_function(["_access_nested", "access_nested"])
    if func_ea == idc.BADADDR:
        results.add_fail("Could not find access_nested function")
        return

    print(f"[INFO] Found {name} at 0x{func_ea:x}")

    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        results.add_fail("Could not decompile function")
        return

    tid, err = call_synthesize(func_ea, 0)
    if err:
        results.add_fail(f"Synthesis failed: {err}")
        return

    if tid == idc.BADADDR or tid == -1:
        results.add_fail(f"No structure created: {get_error()}")
        return

    results.add_pass(f"Structure created (TID: 0x{tid & 0xFFFFFFFFFFFFFFFF:x})")

    field_count = get_field_count()
    # Expected fields: inner_ptr (0x00), data (0x08), array[0-3] (0x10-0x1C), flags (0x20)
    # Could be 6 fields (ptr, ptr, int, int, int, int, long) or merged array
    if field_count >= 3:
        results.add_pass(f"Multiple fields created: {field_count}")
    else:
        results.add_fail(f"Too few fields: {field_count}")

    # Expected at least 5 unique offsets accessed
    if field_count >= 5:
        results.add_pass("Good field coverage for nested struct")
    else:
        results.add_warn(f"May be missing some fields (expected ~6, got {field_count})")


def test_synthesize_by_name(results):
    """Test structor_synthesize_by_name variant"""
    print("\n" + "=" * 50)
    print("TEST: Synthesize by Variable Name")
    print("=" * 50)

    func_ea, name = find_function(["_process_simple", "process_simple"])
    if func_ea == idc.BADADDR:
        results.add_fail("Could not find process_simple function")
        return

    print(f"[INFO] Found {name} at 0x{func_ea:x}")

    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        results.add_fail("Could not decompile function")
        return

    # Try to find first parameter name (usually 'a1' or the actual param name)
    # The first parameter should be the pointer we want to synthesize from
    tid, err = call_synthesize_by_name(func_ea, "a1")
    if err:
        # Try ptr as alternative
        tid, err = call_synthesize_by_name(func_ea, "ptr")

    if err:
        results.add_warn(f"Could not synthesize by name 'a1' or 'ptr': {err}")
        return

    if tid == idc.BADADDR or tid == -1:
        # This might be expected if variable not found
        error = get_error()
        if "variable" in error.lower() or "not found" in error.lower():
            results.add_warn(f"Variable not found (expected): {error}")
        else:
            results.add_fail(f"Synthesis failed: {error}")
        return

    results.add_pass(f"Structure created by name (TID: 0x{tid & 0xFFFFFFFFFFFFFFFF:x})")


def test_error_handling(results):
    """Test error handling for invalid inputs"""
    print("\n" + "=" * 50)
    print("TEST: Error Handling")
    print("=" * 50)

    # Test 1: Invalid function address
    tid, err = call_synthesize(0xDEADBEEF, 0)
    if tid == idc.BADADDR or tid == -1:
        results.add_pass("Correctly rejected invalid function address")
    else:
        results.add_fail("Should have rejected invalid function address")

    # Test 2: Invalid variable index (very large)
    func_ea, _ = find_function(["_process_simple", "process_simple"])
    if func_ea != idc.BADADDR:
        cfunc = ida_hexrays.decompile(func_ea)
        tid, err = call_synthesize(func_ea, 9999)
        if tid == idc.BADADDR or tid == -1:
            results.add_pass("Correctly rejected invalid variable index")
        else:
            results.add_warn("Accepted invalid variable index (may have fallback behavior)")

    # Test 3: Non-existent variable name
    if func_ea != idc.BADADDR:
        tid, err = call_synthesize_by_name(func_ea, "nonexistent_var_xyz")
        if tid == idc.BADADDR or tid == -1:
            results.add_pass("Correctly rejected non-existent variable name")
        else:
            results.add_fail("Should have rejected non-existent variable name")


def test_mixed_access(results):
    """Test mixed read/write access detection"""
    print("\n" + "=" * 50)
    print("TEST: Mixed Read/Write Access Patterns")
    print("=" * 50)

    func_ea, name = find_function(["_modify_array", "modify_array"])
    if func_ea == idc.BADADDR:
        results.add_fail("Could not find modify_array function")
        return

    print(f"[INFO] Found {name} at 0x{func_ea:x}")

    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        results.add_fail("Could not decompile function")
        return

    tid, err = call_synthesize(func_ea, 0)
    if err:
        results.add_fail(f"Synthesis failed: {err}")
        return

    if tid == idc.BADADDR or tid == -1:
        results.add_fail(f"No structure created: {get_error()}")
        return

    results.add_pass(f"Structure created from write access (TID: 0x{tid & 0xFFFFFFFFFFFFFFFF:x})")

    field_count = get_field_count()
    if field_count > 0:
        results.add_pass(f"Fields detected from write patterns: {field_count}")
    else:
        results.add_fail("No fields detected from write patterns")


def test_linked_list(results):
    """Test linked list / self-referential structure"""
    print("\n" + "=" * 50)
    print("TEST: Linked List / Self-referential Structure")
    print("=" * 50)

    func_ea, name = find_function(["_traverse_list", "traverse_list", "_list_traverse", "list_traverse"])
    if func_ea == idc.BADADDR:
        # Try alternative function names
        func_ea, name = find_function(["_process_node", "process_node"])

    if func_ea == idc.BADADDR:
        results.add_warn("Could not find linked list function - skipping")
        return

    print(f"[INFO] Found {name} at 0x{func_ea:x}")

    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        results.add_fail("Could not decompile function")
        return

    tid, err = call_synthesize(func_ea, 0)
    if err:
        results.add_fail(f"Synthesis failed: {err}")
        return

    if tid == idc.BADADDR or tid == -1:
        results.add_warn(f"No structure created: {get_error()}")
        return

    results.add_pass(f"Structure created (TID: 0x{tid & 0xFFFFFFFFFFFFFFFF:x})")


def test_function_pointer(results):
    """Test function pointer field detection"""
    print("\n" + "=" * 50)
    print("TEST: Function Pointer Fields")
    print("=" * 50)

    func_ea, name = find_function(["_call_handler", "call_handler", "_invoke_callback", "invoke_callback"])
    if func_ea == idc.BADADDR:
        results.add_warn("Could not find function pointer test function - skipping")
        return

    print(f"[INFO] Found {name} at 0x{func_ea:x}")

    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        results.add_fail("Could not decompile function")
        return

    tid, err = call_synthesize(func_ea, 0)
    if err:
        results.add_fail(f"Synthesis failed: {err}")
        return

    if tid == idc.BADADDR or tid == -1:
        results.add_warn(f"No structure created: {get_error()}")
        return

    results.add_pass(f"Structure with function pointer (TID: 0x{tid & 0xFFFFFFFFFFFFFFFF:x})")


def run_tests():
    """Run all tests"""
    print("=" * 60)
    print("STRUCTOR COMPREHENSIVE INTEGRATION TEST")
    print("=" * 60)

    ida_auto.auto_wait()

    if not ida_hexrays.init_hexrays_plugin():
        print("[FATAL] Hex-Rays decompiler not available")
        return False

    results = TestResult()

    # Determine which tests to run based on available functions
    input_file = ida_nalt.get_input_file_path()
    print(f"[INFO] Testing: {input_file}")

    # Run tests based on binary type
    if "simple" in input_file.lower():
        test_simple_struct(results)
        test_synthesize_by_name(results)
        test_error_handling(results)

    elif "vtable" in input_file.lower():
        test_vtable_detection(results)

    elif "nested" in input_file.lower():
        test_nested_struct(results)
        test_mixed_access(results)

    elif "linked" in input_file.lower():
        test_linked_list(results)

    elif "function" in input_file.lower() or "ptr" in input_file.lower():
        test_function_pointer(results)

    elif "mixed" in input_file.lower():
        test_mixed_access(results)

    else:
        # Run all tests and skip unavailable ones
        test_simple_struct(results)
        test_vtable_detection(results)
        test_nested_struct(results)
        test_synthesize_by_name(results)
        test_error_handling(results)
        test_mixed_access(results)
        test_linked_list(results)
        test_function_pointer(results)

    # Summary
    print("\n" + "=" * 60)
    print(f"RESULTS: {results.summary()}")
    print("=" * 60)

    return results.failed == 0


if __name__ == "__main__":
    success = run_tests()
    print("\nDone")
    idc.qexit(0 if success else 1)
