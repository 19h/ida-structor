"""
Test cross-function analysis with linked list binary.

This test verifies that when structor is triggered from ANY function
(traverse_list, sum_list, or insert_after), it properly:
1. Traces back to main() via xrefs
2. Discovers ALL sibling callees that receive the same struct
3. Collects access patterns from ALL related functions

Expected struct layout:
  offset 0x00: pointer (next) - accessed by traverse_list, sum_list, insert_after
  offset 0x08: pointer (prev) - accessed by insert_after only
  offset 0x10: int32 (data)   - accessed by traverse_list, sum_list

Usage: idat -A -Stest_linked_list_xfunc.py /path/to/test_linked_list
Output: /tmp/structor_linked_list_xfunc.log
"""

import idc
import ida_name
import ida_auto
import ida_hexrays
import ida_expr
import ida_funcs
import ida_typeinf
import idautils
import sys

LOG_FILE = "/tmp/structor_linked_list_xfunc.log"
log_file = open(LOG_FILE, "w")


def log(msg):
    log_file.write(f"[XFUNC] {msg}\n")
    log_file.flush()
    print(f"[XFUNC] {msg}")


def get_function_ea(name):
    """Get function EA by name, trying with and without underscore prefix."""
    ea = ida_name.get_name_ea(idc.BADADDR, f"_{name}")
    if ea == idc.BADADDR:
        ea = ida_name.get_name_ea(idc.BADADDR, name)
    return ea


def call_structor_analyze(func_ea, var_idx):
    """
    Call structor_analyze to get cross-function analysis info.
    Returns dict with analysis results.
    """
    result = ida_expr.idc_value_t()

    # First, run analysis
    expr = f"structor_analyze(0x{func_ea:x}, {var_idx})"
    err = ida_expr.eval_idc_expr(result, idc.BADADDR, expr)

    if err:
        log(f"Error calling structor_analyze: {err}")
        return None

    # Get cross-function stats
    stats = {}

    # Get functions analyzed count
    fc = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(fc, idc.BADADDR, "structor_get_functions_analyzed()")
    stats["functions_analyzed"] = fc.i64 if hasattr(fc, "i64") else (fc.num if hasattr(fc, "num") else 0)

    # Get total accesses
    ac = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(ac, idc.BADADDR, "structor_get_access_count()")
    stats["total_accesses"] = ac.i64 if hasattr(ac, "i64") else (ac.num if hasattr(ac, "num") else 0)

    # Get flow edges (sibling connections)
    fe = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(fe, idc.BADADDR, "structor_get_flow_edges()")
    stats["flow_edges"] = fe.i64 if hasattr(fe, "i64") else (fe.num if hasattr(fe, "num") else 0)

    # Get contributing functions list
    cf = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(cf, idc.BADADDR, "structor_get_contributing_functions()")
    if hasattr(cf, "c_str"):
        stats["contributing_functions"] = cf.c_str()
    elif hasattr(cf, "str"):
        stats["contributing_functions"] = cf.str
    else:
        stats["contributing_functions"] = ""

    return stats


def call_structor_synthesize(func_ea, var_idx):
    """Call structor_synthesize and return the struct TID."""
    result = ida_expr.idc_value_t()
    expr = f"structor_synthesize(0x{func_ea:x}, {var_idx})"
    err = ida_expr.eval_idc_expr(result, idc.BADADDR, expr)

    if err:
        log(f"Error calling structor_synthesize: {err}")
        return None, {}

    # Get TID from result
    tid = result.i64 if hasattr(result, "i64") else result.num

    # Get field count
    fc = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(fc, idc.BADADDR, "structor_get_field_count()")
    fields = fc.num if hasattr(fc, "num") else 0

    # Get struct size
    sz = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(sz, idc.BADADDR, "structor_get_struct_size()")
    size = sz.num if hasattr(sz, "num") else 0

    # Get error message
    err_val = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(err_val, idc.BADADDR, "structor_get_error()")
    if hasattr(err_val, "c_str"):
        error = err_val.c_str()
    elif hasattr(err_val, "str"):
        error = err_val.str
    else:
        error = ""

    if fields == 0 and error:
        log(f"Synthesis failed: {error}")
        return None, {}

    info = {
        "tid": tid,
        "field_count": fields,
        "size": size,
    }

    return tid, info


def get_all_field_offsets(tid):
    """Get all field offsets from a synthesized struct."""
    offsets = []

    # Get field count
    fc = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(fc, idc.BADADDR, "structor_get_field_count()")
    field_count = fc.num if hasattr(fc, "num") else 0

    for i in range(field_count):
        off = ida_expr.idc_value_t()
        ida_expr.eval_idc_expr(off, idc.BADADDR, f"structor_get_field_offset({i})")
        offset = off.num if hasattr(off, "num") else -1

        sz = ida_expr.idc_value_t()
        ida_expr.eval_idc_expr(sz, idc.BADADDR, f"structor_get_field_size({i})")
        size = sz.num if hasattr(sz, "num") else 0

        ty = ida_expr.idc_value_t()
        ida_expr.eval_idc_expr(ty, idc.BADADDR, f"structor_get_field_type({i})")
        type_str = ""
        if hasattr(ty, "c_str"):
            type_str = ty.c_str()
        elif hasattr(ty, "str"):
            type_str = ty.str

        offsets.append((offset, size, type_str))

    return offsets


def test_cross_function_discovery(func_name, expected_siblings):
    """
    Test that starting analysis from func_name discovers all expected siblings.

    Returns:
        (success, discovered_funcs, missing_funcs, extra_accesses)
    """
    log(f"\n--- Testing from {func_name} ---")

    func_ea = get_function_ea(func_name)
    if func_ea == idc.BADADDR:
        log(f"ERROR: Could not find {func_name}")
        return False, [], expected_siblings, {}

    log(f"{func_name} at 0x{func_ea:x}")

    # Run synthesis (which uses cross-function analysis)
    tid, info = call_structor_synthesize(func_ea, 0)

    if tid is None:
        log("ERROR: Synthesis failed")
        return False, [], expected_siblings, {}

    log(f"Synthesis succeeded: TID=0x{tid:x}, fields={info.get('field_count', 0)}, size={info.get('size', 0)}")

    # Get field information
    fields = get_all_field_offsets(tid)
    log(f"Fields found:")
    for offset, size, type_str in fields:
        log(f"  offset 0x{offset:02x}: size={size}, type={type_str}")

    # Expected offsets based on Node struct:
    # - offset 0x00: pointer (next)
    # - offset 0x08: pointer (prev)
    # - offset 0x10: int32 (data)
    expected_offsets = {0x00, 0x08, 0x10}
    found_offsets = {off for off, _, _ in fields}

    missing_offsets = expected_offsets - found_offsets

    if missing_offsets:
        log(f"WARNING: Missing expected offsets: {[hex(o) for o in missing_offsets]}")

        # This indicates sibling callees were NOT analyzed
        if 0x08 in missing_offsets:
            log("  -> offset 0x08 (prev) is only accessed in insert_after")
            log("  -> This suggests insert_after was NOT discovered as a sibling!")

    success = len(missing_offsets) == 0

    return success, found_offsets, missing_offsets, info


def main():
    log("=" * 70)
    log("LINKED LIST CROSS-FUNCTION ANALYSIS VERIFICATION TEST")
    log("=" * 70)
    log("")
    log("This test verifies that struct reconstruction considers ALL xref callees.")
    log("")
    log("Expected behavior:")
    log("  When starting from traverse_list or sum_list:")
    log("  1. Trace backward to main() (the caller)")
    log("  2. Trace forward from main() to discover ALL sibling callees")
    log("  3. Collect access patterns from traverse_list, sum_list, AND insert_after")
    log("")
    log("Expected struct layout (if ALL siblings analyzed):")
    log("  offset 0x00: pointer (next) - traverse_list, sum_list, insert_after")
    log("  offset 0x08: pointer (prev) - insert_after ONLY")
    log("  offset 0x10: int32 (data)   - traverse_list, sum_list")
    log("")

    # Wait for auto-analysis
    ida_auto.auto_wait()

    if not ida_hexrays.init_hexrays_plugin():
        log("ERROR: Hex-Rays not available")
        idc.qexit(1)

    # Test 1: Start from traverse_list
    log("=" * 70)
    log("TEST 1: Start analysis from traverse_list")
    log("=" * 70)
    success1, found1, missing1, info1 = test_cross_function_discovery(
        "traverse_list",
        ["main", "sum_list", "insert_after"]
    )

    # Test 2: Start from sum_list
    log("=" * 70)
    log("TEST 2: Start analysis from sum_list")
    log("=" * 70)
    success2, found2, missing2, info2 = test_cross_function_discovery(
        "sum_list",
        ["main", "traverse_list", "insert_after"]
    )

    # Summary
    log("")
    log("=" * 70)
    log("SUMMARY")
    log("=" * 70)

    log("")
    log("Test 1 (from traverse_list):")
    log(f"  Found offsets: {[hex(o) for o in sorted(found1)]}")
    log(f"  Missing offsets: {[hex(o) for o in sorted(missing1)]}")
    log(f"  Result: {'PASS' if success1 else 'FAIL'}")

    log("")
    log("Test 2 (from sum_list):")
    log(f"  Found offsets: {[hex(o) for o in sorted(found2)]}")
    log(f"  Missing offsets: {[hex(o) for o in sorted(missing2)]}")
    log(f"  Result: {'PASS' if success2 else 'FAIL'}")

    overall_success = success1 and success2

    log("")
    log("=" * 70)
    if overall_success:
        log("OVERALL: PASS - All xref callees properly considered!")
        log("  -> insert_after (sibling callee) was discovered")
        log("  -> offset 0x08 (prev pointer) was found in synthesized struct")
    else:
        log("OVERALL: FAIL - Some xref callees NOT considered!")
        if 0x08 in missing1 or 0x08 in missing2:
            log("  -> insert_after (sibling callee) was NOT discovered")
            log("  -> offset 0x08 (prev pointer) is MISSING from synthesized struct")
            log("")
            log("This indicates a bug in cross-function sibling discovery!")
    log("=" * 70)

    log_file.close()
    idc.qexit(0 if overall_success else 1)


# Run on load
main()
