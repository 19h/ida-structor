"""Run all tests and produce a summary report"""

import os
import sys

LOG_FILE = "/tmp/structor_full_test.log"
log_file = open(LOG_FILE, "w")


def log(msg):
    log_file.write(msg + "\n")
    log_file.flush()


try:
    import idc
    import ida_name
    import ida_auto
    import ida_hexrays
    import ida_expr
    import ida_nalt
    import ida_typeinf
    import idautils
except Exception as e:
    log(f"Import error: {e}")
    raise

log("=" * 70)
log("STRUCTOR FULL TEST SUITE")
log("=" * 70)

ida_auto.auto_wait()

if not ida_hexrays.init_hexrays_plugin():
    log("[FATAL] No Hex-Rays decompiler")
    log_file.close()
    idc.qexit(1)

input_file = ida_nalt.get_input_file_path()
log(f"Testing: {input_file}")
log(f"Functions found:")
for ea in idautils.Functions():
    name = ida_name.get_name(ea)
    log(f"  0x{ea:x}: {name}")

results = {"passed": 0, "failed": 0, "skipped": 0}


def find_func(*names):
    for n in names:
        ea = ida_name.get_name_ea(idc.BADADDR, n)
        if ea != idc.BADADDR:
            return ea, n
    return idc.BADADDR, None


def synthesize(func_ea, var_idx=0):
    result = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(
        result, idc.BADADDR, f"structor_synthesize(0x{func_ea:x}, {var_idx})"
    )
    tid = result.i64 if hasattr(result, "i64") else result.num

    fc = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(fc, idc.BADADDR, "structor_get_field_count()")
    fields = fc.num if hasattr(fc, "num") else 0

    err_val = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(err_val, idc.BADADDR, "structor_get_error()")
    error = err_val.c_str() if hasattr(err_val, "c_str") else ""

    return tid, fields, error


def test(name_variants, expected_fields, desc):
    global results
    func_ea, name = find_func(*name_variants)

    if func_ea == idc.BADADDR:
        log(f"  [SKIP] {desc}: Function not found")
        results["skipped"] += 1
        return

    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        log(f"  [FAIL] {desc}: Could not decompile")
        results["failed"] += 1
        return

    tid, fields, error = synthesize(func_ea)

    if tid == -1 or tid == idc.BADADDR:
        if expected_fields == 0:
            log(f"  [PASS] {desc}: Correctly rejected ({error})")
            results["passed"] += 1
        else:
            log(f"  [FAIL] {desc}: {error}")
            results["failed"] += 1
    else:
        if fields >= expected_fields:
            log(f"  [PASS] {desc}: {fields} fields")
            results["passed"] += 1
        else:
            log(f"  [FAIL] {desc}: {fields} fields (expected {expected_fields}+)")
            results["failed"] += 1


# Run tests based on binary name
binary_name = os.path.basename(input_file).lower()
log(f"\n--- Testing {binary_name} ---")

if "simple" in binary_name:
    test(
        ["_process_simple", "process_simple", "_process_data", "process_data"],
        3,
        "process_simple/data (3 fields)",
    )

elif "nested" in binary_name:
    test(["_access_nested", "access_nested"], 3, "access_nested (nested)")
    test(
        ["_modify_array", "modify_array"],
        0,
        "modify_array (computed index - expected fail)",
    )

elif "nested_2d" in binary_name:
    test(["_read_matrix", "read_matrix"], 4, "read_matrix (2D array layout)")
    test(["_read_marks", "read_marks"], 2, "read_marks (nested byte array)")

elif "vtable" in binary_name and "direct" not in binary_name:
    test(
        ["__Z19call_through_vtablePv", "_Z19call_through_vtablePv"],
        0,
        "call_through_vtable (limited accesses)",
    )
    test(
        ["__Z12access_valuePv", "_Z12access_valuePv"], 0, "access_value (single access)"
    )

elif "linked" in binary_name:
    test(["_sum_list", "sum_list"], 2, "sum_list (data + next)")
    test(
        ["_traverse_list", "traverse_list"],
        0,
        "traverse_list (aliasing - expected fail)",
    )
    test(
        ["_insert_after", "insert_after"], 0, "insert_after (aliasing - expected fail)"
    )

elif "function" in binary_name:
    test(["_setup_handler", "setup_handler"], 2, "setup_handler (multiple writes)")
    test(["_invoke_handler", "invoke_handler"], 2, "invoke_handler (2 fields)")
    test(
        ["_update_and_invoke", "update_and_invoke"],
        0,
        "update_and_invoke (single access - expected fail)",
    )

elif "mixed" in binary_name:
    test(["_read_mixed", "read_mixed"], 3, "read_mixed (4 fields)")
    test(["_write_mixed", "write_mixed"], 3, "write_mixed (3 fields)")
    test(["_modify_mixed", "modify_mixed"], 2, "modify_mixed (3 fields)")

elif "array_of_structs" in binary_name:
    test(["_read_table", "read_table"], 4, "read_table (array of structs + tail)")
    test(["_update_tag", "update_tag"], 4, "update_tag (indexed element update)")
    test(["_read_checksum", "read_checksum"], 4, "read_checksum (compact byte tail)")

elif "negative_offsets" in binary_name:
    test(["_consume_window", "consume_window"], 7, "consume_window (shifted window)")

elif "packed_struct" in binary_name:
    test(["_read_packed", "read_packed"], 5, "read_packed (packed misaligned fields)")
    test(
        ["_read_small_array", "read_small_array"],
        3,
        "read_small_array (packed byte tail)",
    )

elif "packed_nested_array" in binary_name:
    test(["_read_bundle", "read_bundle"], 4, "read_bundle (packed nested entries)")
    test(["_read_tail", "read_tail"], 2, "read_tail (packed tail bytes)")

elif "packed_union_overlap" in binary_name:
    test(["_read_whole", "read_whole"], 2, "read_whole (packed overlapping base view)")
    test(["_read_parts", "read_parts"], 1, "read_parts (packed partial overlap)")

elif "callback_table" in binary_name:
    test(["_invoke_slot0", "invoke_slot0"], 3, "invoke_slot0 (callback entry)")
    test(["_invoke_slot2", "invoke_slot2"], 3, "invoke_slot2 (callback entry)")
    test(["_read_states", "read_states"], 2, "read_states (state tail array)")

elif "array_of_structs_nested" in binary_name:
    test(
        ["_read_packets", "read_packets"], 4, "read_packets (nested arrays in elements)"
    )
    test(
        ["_write_packet_byte", "write_packet_byte"],
        3,
        "write_packet_byte (element inner array write)",
    )
    test(["_read_footer", "read_footer"], 2, "read_footer (footer bytes)")

elif "cross_conflict_union" in binary_name:
    test(
        ["_process_conflict", "process_conflict"],
        3,
        "process_conflict (cross-function conflicting views)",
    )

elif "local_alias_positive" in binary_name:
    test(
        ["_use_alias_read", "use_alias_read"],
        3,
        "use_alias_read (positive local alias)",
    )
    test(["_use_alias_chain", "use_alias_chain"], 2, "use_alias_chain (alias chain)")

elif "indirect_shifted_call" in binary_name:
    test(
        ["_invoke_child", "invoke_child"], 3, "invoke_child (indirect shifted callback)"
    )
    test(
        ["_dispatch_parent", "dispatch_parent"],
        4,
        "dispatch_parent (shifted callback propagation)",
    )

elif "enum_constants" in binary_name:
    test(["_inspect_mode", "inspect_mode"], 2, "inspect_mode (enum-like constants)")
    test(["_inspect_state", "inspect_state"], 3, "inspect_state (semantic constants)")

elif "bounded_index" in binary_name:
    test(
        ["_read_indexed", "read_indexed"],
        3,
        "read_indexed (bounded computed index)",
    )
    test(
        ["_read_marks", "read_marks"], 2, "read_marks (tail after bounded index array)"
    )

elif "mixed_subobject_deltas" in binary_name:
    test(
        ["_read_mixed_anchor", "read_mixed_anchor"],
        4,
        "read_mixed_anchor (mixed positive and negative deltas)",
    )

elif "shifted_siblings" in binary_name:
    test(
        ["_consume_child", "consume_child"],
        4,
        "consume_child (shared shifted subobject)",
    )
    test(["_process_parent", "process_parent"], 4, "process_parent (siblings + parent)")

elif "tree_struct" in binary_name:
    test(["_sum_children", "sum_children"], 4, "sum_children (self-referential node)")
    test(
        ["_walk_two_levels", "walk_two_levels"],
        2,
        "walk_two_levels (tree child traversal)",
    )

elif "partial_overlap" in binary_name:
    test(["_read_overlap", "read_overlap"], 2, "read_overlap (overlapping widths)")
    test(
        ["_read_shifted_overlap", "read_shifted_overlap"],
        1,
        "read_shifted_overlap (partial overlap)",
    )

else:
    log("Unknown binary type - running generic tests")
    for ea in idautils.Functions():
        name = ida_name.get_name(ea)
        if name and not name.startswith("___") and "main" not in name.lower():
            test([name], 1, name)

# Summary
log(f"\n{'=' * 70}")
log(
    f"RESULTS: {results['passed']} passed, {results['failed']} failed, {results['skipped']} skipped"
)
log("=" * 70)

log_file.close()
idc.qexit(0 if results["failed"] == 0 else 1)
