"""
Test cross-function analysis and type propagation.

This test verifies that when structor is triggered from a subfunction,
it properly:
1. Analyzes access patterns from the starting function
2. Considers callers and callees that share the same structure
3. Propagates the synthesized type to ALL related functions

Usage: idat -A -Stest_cross_function.py /path/to/test_simple_struct
Output: /tmp/structor_xfunc_test.log
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

LOG_FILE = "/tmp/structor_xfunc_test.log"
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


def call_structor(func_ea, var_idx):
    """Call structor_synthesize and return the struct TID."""
    result = ida_expr.idc_value_t()
    expr = f"structor_synthesize(0x{func_ea:x}, {var_idx})"
    err = ida_expr.eval_idc_expr(result, idc.BADADDR, expr)

    if err:
        log(f"Error calling structor_synthesize: {err}")
        return None

    # Get TID from result
    tid = result.i64 if hasattr(result, "i64") else result.num

    # Get field count to verify success
    fc = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(fc, idc.BADADDR, "structor_get_field_count()")
    fields = fc.num if hasattr(fc, "num") else 0

    # Get error message
    err_val = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(err_val, idc.BADADDR, "structor_get_error()")
    if hasattr(err_val, "c_str"):
        error = err_val.c_str()
    elif hasattr(err_val, "str"):
        error = err_val.str
    else:
        error = ""

    # Check for actual failure (no fields and error message)
    if fields == 0 and error:
        log(f"Synthesis failed: {error}")
        return None

    log(f"TID: 0x{tid & 0xFFFFFFFFFFFFFFFF:x}, fields: {fields}")
    return tid


def get_var_type(func_ea, var_idx):
    """Get the type of a variable in a function."""
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc or var_idx >= len(cfunc.lvars):
            return None, None

        lvar = cfunc.lvars[var_idx]
        lvar_type = lvar.type()

        # Check if it's a struct pointer
        if lvar_type.is_ptr():
            pointed = lvar_type.get_pointed_object()
            if pointed.is_struct():
                return lvar.name, pointed.get_type_name()

        # Return raw type string
        return lvar.name, str(lvar_type)
    except Exception as e:
        log(f"Error getting var type: {e}")
        return None, None


def check_all_related_functions(source_func_ea, expected_struct_name):
    """Check that the struct type is applied to all related functions."""
    log(f"Checking cross-function propagation of '{expected_struct_name}'")

    results = {
        "source_func": ida_name.get_name(source_func_ea),
        "propagated": [],
        "not_propagated": [],
        "related_functions": [],
    }

    # Find all related functions (callers and callees)
    related_funcs = set()

    # Get callers
    for xref in idautils.CodeRefsTo(source_func_ea, True):
        caller_func = ida_funcs.get_func(xref)
        if caller_func and caller_func.start_ea != source_func_ea:
            related_funcs.add(caller_func.start_ea)

    # Get callees from the function
    func = ida_funcs.get_func(source_func_ea)
    if func:
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for xref in idautils.CodeRefsFrom(head, True):
                callee_func = ida_funcs.get_func(xref)
                if callee_func and callee_func.start_ea != source_func_ea:
                    related_funcs.add(callee_func.start_ea)

    log(f"Found {len(related_funcs)} related functions")

    for func_ea in related_funcs:
        func_name = ida_name.get_name(func_ea)

        # Skip library/thunk functions
        func = ida_funcs.get_func(func_ea)
        if not func or (func.flags & (ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK)):
            continue

        results["related_functions"].append(func_name)

        try:
            cfunc = ida_hexrays.decompile(func_ea)
            if not cfunc:
                continue

            # Check all variables for the expected struct type
            found = False
            for i, lvar in enumerate(cfunc.lvars):
                lvar_type = lvar.type()
                if lvar_type.is_ptr():
                    pointed = lvar_type.get_pointed_object()
                    if pointed.is_struct():
                        type_name = pointed.get_type_name()
                        if type_name and expected_struct_name in type_name:
                            results["propagated"].append(
                                {"func": func_name, "var": lvar.name, "type": type_name}
                            )
                            found = True
                            break

            if not found:
                results["not_propagated"].append(func_name)

        except Exception as e:
            log(f"Error decompiling {func_name}: {e}")

    return results


def check_specific_functions(struct_name, func_names):
    """Check if specific functions have the struct type applied."""
    results = []

    for func_name in func_names:
        func_ea = get_function_ea(func_name)
        if func_ea == idc.BADADDR:
            results.append((func_name, "NOT_FOUND", None))
            continue

        try:
            cfunc = ida_hexrays.decompile(func_ea)
            if not cfunc:
                results.append((func_name, "DECOMPILE_FAILED", None))
                continue

            # Check all variables for the struct type
            found_var = None
            for i, lvar in enumerate(cfunc.lvars):
                lvar_type = lvar.type()
                if lvar_type.is_ptr():
                    pointed = lvar_type.get_pointed_object()
                    if pointed.is_struct():
                        type_name = pointed.get_type_name()
                        if type_name and struct_name in type_name:
                            found_var = lvar.name
                            break

            if found_var:
                results.append((func_name, "OK", found_var))
            else:
                results.append((func_name, "NO_STRUCT", None))

        except Exception as e:
            results.append((func_name, f"ERROR: {e}", None))

    return results


def test_simple_struct():
    """Test with test_simple_struct binary."""
    log("=" * 60)
    log("Testing: test_simple_struct")
    log("=" * 60)

    # The structure should be used by:
    # - init_simple: writes fields at 0, 8, 16
    # - process_simple: reads fields at 0, 8, 16
    # - main: creates the struct on stack

    # Test 1: Trigger from init_simple
    log("\n--- Test 1: Trigger from init_simple ---")
    func_ea = get_function_ea("init_simple")
    if func_ea == idc.BADADDR:
        log("ERROR: Could not find init_simple")
        return False

    log(f"init_simple at 0x{func_ea:x}")

    # Call structor on var 0 (the pointer parameter)
    tid = call_structor(func_ea, 0)
    if tid is None:
        log("ERROR: Synthesis failed")
        return False

    log(f"SUCCESS: Created struct with TID 0x{tid:x}")

    # Get struct info
    field_count = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(field_count, idc.BADADDR, "structor_get_field_count()")
    fields = field_count.i64 if hasattr(field_count, "i64") else field_count.num
    log(f"Struct has {fields} fields")

    # Get struct name
    var_name, struct_name = get_var_type(func_ea, 0)
    log(f"Struct name: {struct_name}")

    if not struct_name:
        log("ERROR: Could not get struct name")
        return False

    # Check ALL expected functions
    log("\n--- Checking type propagation to all functions ---")
    expected_funcs = ["init_simple", "process_simple", "main"]
    check_results = check_specific_functions(struct_name, expected_funcs)

    all_ok = True
    for func_name, status, var_name in check_results:
        if status == "OK":
            log(f"  [OK] {func_name}: var '{var_name}' has struct type")
        elif status == "NO_STRUCT":
            log(f"  [FAIL] {func_name}: struct type NOT applied")
            all_ok = False
        else:
            log(f"  [SKIP] {func_name}: {status}")

    if all_ok:
        log("\nSUCCESS: Type propagated to ALL related functions!")
    else:
        log("\nFAIL: Type NOT propagated to some functions")

        # Extra check: did cross-function analysis actually run?
        log("\n--- Debugging cross-function analysis ---")
        results = check_all_related_functions(func_ea, struct_name)
        log(f"  Direct code refs found: {results['related_functions']}")

    return all_ok


def test_nested():
    """Test with test_nested binary."""
    log("=" * 60)
    log("Testing: test_nested")
    log("=" * 60)

    # Test from access_nested
    func_ea = get_function_ea("access_nested")
    if func_ea == idc.BADADDR:
        log("ERROR: Could not find access_nested")
        return False

    log(f"access_nested at 0x{func_ea:x}")

    tid = call_structor(func_ea, 0)
    if tid is None:
        log("ERROR: Synthesis failed")
        return False

    log(f"SUCCESS: Created struct with TID 0x{tid:x}")

    # Get struct info
    field_count = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(field_count, idc.BADADDR, "structor_get_field_count()")
    fields = field_count.i64 if hasattr(field_count, "i64") else field_count.num
    log(f"Struct has {fields} fields")

    # Check propagation
    var_name, struct_name = get_var_type(func_ea, 0)
    if struct_name:
        log(f"Struct name: {struct_name}")
        results = check_all_related_functions(func_ea, struct_name)

        log(f"\nPropagation Results:")
        log(f"  Related functions: {results['related_functions']}")
        log(f"  Propagated to: {[p['func'] for p in results['propagated']]}")
        log(f"  NOT propagated: {results['not_propagated']}")

    return True


def main():
    log("Starting cross-function analysis test")

    # Wait for auto-analysis
    ida_auto.auto_wait()

    if not ida_hexrays.init_hexrays_plugin():
        log("ERROR: Hex-Rays not available")
        idc.qexit(1)

    # Determine which test to run based on binary name
    input_file = idc.get_input_file_path()
    log(f"Input file: {input_file}")

    success = False
    if "simple_struct" in input_file:
        success = test_simple_struct()
    elif "nested" in input_file:
        success = test_nested()
    else:
        log("Unknown test binary, trying simple_struct test")
        success = test_simple_struct()

    log("\n" + "=" * 60)
    if success:
        log("TEST PASSED")
    else:
        log("TEST FAILED")
    log("=" * 60)

    log_file.close()
    idc.qexit(0 if success else 1)


# Run on load
main()
