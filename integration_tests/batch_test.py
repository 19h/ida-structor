"""
IDA batch test script for Structor plugin.
Run with: idat -A -S"batch_test.py" binary
"""

import sys
import idc
import ida_funcs
import ida_name
import ida_hexrays
import ida_auto
import ida_typeinf

def test_function(func_name, expected_fields):
    """Test structure synthesis on a function"""
    # Find the function
    func_ea = ida_name.get_name_ea(idc.BADADDR, "_" + func_name)
    if func_ea == idc.BADADDR:
        func_ea = ida_name.get_name_ea(idc.BADADDR, func_name)

    if func_ea == idc.BADADDR:
        print(f"ERROR: Could not find {func_name} function")
        return False

    print(f"\nTesting {func_name} at 0x{func_ea:x}")
    print("-" * 40)

    # Decompile
    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        print("  ERROR: Could not decompile")
        return False

    print(f"  Decompilation OK - {len(cfunc.get_lvars())} local variables")

    # List variables
    for i, lvar in enumerate(cfunc.get_lvars()):
        tstr = str(lvar.type()) if lvar.type() else "unknown"
        print(f"    [{i}] {lvar.name}: {tstr}")

    # Call synthesis
    print("  Calling structor_synthesize...")
    result = idc.eval_idc(f"structor_synthesize({func_ea}, 0)")
    print(f"  Result TID: {result}")

    if result == idc.BADADDR:
        print("  SYNTHESIS FAILED")
        return False

    # Check the created structure
    tif = ida_typeinf.tinfo_t()
    if tif.get_type_by_tid(result):
        name = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, tif, '', '')
        print(f"  Created type: {name}")

        # Get struct details
        if tif.is_struct():
            udt = ida_typeinf.udt_type_data_t()
            if tif.get_udt_details(udt):
                print(f"  Structure size: {udt.total_size // 8} bytes")
                print(f"  Field count: {len(udt)}")
                for i, udm in enumerate(udt):
                    print(f"    +{udm.offset // 8:04x}: {udm.name}")

    return True

def main():
    print("=" * 60)
    print("Structor Plugin Comprehensive Test Suite")
    print("=" * 60)

    # Wait for analysis
    ida_auto.auto_wait()

    # Initialize Hex-Rays
    if not ida_hexrays.init_hexrays_plugin():
        print("ERROR: Hex-Rays not available")
        idc.qexit(1)

    print("Hex-Rays decompiler initialized")

    # Test cases
    tests = [
        ("process_simple", ["field_0", "field_8", "field_10"]),
        ("init_simple", ["field_0", "field_8", "field_10"]),
    ]

    passed = 0
    failed = 0

    for func_name, expected in tests:
        if test_function(func_name, expected):
            passed += 1
        else:
            failed += 1

    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

    idc.qexit(0 if failed == 0 else 1)

if __name__ == "__main__":
    main()
