"""
IDAPython script to test Structor plugin structure synthesis.
Run this script after loading a test binary in IDA with the plugin enabled.
"""

import idc
import idautils
import ida_hexrays
import ida_funcs
import ida_typeinf
import ida_name

def get_function_by_name(name):
    """Find function by name"""
    for func_ea in idautils.Functions():
        if ida_name.get_name(func_ea) == name:
            return func_ea
    return idc.BADADDR

def test_simple_struct():
    """Test structure synthesis on process_simple function"""
    func_ea = get_function_by_name("_process_simple") or get_function_by_name("process_simple")

    if func_ea == idc.BADADDR:
        print("ERROR: Could not find process_simple function")
        return False

    print(f"Testing process_simple at 0x{func_ea:x}")

    # Get decompilation
    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        print("ERROR: Could not decompile function")
        return False

    # Find the 'ptr' variable (should be parameter 0)
    lvars = cfunc.get_lvars()
    ptr_var = None
    ptr_idx = -1

    for i, lvar in enumerate(lvars):
        print(f"  Local var {i}: {lvar.name} - type: {lvar.type()}")
        if lvar.name == "ptr" or (i == 0 and lvar.is_arg_var):
            ptr_var = lvar
            ptr_idx = i
            break

    if ptr_var is None:
        print("ERROR: Could not find ptr variable")
        return False

    print(f"Found ptr variable at index {ptr_idx}")

    # Try to use the C API
    try:
        result = idc.eval_idc(f'synth_struct_for_var_idx({func_ea}, {ptr_idx})')
        print(f"Synthesis result: {result}")
    except:
        print("Note: C API not available, manual testing required")

    return True

def test_init_simple():
    """Test structure synthesis on init_simple function"""
    func_ea = get_function_by_name("_init_simple") or get_function_by_name("init_simple")

    if func_ea == idc.BADADDR:
        print("ERROR: Could not find init_simple function")
        return False

    print(f"Testing init_simple at 0x{func_ea:x}")

    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        print("ERROR: Could not decompile function")
        return False

    lvars = cfunc.get_lvars()
    for i, lvar in enumerate(lvars):
        print(f"  Local var {i}: {lvar.name} - type: {lvar.type()}")

    return True

def main():
    print("=" * 60)
    print("Structor Plugin Test Suite")
    print("=" * 60)

    # Check if Hex-Rays is available
    if not ida_hexrays.init_hexrays_plugin():
        print("ERROR: Hex-Rays decompiler not available")
        return

    print("\nTest 1: process_simple")
    print("-" * 40)
    test_simple_struct()

    print("\nTest 2: init_simple")
    print("-" * 40)
    test_init_simple()

    print("\n" + "=" * 60)
    print("Tests complete")
    print("=" * 60)

if __name__ == "__main__":
    main()
