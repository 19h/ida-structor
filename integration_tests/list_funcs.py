"""List all functions in the database"""
import idc
import ida_funcs
import ida_auto
import ida_name
import idautils

ida_auto.auto_wait()

print("=== ALL FUNCTIONS ===")
for func_ea in idautils.Functions():
    name = ida_name.get_name(func_ea) or f"sub_{func_ea:x}"
    print(f"  0x{func_ea:x}: {name}")

print("\nDone")
idc.qexit(0)
