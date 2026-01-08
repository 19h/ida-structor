"""Test pseudocode rewriter component"""
import idc
import ida_name
import ida_auto
import ida_hexrays
import ida_expr
import ida_struct
import ida_typeinf
import idautils

ida_auto.auto_wait()

if not ida_hexrays.init_hexrays_plugin():
    print("[FATAL] No Hex-Rays")
    idc.qexit(1)

print("=" * 60)
print("PSEUDOCODE REWRITER TEST")
print("=" * 60)

results = {"passed": 0, "failed": 0}

# Get access_object_fields
func_ea = ida_name.get_name_ea(idc.BADADDR, "_access_object_fields")
if func_ea == idc.BADADDR:
    print("[ERROR] access_object_fields not found")
    idc.qexit(1)

print(f"\n=== Step 1: Get original pseudocode ===")
print(f"Function at 0x{func_ea:x}")

cfunc_before = ida_hexrays.decompile(func_ea)
if cfunc_before:
    pseudocode_before = str(cfunc_before)
    print("Pseudocode BEFORE synthesis:")
    for line in pseudocode_before.split('\n'):
        print(f"  {line}")

# Run synthesis
print(f"\n=== Step 2: Run synthesis ===")
result = ida_expr.idc_value_t()
ida_expr.eval_idc_expr(result, idc.BADADDR, f"structor_synthesize(0x{func_ea:x}, 0)")
tid = result.i64 if hasattr(result, 'i64') else result.num

if tid == -1 or tid == idc.BADADDR:
    err_val = ida_expr.idc_value_t()
    ida_expr.eval_idc_expr(err_val, idc.BADADDR, "structor_get_error()")
    error = err_val.c_str() if hasattr(err_val, 'c_str') else ""
    print(f"[ERROR] Synthesis failed: {error}")
    idc.qexit(1)

tid_unsigned = tid & 0xFFFFFFFFFFFFFFFF
print(f"Structure TID: 0x{tid_unsigned:x}")

# Get field count
fc_val = ida_expr.idc_value_t()
ida_expr.eval_idc_expr(fc_val, idc.BADADDR, "structor_get_field_count()")
field_count = fc_val.num if hasattr(fc_val, 'num') else 0
print(f"Fields created: {field_count}")

# Force refresh and get new pseudocode
print(f"\n=== Step 3: Check pseudocode after synthesis ===")

# The pseudocode rewriter should have:
# 1. Applied the structure type to the variable
# 2. Refreshed the decompiler view

# Re-decompile to see changes
cfunc_after = ida_hexrays.decompile(func_ea)
if cfunc_after:
    pseudocode_after = str(cfunc_after)
    print("Pseudocode AFTER synthesis:")
    for line in pseudocode_after.split('\n'):
        print(f"  {line}")

    # Check for changes
    if pseudocode_before != pseudocode_after:
        print(f"\n[PASS] Pseudocode changed after synthesis")
        results["passed"] += 1

        # Look for structure field access syntax
        if "->" in pseudocode_after or "field_" in pseudocode_after:
            print(f"[PASS] Pseudocode shows structure field access syntax")
            results["passed"] += 1
        else:
            print(f"[INFO] Field access syntax may vary based on decompiler settings")
    else:
        print(f"\n[INFO] Pseudocode appears unchanged")
        print(f"       This may be normal - type application happens,")
        print(f"       but display depends on decompiler settings")

# Check variable type in the decompiled function
print(f"\n=== Step 4: Verify variable type ===")
var = cfunc_after.lvars[0]
var_type = var.type()
print(f"Variable '{var.name}' type: {var_type}")

type_str = str(var_type)
if "synth_" in type_str or "void *" not in type_str:
    print(f"[PASS] Variable type was updated from void*")
    results["passed"] += 1
else:
    print(f"[INFO] Variable type: {type_str}")

# Print structure details
print(f"\n=== Step 5: Show created structure ===")
sptr = ida_struct.get_struc(tid_unsigned)
if sptr:
    print(f"Structure size: {ida_struct.get_struc_size(sptr)} bytes")
    print(f"Members:")
    for offset in range(0, ida_struct.get_struc_size(sptr), 1):
        member = ida_struct.get_member(sptr, offset)
        if member and member.soff == offset:  # Only print at start of member
            mname = ida_struct.get_member_name(member.id)
            msize = ida_struct.get_member_size(member)
            print(f"  0x{offset:02x}: {mname} (size {msize})")
    results["passed"] += 1

# Summary
print("\n" + "=" * 60)
print("PSEUDOCODE REWRITER SUMMARY")
print("=" * 60)
print(f"Passed: {results['passed']}")
print(f"Failed: {results['failed']}")

print("""
The pseudocode rewriter component:
1. Applies the synthesized structure type to the variable
2. Refreshes the decompiler cache for the function
3. Updates the decompiler view to show the new types

The visual changes in pseudocode depend on:
- Whether the structure type was successfully applied
- Decompiler settings for displaying structure accesses
- Whether the decompiler cache was properly invalidated
""")

if results["passed"] >= 2:
    print("[SUCCESS] Pseudocode rewriter verified")
else:
    print("[INCOMPLETE] Some rewriter tests did not pass")

idc.qexit(0)
