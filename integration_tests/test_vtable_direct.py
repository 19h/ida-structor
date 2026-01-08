"""Test VTable/Structure detection with multiple direct field accesses"""
# Write immediately to verify script starts
log_file = open("/tmp/vtable_direct_test.log", "w")
log_file.write("Script starting...\n")
log_file.flush()

def log(msg):
    log_file.write(msg + "\n")
    log_file.flush()

try:
    import idc
    log("Imported idc")
    import ida_name
    log("Imported ida_name")
    import ida_auto
    log("Imported ida_auto")
    import ida_hexrays
    log("Imported ida_hexrays")
    import ida_expr
    log("Imported ida_expr")
    import ida_typeinf
    log("Imported ida_typeinf")
    import idautils
    log("Imported idautils")
    import traceback
    log("All imports complete")
except Exception as e:
    log(f"Import error: {e}")
    import traceback
    log(traceback.format_exc())
    log_file.close()
    raise

try:
    log("Waiting for auto analysis...")
    ida_auto.auto_wait()
    log("Auto analysis complete")

    # Try to initialize Hex-Rays
    hexrays_available = ida_hexrays.init_hexrays_plugin()
    log(f"Hex-Rays init result: {hexrays_available}")

    if not hexrays_available:
        log("[FATAL] No Hex-Rays decompiler available")
        log_file.close()
        idc.qexit(1)

    log("=" * 60)
    log("VTABLE DIRECT ACCESS TEST")
    log("=" * 60)

    results = {"passed": 0, "failed": 0}

    # List functions first
    log("\nFunctions in binary:")
    for func_ea in idautils.Functions():
        name = ida_name.get_name(func_ea)
        log(f"  0x{func_ea:x}: {name}")

    def test_function(name, var_idx, expected_min_fields):
        """Test synthesis on a function"""
        global results

        # Try various name forms
        func_ea = idc.BADADDR
        for n in [name, f"_{name}", f"__{name}"]:
            func_ea = ida_name.get_name_ea(idc.BADADDR, n)
            if func_ea != idc.BADADDR:
                log(f"Found {name} as '{n}' at 0x{func_ea:x}")
                break

        if func_ea == idc.BADADDR:
            log(f"\n[SKIP] {name}: function not found")
            return None

        log(f"\n=== {name} (0x{func_ea:x}) ===")

        # Decompile to see the code
        try:
            cfunc = ida_hexrays.decompile(func_ea)
        except Exception as e:
            log(f"Decompile error: {e}")
            cfunc = None

        if cfunc:
            log("Pseudocode:")
            for line in str(cfunc).split('\n')[:15]:
                log(f"  {line}")

            log(f"\nVariables:")
            for i, v in enumerate(cfunc.lvars):
                log(f"  [{i}] {v.name}: {v.type()}")

        # Run synthesis
        result = ida_expr.idc_value_t()
        eval_res = ida_expr.eval_idc_expr(result, idc.BADADDR, f"structor_synthesize(0x{func_ea:x}, {var_idx})")
        log(f"eval_idc_expr returned: {eval_res}")

        tid = result.i64 if hasattr(result, 'i64') else result.num
        log(f"TID value: {tid}")

        # Get error message
        err_val = ida_expr.idc_value_t()
        ida_expr.eval_idc_expr(err_val, idc.BADADDR, "structor_get_error()")
        error = err_val.c_str() if hasattr(err_val, 'c_str') else ""

        # Get field count
        fc_val = ida_expr.idc_value_t()
        ida_expr.eval_idc_expr(fc_val, idc.BADADDR, "structor_get_field_count()")
        field_count = fc_val.num if hasattr(fc_val, 'num') else 0

        # Get vtable TID
        vt_val = ida_expr.idc_value_t()
        ida_expr.eval_idc_expr(vt_val, idc.BADADDR, "structor_get_vtable_tid()")
        vtable_tid = vt_val.i64 if hasattr(vt_val, 'i64') else vt_val.num

        if tid != -1 and tid != idc.BADADDR:
            tid_unsigned = tid & 0xFFFFFFFFFFFFFFFF
            log(f"\nResult: SUCCESS")
            log(f"  Structure TID: 0x{tid_unsigned:x}")
            log(f"  Field count: {field_count}")

            if field_count >= expected_min_fields:
                log(f"  [PASS] Got {field_count} fields (expected >= {expected_min_fields})")
                results["passed"] += 1
            else:
                log(f"  [FAIL] Got {field_count} fields (expected >= {expected_min_fields})")
                results["failed"] += 1

            # Check VTable detection
            if vtable_tid != -1 and vtable_tid != idc.BADADDR and vtable_tid != 0:
                vt_unsigned = vtable_tid & 0xFFFFFFFFFFFFFFFF
                log(f"  [INFO] VTable TID: 0x{vt_unsigned:x}")
            else:
                log(f"  [INFO] No VTable TID returned")

            # Print structure details using ida_typeinf
            tif = ida_typeinf.tinfo_t()
            if tif.get_type_by_tid(tid_unsigned):
                log(f"\n  Structure type: {tif}")
                # Get structure details
                udt = ida_typeinf.udt_type_data_t()
                if tif.get_udt_details(udt):
                    log(f"  Member count: {len(udt)}")
                    for i in range(len(udt)):
                        member = udt[i]
                        log(f"    offset 0x{member.offset // 8:02x}: {member.name} ({member.type})")

            return tid_unsigned
        else:
            log(f"\nResult: FAILED - {error}")
            if expected_min_fields > 0:
                results["failed"] += 1
            return None

    # Test access_object_fields - has 5 direct field accesses
    log("\n" + "=" * 60)
    log("TEST 1: access_object_fields (5 field accesses)")
    log("=" * 60)
    test_function("access_object_fields", 0, 5)

    # Test modify_object_fields - has 3 write accesses
    log("\n" + "=" * 60)
    log("TEST 2: modify_object_fields (3 field writes)")
    log("=" * 60)
    test_function("modify_object_fields", 0, 3)

    # Test increment_fields - has 6 accesses (3 reads + 3 writes)
    log("\n" + "=" * 60)
    log("TEST 3: increment_fields (6 accesses on 3 fields)")
    log("=" * 60)
    test_function("increment_fields", 0, 3)

    # Summary
    log("\n" + "=" * 60)
    log("SUMMARY")
    log("=" * 60)
    log(f"Passed: {results['passed']}")
    log(f"Failed: {results['failed']}")

    if results["failed"] == 0 and results["passed"] > 0:
        log("\n[SUCCESS] All tests passed!")
    else:
        log(f"\n[RESULT] {results['passed']} passed, {results['failed']} failed")

except Exception as e:
    log(f"EXCEPTION: {e}")
    import traceback
    log(traceback.format_exc())

log_file.close()
idc.qexit(0)
