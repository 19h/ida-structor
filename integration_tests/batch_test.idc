// IDC script to test Structor plugin synthesis
// Run with: idat -A -S"batch_test.idc" binary

#include <idc.idc>

static main() {
    auto func_ea = get_name_ea_simple("_process_simple");
    if (func_ea == BADADDR) {
        func_ea = get_name_ea_simple("process_simple");
    }

    if (func_ea == BADADDR) {
        msg("ERROR: Could not find process_simple function\n");
        qexit(1);
    }

    msg("Testing Structor on process_simple at 0x%x\n", func_ea);

    // Try the C API
    auto result = structor_synthesize(func_ea, 0);
    if (result != BADADDR) {
        msg("SUCCESS: Created structure TID 0x%x\n", result);
        msg("Fields created: %d\n", structor_get_field_count());
        msg("VTable TID: 0x%x\n", structor_get_vtable_tid());
    } else {
        msg("SYNTHESIS FAILED: %s\n", structor_get_error());
    }

    qexit(0);
}
