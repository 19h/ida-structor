"""
Structor - IDAPython API

High-level Python interface for the Structor structure synthesis plugin.

Example usage:
    import structor

    # Synthesize structure for variable in current function
    result = structor.synth_struct_for_var(here(), "a1")
    if result['success']:
        print(f"Created {result['struct_name']} with {result['fields_created']} fields")

    # Get raw access patterns
    accesses = structor.get_accesses(here(), 0)
    for acc in accesses:
        print(f"Offset 0x{acc['offset']:X}, size {acc['size']}, type {acc['semantic_type']}")

    # Configure options
    structor.set_option('min_accesses', 1)
    structor.set_option('vtable_detection', True)
"""

import ida_idaapi
import ida_hexrays
import ida_typeinf
import ida_struct
import ida_funcs
import idautils

__all__ = [
    'synth_struct_for_var',
    'synth_struct_for_var_idx',
    'get_accesses',
    'set_option',
    'get_option',
    'SynthResult',
    'AccessInfo',
]


class AccessInfo:
    """Information about a single memory access to a structure field."""

    def __init__(self, data: dict):
        self.offset: int = data.get('offset', 0)
        self.size: int = data.get('size', 0)
        self.ea: int = data.get('ea', ida_idaapi.BADADDR)
        self.access_type: str = data.get('access_type', 'unknown')
        self.semantic_type: str = data.get('semantic_type', 'unknown')
        self.is_vtable_access: bool = bool(data.get('is_vtable_access', 0))

    def __repr__(self):
        return (f"AccessInfo(offset=0x{self.offset:X}, size={self.size}, "
                f"type={self.semantic_type}, vtbl={self.is_vtable_access})")


class SynthResult:
    """Result of structure synthesis."""

    def __init__(self, data: dict):
        self.success: bool = bool(data.get('success', 0))
        self.error: str = data.get('error', '')
        self.error_message: str = data.get('error_message', '')
        self.struct_tid: int = data.get('struct_tid', ida_idaapi.BADADDR)
        self.vtable_tid: int = data.get('vtable_tid', ida_idaapi.BADADDR)
        self.fields_created: int = data.get('fields_created', 0)
        self.vtable_slots: int = data.get('vtable_slots', 0)
        self.struct_name: str = data.get('struct_name', '')
        self.struct_size: int = data.get('struct_size', 0)
        self.propagated_count: int = data.get('propagated_count', 0)

    def __repr__(self):
        if self.success:
            return (f"SynthResult(success=True, name='{self.struct_name}', "
                    f"fields={self.fields_created}, vtable_slots={self.vtable_slots})")
        return f"SynthResult(success=False, error='{self.error}')"

    def __bool__(self):
        return self.success

    @property
    def has_vtable(self) -> bool:
        return self.vtable_tid != ida_idaapi.BADADDR


def synth_struct_for_var(ea: int, varname: str) -> SynthResult:
    """
    Synthesize a structure from access patterns for a named variable.

    Args:
        ea: Address within the function (use here() for current location)
        varname: Name of the local variable to analyze

    Returns:
        SynthResult object with synthesis results

    Example:
        result = synth_struct_for_var(here(), "this")
        if result:
            print(f"Created {result.struct_name}")
    """
    # Get function start
    func = ida_funcs.get_func(ea)
    if not func:
        return SynthResult({'success': 0, 'error': 'Not in a function'})

    func_ea = func.start_ea

    # Call native function
    try:
        result = ida_idaapi.IDAPython_ExecScript(
            f"synth_struct_for_var({func_ea}, '{varname}')",
            False
        )
        if isinstance(result, dict):
            return SynthResult(result)
    except Exception as e:
        return SynthResult({'success': 0, 'error': str(e)})

    return SynthResult({'success': 0, 'error': 'Unknown error'})


def synth_struct_for_var_idx(ea: int, var_idx: int) -> SynthResult:
    """
    Synthesize a structure for a variable by its index.

    Args:
        ea: Address within the function
        var_idx: Index of the variable in the local variables array

    Returns:
        SynthResult object
    """
    func = ida_funcs.get_func(ea)
    if not func:
        return SynthResult({'success': 0, 'error': 'Not in a function'})

    func_ea = func.start_ea

    try:
        result = ida_idaapi.IDAPython_ExecScript(
            f"synth_struct_for_var_idx({func_ea}, {var_idx})",
            False
        )
        if isinstance(result, dict):
            return SynthResult(result)
    except Exception as e:
        return SynthResult({'success': 0, 'error': str(e)})

    return SynthResult({'success': 0, 'error': 'Unknown error'})


def get_accesses(ea: int, var_idx: int) -> list[AccessInfo]:
    """
    Get all memory access patterns for a variable.

    Args:
        ea: Address within the function
        var_idx: Variable index

    Returns:
        List of AccessInfo objects
    """
    func = ida_funcs.get_func(ea)
    if not func:
        return []

    func_ea = func.start_ea

    try:
        result = ida_idaapi.IDAPython_ExecScript(
            f"structor_get_accesses({func_ea}, {var_idx})",
            False
        )
        if isinstance(result, (list, tuple)):
            return [AccessInfo(x) for x in result]
        if isinstance(result, dict):
            return [AccessInfo(result)]
    except Exception:
        pass

    return []


def set_option(name: str, value) -> bool:
    """
    Set a Structor configuration option.

    Available options:
        - auto_propagate (bool): Auto-propagate types after synthesis
        - vtable_detection (bool): Enable vtable pattern recognition
        - min_accesses (int): Minimum access count to trigger synthesis
        - alignment (int): Default structure alignment
        - interactive_mode (bool): Prompt user before applying changes
        - max_propagation_depth (int): Maximum propagation depth
        - hotkey (str): Activation hotkey

    Args:
        name: Option name
        value: Option value

    Returns:
        True if option was set successfully
    """
    if isinstance(value, bool):
        value = 1 if value else 0

    try:
        result = ida_idaapi.IDAPython_ExecScript(
            f"structor_set_option('{name}', {value})",
            False
        )
        return bool(result)
    except Exception:
        return False


def get_option(name: str):
    """
    Get a Structor configuration option value.

    Args:
        name: Option name

    Returns:
        Option value, or None if not found
    """
    try:
        result = ida_idaapi.IDAPython_ExecScript(
            f"structor_get_option('{name}')",
            False
        )
        if result == -1:
            return None
        return result
    except Exception:
        return None


def synth_struct_at_cursor() -> SynthResult:
    """
    Synthesize structure for the variable under the cursor.

    Must be called from within a pseudocode view.

    Returns:
        SynthResult object
    """
    widget = ida_kernwin.get_current_widget()
    vdui = ida_hexrays.get_widget_vdui(widget)

    if not vdui:
        return SynthResult({'success': 0, 'error': 'Not in pseudocode view'})

    if not vdui.item.is_citem():
        return SynthResult({'success': 0, 'error': 'No item at cursor'})

    item = vdui.item.it
    if not item:
        return SynthResult({'success': 0, 'error': 'No item at cursor'})

    # Find variable
    expr = item.cexpr if item.is_expr() else None
    while expr:
        if expr.op == ida_hexrays.cot_var:
            var_idx = expr.v.idx
            return synth_struct_for_var_idx(vdui.cfunc.entry_ea, var_idx)

        if expr.op in (ida_hexrays.cot_cast, ida_hexrays.cot_ref,
                       ida_hexrays.cot_ptr, ida_hexrays.cot_memptr,
                       ida_hexrays.cot_idx):
            expr = expr.x
        else:
            break

    return SynthResult({'success': 0, 'error': 'No variable at cursor'})


# Utility functions

def get_synth_structs() -> list[tuple[int, str]]:
    """
    Get all structures created by Structor.

    Returns:
        List of (tid, name) tuples for synthesized structures
    """
    results = []

    for idx in range(ida_struct.get_struc_qty()):
        tid = ida_struct.get_struc_by_idx(idx)
        name = ida_struct.get_struc_name(tid)

        if name and name.startswith('synth_'):
            results.append((tid, name))

    return results


def delete_synth_struct(tid: int) -> bool:
    """
    Delete a synthesized structure.

    Args:
        tid: Type ID of structure to delete

    Returns:
        True if deleted successfully
    """
    sptr = ida_struct.get_struc(tid)
    if not sptr:
        return False

    return ida_struct.del_struc(sptr)


def rename_synth_struct(tid: int, new_name: str) -> bool:
    """
    Rename a synthesized structure.

    Args:
        tid: Type ID of structure
        new_name: New name for the structure

    Returns:
        True if renamed successfully
    """
    return ida_struct.set_struc_name(tid, new_name)
