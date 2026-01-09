"""
Debug script to trace cross-function propagation manually.
"""

import idc
import ida_name
import ida_auto
import ida_hexrays
import ida_funcs
import idautils
import ida_expr

LOG_FILE = "/tmp/structor_debug.log"
log_file = open(LOG_FILE, "w")


def log(msg):
    log_file.write(f"{msg}\n")
    log_file.flush()
    print(msg)


def get_function_ea(name):
    """Get function EA by name, trying with and without underscore prefix."""
    ea = ida_name.get_name_ea(idc.BADADDR, f"_{name}")
    if ea == idc.BADADDR:
        ea = ida_name.get_name_ea(idc.BADADDR, name)
    return ea


def dump_function_vars(func_name):
    """Dump all variables in a function."""
    ea = get_function_ea(func_name)
    if ea == idc.BADADDR:
        log(f"  Function {func_name} not found")
        return

    try:
        cfunc = ida_hexrays.decompile(ea)
        if not cfunc:
            log(f"  Failed to decompile {func_name}")
            return

        log(f"\n=== {func_name} (0x{ea:x}) ===")
        log(f"  Variables ({len(cfunc.lvars)}):")
        for i, lvar in enumerate(cfunc.lvars):
            is_arg = lvar.is_arg_var
            location = "arg" if is_arg else "local"
            log(f"    [{i}] {lvar.name}: {lvar.type()} ({location})")

    except Exception as e:
        log(f"  Error: {e}")


def find_calls_in_function(func_name):
    """Find all function calls in a function and what args are passed."""
    ea = get_function_ea(func_name)
    if ea == idc.BADADDR:
        log(f"  Function {func_name} not found")
        return

    try:
        cfunc = ida_hexrays.decompile(ea)
        if not cfunc:
            log(f"  Failed to decompile {func_name}")
            return

        log(f"\n=== Calls from {func_name} ===")

        class CallVisitor(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                super().__init__(ida_hexrays.CV_FAST)
                self.calls = []

            def visit_expr(self, expr):
                if expr.op == ida_hexrays.cot_call:
                    call_info = {"target": None, "args": []}

                    # Get callee
                    if expr.x.op == ida_hexrays.cot_obj:
                        callee_ea = expr.x.obj_ea
                        callee_name = ida_name.get_name(callee_ea)
                        call_info["target"] = f"{callee_name} (0x{callee_ea:x})"
                    elif expr.x.op == ida_hexrays.cot_helper:
                        call_info["target"] = f"helper: {expr.x.helper}"
                    else:
                        call_info["target"] = f"indirect (op={expr.x.op})"

                    # Get args
                    if expr.a:
                        for i, arg in enumerate(expr.a):
                            arg_str = self.expr_to_str(arg)
                            call_info["args"].append(f"[{i}] {arg_str}")

                    self.calls.append(call_info)

                return 0

            def expr_to_str(self, expr):
                """Convert expression to string representation."""
                # Strip casts
                while expr.op == ida_hexrays.cot_cast:
                    expr = expr.x

                if expr.op == ida_hexrays.cot_var:
                    return f"var[{expr.v.idx}]"
                elif expr.op == ida_hexrays.cot_num:
                    return f"num({expr.n._value})"
                elif expr.op == ida_hexrays.cot_ref:
                    return f"ref({self.expr_to_str(expr.x)})"
                elif expr.op == ida_hexrays.cot_obj:
                    return f"obj(0x{expr.obj_ea:x})"
                elif expr.op == ida_hexrays.cot_add:
                    return (
                        f"add({self.expr_to_str(expr.x)}, {self.expr_to_str(expr.y)})"
                    )
                else:
                    return f"op({expr.op})"

        visitor = CallVisitor()
        visitor.apply_to(cfunc.body, None)

        for call in visitor.calls:
            log(f"  Call: {call['target']}")
            for arg in call["args"]:
                log(f"    {arg}")

    except Exception as e:
        import traceback

        log(f"  Error: {e}")
        log(traceback.format_exc())


def run_structor(func_name, var_idx):
    """Run structor_synthesize on a function/var index."""
    ea = get_function_ea(func_name)
    if ea == idc.BADADDR:
        log(f"  Function {func_name} not found")
        return None

    result = ida_expr.idc_value_t()
    expr = f"structor_synthesize(0x{ea:x}, {var_idx})"
    err = ida_expr.eval_idc_expr(result, idc.BADADDR, expr)
    if err:
        log(f"  structor_synthesize error: {err}")
        return None

    tid = result.i64 if hasattr(result, "i64") else result.num
    log(f"  structor_synthesize returned TID: 0x{tid & 0xFFFFFFFFFFFFFFFF:x}")
    return tid


def trace_variable_usage(func_name, var_idx):
    """Trace how a variable is used in a function."""
    ea = get_function_ea(func_name)
    if ea == idc.BADADDR:
        log(f"  Function {func_name} not found")
        return

    try:
        cfunc = ida_hexrays.decompile(ea)
        if not cfunc:
            return

        log(f"\n=== Variable usage in {func_name}, var[{var_idx}] ===")

        class UsageVisitor(ida_hexrays.ctree_visitor_t):
            def __init__(self, target_idx):
                super().__init__(ida_hexrays.CV_FAST)
                self.target_idx = target_idx
                self.usages = []

            def visit_expr(self, expr):
                if expr.op == ida_hexrays.cot_var and expr.v.idx == self.target_idx:
                    # Check parent context
                    self.usages.append(f"var at ea=0x{expr.ea:x}")
                return 0

        visitor = UsageVisitor(var_idx)
        visitor.apply_to(cfunc.body, None)

        for usage in visitor.usages:
            log(f"  {usage}")

    except Exception as e:
        log(f"  Error: {e}")


def main():
    log("=== Cross-Function Propagation Debug ===")

    ida_auto.auto_wait()

    if not ida_hexrays.init_hexrays_plugin():
        log("ERROR: Hex-Rays not available")
        idc.qexit(1)

    log("\n=== Before structor ===")
    for func in ["main", "init_simple", "process_simple"]:
        dump_function_vars(func)

    find_calls_in_function("main")

    log("\n=== Running structor on init_simple ===")
    run_structor("init_simple", 0)

    log("\n=== After structor ===")
    for func in ["main", "init_simple", "process_simple"]:
        dump_function_vars(func)

    find_calls_in_function("main")

    log("\n=== Done ===")
    log_file.close()
    idc.qexit(0)


main()
