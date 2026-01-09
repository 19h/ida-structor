"""
Check propagation by capturing IDA messages.
"""

import idc
import ida_auto
import ida_expr
import ida_kernwin

LOG_FILE = "/tmp/structor_prop_check.log"
log_file = open(LOG_FILE, "w")


def log(msg):
    log_file.write(f"{msg}\n")
    log_file.flush()


class MsgCapture(ida_kernwin.UI_Hooks):
    def __init__(self):
        super().__init__()
        self.messages = []

    def msg(self, msg):
        self.messages.append(msg)
        log(f"[IDA MSG] {msg}")
        return 0


def main():
    log("=== Propagation Check ===")

    ida_auto.auto_wait()

    # Hook messages
    hooks = MsgCapture()
    hooks.hook()

    # Call synthesize
    log("Calling structor_synthesize...")
    result = ida_expr.idc_value_t()
    err = ida_expr.eval_idc_expr(
        result, idc.BADADDR, "structor_synthesize(0x100000494, 0)"
    )

    if err:
        log(f"ERROR: {err}")
    else:
        tid = result.i64 if hasattr(result, "i64") else result.num
        log(f"TID: 0x{tid & 0xFFFFFFFFFFFFFFFF:x}")

    hooks.unhook()

    log("\n=== Captured Messages ===")
    for msg in hooks.messages:
        log(f"  {msg}")

    log("\n=== Done ===")
    log_file.close()
    idc.qexit(0)


main()
