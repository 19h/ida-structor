"""Dump synthesized struct definition."""

import sys
import idc
import ida_auto
import ida_struct
import ida_typeinf
import idautils

LOG = "/tmp/struct_dump.log"

def log(msg):
    with open(LOG, "a") as f:
        f.write(f"{msg}\n")

with open(LOG, "w") as f:
    f.write("=== STRUCT DUMP ===\n")

ida_auto.auto_wait()

# Enumerate all structures
log("Structures in database:")
for idx, sid, name in idautils.Structs():
    log(f"  [{idx}] 0x{sid:x}: {name}")
    sptr = ida_struct.get_struc(sid)
    if sptr:
        size = ida_struct.get_struc_size(sptr)
        log(f"       Size: {size} bytes")
        
        # Dump fields
        offset = 0
        while offset < size:
            mptr = ida_struct.get_member(sptr, offset)
            if mptr:
                mname = ida_struct.get_member_name(mptr.id)
                msize = ida_struct.get_member_size(mptr)
                moffset = mptr.soff
                
                tif = ida_typeinf.tinfo_t()
                if ida_struct.get_member_tinfo(tif, mptr):
                    mtype = str(tif)
                else:
                    mtype = f"(size {msize})"
                
                log(f"       +0x{moffset:02x}: {mname} : {mtype}")
                offset = moffset + max(msize, 1)
            else:
                offset += 1

log("")
log("=== DONE ===")
idc.qexit(0)
