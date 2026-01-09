import idc

with open("/tmp/minimal.log", "w") as f:
    f.write("Hello from IDA\n")

idc.qexit(0)
