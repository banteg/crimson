import os
import sys

import idaapi
import idautils
import idc

try:
    import ida_hexrays
    import ida_lines
except Exception:  # pragma: no cover - handled at runtime in IDA
    ida_hexrays = None
    ida_lines = None


def _get_argv():
    argv = sys.argv
    try:
        if len(argv) < 2 and hasattr(idc, "ARGV") and idc.ARGV:
            argv = list(idc.ARGV)
    except Exception:
        argv = sys.argv
    return argv


def main():
    argv = _get_argv()
    if len(argv) < 2:
        print("Usage: ida_decompile.py <output_file>")
        return 1

    out_file = argv[1].strip().replace("\r", "").replace("\n", "")
    out_file = os.path.normpath(os.path.abspath(out_file))
    os.makedirs(os.path.dirname(out_file), exist_ok=True)

    try:
        idaapi.auto_wait()
    except Exception:
        pass

    if ida_hexrays is None or not ida_hexrays.init_hexrays_plugin():
        print("Hex-Rays not available")
        return 2

    with open(out_file, "w", encoding="utf-8") as f:
        for ea in idautils.Functions():
            flags = idc.get_func_attr(ea, idc.FUNCATTR_FLAGS)
            if flags & idaapi.FUNC_LIB:
                continue
            if flags & idaapi.FUNC_THUNK:
                continue

            try:
                cfunc = ida_hexrays.decompile(ea)
            except ida_hexrays.DecompilationFailure:
                continue
            if not cfunc:
                continue

            f.write("\n")
            f.write("// %s @ %s\n" % (idc.get_func_name(ea), "0x%08X" % ea))
            for line in cfunc.get_pseudocode():
                text = ida_lines.tag_remove(line.line) if ida_lines else line.line
                f.write(text)
                if not text.endswith("\n"):
                    f.write("\n")

    print("IDA decompile complete:", out_file)
    return 0


if __name__ == "__main__":
    rc = main()
    try:
        idc.qexit(rc)
    except Exception:
        pass
