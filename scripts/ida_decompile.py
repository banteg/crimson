import json
import os
import sys

import idaapi
import idautils
import idc
import ida_typeinf

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


def _basename(path):
    return os.path.basename(path).lower()


def _ida_parse_decl_flags():
    # Prefer silent parsing in batch runs if the constant exists.
    return int(getattr(ida_typeinf, "PT_SIL", 0) or 0) | int(getattr(ida_typeinf, "PT_SILENT", 0) or 0)


def _normalize_signature(signature):
    sig = (signature or "").replace("\r", "").strip()
    if not sig:
        return ""
    # IDA's parser expects a full C declaration terminated with ';'.
    if not sig.endswith(";"):
        sig += ";"
    return sig


def _apply_type_signature(ea, signature):
    sig = _normalize_signature(signature)
    if not sig:
        return False
    tinfo = ida_typeinf.tinfo_t()
    ok = ida_typeinf.parse_decl(tinfo, None, sig, _ida_parse_decl_flags())
    if not ok:
        return False
    try:
        ida_typeinf.apply_tinfo(ea, tinfo, ida_typeinf.TINFO_DEFINITE)
    except Exception:
        return False
    return True


def _apply_name_map(path, program_name):
    if not path:
        return
    try:
        data = json.loads(open(path, "r", encoding="utf-8").read())
    except Exception:
        return
    for entry in data:
        if _basename(entry.get("program", "")) != program_name:
            continue
        addr = entry.get("address", "")
        if not addr:
            continue
        try:
            ea = int(addr, 16)
        except Exception:
            continue
        name = entry.get("name") or ""
        if name:
            idc.set_name(ea, name, idc.SN_NOWARN)
        comment = entry.get("comment") or ""
        if comment:
            idc.set_func_cmt(ea, comment, 0)
        _apply_type_signature(ea, entry.get("signature", ""))


def _apply_data_map(path, program_name):
    if not path:
        return
    try:
        data = json.loads(open(path, "r", encoding="utf-8").read())
    except Exception:
        return
    entries = data.get("entries", []) if isinstance(data, dict) else data
    for entry in entries:
        if _basename(entry.get("program", "")) != program_name:
            continue
        addr = entry.get("address", "")
        if not addr:
            continue
        try:
            ea = int(addr, 16)
        except Exception:
            continue
        name = entry.get("name") or ""
        if name:
            idc.set_name(ea, name, idc.SN_NOWARN)
        comment = entry.get("comment") or ""
        if comment:
            idc.set_cmt(ea, comment, 0)


def main():
    argv = _get_argv()
    if len(argv) < 2:
        print("Usage: ida_decompile.py <output_file> [name_map.json] [data_map.json]")
        return 1

    out_file = argv[1].strip().replace("\r", "").replace("\n", "")
    out_file = os.path.normpath(os.path.abspath(out_file))
    os.makedirs(os.path.dirname(out_file), exist_ok=True)

    try:
        idaapi.auto_wait()
    except Exception:
        pass

    program_name = _basename(idaapi.get_input_file_path())
    name_map = argv[2] if len(argv) > 2 else ""
    data_map = argv[3] if len(argv) > 3 else ""
    _apply_name_map(name_map, program_name)
    _apply_data_map(data_map, program_name)

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
