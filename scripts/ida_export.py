import json
import os
import sys

import idaapi
import idautils
import idc
import ida_typeinf


def _ea_hex(ea):
    return "0x%08X" % ea


def _safe_type(ea):
    try:
        t = idc.get_type(ea)
    except Exception:
        t = None
    return t or ""


def _collect_functions():
    funcs = []
    for ea in idautils.Functions():
        f = idaapi.get_func(ea)
        if not f:
            continue
        name = idc.get_func_name(ea)
        start = f.start_ea
        end = f.end_ea
        size = max(0, end - start)
        flags = idc.get_func_attr(ea, idc.FUNCATTR_FLAGS)
        is_lib = bool(flags & idaapi.FUNC_LIB)
        is_thunk = bool(flags & idaapi.FUNC_THUNK)

        calls = set()
        for insn_ea in idautils.FuncItems(start):
            for ref in idautils.CodeRefsFrom(insn_ea, 0):
                if idaapi.is_call_insn(insn_ea):
                    calls.add(idc.get_func_name(ref) or _ea_hex(ref))

        funcs.append(
            {
                "name": name,
                "address": _ea_hex(start),
                "end": _ea_hex(end),
                "size": size,
                "signature": _safe_type(start),
                "external": False,
                "library": is_lib,
                "thunk": is_thunk,
                "calls": sorted(calls),
            }
        )
    return funcs


def _collect_strings():
    strings = []
    s = idautils.Strings()
    try:
        s.setup()
    except Exception:
        pass
    for item in s:
        strings.append(
            {
                "address": _ea_hex(item.ea),
                "type": "unicode"
                if item.strtype
                in (
                    getattr(idc, "STRTYPE_C_16", -1),
                    getattr(idc, "STRTYPE_C_16L", -1),
                    getattr(idc, "STRTYPE_C_16B", -1),
                )
                else "ascii",
                "value": str(item),
            }
        )
    return strings


def _collect_imports():
    imports = []
    qty = idaapi.get_import_module_qty()
    for i in range(qty):
        name = idaapi.get_import_module_name(i)
        if not name:
            continue
        entries = []

        def cb(ea, imp_name, ordinal):
            entries.append(
                {
                    "address": _ea_hex(ea),
                    "name": imp_name or "",
                    "ordinal": ordinal,
                }
            )
            return True

        idaapi.enum_import_names(i, cb)
        imports.append({"module": name, "entries": entries})
    return imports


def _collect_exports():
    exports = []
    for entry in idautils.Entries():
        if len(entry) == 3:
            ea, ordinal, name = entry
        else:
            _, ea, ordinal, name = entry
        exports.append(
            {
                "address": _ea_hex(ea),
                "name": name or "",
                "ordinal": ordinal,
            }
        )
    return exports


def _collect_segments():
    segs = []
    for ea in idautils.Segments():
        seg = idaapi.getseg(ea)
        if not seg:
            continue
        segs.append(
            {
                "name": idaapi.get_segm_name(seg) or "",
                "start": _ea_hex(seg.start_ea),
                "end": _ea_hex(seg.end_ea),
                "perm": idc.get_segm_attr(seg.start_ea, idc.SEGATTR_PERM),
            }
        )
    return segs


def _collect_metadata():
    md5 = idc.retrieve_input_file_md5()
    if isinstance(md5, (bytes, bytearray)):
        md5 = md5.hex()
    return {
        "ida_version": idaapi.get_kernel_version(),
        "ida_sdk_version": idaapi.IDA_SDK_VERSION,
        "image_base": _ea_hex(idaapi.get_imagebase()),
        "md5": md5,
        "file_path": idaapi.get_input_file_path(),
    }


def _basename(path):
    return os.path.basename(path).lower()


def _apply_type_signature(ea, signature):
    if not signature:
        return False
    tinfo = ida_typeinf.tinfo_t()
    ok = ida_typeinf.parse_decl(tinfo, None, signature, 0)
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
    argv = sys.argv
    try:
        if len(argv) < 2 and hasattr(idc, "ARGV") and idc.ARGV:
            argv = list(idc.ARGV)
    except Exception:
        argv = sys.argv

    if len(argv) < 2:
        print("Usage: ida_export.py <output_dir> [name_map.json] [data_map.json]")
        return 1

    out_dir = argv[1].strip().replace("\r", "").replace("\n", "")
    out_dir = os.path.normpath(os.path.abspath(out_dir))

    try:
        idaapi.auto_wait()
    except Exception:
        pass
    os.makedirs(out_dir, exist_ok=True)

    program_name = _basename(idaapi.get_input_file_path())
    name_map = argv[2] if len(argv) > 2 else ""
    data_map = argv[3] if len(argv) > 3 else ""
    _apply_name_map(name_map, program_name)
    _apply_data_map(data_map, program_name)

    artifacts = {
        "functions.json": _collect_functions(),
        "strings.json": _collect_strings(),
        "imports.json": _collect_imports(),
        "exports.json": _collect_exports(),
        "segments.json": _collect_segments(),
        "metadata.json": _collect_metadata(),
    }

    for name, payload in artifacts.items():
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.write("\n")

    print("IDA export complete:", out_dir)
    return 0


if __name__ == "__main__":
    rc = main()
    try:
        idc.qexit(rc)
    except Exception:
        pass
