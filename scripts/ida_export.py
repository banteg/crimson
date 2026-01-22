import json
import os
import re
import sys

import idaapi
import idautils
import idc
import ida_typeinf

_FAILED_SIGNATURES = set()

_SHARED_HEADER_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "third_party", "headers", "crimsonland_ida_types.h")
)

_TYPE_REPLACEMENTS = {
    "IGrim2D": "void",
    "Byte": "unsigned char",
    "Bytef": "unsigned char *",
    "byte": "unsigned char",
    "png_bytep": "unsigned char *",
    "png_structp": "void *",
    "png_uint_32": "unsigned int",
    "png_voidp": "void *",
    "uInt": "unsigned int",
    "uLong": "unsigned long",
    "uLongf": "unsigned long",
    "uint": "unsigned int",
    "undefined1": "unsigned char",
    "undefined4": "unsigned int",
    "voidp": "void *",
    "voidpf": "void *",
    "z_streamp": "void *",
}



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


def _rewrite_signature(signature):
    if not _TYPE_REPLACEMENTS:
        return signature
    parts = re.split(r"([A-Za-z_][A-Za-z0-9_]*)", signature)
    for i in range(1, len(parts), 2):
        token = parts[i]
        replacement = _TYPE_REPLACEMENTS.get(token)
        if replacement:
            parts[i] = replacement
    return "".join(parts)


def _load_shared_header():
    try:
        with open(_SHARED_HEADER_PATH, "r", encoding="utf-8") as f:
            lines = [line for line in f if not line.lstrip().startswith("#")]
        return "".join(lines).strip()
    except Exception:
        return ""


def _install_typedefs():
    type_text = _load_shared_header()
    if not type_text:
        return
    flags = _ida_parse_decl_flags()
    til = ida_typeinf.get_idati() if hasattr(ida_typeinf, "get_idati") else None
    parse_types2 = getattr(ida_typeinf, "parse_types2", None)
    parse_types = getattr(ida_typeinf, "parse_types", None)
    parsed = False
    if parse_types2:
        try:
            parse_types2(til, type_text + "\n", flags)
            parsed = True
        except Exception:
            parsed = False
    if not parsed and parse_types:
        try:
            parse_types(til, type_text + "\n", flags)
            parsed = True
        except Exception:
            parsed = False
    if not parsed:
        for line in type_text.splitlines():
            decl = line.strip()
            if not decl:
                continue
            tinfo = ida_typeinf.tinfo_t()
            ida_typeinf.parse_decl(tinfo, None, decl, flags)


def _log_parse_failure(ea, sig, reason, rewritten=None):
    if sig in _FAILED_SIGNATURES:
        return
    _FAILED_SIGNATURES.add(sig)
    name = idc.get_name(ea) or ""
    print("parse_decl failed (%s): %s @ %s" % (reason, name, _ea_hex(ea)))
    print("  signature:", sig)
    if rewritten and rewritten != sig:
        print("  rewritten:", rewritten)


def _apply_type_signature(ea, signature):
    sig = _normalize_signature(signature)
    if not sig:
        return False
    flags = _ida_parse_decl_flags()
    tinfo = ida_typeinf.tinfo_t()
    ok = ida_typeinf.parse_decl(tinfo, None, sig, flags)
    if not ok:
        rewritten = _rewrite_signature(sig)
        if rewritten != sig:
            tinfo = ida_typeinf.tinfo_t()
            ok = ida_typeinf.parse_decl(tinfo, None, rewritten, flags)
            if ok:
                sig = rewritten
        if not ok:
            _log_parse_failure(ea, sig, "parse_decl", rewritten)
            return False
    try:
        ida_typeinf.apply_tinfo(ea, tinfo, ida_typeinf.TINFO_DEFINITE)
    except Exception:
        _log_parse_failure(ea, sig, "apply_tinfo")
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
    _install_typedefs()
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
