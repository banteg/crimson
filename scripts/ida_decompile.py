import json
import os
import re
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

_FAILED_SIGNATURES = set()

_TYPEDEF_PRELUDE = """
typedef unsigned char byte;
typedef unsigned char undefined1;
typedef unsigned int undefined4;
typedef unsigned int uint;
typedef unsigned char Byte;
typedef Byte *Bytef;
typedef unsigned int uInt;
typedef unsigned long uLong;
typedef uLong uLongf;
typedef void *voidp;
typedef void *voidpf;
typedef struct z_stream_s { int _dummy; } z_stream;
typedef z_stream *z_streamp;
typedef unsigned char png_byte;
typedef unsigned short png_uint_16;
typedef unsigned int png_uint_32;
typedef int png_int_32;
typedef void *png_voidp;
typedef png_byte *png_bytep;
typedef struct png_struct_def { int _dummy; } png_struct;
typedef png_struct *png_structp;
typedef struct IGrim2D { int _dummy; } IGrim2D;
""".strip()

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


def _install_typedefs():
    if not _TYPEDEF_PRELUDE:
        return
    flags = _ida_parse_decl_flags()
    til = ida_typeinf.get_idati() if hasattr(ida_typeinf, "get_idati") else None
    parse_types2 = getattr(ida_typeinf, "parse_types2", None)
    parse_types = getattr(ida_typeinf, "parse_types", None)
    parsed = False
    if parse_types2:
        try:
            parse_types2(til, _TYPEDEF_PRELUDE + "\n", flags)
            parsed = True
        except Exception:
            parsed = False
    if not parsed and parse_types:
        try:
            parse_types(til, _TYPEDEF_PRELUDE + "\n", flags)
            parsed = True
        except Exception:
            parsed = False
    if not parsed:
        for line in _TYPEDEF_PRELUDE.splitlines():
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
    _install_typedefs()
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
