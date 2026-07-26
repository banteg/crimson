import json
import os

import ida_auto
import ida_loader
import idaapi
import idautils
import idc
from ida_maps_apply import apply_data_map, apply_name_map, basename, get_argv, install_repo_types


def ea_hex(ea):
    return f"0x{ea:08X}"


def collect_functions():
    funcs = []
    for ea in idautils.Functions():
        func = idaapi.get_func(ea)
        if not func:
            continue
        flags = idc.get_func_attr(ea, idc.FUNCATTR_FLAGS)
        calls = set()
        for insn_ea in idautils.FuncItems(func.start_ea):
            for ref in idautils.CodeRefsFrom(insn_ea, 0):
                if idaapi.is_call_insn(insn_ea):
                    calls.add(idc.get_func_name(ref) or ea_hex(ref))
        funcs.append(
            {
                "name": idc.get_func_name(ea),
                "address": ea_hex(func.start_ea),
                "end": ea_hex(func.end_ea),
                "size": max(0, func.end_ea - func.start_ea),
                "signature": idc.get_type(func.start_ea) or "",
                "external": False,
                "library": bool(flags & idaapi.FUNC_LIB),
                "thunk": bool(flags & idaapi.FUNC_THUNK),
                "calls": sorted(calls),
            },
        )
    return funcs


def collect_strings():
    strings = []
    s = idautils.Strings()
    s.setup()
    unicode_types = {idc.STRTYPE_C16, idc.STRTYPE_C_16, idc.STRTYPE_LEN2_16, idc.STRTYPE_PASCAL_16}
    for item in s:
        strings.append(
            {
                "address": ea_hex(item.ea),
                "type": "unicode" if item.strtype in unicode_types else "ascii",
                "value": str(item),
            },
        )
    return strings


def collect_imports():
    imports = []
    for index in range(idaapi.get_import_module_qty()):
        module_name = idaapi.get_import_module_name(index)
        if not module_name:
            continue
        entries = []

        def callback(ea, imp_name, ordinal, out=entries):
            out.append(
                {
                    "address": ea_hex(ea),
                    "name": imp_name or "",
                    "ordinal": ordinal,
                },
            )
            return True

        idaapi.enum_import_names(index, callback)
        imports.append({"module": module_name, "entries": entries})
    return imports


def collect_exports():
    exports = []
    for entry in idautils.Entries():
        if len(entry) == 3:
            ea, ordinal, name = entry
        else:
            _, ea, ordinal, name = entry
        exports.append({"address": ea_hex(ea), "name": name or "", "ordinal": ordinal})
    return exports


def collect_segments():
    segments = []
    for ea in idautils.Segments():
        seg = idaapi.getseg(ea)
        if not seg:
            continue
        segments.append(
            {
                "name": idaapi.get_segm_name(seg) or "",
                "start": ea_hex(seg.start_ea),
                "end": ea_hex(seg.end_ea),
                "perm": idc.get_segm_attr(seg.start_ea, idc.SEGATTR_PERM),
            },
        )
    return segments


def collect_metadata(file_path=None):
    md5 = idc.retrieve_input_file_md5()
    if isinstance(md5, (bytes, bytearray)):
        md5 = md5.hex()
    return {
        "ida_version": idaapi.get_kernel_version(),
        "ida_sdk_version": idaapi.IDA_SDK_VERSION,
        "image_base": ea_hex(idaapi.get_imagebase()),
        "md5": md5,
        "file_path": file_path or idaapi.get_input_file_path(),
    }


def main():
    argv = get_argv()
    if len(argv) < 2:
        print("Usage: ida_export.py <output_dir> [name_map.json] [data_map.json] [file_path]")
        return 1

    out_dir = os.path.normpath(os.path.abspath(argv[1].strip()))
    idaapi.auto_wait()
    os.makedirs(out_dir, exist_ok=True)

    name_map = argv[2] if len(argv) > 2 else ""
    data_map = argv[3] if len(argv) > 3 else ""
    file_path = argv[4] if len(argv) > 4 else idaapi.get_input_file_path()
    program_name = basename(file_path)

    old_auto_state = ida_auto.enable_auto(False)
    try:
        install_repo_types()

        if name_map:
            stats = apply_name_map(name_map, program_name)
            print(
                "Applied name map:",
                name_map,
                f"(updated {stats['updated']}, created {stats['created']}, renamed {stats['renamed']}, signatures {stats['signatures']}, signature errors {stats['signature_errors']}, comments {stats['comments']}, skipped {stats['skipped']})",
            )
        if data_map:
            stats = apply_data_map(data_map, program_name)
            print(
                "Applied data map:",
                data_map,
                f"(updated {stats['updated']}, renamed {stats['renamed']}, types {stats['types']}, type errors {stats['type_errors']}, comments {stats['comments']}, skipped {stats['skipped']})",
            )
    finally:
        ida_auto.enable_auto(old_auto_state)

    idaapi.auto_wait()
    artifacts = {
        "functions.json": collect_functions(),
        "strings.json": collect_strings(),
        "imports.json": collect_imports(),
        "exports.json": collect_exports(),
        "segments.json": collect_segments(),
        "metadata.json": collect_metadata(file_path),
    }

    for name, payload in artifacts.items():
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.write("\n")
    if not ida_loader.save_database():
        raise RuntimeError("failed to save persistent IDA database")

    print("IDA export complete:", out_dir)
    return 0


if __name__ == "__main__":
    rc = main()
    try:
        idc.qexit(rc)
    except Exception:  # noqa: BLE001, S110 - IDA may terminate the interpreter inside qexit
        pass
