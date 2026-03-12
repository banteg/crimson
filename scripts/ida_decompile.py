import os

import ida_hexrays
import ida_lines
import idaapi
import idautils
import idc
from ida_maps_apply import apply_data_map, apply_name_map, basename, get_argv, install_repo_types


def main():
    argv = get_argv()
    if len(argv) < 2:
        print("Usage: ida_decompile.py <output_file> [name_map.json] [data_map.json]")
        return 1

    out_file = os.path.normpath(os.path.abspath(argv[1].strip()))
    os.makedirs(os.path.dirname(out_file), exist_ok=True)

    idaapi.auto_wait()

    program_name = basename(idaapi.get_input_file_path())
    name_map = argv[2] if len(argv) > 2 else ""
    data_map = argv[3] if len(argv) > 3 else ""

    install_repo_types()

    if name_map:
        stats = apply_name_map(name_map, program_name)
        print(
            "Applied name map:",
            name_map,
            f"(updated {stats['updated']}, created {stats['created']}, renamed {stats['renamed']}, signatures {stats['signatures']}, comments {stats['comments']}, skipped {stats['skipped']})",
        )
    if data_map:
        stats = apply_data_map(data_map, program_name)
        print(
            "Applied data map:",
            data_map,
            f"(updated {stats['updated']}, renamed {stats['renamed']}, types {stats['types']}, comments {stats['comments']}, skipped {stats['skipped']})",
        )

    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays not available")

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
            f.write(f"// {idc.get_func_name(ea)} @ 0x{ea:08X}\n")
            for line in cfunc.get_pseudocode():
                text = ida_lines.tag_remove(line.line)
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
