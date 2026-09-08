"""Reproduce the bounded vector ABI controls without writing into scratches."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pefile

from crimson import match, match_toolchain

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
SOURCES = ("vectors.h", "helpers.cpp", "callers.cpp")
FLAGS = ("/c", "/O2", "/GB", "/W3", "/GR-", "/FAs")
HELPERS = {
    "?sub@explicit_vec2_t@@QAEPAMPAM0@Z": 0x417640,
    "??Gvalue_vec2_t@@QBE?AU0@ABU0@@Z": 0x417640,
    "?add@explicit_vec2_t@@QAEPAMPAM0@Z": 0x44ECF0,
    "??Hvalue_vec2_t@@QBE?AU0@ABU0@@Z": 0x44ECF0,
}
CALLERS = (
    ("_value_expression_angle", "_explicit_expression_angle"),
    ("_value_expression_consume", "_explicit_caller"),
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def refs(function):
    return [
        {"offset": ref.offset, "symbol": ref.symbol_name, "addend": ref.addend}
        for ref in function.relocation_references
    ]


def targets(function):
    return [
        (ref.offset, HELPERS.get(ref.symbol_name, ref.symbol_name), ref.addend)
        for ref in function.relocation_references
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    for name in SOURCES:
        shutil.copyfile(HERE / name, out / name)
    environment = dict(os.environ, MSVC_VER="msvc6.5")
    environment.pop("CRIMSON_MATCH_INCLUDE_OVERLAY", None)
    commands = []
    for name in ("helpers.cpp", "callers.cpp"):
        command = [str(REPO / "tools/match/cl.sh"), *FLAGS, name]
        result = subprocess.run(
            command,
            cwd=out,
            env=environment,
            capture_output=True,
            text=True,
            check=True,
        )
        row = {
            "argv": ["tools/match/cl.sh", *FLAGS, name],
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
        commands.append(row)

    image_path = REPO / "game_bins/crimsonland/1.9.93-gog/crimsonland.exe"
    image_bytes = image_path.read_bytes()
    image = pefile.PE(data=image_bytes)
    helpers = match.parse_coff_object((out / "helpers.obj").read_bytes())
    bodies = []
    for symbol, address in HELPERS.items():
        function = match.extract_object_function(helpers, symbol)
        native = image.get_data(address - image.OPTIONAL_HEADER.ImageBase, 26)
        row = {
            "symbol": symbol,
            "native_address": f"0x{address:08x}",
            "size": len(function.data),
            "native_size": len(native),
            "byte_exact": function.data == native,
            "relocations": refs(function),
            "candidate_sha256": sha(function.data),
            "native_sha256": sha(native),
        }
        bodies.append(row)

    callers = match.parse_coff_object((out / "callers.obj").read_bytes())
    pairs = []
    for left, right in CALLERS:
        first = match.extract_object_function(callers, left)
        second = match.extract_object_function(callers, right)
        row = {
            "left": left,
            "right": right,
            "left_size": len(first.data),
            "right_size": len(second.data),
            "object_body_bytes_equal": first.data == second.data,
            "references_equal_after_verified_helper_mapping": targets(first) == targets(second),
            "left_references": refs(first),
            "right_references": refs(second),
            "left_sha256": sha(first.data),
            "right_sha256": sha(second.data),
        }
        pairs.append(row)

    config = match.load_scratch_config(REPO / "tools/match/scratches/vec2_sub")
    compiler = match._compiler_executable_path(config, REPO / "tools/match")
    verified = all(row["byte_exact"] and not row["relocations"] for row in bodies)
    verified &= all(
        row["object_body_bytes_equal"] and row["references_equal_after_verified_helper_mapping"] for row in pairs
    )
    payload = {
        "schema": 1,
        "kind": "vector-return-contract-control",
        "verified": verified,
        "compiler_profile": "msvc6.5",
        "commands": commands,
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "compiler_sha256": sha(compiler.read_bytes()),
        "cl_wrapper_sha256": sha((REPO / "tools/match/cl.sh").read_bytes()),
        "toolchain": match_toolchain.scratch_toolchain_fingerprint(compiler, REPO / "tools/match"),
        "source_sha256": {name: sha((HERE / name).read_bytes()) for name in SOURCES},
        "original_image": {
            "path": str(image_path.relative_to(REPO)),
            "sha256": sha(image_bytes),
            "coff_symbol_table_offset": image.FILE_HEADER.PointerToSymbolTable,
            "coff_symbol_count": image.FILE_HEADER.NumberOfSymbols,
            "export_count": len(image.DIRECTORY_ENTRY_EXPORT.symbols)
            if hasattr(image, "DIRECTORY_ENTRY_EXPORT")
            else 0,
            "name_string_offsets": {
                name: image_bytes.find(name.encode())
                for name in ("vec2_sub", "vec2_add_out", "controls_vec2_t", "vec2_t@@")
            },
        },
        "native_fire_cough_call_and_angle": {
            "address": "0x00413b7f",
            "size": 14,
            "bytes_hex": image.get_data(0x413B7F - image.OPTIONAL_HEADER.ImageBase, 14).hex(),
        },
        "helper_bodies": bodies,
        "caller_pairs": pairs,
    }
    (out / "comparison.json").write_text(json.dumps(payload, indent=2) + "\n")
    print(f"verified={verified}: {out / 'comparison.json'}")
    if not verified:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
