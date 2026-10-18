"""Capture VC6 frontend streams and verify exact standalone backend replay."""

import hashlib
import json
import shutil
import struct
import subprocess
from contextlib import contextmanager
from pathlib import Path

from . import match

HERE = match.DEFAULT_MATCH_ROOT / "c2"
ROOT = match.REPO_ROOT
COMPILERS = match.DEFAULT_MATCH_ROOT / "compilers"
COMPILER = COMPILERS / "msvc6.5"
WIBO = match.DEFAULT_MATCH_ROOT / "bin/wibo"
PROVIDERS = ROOT / "analysis/native/crimsonland.exe/link/providers"
SUFFIXES = ("ex", "in", "sy", "gl")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def windows_path(path: Path) -> str:
    result = "Z:" + str(path.resolve()).replace("/", "\\")
    if len(result.encode("ascii")) >= 240:
        raise ValueError("Use a shorter ASCII output path for this VC6 diagnostic")
    return result


def run(arguments, directory, *, check=True):
    result = subprocess.run(
        [str(argument) for argument in arguments],
        cwd=directory,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if check and result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {arguments}\n{result.stdout}{result.stderr}")
    return result


@contextmanager
def using_compiler(name: str):
    """Point capture, replay and observer builds at `compilers/<name>`, the C2 build being observed."""
    global COMPILER
    previous, COMPILER = COMPILER, COMPILERS / name
    try:
        yield COMPILER
    finally:
        COMPILER = previous


def normalized_coff(path: Path) -> bytes:
    """The object with its IMAGE_FILE_HEADER timestamp zeroed and its `.debug$S` sections removed.

    Only the Processor Pack C2 writes `.debug$S` here: an S_OBJNAME record naming the object's own path, which
    differs between a scratch build and its replay. Everything else, including every file pointer and the
    symbol table, is compared after the removal.
    """
    data = bytearray(path.read_bytes())
    match.parse_coff_object(bytes(data))
    data[4:8] = bytes(4)
    section_count, symbols_at, symbol_count, optional_size = struct.unpack_from("<HxxxxIIH", data, 2)
    headers = 20 + optional_size
    for index in reversed(range(section_count)):
        header = headers + index * 40
        if bytes(data[header : header + 8]).rstrip(b"\0") != b".debug$S":
            continue
        size, start = struct.unpack_from("<II", data, header + 16)
        struct.pack_into("<II", data, header + 16, 0, 0)
        for other in range(section_count):
            for field in (20, 24, 28):  # raw data, relocations, line numbers
                (pointer,) = struct.unpack_from("<I", data, headers + other * 40 + field)
                if pointer > start:
                    struct.pack_into("<I", data, headers + other * 40 + field, pointer - size)
        symbol = 0
        while symbol < symbol_count:
            record = symbols_at + symbol * 18
            aux = data[record + 17]
            if struct.unpack_from("<h", data, record + 12)[0] == index + 1 and aux:
                data[record + 18 : record + 36] = bytes(18)  # the section definition's length and checksum
            symbol += 1 + aux
        if symbols_at > start:
            symbols_at -= size
            struct.pack_into("<I", data, 8, symbols_at)
        del data[start : start + size]
    return bytes(data)


def import_inputs():
    paths = [
        PROVIDERS / (name + suffix)
        for name in ("kernel32-dll", "msvc6-runtime-kernel32")
        for suffix in (".lib", "-aliases.obj")
    ]
    for path in paths:
        if not path.is_file():
            raise FileNotFoundError(
                f"Run `crimson native link --image crimsonland.exe` first; missing diagnostic import input: {path}",
            )
    return paths


def link(directory, output, object_name, *, dll=False):
    arguments = [
        WIBO,
        COMPILER / "Bin/LINK.EXE",
        "/nologo",
        "/nodefaultlib",
        "/dll" if dll else "/subsystem:console",
        "/entry:DllMain@12" if dll else "/entry:start@0",
        "/out:" + output,
        object_name,
        *(windows_path(path) for path in import_inputs()),
    ]
    run(arguments, directory)


def compile_driver(directory, source_name, object_name):
    run(
        [match.DEFAULT_MATCH_ROOT / "cl.sh", "/c", "/O2", "/Fo" + object_name, source_name],
        directory,
    )


def read_arguments(capture):
    raw = (capture / "arguments.bin").read_bytes()
    if not raw.endswith(b"\0"):
        raise ValueError("Captured backend argv is not NUL terminated")
    arguments = [value.decode("ascii") for value in raw[:-1].split(b"\0")]
    if arguments.count("-il") != 1 or arguments[-1] == "-il":
        raise ValueError("Expected one backend -il prefix argument")
    index = arguments.index("-il") + 1
    original_prefix = arguments[index]
    basename = original_prefix.replace("\\", "/").rsplit("/", 1)[-1]
    if not basename or ":" in basename or basename in (".", ".."):
        raise ValueError("Invalid captured stream basename")
    streams = {suffix: capture / (basename + suffix) for suffix in SUFFIXES}
    if not all(path.is_file() and path.stat().st_size for path in streams.values()):
        raise ValueError("Missing or empty captured backend stream")
    arguments[0] = windows_path(COMPILER / "Bin/C2.DLL")
    arguments[index] = windows_path(capture / basename)
    output_indices = [index for index, argument in enumerate(arguments) if argument.startswith("-Fo")]
    if len(output_indices) != 1:
        raise ValueError("Expected one backend output argument")
    arguments[output_indices[0]] = "-Foreplay.obj"
    return arguments, streams


def build_replay(directory, arguments):
    settings = (
        "static const char *backend_path = " + json.dumps(windows_path(COMPILER / "Bin/C2.DLL")) + ";\n"
        "static const char *pdb_path = " + json.dumps(windows_path(COMPILER / "Bin/MSPDB60.DLL")) + ";\n"
        "static char *arguments[] = {\n" + ",\n".join(json.dumps(argument) for argument in arguments) + "\n};\n"
    )
    (directory / "replay_settings.h").write_text(settings)
    shutil.copyfile(HERE / "replay.c", directory / "replay.c")
    compile_driver(directory, "replay.c", "replay-driver.obj")
    link(directory, "replay.exe", "replay-driver.obj")


def function_metrics(config, object_path, target: match.MatchTarget | None = None):
    target = target or match.default_match_target(config.image)
    result = match.run_match(
        obj_path=object_path,
        function=config.function,
        image_path=target.image_path,
        functions_path=target.functions_path,
        metadata_path=target.metadata_path,
        image_name=target.image_name,
        data_map_path=target.data_map_path,
        end_va=config.end_va,
        object_extent=config.archive_extent,
        object_end_symbol=config.archive_end_symbol,
        object_size=config.archive_size,
        symbol_name=config.symbol,
        reference_aliases=config.reference_aliases,
    )
    return {
        "ratio": result.ratio,
        "target_instructions": len(result.target_lines),
        "candidate_instructions": len(result.candidate_lines),
        "prefix_instructions": result.prefix_instructions,
        "references_ok": result.masked_operand_audit.ok_count,
        "reference_problems": result.masked_operand_audit.problem_count,
        "exact": result.exact,
        "body_byte_exact": result.body_byte_exact,
    }
