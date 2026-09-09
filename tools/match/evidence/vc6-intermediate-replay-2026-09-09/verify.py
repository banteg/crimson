"""Capture VC6 frontend streams and verify exact standalone backend replay."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from crimson import match

HERE = Path(__file__).resolve().parent
ROOT = match.REPO_ROOT
COMPILER = match.DEFAULT_MATCH_ROOT / "compilers/msvc6.5"
WIBO = match.DEFAULT_MATCH_ROOT / "bin/wibo"
PROVIDERS = ROOT / "analysis/native/crimsonland.exe/link/providers"
FUNCTIONS = ("statistics_update_check_worker", "highscore_sync_worker")
SUFFIXES = ("ex", "in", "sy", "gl")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def windows_path(path):
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


def normalized_coff(path):
    data = bytearray(path.read_bytes())
    match.parse_coff_object(bytes(data))
    data[4:8] = bytes(4)  # Only the IMAGE_FILE_HEADER timestamp is ignored.
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
    assert raw.endswith(b"\0")
    arguments = [value.decode("ascii") for value in raw[:-1].split(b"\0")]
    assert arguments.count("-il") == 1
    index = arguments.index("-il") + 1
    original_prefix = arguments[index]
    basename = original_prefix.replace("\\", "/").rsplit("/", 1)[-1]
    assert basename and ":" not in basename
    streams = {suffix: capture / (basename + suffix) for suffix in SUFFIXES}
    assert all(path.is_file() and path.stat().st_size for path in streams.values())
    arguments[0] = windows_path(COMPILER / "Bin/C2.DLL")
    arguments[index] = windows_path(capture / basename)
    output_indices = [index for index, argument in enumerate(arguments) if argument.startswith("-Fo")]
    assert len(output_indices) == 1
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


def function_metrics(config, object_path):
    result = match.run_match(
        obj_path=object_path,
        function=config.function,
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


def verify_function(name, out, wrapper):
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches" / name)
    assert config.compiler == "msvc6.5"
    directory = out / name
    capture = directory / "capture"
    source = directory / "source"
    replay = directory / "replay"
    for path in (capture, source, replay):
        path.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(config.directory / config.source, source / config.source)
    normal = match.compile_scratch(config, force=True)
    # Forward slashes survive the matcher's shlex parsing and are accepted by CL.
    wrapper_flag = '/B2"Z:' + str(wrapper) + '"'
    wrapped_config = replace(config, directory=source, cflags=config.cflags + " " + wrapper_flag + " /Bd")
    with patch.dict(os.environ, {"CRIMSON_IL_CAPTURE_DIR": windows_path(capture)}):
        wrapped = match.compile_scratch(wrapped_config, force=True)
    arguments, streams = read_arguments(capture)
    hashes = {suffix: sha(path.read_bytes()) for suffix, path in streams.items()}
    build_replay(replay, arguments)
    replayed = replay / "replay.obj"
    replayed.unlink(missing_ok=True)
    run([WIBO, "replay.exe"], replay)
    assert {suffix: sha(path.read_bytes()) for suffix, path in streams.items()} == hashes
    normal_data = normalized_coff(normal)
    assert normalized_coff(wrapped) == normal_data
    assert normalized_coff(replayed) == normal_data
    metrics = function_metrics(config, replayed)
    assert metrics == function_metrics(config, normal)

    # A failed replay must not be accepted because a previous object exists.
    negative = directory / "missing-stream"
    negative.mkdir(exist_ok=True)
    (negative / "replay.obj").unlink(missing_ok=True)
    missing = streams["ex"]
    backup = missing.with_name(missing.name + ".withheld")
    missing.rename(backup)
    try:
        rejected = run([WIBO, replay / "replay.exe"], negative, check=False)
        assert rejected.returncode != 0
        assert not (negative / "replay.obj").exists()
    finally:
        backup.rename(missing)
    assert {suffix: sha(path.read_bytes()) for suffix, path in streams.items()} == hashes

    displayed_arguments = list(arguments)
    displayed_arguments[0] = "{original-c2}"
    displayed_arguments[displayed_arguments.index("-il") + 1] = "{captured-prefix}"
    return {
        "function": name,
        "source_sha256": sha((config.directory / config.source).read_bytes()),
        "normal_build_key": json.loads((normal.parent / "scratch-build.json").read_text())["key"],
        "cflags": config.cflags,
        "captured_streams": {
            suffix: {"size": path.stat().st_size, "sha256": hashes[suffix]} for suffix, path in streams.items()
        },
        "replayed_backend_arguments": displayed_arguments,
        "normal_wrapped_replayed_objects_equal_except_timestamp": True,
        "normalized_coff_size": len(normal_data),
        "normalized_coff_sha256": sha(normal_data),
        "streams_unchanged_after_replay": True,
        "missing_stream_replay_rejected": True,
        "missing_stream_exit_code": rejected.returncode,
        "metrics": metrics,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--function",
        action="append",
        dest="functions",
        help="Canonical VC6 scratch to verify; repeat to select several (default: both network workers)",
    )
    arguments = parser.parse_args()
    functions = tuple(dict.fromkeys(arguments.functions or FUNCTIONS))
    out = arguments.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    helper = out / "helper"
    helper.mkdir(exist_ok=True)
    environment = {
        "MSVC_VER": "msvc6.5",
        "CRIMSON_MSVC_ROOT": str(COMPILER),
        "CRIMSON_MATCH_INCLUDE_OVERLAY": "",
        "WIBO": str(WIBO),
        "CRIMSON_IL_BACKEND": windows_path(COMPILER / "Bin/C2.DLL"),
    }
    with patch.dict(os.environ, environment):
        shutil.copyfile(HERE / "capture.c", helper / "capture.c")
        compile_driver(helper, "capture.c", "capture.obj")
        link(helper, "capture.dll", "capture.obj", dll=True)
        rows = []
        for name in functions:
            rows.append(verify_function(name, out, helper / "capture.dll"))
            print(
                f"{name}: normal, captured, and replayed COFF objects agree; missing-stream control rejected",
                flush=True,
            )
    compiler_paths = [
        COMPILER / "Bin" / name for name in ("CL.EXE", "C1.DLL", "C1XX.DLL", "C2.DLL", "MSPDB60.DLL", "LINK.EXE")
    ]
    record = {
        "schema_version": 1,
        "kind": "vc6-frontend-capture-and-backend-replay",
        "scope": "Unmodified canonical sources and backend; object equality excludes only COFF timestamp bytes 4..7.",
        "limitations": "Captures serialized frontend streams; does not decode their IR or trace optimizer passes. No new exact function is claimed.",
        "source_hashes": {name: sha((HERE / name).read_bytes()) for name in ("verify.py", "capture.c", "replay.c")},
        "toolchain_hashes": {
            str(path.relative_to(ROOT)): sha(path.read_bytes()) for path in [WIBO, *compiler_paths, *import_inputs()]
        },
        "functions": rows,
    }
    (out / "results.json").write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()
