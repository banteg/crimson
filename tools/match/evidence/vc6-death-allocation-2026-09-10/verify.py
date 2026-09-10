"""Separate an unchanged VC6 allocation trace from a diagnostic counterfactual."""

import argparse
import importlib.util
import json
import os
import shutil
import struct
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
REPLAY = HERE.parent / "vc6-intermediate-replay-2026-09-09"
SPEC = importlib.util.spec_from_file_location("vc6_replay", REPLAY / "verify.py")
replay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(replay)
match = replay.match
FUNCTION = "creature_handle_death"
SOURCE_SHA = "9415ec3cdb1a74fb5236dbbd66d3d0083e10ca0c0d90c44fb4bc6be50a99c48b"
C2_SHA = "d50100ac2380d58f3f6f756961fb1319d35f5248e5fa6cafb866ca657e5dda4a"
REGISTERS = (None, "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")


def register(pointer):
    if not pointer:
        return None
    index, remainder = divmod(pointer - 0x107AC730, 84)
    assert not remainder and 1 <= index <= 8, hex(pointer)
    return REGISTERS[index]


def read_trace(path):
    rows = []
    for values in struct.iter_unpack("<18I", path.read_bytes()):
        rows.append(
            {
                "opcode": values[1],
                "source_line": values[2] & 0xFFFF,
                "cursor_before": values[3],
                "temporary_id": values[4],
                "preference_before_probe": register(values[5]),
                "unavailable_registers": [REGISTERS[i] for i in range(1, 9) if values[6] & (1 << i)],
                "chosen_register": register(values[16]),
                "cursor_after": values[17],
            },
        )
    assert len(rows) == 17
    assert [row["temporary_id"] for row in rows[:5]] == [451, 449, 90, 93, 304]
    assert rows[1]["opcode"] == 0x12 and rows[1]["source_line"] == 2
    return rows


def observe(out, replay_directory, config, *, counterfactual):
    out.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(replay_directory / "replay_settings.h", out / "replay_settings.h")
    shutil.copyfile(HERE / "observer.c", out / "observer.c")
    (out / "probe_settings.h").write_text(f"#define COUNTERFACTUAL {int(counterfactual)}\n")
    replay.compile_driver(out, "observer.c", "observer.obj")
    replay.link(out, "observer.exe", "observer.obj")
    obj = out / "replay.obj"
    obj.unlink(missing_ok=True)
    (out / "allocation.bin").unlink(missing_ok=True)
    replay.run([replay.WIBO, "observer.exe"], out)
    equal = replay.normalized_coff(obj) == replay.normalized_coff(replay_directory / "replay.obj")
    assert equal is not counterfactual
    rows = read_trace(out / "allocation.bin")
    assert [row["chosen_register"] for row in rows[:5]] == (
        ["ecx", "eax", "edx", "eax", "ecx"] if counterfactual else ["ecx", "edx", "eax", "ecx", "edx"]
    )
    metrics = replay.function_metrics(config, obj)
    assert metrics["exact"] is counterfactual
    assert metrics["body_byte_exact"] is counterfactual
    return {
        "compiler_state_modified": counterfactual,
        "same_whole_coff_as_unobserved_except_timestamp": equal,
        "normalized_coff_sha256": replay.sha(replay.normalized_coff(obj)),
        "metrics": metrics,
        "allocation_choices": rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches" / FUNCTION)
    source = (config.directory / config.source).read_bytes()
    assert replay.sha(source) == SOURCE_SHA, "Reassess the probe when canonical source changes"
    assert replay.sha((replay.COMPILER / "Bin/C2.DLL").read_bytes()) == C2_SHA
    assert config.compiler == "msvc6.5" and config.cflags == "/O2 /GB /W3 /GR-"
    old = "    int creature_flags = creature_pool[creature_id].flags;\n    creature_t *creature = &creature_pool[creature_id];"
    new = "    creature_t *creature = &creature_pool[creature_id];\n    int creature_flags = creature->flags;"
    assert source.decode().count(old) == 1
    member_source = out / "member-source"
    member_source.mkdir(exist_ok=True)
    (member_source / config.source).write_text(source.decode().replace(old, new))
    member_config = replace(config, directory=member_source)
    helper = out / "helper"
    helper.mkdir(exist_ok=True)
    environment = {
        "MSVC_VER": "msvc6.5",
        "CRIMSON_MSVC_ROOT": str(replay.COMPILER),
        "CRIMSON_MATCH_INCLUDE_OVERLAY": "",
        "WIBO": str(replay.WIBO),
        "CRIMSON_IL_BACKEND": replay.windows_path(replay.COMPILER / "Bin/C2.DLL"),
    }
    load_config = match.load_scratch_config
    with patch.dict(os.environ, environment):
        shutil.copyfile(REPLAY / "capture.c", helper / "capture.c")
        replay.compile_driver(helper, "capture.c", "capture.obj")
        replay.link(helper, "capture.dll", "capture.obj", dll=True)
        canonical = replay.verify_function(FUNCTION, out / "canonical", helper / "capture.dll")
        with patch.object(
            match,
            "load_scratch_config",
            lambda path: member_config if Path(path) == config.directory else load_config(path),
        ):
            member = replay.verify_function(FUNCTION, out / "member", helper / "capture.dll")
        directory = out / "member" / FUNCTION / "replay"
        observed = observe(out / "observed", directory, config, counterfactual=False)
        diagnostic = observe(out / "counterfactual", directory, config, counterfactual=True)
    assert observed["metrics"] == member["metrics"]
    assert diagnostic["metrics"]["references_ok"] == 87
    assert not canonical["metrics"]["exact"] and not member["metrics"]["exact"]
    manifest = match.load_function_manifest()
    _, start, end = match.resolve_function(manifest, FUNCTION)
    image = match.load_image(match.DEFAULT_IMAGE_PATH)
    record = {
        "schema_version": 1,
        "kind": "vc6-allocation-observation-and-counterfactual",
        "new_source_matches": 0,
        "scope": "The observer preserves whole COFF identity. The counterfactual changes one compiler temporary's preference and is not a matching candidate.",
        "target": {
            "function": FUNCTION,
            "start": hex(start),
            "size": end - start,
            "body_sha256": replay.sha(image.mapped[start - image.image_base : end - image.image_base]),
        },
        "source_hashes": {name: replay.sha((HERE / name).read_bytes()) for name in ("verify.py", "observer.c")},
        "replay_source_hashes": {
            name: replay.sha((REPLAY / name).read_bytes()) for name in ("verify.py", "capture.c", "replay.c")
        },
        "toolchain_hashes": {
            str(path.relative_to(match.REPO_ROOT)): replay.sha(path.read_bytes())
            for path in [
                replay.WIBO,
                *(
                    replay.COMPILER / "Bin" / name
                    for name in (
                        "CL.EXE",
                        "C1.DLL",
                        "C1XX.DLL",
                        "C2.DLL",
                        "MSPDB60.DLL",
                        "LINK.EXE",
                    )
                ),
                *replay.import_inputs(),
            ]
        },
        "canonical": canonical,
        "pointer_member_source": member,
        "observer": observed,
        "diagnostic_counterfactual": diagnostic,
    }
    (out / "results.json").write_text(json.dumps(record, indent=2) + "\n")
    print(
        "Observer preserves the complete COFF object; one diagnostic preference change gives 204/204 instructions and 87 clean references. New source matches: 0.",
    )


if __name__ == "__main__":
    main()
