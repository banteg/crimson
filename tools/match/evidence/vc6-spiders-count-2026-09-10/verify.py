"""Observe the two Spiders count representations without modifying compiler decisions."""

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
FUNCTION = "quest_build_spiders_inc"
SOURCE_SHA = "36596b7961beb2da9bb0cedab291af0e5eb4b56a5c398b46d3d11f38cf658338"
C2_SHA = "d50100ac2380d58f3f6f756961fb1319d35f5248e5fa6cafb866ca657e5dda4a"
PHASES = ("before_281cd", "before_2930f", "after_2930f", "before_336f4")


def read_trace(path, *, late):
    data = path.read_bytes()
    offset = 0
    snapshots = []
    while offset < len(data):
        phase, count = struct.unpack_from("<2I", data, offset)
        offset += 8
        nodes = [struct.unpack_from("<9I", data, offset + i * 36) for i in range(count)]
        offset += count * 36
        snapshots.append((phase, nodes))
    assert offset == len(data)
    assert [phase for phase, _ in snapshots] == list(range(4))
    initial = snapshots[0][1]
    additions = [node for node in initial if node[1:3] == (0x16D, 35)]
    divisions = [node for node in initial if node[1:3] == (0x175, 35)]
    # The canonical chained assignment has further address additions on line 35.
    pairs = [(add, div) for add in additions for div in divisions if add[4] == div[6]]
    assert len(pairs) == 1
    addition, division = pairs[0]
    assert addition[5] == (1 if late else 2)
    expected_additions = (0x16D, 0x16D, 0x2D, 0x2D) if late else (0x16D, 0x16D, 0x12, 0x12)
    result = []
    for phase, nodes in snapshots:
        by_pointer = {node[0]: node for node in nodes}
        add, div = by_pointer[addition[0]], by_pointer[division[0]]
        assert add[1] == expected_additions[phase]
        assert div[1] == (0x29 if phase == 3 else 0x175)
        same_owner = add[7] == div[7]
        if phase == 3:
            assert same_owner == late
        result.append(
            {
                "phase": PHASES[phase],
                "total_instructions": len(nodes),
                "addition_opcode": hex(add[1]),
                "division_opcode": hex(div[1]),
                "addition_destination_operand_kind": add[5],
                "division_and_addition_share_destination_storage_owner": same_owner,
            },
        )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    match = replay.match
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches" / FUNCTION)
    source = (config.directory / config.source).read_bytes()
    assert replay.sha(source) == SOURCE_SHA
    assert replay.sha((replay.COMPILER / "Bin/C2.DLL").read_bytes()) == C2_SHA
    assert config.compiler == "msvc6.5" and config.cflags == "/O2 /GB /W3 /GR-"
    early_count = "int wave_count = builder.spawns[builder.count].count = step_count / 2 + 3;"
    late_site = "        builder.spawns[builder.count].trigger_time_ms = trigger_time_ms;"
    text = source.decode()
    assert text.count(early_count) == text.count(late_site) == 1
    late_source = text.replace(early_count, "int wave_count = step_count / 2 + 3;").replace(
        late_site,
        late_site + "\n        builder.spawns[builder.count].count = wave_count;",
    )
    late_directory = out / "late-source"
    late_directory.mkdir(exist_ok=True)
    (late_directory / config.source).write_text(late_source)
    late_config = replace(config, directory=late_directory)
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
    variants = {}
    with patch.dict(os.environ, environment):
        shutil.copyfile(REPLAY / "capture.c", helper / "capture.c")
        replay.compile_driver(helper, "capture.c", "capture.obj")
        replay.link(helper, "capture.dll", "capture.obj", dll=True)
        for name, selected in (("canonical", config), ("late", late_config)):
            with patch.object(
                match,
                "load_scratch_config",
                lambda path, selected=selected: selected if Path(path) == config.directory else load_config(path),
            ):
                baseline = replay.verify_function(FUNCTION, out / name, helper / "capture.dll")
            directory = out / name / FUNCTION / "replay"
            observed = out / name / "observed"
            observed.mkdir(exist_ok=True)
            shutil.copyfile(directory / "replay_settings.h", observed / "replay_settings.h")
            shutil.copyfile(HERE / "observer.c", observed / "observer.c")
            replay.compile_driver(observed, "observer.c", "observer.obj")
            replay.link(observed, "observer.exe", "observer.obj")
            for filename in ("replay.obj", "phases.bin"):
                (observed / filename).unlink(missing_ok=True)
            replay.run([replay.WIBO, "observer.exe"], observed)
            assert replay.normalized_coff(directory / "replay.obj") == replay.normalized_coff(observed / "replay.obj")
            metrics = replay.function_metrics(selected, observed / "replay.obj")
            assert metrics == baseline["metrics"]
            assert metrics["candidate_instructions"] == (106 if name == "late" else 105)
            assert metrics["references_ok"] == 7 and metrics["reference_problems"] == 0
            assert not metrics["exact"] and not metrics["body_byte_exact"]
            variants[name] = {
                "baseline": baseline,
                "observed_whole_coff_equal_except_timestamp": True,
                "snapshots": read_trace(observed / "phases.bin", late=name == "late"),
            }
    manifest = match.load_function_manifest()
    _, start, end = match.resolve_function(manifest, FUNCTION)
    image = match.load_image(match.DEFAULT_IMAGE_PATH)
    record = {
        "schema_version": 1,
        "kind": "vc6-spiders-count-representation",
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
        "canonical_source_sha256": SOURCE_SHA,
        "late_source_sha256": replay.sha(late_source.encode()),
        "c2_sha256": C2_SHA,
        "compiler_decisions_modified": False,
        "variants": variants,
        "new_source_matches": 0,
    }
    (out / "results.json").write_text(json.dumps(record, indent=2) + "\n")
    print("Both whole COFF objects unchanged; C2+0x2930f chooses LEA versus ADD. New source matches: 0.")


if __name__ == "__main__":
    main()
