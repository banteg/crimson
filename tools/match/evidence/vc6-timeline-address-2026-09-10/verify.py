"""Locate removal of the timeline template pointer without changing compiler decisions."""

import argparse
import importlib.util
import json
import os
import shutil
import struct
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
REPLAY = HERE.parent / "vc6-intermediate-replay-2026-09-09"
SPEC = importlib.util.spec_from_file_location("vc6_replay", REPLAY / "verify.py")
replay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(replay)
FUNCTION = "quest_spawn_timeline_update"
SOURCE_SHA = "a448391479030f257a8e5626e795be585674e2b4ec3e0fdb5e95ff9a08ff44d9"
C2_SHA = "d50100ac2380d58f3f6f756961fb1319d35f5248e5fa6cafb866ca657e5dda4a"
PHASES = ("before_30308", "before_306c1", "after_306c1", "before_336f4")


def read_trace(path):
    data = path.read_bytes()
    offset = 0
    snapshots = []
    while offset < len(data):
        phase, count = struct.unpack_from("<2I", data, offset)
        offset += 8
        nodes = [struct.unpack_from("<3I", data, offset + i * 12) for i in range(count)]
        offset += count * 12
        snapshots.append((phase, nodes))
    assert offset == len(data)
    assert [phase for phase, _ in snapshots] == list(range(4))
    assert [len(nodes) for _, nodes in snapshots] == [172, 170, 165, 155]
    selected = [[node for node in nodes if node[2] == 40] for _, nodes in snapshots]
    assert [[node[1] for node in nodes] for nodes in selected] == [[0x12, 1], [0x12, 1], [], []]
    removed = {node[0] for node in selected[1]}
    assert removed == {node[0] for node in selected[0]}
    for _, nodes in snapshots[2:]:
        assert removed.isdisjoint(node[0] for node in nodes), "Instructions were relabeled, not removed"
    return [
        {
            "phase": PHASES[phase],
            "total_instructions": len(nodes),
            "template_pointer_opcodes": [hex(node[1]) for node in selected[phase]],
        }
        for phase, nodes in snapshots
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    config = replay.match.load_scratch_config(replay.match.DEFAULT_MATCH_ROOT / "scratches" / FUNCTION)
    assert replay.sha((config.directory / config.source).read_bytes()) == SOURCE_SHA
    assert replay.sha((replay.COMPILER / "Bin/C2.DLL").read_bytes()) == C2_SHA
    assert config.compiler == "msvc6.5" and config.cflags == "/O2 /GB /W3 /GR-"
    helper = out / "helper"
    observed = out / "observed"
    helper.mkdir(exist_ok=True)
    observed.mkdir(exist_ok=True)
    environment = {
        "MSVC_VER": "msvc6.5",
        "CRIMSON_MSVC_ROOT": str(replay.COMPILER),
        "CRIMSON_MATCH_INCLUDE_OVERLAY": "",
        "WIBO": str(replay.WIBO),
        "CRIMSON_IL_BACKEND": replay.windows_path(replay.COMPILER / "Bin/C2.DLL"),
    }
    with patch.dict(os.environ, environment):
        shutil.copyfile(REPLAY / "capture.c", helper / "capture.c")
        replay.compile_driver(helper, "capture.c", "capture.obj")
        replay.link(helper, "capture.dll", "capture.obj", dll=True)
        baseline = replay.verify_function(FUNCTION, out, helper / "capture.dll")
        replay_dir = out / FUNCTION / "replay"
        shutil.copyfile(replay_dir / "replay_settings.h", observed / "replay_settings.h")
        shutil.copyfile(HERE / "observer.c", observed / "observer.c")
        replay.compile_driver(observed, "observer.c", "observer.obj")
        replay.link(observed, "observer.exe", "observer.obj")
        for name in ("replay.obj", "phases.bin"):
            (observed / name).unlink(missing_ok=True)
        replay.run([replay.WIBO, "observer.exe"], observed)
    original = replay.normalized_coff(replay_dir / "replay.obj")
    assert replay.normalized_coff(observed / "replay.obj") == original
    metrics = replay.function_metrics(config, observed / "replay.obj")
    assert metrics == baseline["metrics"]
    assert not metrics["exact"] and not metrics["body_byte_exact"]
    record = {
        "schema_version": 1,
        "kind": "vc6-timeline-template-pointer-removal",
        "source_hashes": {name: replay.sha((HERE / name).read_bytes()) for name in ("verify.py", "observer.c")},
        "replay_source_hashes": {
            name: replay.sha((REPLAY / name).read_bytes()) for name in ("verify.py", "capture.c", "replay.c")
        },
        "c2_sha256": C2_SHA,
        "canonical_source_sha256": SOURCE_SHA,
        "baseline": baseline,
        "observed_whole_coff_equal_except_timestamp": True,
        "compiler_decisions_modified": False,
        "snapshots": read_trace(observed / "phases.bin"),
        "new_source_matches": 0,
    }
    (out / "results.json").write_text(json.dumps(record, indent=2) + "\n")
    print("Timeline: unchanged whole COFF; template LEA and copy removed inside C2+0x306c1; no new match.")


if __name__ == "__main__":
    main()
