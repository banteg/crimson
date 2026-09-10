"""Compare late memset stores with timeline pointer folding using a preserving observer."""

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
C2_SHA = "d50100ac2380d58f3f6f756961fb1319d35f5248e5fa6cafb866ca657e5dda4a"
SOURCE_HASHES = {
    "dx_get_version_from_dxdiag": "a11b9bf5571fdc3f5ab8b458cb70380c67f60154cfd30954848e7e6c8e6bf713",
    "quest_spawn_timeline_update": "a448391479030f257a8e5626e795be585674e2b4ec3e0fdb5e95ff9a08ff44d9",
}
PHASES = (
    "before_130cb", "after_130cb", "before_281cd", "before_2930f",
    "before_29511", "after_29511", "before_26d75", "after_26d75", "before_30308", "before_306c1",
    "after_306c1", "before_336f4",
)
COUNTS = {
    "dx_get_version_from_dxdiag": [182, 175, 175, 175, 175, 192, 192, 212, 212, 212, 212, 229],
    "quest_spawn_timeline_update": [154, 147, 146, 155, 140, 158, 153, 172, 172, 170, 165, 155],
}


def read_trace(path, name):
    data = path.read_bytes()
    offset = 0
    snapshots = []
    while offset < len(data):
        phase, count = struct.unpack_from("<2I", data, offset)
        offset += 8
        nodes = [struct.unpack_from("<16I", data, offset + i * 64) for i in range(count)]
        offset += count * 64
        snapshots.append((phase, nodes))
    assert offset == len(data)
    assert [phase for phase, _ in snapshots] == list(range(len(PHASES)))
    assert [len(nodes) for _, nodes in snapshots] == COUNTS[name]
    return [nodes for _, nodes in snapshots]


def verify_dxdiag(snapshots):
    # Source lines are relative to the last line of the function signature.
    intrinsic = [node for node in snapshots[4] if node[2] == 18 and node[1] == 0x190]
    assert len(intrinsic) == 1
    for nodes in snapshots[:5]:
        assert any(node[0] == intrinsic[0][0] and node[1] == 0x190 for node in nodes)
    assert all(node[1] != 0x190 for node in snapshots[5] if node[2] == 18)
    stores = [node for node in snapshots[5] if node[2] == 18 and node[1] == 1 and node[11] == 2]
    assert len(stores) == 4
    fields = [node for node in snapshots[5] if 19 <= node[2] <= 22 and node[1] == 1 and node[11] == 1]
    assert len(fields) == 4
    assert [node[13] for node in stores] == [node[13] for node in fields]
    assert len({node[13] for node in stores}) == 4
    # All four zeroing writes use the zero seed's common temporary home.
    seed = [node for node in snapshots[5] if node[2] == 18 and node[5] == 7 and node[8] == 0]
    assert len(seed) == 1 and seed[0][11] == 1
    assert {node[8] for node in stores} == {seed[0][14]}
    for phase, nodes in enumerate(snapshots[5:], start=5):
        by_id = {node[0]: node for node in nodes}
        for original in stores:
            current = by_id[original[0]]
            assert (current[1], current[11], current[13]) == (1, 2, original[13])
        for original in fields:
            current = by_id[original[0]]
            assert (current[1], current[11], current[13]) == (1, 1 if phase < 7 else 2, original[13])
    return {
        "intrinsic_survives_global_optimization": True,
        "intrinsic_expansion_pass_rva": "0x29511",
        "zeroing_memory_stores_created": 4,
        "following_field_stores_same_destination_symbols": 4,
        "following_field_destination_kind_after_29511": 1,
        "following_field_destination_kind_after_26d75": 2,
        "zeroing_store_identities_survive_306c1_and_reach_336f4": True,
        "memory_destination_kind": 2,
    }


def verify_timeline(snapshots):
    selected = [[node for node in nodes if node[2] == 40] for nodes in snapshots]
    assert [node[1] for node in selected[2]] == [0x16D, 0x15B]
    assert selected[2][1][11] == 2
    assert selected[3][1][11] == 1
    assert [node[1] for node in selected[4]] == [0x12, 0x15B]
    for phase in (5, 6, 7, 8, 9):
        assert [node[1] for node in selected[phase]] == [0x12, 1]
        assert all(node[11] == 1 for node in selected[phase])
    removed = {node[0] for node in selected[9]}
    assert removed == {node[0] for node in selected[8]}
    for phase in (10, 11):
        assert not selected[phase]
        assert removed.isdisjoint(node[0] for node in snapshots[phase])
    return {
        "pointer_copy_destination_kind_before_281cd": 2,
        "pointer_copy_destination_kind_before_2930f": 1,
        "pointer_opcodes_before_306c1": ["0x12", "0x1"],
        "pointer_node_identities_removed_in_306c1": True,
        "pointer_copy_is_memory_store_before_306c1": False,
    }


def summarize(snapshots, name):
    # Runtime addresses are only compared within a replay; do not publish them
    # as durable identities. Relevant source lines and operand kinds are stable.
    lines = range(18, 23) if name.startswith("dx_") else (40,)
    return [
        {
            "phase": PHASES[phase],
            "node_count": len(nodes),
            "selected": [
                {
                    "relative_source_line": node[2],
                    "opcode": hex(node[1]),
                    "source_kind": node[5],
                    "destination_kind": node[11],
                }
                for node in nodes if node[2] in lines
            ],
        }
        for phase, nodes in enumerate(snapshots)
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    helper = out / "helper"
    helper.mkdir(exist_ok=True)
    assert replay.sha((replay.COMPILER / "Bin/C2.DLL").read_bytes()) == C2_SHA
    environment = {
        "MSVC_VER": "msvc6.5",
        "CRIMSON_MSVC_ROOT": str(replay.COMPILER),
        "CRIMSON_MATCH_INCLUDE_OVERLAY": "",
        "WIBO": str(replay.WIBO),
        "CRIMSON_IL_BACKEND": replay.windows_path(replay.COMPILER / "Bin/C2.DLL"),
    }
    records = []
    with patch.dict(os.environ, environment):
        shutil.copyfile(REPLAY / "capture.c", helper / "capture.c")
        replay.compile_driver(helper, "capture.c", "capture.obj")
        replay.link(helper, "capture.dll", "capture.obj", dll=True)
        for name, source_hash in SOURCE_HASHES.items():
            config = replay.match.load_scratch_config(replay.match.DEFAULT_MATCH_ROOT / "scratches" / name)
            assert replay.sha((config.directory / config.source).read_bytes()) == source_hash
            assert config.compiler == "msvc6.5" and config.cflags == "/O2 /GB /W3 /GR-"
            baseline = replay.verify_function(name, out, helper / "capture.dll")
            observed = out / name / "observed"
            observed.mkdir(exist_ok=True)
            replay_dir = out / name / "replay"
            shutil.copyfile(replay_dir / "replay_settings.h", observed / "replay_settings.h")
            shutil.copyfile(HERE / "observer.c", observed / "observer.c")
            replay.compile_driver(observed, "observer.c", "observer.obj")
            replay.link(observed, "observer.exe", "observer.obj")
            for filename in ("replay.obj", "phases.bin"):
                (observed / filename).unlink(missing_ok=True)
            replay.run([replay.WIBO, "observer.exe"], observed)
            assert replay.normalized_coff(observed / "replay.obj") == replay.normalized_coff(replay_dir / "replay.obj")
            assert replay.function_metrics(config, observed / "replay.obj") == baseline["metrics"]
            assert baseline["metrics"]["body_byte_exact"] == name.startswith("dx_")
            snapshots = read_trace(observed / "phases.bin", name)
            findings = verify_dxdiag(snapshots) if name.startswith("dx_") else verify_timeline(snapshots)
            records.append({
                "baseline": baseline,
                "observed_whole_coff_equal_except_timestamp": True,
                "findings": findings,
                "snapshots": summarize(snapshots, name),
            })
            print(name, "unchanged whole COFF; trace assertions passed", flush=True)
    record = {
        "schema_version": 1,
        "kind": "vc6-store-pass-comparison",
        "source_hashes": {name: replay.sha((HERE / name).read_bytes()) for name in ("verify.py", "observer.c")},
        "replay_source_hashes": {
            name: replay.sha((REPLAY / name).read_bytes()) for name in ("verify.py", "capture.c", "replay.c")
        },
        "c2_sha256": C2_SHA,
        "compiler_decisions_modified": False,
        "functions": records,
        "new_source_matches": 0,
    }
    (out / "results.json").write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()
