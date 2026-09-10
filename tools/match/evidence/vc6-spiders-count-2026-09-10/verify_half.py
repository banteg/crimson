"""Observe creation, allocation, and removal of signed-division copies in current Spiders."""

import argparse
import importlib.util
import json
import os
import shutil
import struct
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("count_evidence", HERE / "verify.py")
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)
replay = evidence.replay
SOURCE_SHA = "a7f6f8080ee2c0f2fd2a9766f405d1549a499ea650f0895d9fc46a91f93d81be"
# Storage-owner pointers for the fingerprinted, fixed-base C2 image.
EAX, EBP = 0x107AC784, 0x107AC928
PHASES = (
    "before_29511",
    "after_29511",
    "before_2fb58",
    "after_2fb58",
    "after_336f4",
    "before_3536c",
    "after_3536c",
    "after_374aa",
)


def read_trace(path):
    data = path.read_bytes()
    offset = 0
    phases = []
    while offset < len(data):
        phase, count = struct.unpack_from("<2I", data, offset)
        offset += 8
        assert phase == len(phases) and count < 4096
        nodes = [struct.unpack_from("<7I", data, offset + i * 28) for i in range(count)]
        offset += count * 28
        phases.append(nodes)
    assert offset == len(data) and len(phases) == len(PHASES)
    divisions = [row for row in phases[0] if row[1:3] in ((0x175, 35), (0x175, 39))]
    assert len(divisions) == 2
    result = {}
    for division in divisions:
        line = division[2]
        by_phase = [{row[0]: row for row in nodes} for nodes in phases]
        shifts = [nodes[division[0]] for nodes in by_phase[1:]]
        assert all(row[1] == 0x29 for row in shifts)
        # The lowering pass introduces a copy into the division's existing result.
        copies = [row for row in phases[1] if row[1:3] == (1, line) and row[4] == EAX and row[6] == division[6]]
        assert len(copies) == 1
        copy = copies[0]
        assert copy[0] not in by_phase[0]
        assert shifts[0][4] == shifts[0][6] == division[6]
        is_wave = line == 35
        allocated = EBP if is_wave else EAX
        # Global allocation binds the wave quotient first; forward allocation binds the midpoint.
        assert by_phase[3][division[0]][6] == (EBP if is_wave else division[6])
        assert by_phase[4][division[0]][4] == by_phase[4][division[0]][6] == allocated
        allocated_copy = by_phase[4][copy[0]]
        assert allocated_copy[4] == EAX and allocated_copy[6] == allocated
        assert copy[0] in by_phase[5]
        assert (copy[0] in by_phase[6]) == is_wave
        assert (copy[0] in by_phase[7]) == is_wave
        if is_wave:
            assert by_phase[7][copy[0]][4] == EAX and by_phase[7][copy[0]][6] == EBP
        result["wave_increase" if is_wave else "terrain_midpoint"] = {
            "original_il_line": line,
            "copy_introduced_by_29511": True,
            "shift_retains_division_node_identity": True,
            "copy_after_allocation": f"EAX -> {'EBP' if is_wave else 'EAX'}",
            "copy_present_before_3536c": True,
            "copy_present_after_3536c": is_wave,
            "copy_present_after_scheduling": is_wave,
        }
    return {
        "phases": [{"name": name, "instructions": len(nodes)} for name, nodes in zip(PHASES, phases, strict=True)],
        "divisions": result,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    config = replay.match.load_scratch_config(replay.match.DEFAULT_MATCH_ROOT / "scratches" / evidence.FUNCTION)
    assert replay.sha((config.directory / config.source).read_bytes()) == SOURCE_SHA
    assert replay.sha((replay.COMPILER / "Bin/C2.DLL").read_bytes()) == evidence.C2_SHA
    assert config.compiler == "msvc6.5" and config.cflags == "/O2 /GB /W3 /GR-"
    helper = out / "helper"
    helper.mkdir(exist_ok=True)
    environment = {
        "MSVC_VER": "msvc6.5",
        "CRIMSON_MSVC_ROOT": str(replay.COMPILER),
        "CRIMSON_MATCH_INCLUDE_OVERLAY": "",
        "WIBO": str(replay.WIBO),
        "CRIMSON_IL_BACKEND": replay.windows_path(replay.COMPILER / "Bin/C2.DLL"),
    }
    with patch.dict(os.environ, environment):
        shutil.copyfile(evidence.REPLAY / "capture.c", helper / "capture.c")
        replay.compile_driver(helper, "capture.c", "capture.obj")
        replay.link(helper, "capture.dll", "capture.obj", dll=True)
        baseline = replay.verify_function(evidence.FUNCTION, out / "current", helper / "capture.dll")
        directory = out / "current" / evidence.FUNCTION / "replay"
        observed = out / "observed"
        observed.mkdir(exist_ok=True)
        shutil.copyfile(directory / "replay_settings.h", observed / "replay_settings.h")
        shutil.copyfile(HERE / "observer_half.c", observed / "observer_half.c")
        replay.compile_driver(observed, "observer_half.c", "observer.obj")
        replay.link(observed, "observer.exe", "observer.obj")
        for name in ("replay.obj", "phases.bin"):
            (observed / name).unlink(missing_ok=True)
        replay.run([replay.WIBO, "observer.exe"], observed)
        assert replay.normalized_coff(directory / "replay.obj") == replay.normalized_coff(observed / "replay.obj")
        metrics = replay.function_metrics(config, observed / "replay.obj")
        assert metrics == baseline["metrics"]
        assert metrics["candidate_instructions"] == 106 and metrics["references_ok"] == 8
        assert metrics["reference_problems"] == 0 and not metrics["exact"] and not metrics["body_byte_exact"]
    trace = read_trace(observed / "phases.bin")
    record = {
        "schema_version": 1,
        "kind": "vc6-spiders-half-copy-lifecycle",
        "canonical_source_sha256": SOURCE_SHA,
        "c2_sha256": evidence.C2_SHA,
        "source_hashes": {
            name: replay.sha((HERE / name).read_bytes()) for name in ("verify_half.py", "observer_half.c", "verify.py")
        },
        "replay_source_hashes": {
            name: replay.sha((evidence.REPLAY / name).read_bytes()) for name in ("verify.py", "capture.c", "replay.c")
        },
        "baseline": baseline,
        "observed_whole_coff_equal_except_timestamp": True,
        "compiler_decisions_modified": False,
        "trace": trace,
        "new_source_matches": 0,
    }
    (out / "half.json").write_text(json.dumps(record, indent=2) + "\n")
    print("Whole COFF unchanged; wave copy survives, midpoint self-copy removed. New source matches: 0.")


if __name__ == "__main__":
    main()
