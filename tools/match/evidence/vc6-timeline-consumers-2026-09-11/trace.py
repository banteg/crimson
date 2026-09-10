"""Preserving complete-operand traces for timeline consumer-rewrite controls."""

import argparse
import importlib.util
import json
import os
import shutil
import struct
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import probes

from analysis import PARTIAL, analyze, analyze_decisions
from crimson import match

HERE = Path(__file__).resolve().parent
OLD = HERE.parent / "vc6-store-pass-comparison-2026-09-11"
SPEC = importlib.util.spec_from_file_location("store_trace", OLD / "verify.py")
old = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(old)
r = old.replay


def read_trace(path):
    data = path.read_bytes()
    offset = 0
    snapshots = []
    while offset < len(data):
        phase, count = struct.unpack_from("<2I", data, offset)
        offset += 8
        nodes = []
        for _ in range(count):
            words = struct.unpack_from("<230I", data, offset)
            offset += 920
            sides = []
            for side in range(2):
                start = 4 + side * 113
                assert words[start] <= 16
                sides.append([list(words[start + 1 + k * 7 : start + 1 + (k + 1) * 7]) for k in range(words[start])])
            nodes.append(
                {"id": words[0], "op": words[1], "line": words[2], "flags": words[3], "src": sides[0], "dst": sides[1]},
            )
        snapshots.append(nodes)
        assert phase == len(snapshots) - 1
    assert offset == len(data) and len(snapshots) == len(old.PHASES)
    return snapshots


def trace(config, out, label, source, capture_dll):
    row, candidate, normal = probes.build(config, out, label, source)
    root = candidate.directory
    capture = root / "capture"
    captured_source = root / "captured-source"
    replay = root / "replay"
    observed = root / "observed"
    for directory in (capture, captured_source, replay, observed):
        directory.mkdir(exist_ok=True)
    (captured_source / config.source).write_text(source)
    wrapped = replace(
        candidate,
        directory=captured_source,
        cflags=candidate.cflags + ' /B2"Z:' + str(capture_dll) + '" /Bd',
    )
    with patch.dict(os.environ, {"CRIMSON_IL_CAPTURE_DIR": r.windows_path(capture)}):
        captured = match.compile_scratch(wrapped, force=True)
    arguments, streams = r.read_arguments(capture)
    stream_hashes = {suffix: r.sha(path.read_bytes()) for suffix, path in streams.items()}
    r.build_replay(replay, arguments)
    (replay / "replay.obj").unlink(missing_ok=True)
    r.run([r.WIBO, "replay.exe"], replay)
    shutil.copyfile(replay / "replay_settings.h", observed / "replay_settings.h")
    shutil.copyfile(HERE / "observer.c", observed / "observer.c")
    r.compile_driver(observed, "observer.c", "observer.obj")
    r.link(observed, "observer.exe", "observer.obj")
    (observed / "replay.obj").unlink(missing_ok=True)
    (observed / "phases.bin").unlink(missing_ok=True)
    r.run([r.WIBO, "observer.exe"], observed)
    normal_data = r.normalized_coff(normal)
    for obj in (captured, replay / "replay.obj", observed / "replay.obj"):
        assert r.normalized_coff(obj) == normal_data
        assert r.function_metrics(candidate, obj) == r.function_metrics(candidate, normal)
    assert {suffix: r.sha(path.read_bytes()) for suffix, path in streams.items()} == stream_hashes
    negative = root / "missing-stream"
    negative.mkdir(exist_ok=True)
    (negative / "replay.obj").unlink(missing_ok=True)
    missing = streams["ex"]
    backup = missing.with_name(missing.name + ".withheld")
    missing.rename(backup)
    try:
        rejected = r.run([r.WIBO, replay / "replay.exe"], negative, check=False)
        assert rejected.returncode != 0 and not (negative / "replay.obj").exists()
    finally:
        backup.rename(missing)
    assert {suffix: r.sha(path.read_bytes()) for suffix, path in streams.items()} == stream_hashes
    snapshots = read_trace(observed / "phases.bin")
    (root / "raw-operands.json").write_text(json.dumps(snapshots))
    row.update(
        {
            "observed_whole_coff_equal_except_timestamp": True,
            "missing_stream_rejected": True,
            "compiler_decisions_modified": False,
            "stream_hashes": stream_hashes,
            "node_counts": [len(nodes) for nodes in snapshots],
            "consumer_findings": analyze(snapshots, label, source),
        },
    )
    return row, snapshots


def trace_decisions(config, root, label, source, expected_findings):
    out = root / "decision-observed"
    out.mkdir(exist_ok=True)
    shutil.copyfile(root / "replay/replay_settings.h", out / "replay_settings.h")
    shutil.copyfile(HERE / "decision_observer.c", out / "observer.c")
    r.compile_driver(out, "observer.c", "observer.obj")
    r.link(out, "observer.exe", "observer.obj")
    for name in ("replay.obj", "phases.bin", "decisions.bin"):
        (out / name).unlink(missing_ok=True)
    r.run([r.WIBO, "observer.exe"], out)
    assert r.normalized_coff(out / "replay.obj") == r.normalized_coff(root / "replay/replay.obj")
    assert r.function_metrics(config, out / "replay.obj") == r.function_metrics(config, root / "replay/replay.obj")
    snapshots = read_trace(out / "phases.bin")
    assert analyze(snapshots, label, source) == expected_findings
    return {
        "observed_whole_coff_equal_except_timestamp": True,
        **analyze_decisions(out / "decisions.bin", snapshots, label),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    helper = out / "helper"
    helper.mkdir(exist_ok=True)
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/quest_spawn_timeline_update")
    source = (config.directory / config.source).read_text()
    assert r.sha(source.encode()) == probes.SOURCE_SHA
    assert config.compiler == "msvc6.5" and config.cflags == "/O2 /GB /W3 /GR-"
    assert r.sha((r.COMPILER / "Bin/C2.DLL").read_bytes()) == old.C2_SHA
    controls = [
        ("baseline", source),
        ("relative-heading", source.replace("entry->heading", "((float *)template_id)[-1]")),
    ]
    controls += [
        (label, text)
        for label, text, _, flags in probes.variants(source)
        if label in ("assignment-entry", "memcpy-entry", "memcpy-relative") and not flags
    ]
    plan = out / "historical-plan.json"
    generator = config.directory / "source-boundary-controls-2026-09-11.py"
    subprocess.run([sys.executable, str(generator), str(plan)], check=True)
    assert r.sha(plan.read_bytes()) == "4ed2622a03304b4f58577a953297d1509b4a520bd26d8b3c68e475bcba2ac98a"
    historical = json.loads(plan.read_text())["sites"][0]["replacements"]
    partial_source = next(item["text"] for item in historical if item["name"] == PARTIAL)
    assert r.sha(partial_source.encode()) == "b418b27e9efcafa1cc8ebecedb5b0447a651c759c2f715df84b21c738bb2ae53"
    controls.append((PARTIAL, partial_source))
    environment = {
        "MSVC_VER": "msvc6.5",
        "CRIMSON_MSVC_ROOT": str(r.COMPILER),
        "CRIMSON_MATCH_INCLUDE_OVERLAY": "",
        "WIBO": str(r.WIBO),
        "CRIMSON_IL_BACKEND": r.windows_path(r.COMPILER / "Bin/C2.DLL"),
    }
    rows = []
    with patch.dict(os.environ, environment):
        shutil.copyfile(r.HERE / "capture.c", helper / "capture.c")
        r.compile_driver(helper, "capture.c", "capture.obj")
        r.link(helper, "capture.dll", "capture.obj", dll=True)
        for label, text in controls:
            row, _ = trace(config, out, label, text, helper / "capture.dll")
            if label in ("baseline", PARTIAL):
                row["decision_findings"] = trace_decisions(config, out / label, label, text, row["consumer_findings"])
            rows.append(row)
            print(label, "whole COFF preserved; trace recorded", flush=True)
    record = {
        "schema_version": 1,
        "kind": "vc6-timeline-consumer-rewrite",
        "canonical_source_sha256": probes.SOURCE_SHA,
        "compiler_decisions_modified": False,
        "c2_sha256": old.C2_SHA,
        "source_hashes": {
            name: r.sha((HERE / name).read_bytes())
            for name in ("trace.py", "analysis.py", "probes.py", "observer.c", "decision_observer.c")
        },
        "replay_source_hashes": {
            name: r.sha((r.HERE / name).read_bytes()) for name in ("verify.py", "capture.c", "replay.c")
        },
        "compiler_hashes": {
            name: r.sha((r.COMPILER / "Bin" / name).read_bytes())
            for name in ("CL.EXE", "C1.DLL", "C1XX.DLL", "C2.DLL", "MSPDB60.DLL", "LINK.EXE")
        },
        "results": rows,
        "new_source_matches": 0,
    }
    (out / "results.json").write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()
