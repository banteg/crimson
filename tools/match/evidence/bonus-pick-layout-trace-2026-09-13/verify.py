"""Locate bonus-picker block motion without changing any compiler decision."""

import argparse
import hashlib
import json
import runpy
import struct
from pathlib import Path

from crimson import match
from crimson import match_c2 as c2

HERE = Path(__file__).resolve().parent
CONTROLS = HERE.parent / "bonus-pick-cold-edge-2026-09-11"
NAMES = {
    "baseline": None,
    "freeze-prefix": "common-prefix-controls/five-1",
    "full-filters": "duplicated-tail/stage-five-only",
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def decode(data):
    at, events = 0, []
    while at < len(data):
        phase, count, insert, first, last = struct.unpack_from("<5I", data, at)
        at += 20
        assert phase in (18, 118, 26) and 0 < count <= c2.MAX_NODES
        nodes = []
        for _ in range(count):
            w = struct.unpack_from("<12I", data, at)
            at += 48
            nodes.append(
                {
                    "id": w[0],
                    "next": w[1],
                    "op": w[2],
                    "flags": w[3],
                    "prev": w[4],
                    "line": w[5] & 65535,
                    "condition": w[9],
                    "target": w[11],
                },
            )
        indices = {n["id"]: i for i, n in enumerate(nodes)}
        assert len(indices) == count
        for i, node in enumerate(nodes):
            assert node["next"] == (nodes[i + 1]["id"] if i + 1 < count else 0)
            if i:
                assert node["prev"] == nodes[i - 1]["id"]
            node["target"] = indices.get(node["target"])
        move = [indices[x] for x in (insert, first, last)] if phase == 26 else None
        events.append({"phase": phase, "move": move, "nodes": nodes})
    assert at == len(data)
    assert [e["phase"] for e in events].count(18) == 1
    assert [e["phase"] for e in events].count(118) == 1
    return events


def stage(nodes, line):
    hits = [i for i, n in enumerate(nodes) if n["op"] == 0x2F and n["line"] == line]
    assert len(hits) == 1, (line, hits)
    return hits[0]


def describe(events):
    before = next(e["nodes"] for e in events if e["phase"] == 18)
    after = next(e["nodes"] for e in events if e["phase"] == 118)
    skip = next(n for n in before if n["op"] == 0x10 and n["line"] == 75)
    predecessor = before[skip["target"] - 1]
    moves = []
    for e in events:
        if e["phase"] != 26:
            continue
        insert, first, last = e["move"]
        nodes = e["nodes"]
        assert first <= last < insert
        moves.append(
            {
                "insert_before": insert,
                "first": first,
                "last": last,
                "contains_stage_four": first <= stage(nodes, 66) <= last,
                "contains_stage_five": first <= stage(nodes, 75) <= last,
                "first_comparisons": [n["line"] for n in nodes[first : last + 1] if n["op"] == 0x2F][:6],
            },
        )
    return {
        "before": {"nodes": len(before), "stage_four": stage(before, 66), "stage_five": stage(before, 75)},
        "after": {"nodes": len(after), "stage_four": stage(after, 66), "stage_five": stage(after, 75)},
        "stage_four_skip_destination_predecessor": {
            "opcode": predecessor["op"],
            "flags": predecessor["flags"],
            "has_condition": bool(predecessor["condition"]),
            "line": predecessor["line"],
            "unconditional": predecessor["flags"] & 255 == 0x11 and predecessor["condition"] == 0,
        },
        "range_moves": moves,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    original_loader, original_observer = c2.load_profile, c2.observer_source
    stock = original_loader()  # Verifies the actual C2 hash before installing hooks.
    profile = json.loads((HERE / "profile.json").read_text())
    assert profile["c2_sha256"] == stock["c2_sha256"]
    assert profile["hooks"][:12] == stock["hooks"][:12]
    addition = (HERE / "layout.c.in").read_text()

    def observer(p):
        source = original_observer(p).replace("static HANDLE trace_file;", "static HANDLE trace_file;\n" + addition)
        source = source.replace(
            "    node = first;",
            "    if(phase==18 || phase==118 || phase==26)layout_observe(phase,first,registers);\n    node = first;",
        )
        source = source.replace(
            "    trace_file = CreateFileA(",
            """    layout_file=CreateFileA("layout.bin",GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);
    if(layout_file==INVALID_HANDLE_VALUE)ExitProcess(80);
    trace_file = CreateFileA(""",
        )
        return source.replace(
            "    CloseHandle(trace_file);", "    CloseHandle(layout_file);\n    CloseHandle(trace_file);",
        )

    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/bonus_pick_random_type")
    base = (config.directory / config.source).read_text()
    controls = json.loads((CONTROLS / "source-controls.json").read_text())
    assert sha(base.encode()) == controls["baseline_sha256"]
    assert config.compiler == controls["baseline_compiler"] and config.cflags == controls["baseline_cflags"]
    reconstruct = runpy.run_path(str(CONTROLS / "verify_controls.py"))["reconstruct"]
    rows = []
    c2.load_profile, c2.observer_source = lambda: profile, observer
    try:
        for name, control_name in NAMES.items():
            control = next((c for c in controls["controls"] if c["name"] == control_name), None)
            source = reconstruct(base, control) if control else base
            directory = args.out / (name + "-source")
            directory.mkdir()
            (directory / config.source).write_text(source)
            (directory / "scratch.conf").write_bytes((config.directory / "scratch.conf").read_bytes())
            out = args.out / name
            receipt = c2.trace(directory, out)
            assert receipt["whole_coff_equal_except_timestamp"] and receipt["missing_stream_rejected"]
            metrics = receipt["metrics"]
            assert not metrics["exact"] and not metrics["body_byte_exact"]
            assert metrics["references_ok"] == 20 and metrics["reference_problems"] == 0
            assert (
                metrics["candidate_instructions"] == {"baseline": 162, "freeze-prefix": 167, "full-filters": 203}[name]
            )
            data = (out / "observed/layout.bin").read_bytes()
            events = decode(data)
            finding = describe(events)
            moved = [m for m in finding["range_moves"] if m["contains_stage_five"]]
            assert bool(moved) == (name != "baseline")
            assert all(m["contains_stage_four"] for m in moved)
            assert finding["stage_four_skip_destination_predecessor"]["unconditional"] == (name != "baseline")
            (out / "layout.json").write_text(json.dumps(events, indent=2) + "\n")
            rows.append(
                {
                    "name": name,
                    "historical_control": control_name,
                    "source_sha256": sha(source.encode()),
                    "metrics": metrics,
                    "finding": finding,
                    "whole_coff_equal_except_timestamp": True,
                    "missing_stream_rejected": True,
                    "manifest_sha256": sha((out / "manifest.json").read_bytes()),
                    "layout_sha256": sha(data),
                    "trace_sha256": receipt["trace_sha256"],
                },
            )
            print(name, "preserved; stage-five range moves", len(moved), flush=True)
    finally:
        c2.load_profile, c2.observer_source = original_loader, original_observer
    result = {
        "schema_version": 1,
        "c2_sha256": stock["c2_sha256"],
        "compiler_decisions_modified": False,
        "rows": rows,
        "harness_sha256": {n: sha((HERE / n).read_bytes()) for n in ("verify.py", "profile.json", "layout.c.in")},
        "controls_sha256": sha((CONTROLS / "source-controls.json").read_bytes()),
    }
    (args.out / "results.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
