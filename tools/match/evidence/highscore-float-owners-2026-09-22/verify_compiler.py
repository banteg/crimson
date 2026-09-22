"""Verify float-width dataflow and the scheduling-window cause with preserving C2 traces."""

import argparse
import json
import shutil
from pathlib import Path
from unittest.mock import patch

from controls import HERE, WITNESS, build, measure, previous_module, sha, sources

from crimson import match
from crimson import match_c2 as c2
from crimson import match_c2_replay as replay

prior = previous_module("verify_compiler.py")
STOCK = ("scoped-double-x", "scoped-float-x", WITNESS)


def observer(profile):
    # Additional source lines move the final scheduler's monotonically assigned
    # line numbers past the old observer's cutoff. No compiler state is changed.
    return prior.observer(profile).replace("line<=386", "line<=395")


def graph(data):
    groups = []
    for row in prior.graph_records(data):
        if row[0] != 128:
            continue
        if row[3] == 0:
            groups.append([])
        groups[-1].append(
            {
                "ordinal": row[3],
                "line": row[24] & 65535,
                "opcode": row[21] & 65535,
                "priority": row[14],
                "depth": row[17] & 65535,
            },
        )
    return groups


def copies(events, source):
    lines = source.splitlines()
    first = next(i for i, line in enumerate(lines) if "void highscore_screen_update" in line)
    start = next(i for i, line in enumerate(lines) if " x_value = right_panel.x;" in line) - first
    result = {}
    for phase in (0, 1, 5, 10, 11, 22):
        event = next(e for e in events if e["phase"] == phase)
        rows = [n for n in event["nodes"] if start <= n["line"] <= start + 2]
        result[str(phase)] = [
            {
                "line": n["line"] - start,
                "opcode": n["op"] & 65535,
                "dst_types": [o["raw"][2] >> 16 for o in n["dst"]],
                "src_types": [o["raw"][2] >> 16 for o in n["src"]],
            }
            for n in rows
        ]
    return result


def check_graphs(before, after):
    assert len(before[0]) == len(after[0]) == 83
    assert len(before[1]) == 20 and len(after[1]) == 21
    a = [n["opcode"] for g in before[:2] for n in g[1:-1]]
    b = [n["opcode"] for g in after[:2] for n in g[1:-1]]
    assert b[74:77] == [0x56, 0x162, 0x45]
    assert a[74:76] == [0x56, 0x45]
    assert b[:75] + b[76:] == a
    assert before[0][-2]["opcode"] == 0x162
    assert after[0][-2]["opcode"] == 0x45
    assert [n["opcode"] for n in before[1][1:4]] == [0x63, 1, 1]
    assert [n["opcode"] for n in after[1][1:5]] == [0x162, 0x63, 1, 1]
    assert [n["priority"] for n in after[1][1:4]] == [163840, 221184, 212992]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    profile = prior.profile()
    results = {}
    for name in STOCK:
        cfg, _, _, _, metrics = build(name, out / "builds")
        with (
            patch.object(c2, "load_profile", return_value=profile),
            patch.object(c2, "observer_source", side_effect=observer),
        ):
            manifest = c2.trace(cfg.directory, out / name)
        assert manifest["whole_coff_equal_except_timestamp"] and manifest["missing_stream_rejected"]
        assert manifest["normalized_coff_sha256"] == metrics["normalized_coff_sha256"]
        events = c2.read_verified(out / name)
        results[name] = {
            "manifest": manifest,
            "copies": copies(events, sources()[name][0]),
            "graph": graph((out / name / "observed/graph.bin").read_bytes()),
        }
        print("Verified preserving stock trace", name, flush=True)
    wide = results["scoped-double-x"]["copies"]
    narrow = results["scoped-float-x"]["copies"]
    assert wide["0"][0] == {"line": 0, "opcode": 0x15F, "dst_types": [0x4008], "src_types": [0x4004]}
    assert narrow["0"][0] == {"line": 0, "opcode": 0x15B, "dst_types": [0x4004], "src_types": [0x4004]}
    assert wide["22"][0]["opcode"] == 0x60 and wide["22"][0]["dst_types"] == [0x4008]
    assert [r["opcode"] for r in wide["22"][:4]] == [0x60, 0x62, 0x63, 0x60]
    assert [r["opcode"] for r in narrow["11"][:4]] == [1, 1, 1, 1]
    before, after = results["scoped-double-x"]["graph"], results[WITNESS]["graph"]
    check_graphs(before, after)
    damaged = json.loads(json.dumps(after))
    damaged[0][76]["opcode"] = 0x15B
    rejected = prior.reject("missing-center-round-marker", lambda: check_graphs(before, damaged))

    # Diagnostic only: move the old window endpoint from ROUND back to FADD.
    # The accepted witness above was compiled independently without this hook.
    diagnostic = out / "boundary-diagnostic"
    diagnostic.mkdir()
    shutil.copyfile(out / "scoped-double-x/replay/replay_settings.h", diagnostic / "replay_settings.h")
    src = prior.observer(profile, force=1)
    old = "        previous=*(unsigned long *)(previous+0xc);\n        if(*(unsigned long *)(previous+4)!=0x60 || *(unsigned short *)(previous+0x10)!=43)ExitProcess(85);"
    assert src.count(old) == 1
    (diagnostic / "observer.c").write_text(src.replace(old, ""))
    with c2.compiler_environment():
        replay.compile_driver(diagnostic, "observer.c", "observer.obj")
        replay.link(diagnostic, "observer.exe", "observer.obj")
        replay.run([replay.WIBO, "observer.exe"], diagnostic)
    changes = [r for r in prior.graph_records((diagnostic / "graph.bin").read_bytes()) if r[0] == 300]
    assert len(changes) == 1 and changes[0][3] == 43 and changes[0][1] != changes[0][2]
    cfg = match.load_scratch_config(out / "builds/scoped-double-x")
    _, _, metrics = measure(diagnostic / "replay.obj", cfg)
    expected = sources()[WITNESS][1]
    assert metrics["normalized_coff_sha256"] == expected["normalized_coff_sha256"]
    result = {
        "schema_version": 1,
        "kind": "highscore-float-owner-and-window-proof",
        "stock": results,
        "graph_corruptions_rejected": [rejected],
        "boundary_diagnostic": {"changes": 1, "match_credit": False, "metrics": metrics},
        "full_function_stock_match": True,
        "inputs": {
            str(p.relative_to(match.REPO_ROOT)): sha(p.read_bytes())
            for p in (
                HERE / "controls.py",
                HERE / "controls.json",
                Path(__file__),
                Path(prior.__file__),
                prior.HERE / "watch.c.in",
            )
        },
    }
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print("Verified float-width control and stock scheduling-window recovery", flush=True)


if __name__ == "__main__":
    main()
