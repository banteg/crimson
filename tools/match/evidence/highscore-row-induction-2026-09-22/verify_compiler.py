"""Verify the flags use-count boundary with preserving replays and one scoped intervention."""

import argparse
import json
import shutil
import struct
from pathlib import Path
from unittest.mock import patch

from controls import HERE, build, sha

from crimson import match_c2 as c2
from crimson import match_c2_replay as replay


def profile():
    stock = c2.load_profile()
    return dict(
        stock,
        hooks=stock["hooks"][:12]
        + [
            {"site": 0x45DE5, "target": 0x47C9A, "return": True},
            {"site": 0x46AD2, "target": 0x48E8B, "return": True},
            {"site": 0x46B56, "target": 0x48E8B, "return": True},
        ],
    )


def observer(original, hooks, cost):
    source = original(hooks).replace(
        "static HANDLE trace_file;",
        f"#define COST_VALUE {cost}\nstatic HANDLE trace_file;\n" + (HERE / "watch.c.in").read_text(),
    )
    source = source.replace(
        "    node = first;", "    watch(phase,registers,first);\n    if(phase>=12)return;\n    node = first;",
    )
    source = source.replace(
        "    trace_file = CreateFileA(",
        '    costs_file=CreateFileA("costs.bin",GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);\n'
        "    if(costs_file==INVALID_HANDLE_VALUE)ExitProcess(80);\n    trace_file = CreateFileA(",
    )
    return source.replace("    CloseHandle(trace_file);", "    finish_watch();\n    CloseHandle(trace_file);")


def inspect(directory):
    raw = (directory / "costs.bin").read_bytes()
    assert len(raw) >= 16 and (len(raw) - 16) % 32 == 0
    counts = struct.unpack("<4I", raw[-16:])
    decisions = [list(row) for row in struct.iter_unpack("<8I", raw[:-16])]
    assert counts[1] == len(decisions) == 1
    assert decisions[0][0] == 113 and decisions[0][2] == decisions[0][4]
    return {
        "counts": list(counts),
        "decisions": decisions,
        "normalized_coff_sha256": sha(replay.normalized_coff(directory / "replay.obj")),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    root = parser.parse_args().out.resolve()
    root.mkdir(parents=True, exist_ok=False)
    hooks = profile()
    original = c2.observer_source
    rows, receipts = {}, {}
    for name in ("prefix-before-empty-indexed", "flags-split-mask"):
        cfg, _, _, _ = build(name, root)
        out = root / (name + "-trace")
        with (
            patch.object(c2, "load_profile", lambda: hooks),
            patch.object(c2, "observer_source", lambda p: observer(original, p, -1)),
        ):
            manifest = c2.trace(cfg.directory, out)
        rows[name] = inspect(out / "observed")
        receipts[name] = {
            "manifest_sha256": sha((out / "manifest.json").read_bytes()),
            "source_sha256": manifest["source_sha256"],
            "whole_coff_equal_except_timestamp": manifest["whole_coff_equal_except_timestamp"],
            "missing_stream_rejected": manifest["missing_stream_rejected"],
        }
        print("Preserved", name, rows[name]["counts"], flush=True)
    assert rows["prefix-before-empty-indexed"]["decisions"][0][1] == 4
    assert rows["flags-split-mask"]["decisions"][0][1] == 5
    assert all(rows[n]["counts"][2] == 0 for n in receipts)
    for cost in (4, 5):
        out = root / f"cost-{cost}"
        out.mkdir()
        shutil.copyfile(
            root / "prefix-before-empty-indexed-trace/observed/replay_settings.h", out / "replay_settings.h",
        )
        (out / "observer.c").write_text(observer(original, hooks, cost))
        with c2.compiler_environment():
            replay.compile_driver(out, "observer.c", "observer.obj")
            replay.link(out, "observer.exe", "observer.obj")
            replay.run([replay.WIBO, "observer.exe"], out)
        rows[f"cost-{cost}"] = inspect(out)
        assert rows[f"cost-{cost}"]["counts"][2] == 1
        assert rows[f"cost-{cost}"]["decisions"][0][1] == 4
        expected = "prefix-before-empty-indexed" if cost == 4 else "flags-split-mask"
        assert rows[f"cost-{cost}"]["normalized_coff_sha256"] == rows[expected]["normalized_coff_sha256"]
        print("Verified cost", cost, flush=True)
    result = {
        "schema": 1,
        "kind": "highscore-row-induction-count",
        "compiler_interventions_are_diagnostic": True,
        "new_exact_matches": 0,
        "c2_sha256": hooks["c2_sha256"],
        "receipts": receipts,
        "controls": rows,
        "harness_sha256": {
            n: sha((HERE / n).read_bytes())
            for n in ("controls.py", "controls.json", "verify_compiler.py", "watch.c.in")
        },
    }
    (root / "results.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
