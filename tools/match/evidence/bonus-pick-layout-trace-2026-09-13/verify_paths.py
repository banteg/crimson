"""Check the early reorder and the stage-five-only late move without patching decisions."""

import argparse
import json
import runpy
from pathlib import Path

from crimson import match
from crimson import match_c2 as c2

HERE = Path(__file__).resolve().parent
LAYOUT = runpy.run_path(str(HERE / "verify.py"))
sha = LAYOUT["sha"]
decode_layout = LAYOUT["decode"]


def compiler_line(source, needle):
    lines = source.splitlines()
    entry = next(i for i, line in enumerate(lines) if 'extern "C"' in line)
    hits = [i - entry for i, line in enumerate(lines) if needle in line]
    assert len(hits) == 1, (needle, hits)
    return hits[0]


def comparison(nodes, line, opcode, immediate=None):
    hits = []
    for i, node in enumerate(nodes):
        if node["op"] != opcode or node["line"] != line:
            continue
        if immediate is not None and not any(
            operand["kind"] == 7 and operand["raw"][6] == immediate for operand in node["src"]
        ):
            continue
        hits.append(i)
    assert hits, (line, opcode, immediate)
    return hits[0]


def observe_layout(original, profile):
    source = original(profile).replace(
        "static HANDLE trace_file;",
        "static HANDLE trace_file;\n" + (HERE / "layout.c.in").read_text(),
    )
    source = source.replace(
        "    node = first;",
        "    if(phase==18 || phase==118 || phase==26)layout_observe(phase,first,registers);\n    node = first;",
    ).replace(
        "    trace_file = CreateFileA(",
        '    layout_file=CreateFileA("layout.bin",GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);\n'
        "    if(layout_file==INVALID_HANDLE_VALUE)ExitProcess(80);\n    trace_file = CreateFileA(",
    )
    return source.replace("    CloseHandle(trace_file);", "    CloseHandle(layout_file);\n    CloseHandle(trace_file);")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/bonus_pick_random_type")
    baseline = (config.directory / config.source).read_bytes()
    assert sha(baseline) == "286648fb568fe81709b52093a204a820f7f7e9bf06968ed8e50042c063c26f42"
    assert config.compiler == "msvc6.5" and config.cflags == "/O2 /GB /W3 /GR-"
    loader, observer = c2.load_profile, c2.observer_source
    stock = loader()
    early = dict(
        stock,
        hooks=[
            {"site": 0x5818F, "target": 0x53DE, "return": True},
            {"site": 0x53F2, "target": 0x12D16, "return": True},
        ],
    )
    late = json.loads((HERE / "profile.json").read_text())
    assert late["c2_sha256"] == stock["c2_sha256"]
    rows = []
    try:
        for name, profile in [("explicit-stage-five-tail", early), ("inverted-hardcore-prefix", late)]:
            source = (HERE / "controls" / (name + ".cpp")).read_text()
            directory = args.out / (name + "-source")
            directory.mkdir()
            (directory / config.source).write_text(source)
            (directory / "scratch.conf").write_bytes((config.directory / "scratch.conf").read_bytes())
            c2.load_profile = lambda p=profile: p
            c2.observer_source = observer if name.startswith("explicit") else lambda p: observe_layout(observer, p)
            out = args.out / name
            receipt = c2.trace(directory, out)
            metrics = receipt["metrics"]
            obj = match.parse_coff_object((out / receipt["object_paths"][0]).read_bytes())
            body_sha = sha(match.extract_object_function(obj, config.symbol).data)
            assert receipt["whole_coff_equal_except_timestamp"] and receipt["missing_stream_rejected"]
            assert not metrics["exact"] and not metrics["body_byte_exact"]
            assert metrics["references_ok"] == 20 and metrics["reference_problems"] == 0
            assert metrics["candidate_instructions"] == (162 if name.startswith("explicit") else 169)
            if name.startswith("explicit"):
                assert body_sha == "c4cb6604f582d306a8531efbe51aff37ca6f5f3d47450d6dfd7c96d00e8158e7"
                events = json.loads((out / "snapshots.json").read_text())
                assert [e["phase"] for e in events] == [0, 1, 101, 100]
                five_line = compiler_line(source, "if (quest_stage_major == 5")
                retry_line = compiler_line(source, "while (retries++ < 100)")
                positions = []
                for phase in (1, 101):
                    nodes = next(e["nodes"] for e in events if e["phase"] == phase)
                    position = {
                        "phase": phase,
                        "stage_five": comparison(nodes, five_line, 0x17D, 5),
                        "retry_limit": comparison(nodes, retry_line, 0x17D, 100),
                    }
                    positions.append(position)
                assert positions[0]["stage_five"] > positions[0]["retry_limit"]
                assert positions[1]["stage_five"] < positions[1]["retry_limit"]
                finding = {"reordering_callee_rva": "0x12d16", "positions": positions}
            else:
                events = decode_layout((out / "observed/layout.bin").read_bytes())
                four_line = compiler_line(source, "if (quest_stage_major == 4)")
                five_line = compiler_line(source, "if (quest_stage_major == 5)")
                moves = []
                for event in events:
                    if event["phase"] != 26:
                        continue
                    insert, first, last = event["move"]
                    assert first <= last < insert
                    four = comparison(event["nodes"], four_line, 0x2F)
                    five = comparison(event["nodes"], five_line, 0x2F)
                    move = {
                        "insert_before": insert,
                        "first": first,
                        "last": last,
                        "contains_stage_four": first <= four <= last,
                        "contains_stage_five": first <= five <= last,
                    }
                    moves.append(move)
                selected = [move for move in moves if move["contains_stage_five"]]
                assert len(selected) == 1 and not selected[0]["contains_stage_four"]
                finding = {"range_moves": moves}
                (out / "layout.json").write_text(json.dumps(events, indent=2) + "\n")
            row = {
                "name": name,
                "source_sha256": sha(source.encode()),
                "body_sha256": body_sha,
                "metrics": metrics,
                "whole_coff_equal_except_timestamp": True,
                "missing_stream_rejected": True,
                "finding": finding,
                "trace_sha256": receipt["trace_sha256"],
                "manifest_sha256": sha((out / "manifest.json").read_bytes()),
            }
            rows.append(row)
            print(name, "preserved; expected compiler path verified", flush=True)
    finally:
        c2.load_profile, c2.observer_source = loader, observer
    result = {
        "schema_version": 1,
        "c2_sha256": stock["c2_sha256"],
        "compiler_decisions_modified": False,
        "canonical_source_sha256": sha(baseline),
        "rows": rows,
        "harness_sha256": {
            name: sha((HERE / name).read_bytes())
            for name in (
                "verify_paths.py",
                "verify.py",
                "profile.json",
                "layout.c.in",
            )
        },
    }
    (args.out / "results.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
