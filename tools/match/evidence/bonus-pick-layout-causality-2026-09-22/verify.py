"""Prove the bonus selector's remaining layout constraint, without match credit."""

import argparse
import json
import shutil
import struct
from pathlib import Path

from crimson import match, match_flow_graph
from crimson import match_c2 as c2
from crimson import match_c2_replay as replay

HERE = Path(__file__).resolve().parent
SOURCE_SHA = "286648fb568fe81709b52093a204a820f7f7e9bf06968ed8e50042c063c26f42"
LATE_PROFILE = HERE.parent / "bonus-pick-layout-trace-2026-09-13/profile.json"


def early_observer(original, profile):
    source = original(profile).replace(
        "static HANDLE trace_file;", "static HANDLE trace_file;\n" + (HERE / "blocks.c.in").read_text(),
    )
    source = source.replace("    node = first;", "    block_dump(phase,saved_function);\n    node = first;")
    source = source.replace(
        "    trace_file = CreateFileA(",
        '    blocks_file=CreateFileA("blocks.bin",GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);\n'
        "    if(blocks_file==INVALID_HANDLE_VALUE)ExitProcess(80);\n    trace_file = CreateFileA(",
    )
    return source.replace("    CloseHandle(trace_file);", "    CloseHandle(blocks_file);\n    CloseHandle(trace_file);")


def decode_blocks(directory):
    snapshots = c2.read_verified(directory)
    data = (directory / "observed/blocks.bin").read_bytes()
    at, events = 0, []
    while at < len(data):
        phase, function, count = struct.unpack_from("<3I", data, at)
        at += 12
        snapshot = next(s for s in snapshots if s["phase"] == phase)
        assert snapshot["function_address"] == function
        nodes = snapshot["nodes"]
        indices = {node["id"]: i for i, node in enumerate(nodes)}
        blocks = []
        for _ in range(count):
            w = struct.unpack_from("<11I", data, at)
            at += 44
            edges = []
            for _ in range(w[10]):
                _, target = struct.unpack_from("<2I", data, at)
                at += 8
                edges.append(target)
            lines = sorted({n["line"] for n in nodes[indices[w[8]] : indices[w[9]] + 1]})
            blocks.append({"id": w[0], "next": w[1], "edges": edges, "lines": lines})
        assert all(b["next"] == (blocks[i + 1]["id"] if i + 1 < count else 0) for i, b in enumerate(blocks))
        events.append({"phase": phase, "blocks": blocks})
    assert at == len(data)
    return events


def dfs_proof(events):
    blocks = next(e["blocks"] for e in events if e["phase"] == 1)
    indices = {b["id"]: i for i, b in enumerate(blocks)}
    graph = {i: [indices[t] for t in b["edges"]] for i, b in enumerate(blocks)}
    seen, postorder = set(), []

    def visit(node):
        if node not in seen:
            seen.add(node)
            for target in graph[node]:
                visit(target)
            postorder.append(node)

    visit(0)
    observed = [indices[b["id"]] for b in next(e["blocks"] for e in events if e["phase"] == 102)]
    assert observed == postorder[::-1], "DFS model must reproduce the actual rebuilt block list"

    def select(line, degree=None):
        hits = [i for i, b in enumerate(blocks) if line in b["lines"] and (degree is None or len(graph[i]) == degree)]
        assert len(hits) == 1, (line, hits)
        return hits[0]

    header, five, latch = select(14), select(75, 2), select(103)
    predecessors = {i: {p for p in seen if i in graph[p]} for i in seen}
    dominators = {i: ({0} if i == 0 else set(seen)) for i in seen}
    while True:
        updated = {
            i: ({0} if i == 0 else {i} | set.intersection(*(dominators[p] for p in predecessors[i])))
            for i in seen
        }
        if updated == dominators:
            break
        dominators = updated
    assert header in dominators[five] and header in dominators[latch]
    active, finished = set(), set()

    def acyclic(node):
        if node == header or node in finished:
            return
        assert node not in active, "A cycle avoiding the draw header invalidates this argument"
        active.add(node)
        for target in graph[node]:
            acyclic(target)
        active.remove(node)
        finished.add(node)

    acyclic(five)
    assert latch in finished, "Stage five must reach the retry latch without passing through the header"
    return {
        "model_matches_observed_order": True,
        "initial_blocks": len(blocks),
        "reachable_blocks": len(seen),
        "unreachable_blocks": sorted(set(graph) - seen),
        "header": header,
        "stage_five": five,
        "retry_latch": latch,
        "header_dominates_stage_five_and_latch": True,
        "stage_five_reachable_subgraph_without_header_is_acyclic": True,
        "stage_five_reaches_latch_without_header": True,
        "rpo_constraint": "stage five precedes retry latch for every successor visitation order in this graph",
        "blocks": [{"index": i, "lines": b["lines"], "successors": graph[i]} for i, b in enumerate(blocks)],
        "observed_reverse_postorder": observed,
    }


def controlled_replay(baseline, out, config, relocate):
    c2.read_verified(baseline)
    out.mkdir()
    shutil.copyfile(baseline / "observed/replay_settings.h", out / "replay_settings.h")
    source = (baseline / "observed/observer.c").read_text().replace(
        "static HANDLE trace_file;",
        f"#define DO_RELOCATE {int(relocate)}\nstatic HANDLE trace_file;\n" + (HERE / "relocate.c.in").read_text(),
    )
    source = source.replace("    node = first;", "    if(phase==18)relocate_stage_five(first);\n    node = first;")
    source = source.replace("    CloseHandle(trace_file);", "    if(intervention_count!=1)ExitProcess(70);\n    CloseHandle(trace_file);")
    (out / "observer.c").write_text(source)
    with c2.compiler_environment():
        replay.compile_driver(out, "observer.c", "observer.obj")
        replay.link(out, "observer.exe", "observer.obj")
        replay.run([replay.WIBO, "observer.exe"], out)
    obj = out / "replay.obj"
    metrics = replay.function_metrics(config, obj)
    if relocate:
        assert metrics["exact"] and metrics["body_byte_exact"]
        assert metrics["candidate_instructions"] == metrics["target_instructions"] == 162
        assert metrics["references_ok"] == 20 and metrics["reference_problems"] == 0
        result = match.run_match(obj_path=obj, function=config.function, symbol_name=config.symbol,
                                 reference_aliases=config.reference_aliases)
        assert match_flow_graph.flow_graph_payload(result)["status"] == "matched"
    else:
        assert replay.normalized_coff(obj) == replay.normalized_coff(baseline / "observed/replay.obj")
    return {
        "compiler_decisions_modified": relocate,
        "match_credit": False,
        "metrics": metrics,
        "normalized_coff_sha256": replay.sha(replay.normalized_coff(obj)),
        "observer_sha256": replay.sha(source.encode()),
        "trace_sha256": replay.sha((out / "phases.bin").read_bytes()),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/bonus_pick_random_type")
    assert replay.sha((config.directory / config.source).read_bytes()) == SOURCE_SHA
    assert config.compiler == "msvc6.5" and config.cflags == "/O2 /GB /W3 /GR-"
    loader, observer = c2.load_profile, c2.observer_source
    stock = loader()
    early = dict(stock, hooks=[
        {"site": 0x5818F, "target": 0x53DE, "return": True},
        {"site": 0x53EB, "target": 0x440D, "return": True},
        {"site": 0x53F2, "target": 0x12D16, "return": True},
    ])
    late = json.loads(LATE_PROFILE.read_text())
    assert late["c2_sha256"] == stock["c2_sha256"]
    assert late["hooks"][18] == {"site": 0x584BC, "target": 0x3663C, "return": True}
    try:
        c2.load_profile = lambda: early
        c2.observer_source = lambda p: early_observer(observer, p)
        early_receipt = c2.trace(config.directory, out / "early")
        proof = dfs_proof(decode_blocks(out / "early"))
        print("Preserved early COFF; DFS model and order constraint verified", flush=True)
        c2.load_profile = lambda: late
        c2.observer_source = observer
        late_receipt = c2.trace(config.directory, out / "late")
    finally:
        c2.load_profile, c2.observer_source = loader, observer
    assert early_receipt["normalized_coff_sha256"] == late_receipt["normalized_coff_sha256"]
    control = controlled_replay(out / "late", out / "disabled", config, False)
    intervention = controlled_replay(out / "late", out / "relocated", config, True)
    assert replay.sha((config.directory / config.source).read_bytes()) == SOURCE_SHA
    result = {
        "schema_version": 1,
        "kind": "compiler-layout-causality-diagnostic",
        "match_credit": False,
        "canonical_source_modified": False,
        "canonical_source_sha256": SOURCE_SHA,
        "canonical_metrics": late_receipt["metrics"],
        "c2_sha256": stock["c2_sha256"],
        "image_sha256": replay.sha(match.DEFAULT_IMAGE_PATH.read_bytes()),
        "early_graph": proof,
        "disabled_intervention": control,
        "layout_intervention": intervention,
        "preserving_manifests": {name: replay.sha((out / name / "manifest.json").read_bytes()) for name in ("early", "late")},
        "blocks_sha256": replay.sha((out / "early/observed/blocks.bin").read_bytes()),
        "harness_sha256": {name: replay.sha((HERE / name).read_bytes()) for name in ("verify.py", "blocks.c.in", "relocate.c.in")},
        "late_profile_sha256": replay.sha(LATE_PROFILE.read_bytes()),
    }
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print("Disabled intervention preserves COFF; relocating existing nodes yields encoded-exact body (no credit)")


if __name__ == "__main__":
    main()
