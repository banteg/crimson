"""Trace state-register allocation and the two remaining scheduling constraints."""

import argparse
import json
import shutil
import struct
from pathlib import Path
from unittest.mock import patch

from controls import HERE, WITNESS, build, previous, sha
from verify import reject

from crimson import match_c2 as c2
from crimson import match_c2_replay as replay

ORIGINAL_OBSERVER = c2.observer_source
STOCK = ("quest-arm-direct", "status-shared-sleep", WITNESS)
LATE = (
    (0x583E9, 0x337EC),
    (0x583FC, 0x33B7B),
    (0x5840F, 0x34032),
    (0x5842F, 0x3404F),
    (0x58466, 0x35042),
    (0x58479, 0x3536C),
    (0x584A9, 0x35042),
    (0x584BC, 0x3663C),
    (0x584DD, 0x36AB0),
    (0x584F9, 0x36B27),
    (0x58526, 0x374AA),
    (0x58541, 0x3E113),
    (0x58554, 0x3E591),
    (0x5857E, 0x3E945),
    (0x58591, 0x3EB93),
    (0x3758C, 0x396F6),
    (0x37597, 0x3A684),
    (0x37549, 0x37A43),
)
REGISTERS = {
    0xAC784: "eax",
    0xAC7D8: "ecx",
    0xAC82C: "edx",
    0xAC880: "ebx",
    0xAC8D4: "esp",
    0xAC928: "ebp",
    0xAC97C: "esi",
    0xAC9D0: "edi",
}


def profile():
    p = c2.load_profile()
    hooks = [dict(h) for h in p["hooks"][:12]]
    hooks[11]["return"] = True
    hooks += [{"site": site, "target": target, "return": True} for site, target in LATE]
    return dict(p, hooks=hooks)


def observer(p, force=0):
    s = ORIGINAL_OBSERVER(p).replace(
        "static HANDLE trace_file;",
        "static HANDLE trace_file;\n#define FORCE_BOUNDARY " + str(force) + "\n" + (HERE / "watch.c.in").read_text(),
    )
    s = s.replace(
        "    function = (unsigned long *)saved_function;",
        "    watch(phase,registers);\n    if((phase>=27 && phase<100)||phase>=127||ordinal!=1)return;\n"
        "    function = (unsigned long *)saved_function;",
    )
    # Retain all nodes before allocation. Later snapshots cover the two float
    # sites and the restoration block; graph records retain complete windows.
    s = s.replace(
        "static HANDLE trace_file;",
        "static int interesting(unsigned long node) {\n"
        "unsigned long line=*(unsigned short *)(node+0x10);\n"
        "return (line>=35 && line<=47)||(line>=328 && line<=350)||(line>=366 && line<=386);}\n"
        "static HANDLE trace_file;",
    )
    s = s.replace(
        "++count; node = *(unsigned long *)node;",
        "if(phase<11 || interesting(node))++count; node = *(unsigned long *)node;",
    )
    s = s.replace(
        "    for (node = first; node; node = *(unsigned long *)node) {",
        "    for (node = first; node; node = *(unsigned long *)node) {\n        if(phase>=11 && !interesting(node))continue;",
    )
    s = s.replace(
        "    trace_file = CreateFileA(",
        '    graph_file=CreateFileA("graph.bin",GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);\n'
        "    if(graph_file==INVALID_HANDLE_VALUE)ExitProcess(81);\n    trace_file = CreateFileA(",
    )
    return s.replace(
        "    CloseHandle(trace_file);",
        "    if(boundary_changes!=FORCE_BOUNDARY)ExitProcess(87);\n"
        "    CloseHandle(graph_file);\n    CloseHandle(trace_file);",
    )


def state(events, source):
    rows = source.splitlines()
    start = next(i for i, row in enumerate(rows) if "void highscore_screen_update" in row)
    fragments = {
        "minor": "quest_stage_minor = highscore_return_quest_stage_minor;",
        "major": "quest_stage_major = highscore_return_quest_stage_major;",
        "mode": "config_blob.game_mode = highscore_return_game_mode_id;",
        "hardcore": "config_blob.hardcore = highscore_return_hardcore_flag;",
        "overlay": "player_overlay_suppressed_latch = 1;",
        "transition": "ui_transition_direction = 0;",
        "pending": "game_state_pending =",
    }
    lo = next(i for i, row in enumerate(rows) if "quest_stage_major = highscore_return_quest_stage_major;" in row) - 3
    hi = next(i for i in range(lo, len(rows)) if rows[i].strip() == "} else {")
    line_map = {}
    for name, fragment in fragments.items():
        matches = [i for i in range(lo, hi) if fragment in rows[i]]
        assert len(matches) == 1, (name, matches)
        line_map[name] = matches[0] - start
    # The multiline ternary is attributed to its final source line.
    line_map["pending"] = next(i for i in range(lo, hi) if "GAME_STATE_GAME_OVER;" in rows[i]) - start
    first = next(e for e in events if e["phase"] == 0)
    names = {}
    for name, line in line_map.items():
        matches = [
            n
            for n in first["nodes"]
            if n["line"] == line and n["op"] & 0xFFFF == 0x15B and len(n["dst"]) == 1 and n["dst"][0]["kind"] == 2
        ]
        assert len(matches) == 1, (name, line, len(matches))
        node = matches[0]
        names[node["dst"][0]["raw"][5]] = "store-" + name
        if name in ("minor", "major", "mode", "hardcore"):
            assert len(node["src"]) == 1 and node["src"][0]["kind"] == 2
            names[node["src"][0]["raw"][5]] = "load-" + name
    result = {}
    for phase in (11, 111, 22, 122):
        event = next(e for e in events if e["phase"] == phase)
        found = []
        for node in event["nodes"]:
            if not lo - start <= node["line"] < hi - start:
                continue
            if node["op"] & 0xFFFF != 1:
                continue
            for side in ("src", "dst"):
                ops = node[side]
                if len(ops) != 1 or ops[0]["kind"] != 2 or ops[0]["raw"][5] not in names:
                    continue
                name = names[ops[0]["raw"][5]]
                opposite = node["dst" if side == "src" else "src"]
                assert len(opposite) == 1
                op = opposite[0]
                word = op["temp_words"][2] if len(op["temp_words"]) > 2 else 0
                home = REGISTERS.get(op["raw"][6] - event["c2_base"], REGISTERS.get(word - event["c2_base"]))
                found.append({"operation": name, "home": home})
        result[str(phase)] = found
    return result


def graph_records(data):
    assert len(data) % 144 == 0
    return [struct.unpack_from("<36I", data, i) for i in range(0, len(data), 144)]


def graph_proof(data):
    groups = []
    for row in graph_records(data):
        if row[0] == 128 and row[3] == 0:
            groups.append([])
        if row[0] in (128, 228):
            groups[-1].append(row)
    assert len(groups) == 3
    result = []
    for group in groups:
        nodes = {r[2]: r for r in group if r[0] == 128}
        ids = {ptr: r[3] for ptr, r in nodes.items()}
        compact = []
        for ptr, row in nodes.items():
            edges = []
            for e in group:
                if e[0] == 228 and e[2] == ptr:
                    assert e[6] == ptr and e[7] in ids
                    edges.append([ids[e[7]], e[8], e[9] & 65535])
            compact.append(
                {
                    "ordinal": row[3],
                    "line": row[24] & 65535,
                    "opcode": row[21] & 65535,
                    "priority": row[14],
                    "depth": row[17] & 65535,
                    "outgoing": edges,
                },
            )
        result.append(compact)
    assert [len(g) for g in result] == [83, 20, 19]
    assert [(n["line"], n["opcode"]) for n in result[0][-4:]] == [(43, 0x60), (43, 0x45), (43, 0x162), (0, 0)]
    assert [(n["opcode"], n["priority"], n["depth"]) for n in result[1][1:5]] == [
        (0x63, 221184, 19),
        (1, 212992, 18),
        (1, 172032, 13),
        (0xD, 139264, 17),
    ]
    assert [(n["line"], n["opcode"]) for n in result[2][1:8]] == [
        (378, 0x60),
        (378, 0x162),
        (378, 0x62),
        (378, 0x60),
        (378, 0x162),
        (378, 0x63),
        (379, 0x63),
    ]
    for origin, target in ((3, 4), (4, 5), (5, 6), (6, 7)):
        assert any(e[0] == target for e in result[2][origin]["outgoing"])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    p = profile()
    results = {}
    for name in STOCK:
        builder = previous.build if name == "quest-arm-direct" else build
        cfg, _, _, _, _ = builder(name, out / "builds")
        with (
            patch.object(c2, "load_profile", return_value=p),
            patch.object(c2, "observer_source", side_effect=observer),
        ):
            manifest = c2.trace(cfg.directory, out / name)
        events = c2.read_verified(out / name)
        evidence = state(events, (cfg.directory / cfg.source).read_text())
        assert next(r["home"] for r in evidence["11"] if r["operation"] == "load-mode") == "eax"
        assert all(
            r["home"] is None for r in evidence["11"] if r["operation"] in ("load-minor", "load-major", "load-hardcore")
        )
        assert evidence["111"] == evidence["22"]
        expected = (
            {"minor": "edx", "major": "eax", "mode": "eax", "hardcore": "ecx"}
            if name == "quest-arm-direct"
            else {
                "minor": "ecx",
                "major": "edx",
                "mode": "eax",
                "hardcore": "edx",
            }
        )
        assert {
            r["operation"][5:]: r["home"] for r in evidence["111"] if r["operation"].startswith("load-")
        } == expected
        if name != "quest-arm-direct":
            assert [r["operation"] for r in evidence["122"]] == [
                "load-minor",
                "load-mode",
                "load-major",
                "store-minor",
                "store-major",
                "load-hardcore",
                "store-overlay",
                "store-mode",
                "store-hardcore",
                "store-transition",
                "store-pending",
            ]
        results[name] = {"manifest": manifest, "state": evidence}
        print("Verified preserving state trace", name, flush=True)
    graphs = (out / WITNESS / "observed/graph.bin").read_bytes()
    graph = graph_proof(graphs)
    corruptions = []
    for label, line, opcode, ordinal, column in (
        ("separator-priority", 43, 0x63, 1, 14),
        ("widget-store-kind", 378, 0x62, 3, 21),
    ):
        rows = [list(r) for r in graph_records(graphs)]
        selected = next(
            r for r in rows if r[0] == 128 and r[3] == ordinal and r[24] & 65535 == line and r[21] & 65535 == opcode
        )
        selected[column] ^= 1
        damaged = b"".join(struct.pack("<36I", *r) for r in rows)
        corruptions.append(reject(label, lambda damaged=damaged: graph_proof(damaged)))
    diagnostic = out / "boundary-diagnostic"
    diagnostic.mkdir()
    shutil.copyfile(out / WITNESS / "replay/replay_settings.h", diagnostic / "replay_settings.h")
    (diagnostic / "observer.c").write_text(observer(p, force=1))
    with c2.compiler_environment():
        replay.compile_driver(diagnostic, "observer.c", "observer.obj")
        replay.link(diagnostic, "observer.exe", "observer.obj")
        replay.run([replay.WIBO, "observer.exe"], diagnostic)
    changes = [r for r in graph_records((diagnostic / "graph.bin").read_bytes()) if r[0] == 300]
    assert len(changes) == 1 and changes[0][3] == 43 and changes[0][1] != changes[0][2]
    cfg = c2.match.load_scratch_config(out / "builds" / WITNESS)
    _, _, metrics = previous.measure(diagnostic / "replay.obj", cfg)
    assert metrics["body_sha256"] == "89f8f2156b6cd819de4b5c7a7705743dd360ed2566f1112301d5804b43b3a78b"
    assert metrics["prefix"] == 110 and not metrics["exact"] and not metrics["body_byte_exact"]
    result = {
        "schema_version": 1,
        "kind": "highscore-state-and-scheduler-trace",
        "stock": results,
        "graph": graph,
        "graph_sha256": sha(graphs),
        "boundary_diagnostic": metrics,
        "boundary_changes": 1,
        "full_function_match": False,
        "graph_corruptions_rejected": corruptions,
        "inputs": {
            x.name: sha(x.read_bytes())
            for x in (HERE / "controls.py", HERE / "controls.json", HERE / "watch.c.in", Path(__file__))
        },
    }
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print("Verified scheduling graph and bounded negative diagnostic", flush=True)


if __name__ == "__main__":
    main()
