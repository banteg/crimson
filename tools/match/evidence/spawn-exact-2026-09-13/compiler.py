"""Preserve whole compiler objects while observing the alias budget and scheduler DAG."""

import argparse
import json
import struct
from pathlib import Path

from recover import HERE, recover, sha

from crimson import match_c2 as c2


def decode(data, aliases):
    at, events = 0, []

    def words(count):
        nonlocal at
        values = list(struct.unpack_from(f"<{count}I", data, at))
        at += count * 4
        return values

    while at < len(data):
        phase, address, count = words(3)
        assert phase in (12, 13) and 0 < count <= 512
        nodes = []
        for _ in range(count):
            address = words(1)[0]
            raw, ir = words(15), words(8)
            edge_count = words(1)[0]
            assert edge_count <= 512
            nodes.append({"id": address, "raw": raw, "ir": ir, "edges": [words(6) for _ in range(edge_count)]})
        ids = {node["id"]: i for i, node in enumerate(nodes)}
        compact = []
        for node in nodes:
            memories = [row for row in aliases if row[0] == phase and row[1] == node["raw"][7]]
            compact.append({
                "opcode": node["ir"][1] & 0xffff, "line": node["ir"][4] & 0xffff,
                "priority": node["raw"][10:12], "critical_path": node["raw"][13],
                "memory": [{"side": row[3], "alias": row[12], "displacement": row[14]} for row in memories],
                "edges": [[ids[edge[2]], ids[edge[3]], edge[4], edge[5]] for edge in node["edges"]],
            })
        events.append({"phase": phase, "nodes": compact})
    assert at == len(data)
    return events


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    base_loader, base_source = c2.load_profile, c2.observer_source
    base_profile = base_loader()
    profile = {**base_profile, "hooks": base_profile["hooks"][:12] + [
        {"site": 0x37597, "target": 0x3a684, "return": False},
        {"site": 0x375a2, "target": 0x3af90, "return": False},
    ]}
    addition = (HERE / "scheduler.c.in").read_text()

    def observer(p):
        source = base_source(p).replace("static HANDLE trace_file;", "static HANDLE trace_file;\n" + addition)
        budget = r'''
    if (phase == 0) {
        unsigned long rec[4]; HANDLE h; DWORD written;
        rec[0]=*(unsigned long *)(compiler_base+0x9d670);
        rec[1]=*(unsigned long *)(compiler_base+0xadfd8);
        rec[2]=*(unsigned long *)(compiler_base+0xac098);
        rec[3]=*(unsigned long *)(compiler_base+0xac0d8);
        h=CreateFileA("budget.bin",GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);
        if(h==INVALID_HANDLE_VALUE)ExitProcess(78);
        if(!WriteFile(h,rec,sizeof(rec),&written,0)||written!=sizeof(rec))ExitProcess(77);
        CloseHandle(h);
    }
    if (phase >= 12) { graph_observe(phase,registers); return; }
'''
        source = source.replace("    if (phase < 12) saved_function", budget + "    if (phase < 12) saved_function")
        source = source.replace("    trace_file = CreateFileA(", '''    compiler_base = (unsigned long)base;
    graph_file = CreateFileA("graph.bin",GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);
    alias_file = CreateFileA("alias.bin",GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);
    if(graph_file==INVALID_HANDLE_VALUE || alias_file==INVALID_HANDLE_VALUE)ExitProcess(82);
    trace_file = CreateFileA(''')
        return source.replace("    CloseHandle(trace_file);", "    CloseHandle(alias_file);\n    CloseHandle(graph_file);\n    CloseHandle(trace_file);")

    c2.load_profile, c2.observer_source = lambda: profile, observer
    receipts = []
    try:
        for name in ("grid-b2-add", "color-c4-ctor-assignment", "exact-bt-format"):
            directory = args.out / (name + "-source")
            directory.mkdir()
            (directory / "scratch.cpp").write_text(recover(name))
            (directory / "scratch.conf").write_text("FUNCTION=creature_spawn_template\nSYMBOL=creature_spawn_template\nSOURCE=scratch.cpp\n")
            out = args.out / name
            receipt = c2.trace(directory, out)
            assert receipt["whole_coff_equal_except_timestamp"]
            aliases = list(struct.iter_unpack("<17I", (out / "observed/alias.bin").read_bytes()))
            graphs = decode((out / "observed/graph.bin").read_bytes(), aliases)
            budget = struct.unpack("<4I", (out / "observed/budget.bin").read_bytes())
            before_cost = [event for event in graphs if event["phase"] == 12]
            assert len(before_cost) == 6
            blue = []
            for event in before_cost[:3]:
                # The first seven stores are type, size, AI, health, speed, reward and alpha.
                fields = [memory for node in event["nodes"] for memory in node["memory"] if memory["side"] == 1]
                assert [field["displacement"] for field in fields] == [108, 52, 144, 36, 92, 100, 72]
                classes = [field["alias"] for field in fields]
                assert (len(set(classes)) == 1) == (name == "color-c4-ctor-assignment")
                stores = {i for i, node in enumerate(event["nodes"]) if any(memory["side"] == 1 for memory in node["memory"])}
                write_edges = {tuple(edge[:2]) for node in event["nodes"] for edge in node["edges"] if edge[0] in stores and edge[1] in stores and edge[2] & 0x80}
                expected = {(a, b) for a in stores for b in stores if a < b} if name == "color-c4-ctor-assignment" else set()
                assert write_edges == expected
                blue.append({"classes": classes, "store_order_edges": len(write_edges)})
            assert budget[2:] == (0, 0)  # Not a source-triggered pointer-option toggle.
            row = {"name": name, "source_sha256": sha(recover(name).encode()), "manifest_sha256": sha((out / "manifest.json").read_bytes()),
                   "whole_coff_equal_except_timestamp": True, "alias_base_count": budget[0], "alias_max": budget[1],
                   "pointer_options": budget[2:], "blue_alias_classes": blue, "graphs": graphs,
                   "observations_sha256": {file: sha((out / "observed" / file).read_bytes()) for file in ("graph.bin", "alias.bin", "budget.bin")}}
            receipts.append(row)
            print(name, "preserved; alias base", budget[0], "blue classes", blue, flush=True)
    finally:
        c2.load_profile, c2.observer_source = base_loader, base_source
    (args.out / "results.json").write_text(json.dumps({"schema_version": 1, "c2_sha256": base_profile["c2_sha256"],
        "rows": receipts, "harness_sha256": {file: sha((HERE / file).read_bytes()) for file in ("compiler.py", "scheduler.c.in", "recover.py")},
        "scope": "Read-only diagnostic hooks, checked call destinations and register/flag preservation. Normal, captured, replayed and observed whole COFFs must agree except timestamp; missing-stream negative control retained. No compiler choice or emitted instruction is patched."}, indent=2) + "\n")


if __name__ == "__main__":
    main()
