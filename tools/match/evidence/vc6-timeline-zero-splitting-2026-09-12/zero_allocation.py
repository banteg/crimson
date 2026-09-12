"""Preserving compiler trace of zero splitting and allocation; no source-match credit."""

import argparse
import importlib.util
import json
import os
import shutil
import struct
import sys
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent.parent / "vc6-timeline-consumers-2026-09-11"
sys.path.insert(0, str(HERE))
s = importlib.util.spec_from_file_location("t", HERE / "trace.py")
t = importlib.util.module_from_spec(s)
s.loader.exec_module(t)
r = t.r

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--canonical-root", type=Path, required=True)
parser.add_argument("--witness-root", type=Path, required=True)
parser.add_argument("--out", type=Path, required=True)
args = parser.parse_args()
assert r.sha((r.COMPILER / "Bin/C2.DLL").read_bytes()) == t.old.C2_SHA
extra = [
    (0x2FBE3, 0x2FEF2),
    (0x2FBEC, 0x2F8FC),
    (0x2FBF3, 0x30A91),
    (0x2FC1E, 0x30AB7),
    (0x2FC30, 0x24B25),
    (0x2FC41, 0x25B42),
    (0x2FC6D, 0x33569),
    (0x2FCB7, 0x388F3),
    (0x2FE4D, 0x32216),
    (0x2FE5F, 0x32F7C),
    (0x2FE73, 0x33230),
    (0x2FED5, 0x31D21),
    (0x2FEE8, 0x62F4A),
    (0x2FD3D, 0x204D6),
    (0x2FD62, 0x24B25),
    (0x2FD84, 0x2158F),
    (0x2FDC7, 0x32001),
]
src = (HERE / "observer.c").read_text().replace("targets[12]", "targets[29]").replace("i < 12;", "i < 29;")
src = src.replace(
    "static HANDLE trace_file;",
    "static HANDLE trace_file, temp_file;\nstatic unsigned long saved_function, zero_temp, subject_temp, returns[29];",
)
src = src.replace(
    "/* Capture",
    """static void temp_record(unsigned long phase, unsigned long node, unsigned long side, unsigned long temp) {
 unsigned long rec[21],j; DWORD written;
 rec[0]=phase;rec[1]=node;rec[2]=side;rec[3]=temp;rec[4]=zero_temp;
 for(j=0;j<16;++j)rec[5+j]=*(unsigned long *)(temp+4*j);
 if(!WriteFile(temp_file,rec,sizeof(rec),&written,0)||written!=sizeof(rec))ExitProcess(87);
}
/* Capture""",
)
src = src.replace("(unsigned long *)registers[6]", "(unsigned long *)(phase>=12 ? saved_function : registers[6])")
src = src.replace(
    "    while (node &&",
    """    if(phase==9) {
      saved_function=registers[6];
      for(node=first;node;node=*(unsigned long *)node) {
        if(*(unsigned long *)(node+4)!=0x163)continue;
        op=*(unsigned long *)(node+0x18);
        if(!op || *(unsigned char *)(op+8)!=7 || *(unsigned long *)(op+0x18))continue;
        op=*(unsigned long *)(node+0x1c);
        if(!op || *(unsigned char *)(op+8)!=1 || zero_temp)ExitProcess(86);
        zero_temp=*(unsigned long *)(op+0x18);
      }
      if(!zero_temp)ExitProcess(85);
      node=first;
    }
    if(phase>=9 && zero_temp)temp_record(phase,0,2,zero_temp);
    if(phase==21)subject_temp=registers[6];
    if(phase==21 || phase==121)temp_record(phase,0,3,subject_temp);
    while (node &&""",
)
src = src.replace(
    "for (j=0;j<7;++j) record[at+1+k*7+j]=*(unsigned long *)(op+j*4);",
    """for (j=0;j<7;++j) record[at+1+k*7+j]=*(unsigned long *)(op+j*4);
                    if(phase>=9 && *(unsigned char *)(op+8)==1)temp_record(phase,node,side,*(unsigned long *)(op+0x18));""",
)
wrappers = ""
for i in range(12, 29):
    wrappers += (
        """__declspec(naked) static void extra_I(void) {
 __asm { pushfd
 pushad
 mov eax,esp
 push eax
 push I
 call observe
 add esp,8
 popad
 popfd
 push eax
 mov eax,dword ptr [esp+4]
 mov dword ptr [returns+O],eax
 mov dword ptr [esp+4],offset after_call
 pop eax
 jmp dword ptr [targets+O]
 after_call:
 pushfd
 pushad
 mov eax,esp
 push eax
 push A
 call observe
 add esp,8
 popad
 popfd
 jmp dword ptr [returns+O]
 }
}
""".replace("extra_I", "extra_" + str(i))
        .replace("push I", "push " + str(i))
        .replace("push A", "push " + str(i + 100))
        .replace("+O", "+" + str(i * 4))
    )
src = src.replace("void __stdcall start(void)", wrappers + "void __stdcall start(void)")
for name, vals in [
    ("sites", [hex(x[0]) for x in extra]),
    ("offsets", [hex(x[1]) for x in extra]),
    ("hooks", ["extra_" + str(i) for i in range(12, 29)]),
]:
    lines = src.splitlines()
    idx = next(i for i, x in enumerate(lines) if "static " in x and name + "[]" in x)
    lines[idx] = lines[idx].replace("};", ", " + ", ".join(vals) + "};")
    src = "\n".join(lines) + "\n"
src = src.replace(
    "trace_file = CreateFileA(",
    'temp_file=CreateFileA("temps.bin",GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);\n    if(temp_file==INVALID_HANDLE_VALUE)ExitProcess(84);\n    trace_file = CreateFileA(',
).replace("CloseHandle(trace_file);", "CloseHandle(temp_file);\n    CloseHandle(trace_file);")
for label, root in [("canonical", args.canonical_root.resolve()), ("witness", args.witness_root.resolve())]:
    expected = (
        t.probes.SOURCE_SHA
        if label == "canonical"
        else "5ad0be6a087969c28411fe3658c58a1dd2863f4611f4e843d684210f0a257cf9"
    )
    assert r.sha((root / "captured-source/scratch.cpp").read_bytes()) == expected
    out = args.out.resolve() / label
    out.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(root / "replay/replay_settings.h", out / "replay_settings.h")
    (out / "observer.c").write_text(src)
    with patch.dict(
        os.environ,
        {
            "MSVC_VER": "msvc6.5",
            "CRIMSON_MSVC_ROOT": str(r.COMPILER),
            "CRIMSON_MATCH_INCLUDE_OVERLAY": "",
            "WIBO": str(r.WIBO),
        },
    ):
        r.compile_driver(out, "observer.c", "observer.obj")
        r.link(out, "observer.exe", "observer.obj")
        (out / "replay.obj").unlink(missing_ok=True)
        r.run([r.WIBO, "observer.exe"], out)
    assert r.normalized_coff(out / "replay.obj") == r.normalized_coff(root / "replay/replay.obj")
    raw = (out / "temps.bin").read_bytes()
    rows = [list(struct.unpack_from("<21I", raw, i)) for i in range(0, len(raw), 84)]
    (out / "temps.json").write_text(json.dumps(rows))
    zero = [x for x in rows if x[2] == 2]
    print(label, "COFF preserved", len(zero), "events", flush=True)

# Preserve every complete-operand event; summarize only currently defined zero
# seeds, since allocator arena addresses are recycled after splitting.
summary = []
for label in ["canonical", "witness"]:
    d = args.out.resolve() / label
    raw = (d / "phases.bin").read_bytes()
    off = 0
    snaps = []
    while off < len(raw):
        phase, n = struct.unpack_from("<2I", raw, off)
        off += 8
        nodes = []
        for _ in range(n):
            w = struct.unpack_from("<230I", raw, off)
            off += 920

            def operands(at, w=w):
                return [list(w[at + 1 + 7 * k : at + 8 + 7 * k]) for k in range(w[at])]

            nodes.append(
                {"id": w[0], "op": w[1], "line": w[2], "flags": w[3], "src": operands(4), "dst": operands(117)},
            )
        snaps.append({"phase": phase, "nodes": nodes})
    assert off == len(raw)
    (d / "snapshots.json").write_text(json.dumps(snaps) + "\n")
    groups = []
    for row in json.loads((d / "temps.json").read_text()):
        if row[2] == 2:
            groups.append([])
        groups[-1].append(row)
    events = [e for e in snaps if e["phase"] >= 9]
    assert len(events) == len(groups)
    changes = []
    allocations = []
    old = None
    for ix, (event, group) in enumerate(zip(events, groups)):
        nodes = event["nodes"]
        seeds = {
            n["dst"][0][6]
            for n in nodes
            if n["op"] == 0x163 and n["src"] and n["src"][0][2] & 255 == 7 and n["src"][0][6] == 0 and n["dst"]
        }
        shape = []
        for temp in sorted(seeds):
            row = next((x for x in group if x[3] == temp and x[2] not in [2, 3]), None)
            assert row is not None
            words = row[5:]
            users = [n for n in nodes if any(op[2] & 255 == 1 and op[6] == temp for op in n["src"])]
            signed = lambda v: v - 2**32 if v >= 2**31 else v
            shape.append(
                {
                    "temporary": temp,
                    "flags": words[1],
                    "priority": signed(words[3]),
                    "allocated_register": words[4],
                    "count_field": words[9],
                    "cost": signed(words[15]),
                    "users": [{"id": n["id"], "op": n["op"], "line": n["line"]} for n in users],
                },
            )
        signature = [{**x, "users": [(n["op"], n["line"]) for n in x["users"]]} for x in shape]
        if signature != old:
            changes.append({"event": ix, "phase": event["phase"], "zeros": shape})
            old = signature
        if event["phase"] in [21, 121]:
            row = next(x for x in group if x[2] == 3)
            temp = row[3]
            uses = [n for n in nodes if any(o[2] & 255 == 1 and o[6] == temp for o in n["src"] + n["dst"])]
            allocations.append(
                {
                    "event": ix,
                    "phase": event["phase"],
                    "temporary": temp,
                    "register": row[9],
                    "source_lines": sorted({n["line"] for n in uses}),
                },
            )
    frames = [sorted([len(z["users"]) for z in x["zeros"]]) for x in changes]
    assert [12] in frames and [9] in frames
    if label == "canonical":
        assert [1, 8] in frames and [8] in frames
    else:
        assert [3, 6] in frames and [1, 2, 4] in frames
    summary.append(
        {
            "label": label,
            "whole_coff_equal_except_timestamp": True,
            "events": len(events),
            "trace_sha256": r.sha(raw),
            "coff_sha256": r.sha(r.normalized_coff(d / "replay.obj")),
            "zero_changes": changes,
            "allocations": allocations,
        },
    )
(args.out / "results.json").write_text(json.dumps({"c2_sha256": t.old.C2_SHA, "controls": summary}, indent=2) + "\n")
