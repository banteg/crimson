"""Isolated diagnostic changes to zero priorities/costs and the known frame extent."""

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
parser.add_argument("--root", type=Path, required=True)
parser.add_argument("--observer", type=Path, required=True)
parser.add_argument("--out", type=Path, required=True)
args = parser.parse_args()
root = args.root.resolve()
out = args.out.resolve()
out.mkdir(parents=True, exist_ok=True)
assert r.sha((r.COMPILER / "Bin/C2.DLL").read_bytes()) == t.old.C2_SHA
assert (
    r.sha((root / "captured-source/scratch.cpp").read_bytes())
    == "5ad0be6a087969c28411fe3658c58a1dd2863f4611f4e843d684210f0a257cf9"
)
c = t.match.load_scratch_config(t.match.DEFAULT_MATCH_ROOT / "scratches/quest_spawn_timeline_update")
base = args.observer.read_text().replace("targets[14]", "targets[17]").replace("i < 14;", "i < 17;")
base = base.replace(
    "static HANDLE trace_file, layout_file;",
    "static HANDLE trace_file, layout_file;\nstatic HANDLE priority_file;\nstatic unsigned long extent_writes;",
)
fun = """static void __cdecl priority(unsigned long *regs) {
 unsigned long temp=regs[6],def=*(unsigned long *)(temp+0x38),op,rec[8]; long *value=(long *)(temp+0xc); DWORD written;
 if(!def || *(unsigned long *)(def+4)!=0x163)return;
 op=*(unsigned long *)(def+0x18);
 if(!op || *(unsigned char *)(op+8)!=7 || *(unsigned long *)(op+0x18))return;
 rec[0]=temp;rec[1]=def;rec[2]=*value;rec[5]=*(unsigned long *)(temp+0x3c);
 MUTATE
 rec[3]=*value;rec[4]=*(unsigned long *)(temp+0x24);rec[6]=*(unsigned long *)(temp+0x3c);rec[7]=*(unsigned long *)(temp+4);
 if(!WriteFile(priority_file,rec,sizeof(rec),&written,0)||written!=sizeof(rec))ExitProcess(83);
}
"""
for i in range(14, 17):
    fun += """__declspec(naked) static void queue_I(void) {
 __asm { pushfd
 pushad
 mov eax,esp
 push eax
 call priority
 add esp,4
 popad
 popfd
 jmp dword ptr [targets+O]
 }
}
""".replace("queue_I", "queue_" + str(i)).replace("+O", "+" + str(i * 4))
base = base.replace("void __stdcall start(void)", fun + "void __stdcall start(void)")
for name, vals in [
    ("sites", ["0x2fed5", "0x33607", "0x215bb"]),
    ("offsets", ["0x31d21"] * 3),
    ("hooks", ["queue_" + str(i) for i in range(14, 17)]),
]:
    lines = base.splitlines()
    idx = next(i for i, x in enumerate(lines) if "static " in x and name + "[]" in x)
    lines[idx] = lines[idx].replace("};", ", " + ", ".join(vals) + "};")
    base = "\n".join(lines) + "\n"
base = base.replace(
    "trace_file = CreateFileA(",
    'priority_file=CreateFileA("priority.bin",GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);\n    if(priority_file==INVALID_HANDLE_VALUE)ExitProcess(84);\n    trace_file = CreateFileA(',
).replace("CloseHandle(trace_file);", "CloseHandle(priority_file);\n    CloseHandle(trace_file);")
rows = []
modes = [
    ("control", ""),
    ("initial", "if(*value==-68)*value=-64;"),
    ("replacement", "if(*value==-57)*value=-53;"),
    ("both", "if(*value==-68)*value=-64; if(*value==-57)*value=-53;"),
    ("first", "*value=1000;"),
    ("last", "*value=-1000;"),
    ("cost-original", "if(*(unsigned long *)(temp+0x24)==12)*(long *)(temp+0x3c)=20;"),
    ("cost-replacement", "if(*(unsigned long *)(temp+0x24)==9)*(long *)(temp+0x3c)=1;"),
    ("cost-all", "*(long *)(temp+0x3c)=1;"),
]
for selected in [(6,), (3,), (4,), (2,), (6, 3), (4, 2), (6, 3, 4, 2)]:
    modes.append(
        (
            "cost-" + "-".join(str(x) for x in selected),
            "if("
            + " || ".join("*(unsigned long *)(temp+0x24)==" + str(n) for n in selected)
            + ")*(long *)(temp+0x3c)=1;",
        ),
    )
for name, mutation in modes:
    for extent in (
        [True]
        if name in ["cost-6", "cost-3", "cost-4", "cost-2", "cost-6-3", "cost-4-2", "cost-6-3-4-2"]
        else [False, True]
    ):
        d = out / (name + ("-extent" if extent else ""))
        d.mkdir(exist_ok=True)
        shutil.copyfile(root / "replay/replay_settings.h", d / "replay_settings.h")
        code = base.replace("MUTATE", mutation)
        if extent:
            code = code.replace(
                "    write_block(&phase, 4);",
                """    if(phase==12)for(node=first;node;node=*(unsigned long *)node) {
     unsigned long op,parent;
     if(*(unsigned short *)(node+0x10)!=40 || *(unsigned long *)(node+4)!=1)continue;
     op=*(unsigned long *)(node+0x1c);
     if(!op || *(unsigned char *)(op+8)!=2)continue;
     parent=*(unsigned long *)(*(unsigned long *)(op+0x14)+8);
     if(*(unsigned long *)(parent+0x20)!=8)ExitProcess(82);
     *(unsigned long *)(parent+0x20)=4; ++extent_writes;
    }
    write_block(&phase, 4);""",
            )
        code = code.replace(
            "    CloseHandle(priority_file);",
            "    if(extent_writes!=" + str(int(extent)) + ")ExitProcess(81);\n    CloseHandle(priority_file);",
        )
        (d / "observer.c").write_text(code)
        with patch.dict(
            os.environ,
            {
                "MSVC_VER": "msvc6.5",
                "CRIMSON_MSVC_ROOT": str(r.COMPILER),
                "CRIMSON_MATCH_INCLUDE_OVERLAY": "",
                "WIBO": str(r.WIBO),
            },
        ):
            r.compile_driver(d, "observer.c", "observer.obj")
            r.link(d, "observer.exe", "observer.obj")
            (d / "replay.obj").unlink(missing_ok=True)
            r.run([r.WIBO, "observer.exe"], d)
        result = t.match.run_match(
            obj_path=d / "replay.obj",
            function=c.function,
            symbol_name=c.symbol,
            reference_aliases=c.reference_aliases,
        )
        (d / "candidate.asm").write_text("\n".join(result.candidate_lines) + "\n")
        (d / "diff.txt").write_text("\n".join(result.diff_lines(full=True)))
        row = {"mode": d.name, **r.function_metrics(c, d / "replay.obj")}
        data = (d / "priority.bin").read_bytes()
        assert len(data) % 32 == 0
        row["queue_decisions"] = [list(struct.unpack_from("<8I", data, i)) for i in range(0, len(data), 32)]
        row["priority_writes"] = sum(x[2] != x[3] for x in row["queue_decisions"])
        row["cost_writes"] = sum(x[5] != x[6] for x in row["queue_decisions"])
        row["normalized_coff_sha256"] = r.sha(r.normalized_coff(d / "replay.obj"))
        rows.append(row)
        print(d.name, row["ratio"], row["prefix_instructions"], flush=True)
        if name == "control" and not extent:
            assert r.normalized_coff(d / "replay.obj") == r.normalized_coff(root / "replay/replay.obj")

by_name = {row["mode"]: row for row in rows}
for name in ["initial", "replacement", "both", "last"]:
    for suffix in ["", "-extent"]:
        assert by_name[name + suffix]["normalized_coff_sha256"] == by_name["control" + suffix]["normalized_coff_sha256"]
four = by_name["cost-4-extent"]
assert four["candidate_instructions"] == 115 and four["prefix_instructions"] == 48
assert four["references_ok"] == 12 and four["reference_problems"] == 0
assert four["cost_writes"] == 1
write = next(x for x in four["queue_decisions"] if x[5] != x[6])
assert write[4] == 4 and write[5] == 0xFFFFFFFF and write[6] == 1
assert all(not row["body_byte_exact"] for row in rows)
lines = (out / "cost-4-extent/candidate.asm").read_text().splitlines()
triplet = ["lea edi, dword [esi+0xc]", "mov dword [esp+0x10], edi", "mov dword [esp+0x10], ebx"]
assert any(lines[i : i + 3] == triplet for i in range(len(lines) - 2))
assert "sub esp, 0x1c" in lines
assert "mov eax, dword [edi+-0x4]" in lines and "mov edx, dword [edi]" in lines

(out / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
