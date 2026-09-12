"""Observe compiler stack-object descriptors before and after local allocation."""

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
spec = importlib.util.spec_from_file_location("t", HERE / "trace.py")
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
r = t.r
p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--root", type=Path, required=True)
p.add_argument("--out", type=Path, required=True)
a = p.parse_args()
root = a.root.resolve()
out = a.out.resolve()
out.mkdir(parents=True, exist_ok=True)
input_source = (root / "scratch.cpp").read_text()
source_sha = r.sha(input_source.encode())
assert source_sha == "5ad0be6a087969c28411fe3658c58a1dd2863f4611f4e843d684210f0a257cf9"
assert r.sha((r.COMPILER / "Bin/C2.DLL").read_bytes()) == t.old.C2_SHA
shutil.copyfile(root / "replay/replay_settings.h", out / "replay_settings.h")
source = (HERE / "observer.c").read_text().replace("targets[12]", "targets[14]").replace("i < 12;", "i < 14;")
source = source.replace("static HANDLE trace_file;", "static HANDLE trace_file, layout_file;")
source = source.replace(
    "static void __cdecl observe(",
    """static void __cdecl layout(unsigned long phase, unsigned long node, unsigned long side, unsigned long op) {
    unsigned long rec[36], symbol, parent, root, j; DWORD written;
    if (phase < 11 || *(unsigned char *)(op+8)!=2) return;
    symbol=*(unsigned long *)(op+0x14);
    if(!symbol) return;
    parent=*(unsigned long *)(symbol+8);
    if(!parent || *(unsigned char *)(parent+4)!=4) return;
    for(j=0;j<36;++j)rec[j]=0;
    rec[0]=phase; rec[1]=node; rec[2]=side; rec[3]=op; rec[4]=symbol;rec[5]=parent;
    for(j=0;j<21;++j)rec[6+j]=*(unsigned long *)(parent+4*j);
    root=*(unsigned long *)parent;
    if(root)for(j=0;j<8;++j)rec[27+j]=*(unsigned long *)(root+4*j);
    if(!WriteFile(layout_file,rec,sizeof(rec),&written,0)||written!=sizeof(rec))ExitProcess(87);
}
static void __cdecl observe(""",
)
source = source.replace(
    "for (j=0;j<7;++j) record[at+1+k*7+j]=*(unsigned long *)(op+j*4);",
    "for (j=0;j<7;++j) record[at+1+k*7+j]=*(unsigned long *)(op+j*4);\n                    layout(phase,node,side,op);",
)
wrappers = ""
for j in [12, 13]:
    wrappers += """__declspec(naked) static void phase_INDEX(void) {
    __asm { pushfd
      pushad
      mov eax, esp
      push eax
      push INDEX
      call observe
      add esp, 8
      popad
      popfd
      jmp dword ptr [targets + OFFSET]
    }
}
""".replace("INDEX", str(j)).replace("OFFSET", str(j * 4))
source = source.replace("void __stdcall start(void)", wrappers + "void __stdcall start(void)")
source = source.replace("0x2fbc4, 0x583c5};", "0x2fbc4, 0x583c5, 0x583fc, 0x5840f};")
source = source.replace("0x30a40, 0x336f4};", "0x30a40, 0x336f4, 0x33b7b, 0x34032};")
source = source.replace("phase_10, phase_11};", "phase_10, phase_11, phase_12, phase_13};")
source = source.replace(
    "trace_file = CreateFileA(",
    'layout_file = CreateFileA("layout.bin", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);\n    if(layout_file==INVALID_HANDLE_VALUE)ExitProcess(88);\n    trace_file = CreateFileA(',
)
source = source.replace("CloseHandle(trace_file);", "CloseHandle(layout_file);\n    CloseHandle(trace_file);")
(out / "observer.c").write_text(source)
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
t.old.PHASES = (*t.old.PHASES, "before_stack_allocation", "after_stack_allocation")
snaps = t.read_trace(out / "phases.bin")
(out / "operands.json").write_text(json.dumps(snaps))
data = (out / "layout.bin").read_bytes()
assert len(data) % 144 == 0
rows = [list(struct.unpack_from("<36I", data, i)) for i in range(0, len(data), 144)]
(out / "layout.json").write_text(json.dumps(rows, indent=2) + "\n")
print("whole COFF preserved; layout records", len(rows))
source_lines = input_source.splitlines()
signature = next(i for i, line in enumerate(source_lines) if "void quest_spawn_timeline_update" in line)
nodes = {n["id"]: n for n in snaps[12]}


def parent_for(needle):
    line = next(i for i, text in enumerate(source_lines) if needle in text) - signature
    parents = {row[5] for row in rows if row[0] == 12 and row[2] == 1 and nodes[row[1]]["line"] == line}
    assert len(parents) == 1
    return next(iter(parents))


copy_parent = parent_for("for (")
spread_parent = parent_for("spread = 0;")
objects = []
for parent in sorted({row[5] for row in rows}):
    before = next(row for row in rows if row[0] == 12 and row[5] == parent)
    after = next(row for row in rows if row[0] == 13 and row[5] == parent)
    offsets = after[30] if after[30] < 2**31 else after[30] - 2**32
    refs = sorted({nodes[row[1]]["line"] for row in rows if row[0] == 12 and row[5] == parent})
    objects.append(
        {
            "parent": parent,
            "size": before[14],
            "assigned_displacement": offsets,
            "source_lines": [{"relative_line": line, "text": source_lines[signature + line].strip()} for line in refs],
            "before_descriptor": before[6:27],
            "after_descriptor": after[6:27],
            "before_definition": before[27:35],
            "after_definition": after[27:35],
        },
    )
copied = next(obj for obj in objects if obj["parent"] == copy_parent)
spread = next(obj for obj in objects if obj["parent"] == spread_parent)
assert copied["size"] == 8 and spread["size"] == 4
assert copied["assigned_displacement"] == spread["assigned_displacement"] == -32
assert sorted((obj["assigned_displacement"], obj["size"]) for obj in objects) == [
    (-32, 4),
    (-32, 8),
    (-24, 8),
    (-16, 8),
    (-8, 8),
]
(out / "results.json").write_text(
    json.dumps(
        {
            "source_sha256": source_sha,
            "c2_sha256": t.old.C2_SHA,
            "whole_coff_equal_except_timestamp": True,
            "copied_parent": copy_parent,
            "spread_parent": spread_parent,
            "frame_owner_sizes_and_offsets_verified": True,
            "objects": objects,
        },
        indent=2,
    )
    + "\n",
)
print("copied: 8 bytes at -32; spread: 4 bytes at -32; next object begins at -24")
