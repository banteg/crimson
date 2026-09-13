import json
import struct
import sys
from pathlib import Path
from unittest.mock import patch

from crimson import match_c2 as c2

scratch = Path(sys.argv[1]).resolve()
out = Path(sys.argv[2]).resolve()
original = c2.observer_source
profile = c2.load_profile()
profile = {**profile, "hooks": profile["hooks"][:12] + [{"site": 0x583FC, "target": 0x33B7B, "return": True}]}
addon = """static HANDLE layout_file;
static void layout(unsigned long phase, unsigned long node, unsigned long side, unsigned long op) {
    unsigned long rec[36], symbol, parent, root, j; DWORD written;
    if ((phase!=12 && phase!=112) || *(unsigned char *)(op+8)!=2) return;
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
"""


def observer(p):
    s = original(p).replace("static HANDLE trace_file;", "static HANDLE trace_file;\n" + addon)
    s = s.replace(
        "for (j=0;j<7;++j) record[at+1+k*23+j]=*(unsigned long *)(op+j*4);",
        "for (j=0;j<7;++j) record[at+1+k*23+j]=*(unsigned long *)(op+j*4);\n                    layout(phase,node,side,op);",
    )
    s = s.replace(
        "    trace_file = CreateFileA(",
        '    layout_file=CreateFileA("layout.bin",GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);\n    if(layout_file==INVALID_HANDLE_VALUE)ExitProcess(88);\n    trace_file = CreateFileA(',
    )
    return s.replace("    CloseHandle(trace_file);", "    CloseHandle(layout_file);\n    CloseHandle(trace_file);")


with patch.object(c2, "load_profile", lambda: profile), patch.object(c2, "observer_source", observer):
    receipt = c2.trace(scratch, out)
events = c2.read_verified(out)
data = (out / "observed/layout.bin").read_bytes()
assert len(data) % 144 == 0
rows = [list(struct.unpack_from("<36I", data, i)) for i in range(0, len(data), 144)]
before = next(e for e in events if e["phase"] == 12)
nodes = {n["id"]: n for n in before["nodes"]}
source = (scratch / "scratch.cpp").read_text().splitlines()
start = next(i for i, s in enumerate(source) if "void highscore_screen_update" in s)
objects = []
for parent in sorted({r[5] for r in rows}):
    b = next(r for r in rows if r[0] == 12 and r[5] == parent)
    a = next(r for r in rows if r[0] == 112 and r[5] == parent)
    offset = a[30] if a[30] < 2**31 else a[30] - 2**32
    lines = sorted({nodes[r[1]]["line"] for r in rows if r[0] == 12 and r[5] == parent})
    obj = {
        "parent": hex(parent),
        "size": b[14],
        "offset": offset,
        "lines": [
            {"line": l + start + 1, "text": source[l + start] if 0 <= l + start < len(source) else "?"} for l in lines
        ],
        "before_descriptor": b[6:27],
        "after_descriptor": a[6:27],
        "before_definition": b[27:35],
        "after_definition": a[27:35],
    }
    objects.append(obj)
(out / "layout-results.json").write_text(json.dumps({"receipt": receipt, "objects": objects}, indent=2) + "\n")
for o in sorted(objects, key=lambda o: (o["offset"], o["size"])):
    print(o["parent"], o["offset"], o["size"], [(x["line"], x["text"].strip()) for x in o["lines"]], flush=True)
