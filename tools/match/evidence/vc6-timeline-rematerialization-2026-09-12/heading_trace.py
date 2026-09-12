"""Preserving trace of the cursor control with an unused float-value home."""

import argparse
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from unittest.mock import patch

here = Path(__file__).resolve().parent.parent / "vc6-timeline-consumers-2026-09-11"
sys.path.insert(0, str(here))
s = importlib.util.spec_from_file_location("t", here / "trace.py")
t = importlib.util.module_from_spec(s)
s.loader.exec_module(t)
r = t.r
c = t.match.load_scratch_config(t.match.DEFAULT_MATCH_ROOT / "scratches/quest_spawn_timeline_update")
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--out", type=Path, required=True)
parser.add_argument("--source", type=Path, required=True)
parser.add_argument("--capture-dll", type=Path, required=True)
args = parser.parse_args()
out = args.out.resolve()
out.mkdir(parents=True, exist_ok=True)
src = args.source.read_text()
assert r.sha(src.encode()) == "dfc2fcfbde715a59521f71b00502c3fc0a8b787715dddfd0ed69de63823dbb7e"
assert r.sha((r.COMPILER / "Bin/C2.DLL").read_bytes()) == t.old.C2_SHA
# The imported analyzer asserts canonical load placement, which this source
# deliberately changes. Keep its capture/COFF/stream checks and assert our
# float-store history below instead.
t.analyze = lambda *args: {}
with patch.dict(
    os.environ,
    {
        "MSVC_VER": "msvc6.5",
        "CRIMSON_MSVC_ROOT": str(r.COMPILER),
        "CRIMSON_MATCH_INCLUDE_OVERLAY": "",
        "WIBO": str(r.WIBO),
        "CRIMSON_IL_BACKEND": r.windows_path(r.COMPILER / "Bin/C2.DLL"),
    },
):
    row, snap = t.trace(c, out, "heading-predec", src, args.capture_dll.resolve())
lines = src.splitlines()
line = next(i for i, s in enumerate(lines) if "float heading =" in s) - next(
    i for i, s in enumerate(lines) if "void quest_spawn_timeline_update" in s
)
record = []
for k, nodes in enumerate(snap):
    selected = [n for n in nodes if n["line"] == line]
    record.append({"phase": k, "nodes": selected})
    print(k, [(hex(n["op"]), [x[2] & 255 for x in n["src"]], [x[2] & 255 for x in n["dst"]]) for n in selected])
store = next(n for n in snap[5] if n["line"] == line and n["op"] == 0x63 and n["dst"][0][2] & 255 == 2)
for nodes in snap[5:11]:
    assert any(n["id"] == store["id"] and n["op"] == 0x63 for n in nodes)
load = next(n for n in snap[5] if n["line"] == line and n["op"] == 0x60)
assert any(n["id"] == load["id"] and n["op"] == 1 and n["dst"][0][2] & 255 == 2 for n in snap[11])
assert any(n["id"] == store["id"] and n["op"] == 1 and n["src"][0][2] & 255 == 6 for n in snap[11])
listing = (out / "heading-predec/candidate.asm").read_text().splitlines()
begin = listing.index("lea edi, dword [esi+0xc]")
finish = next(i for i in range(begin, len(listing)) if listing[i].startswith("jl "))
sp = 0
accesses = []
for i, text in enumerate(listing[begin : finish + 1], begin):
    for m in re.finditer(r"\[esp([+-](?:0x[0-9a-f]+|[0-9]+))?\]", text):
        if int(m[1] or "0", 0) + sp == 0x14:
            accesses.append({"index": i, "instruction": text})
    if text.startswith("push "):
        sp -= 4
    elif text.startswith("pop "):
        sp += 4
    m = re.fullmatch(r"(add|sub) esp, (0x[0-9a-f]+|[0-9]+)", text)
    if m:
        sp += int(m[2], 0) * (1 if m[1] == "add" else -1)
assert sp == 0
assert len(accesses) == 1 and accesses[0]["instruction"] == "mov dword [esp+0x14], eax"
(out / "results.json").write_text(
    json.dumps(
        {
            "verified": row,
            "heading_line": line,
            "home_slot_loop_accesses": accesses,
            "float_pair_rewritten_to_integer_copies_with_swapped_node_roles": True,
            "phases": record,
        },
        indent=2,
    )
    + "\n",
)
