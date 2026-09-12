"""Isolated compiler intervention; output is diagnostic and never a source match."""

import argparse
import importlib.util
import json
import os
import shutil
import struct
import sys
from pathlib import Path
from unittest.mock import patch

here = Path(__file__).resolve().parent.parent / "vc6-timeline-consumers-2026-09-11"
sys.path.insert(0, str(here))
s = importlib.util.spec_from_file_location("t", here / "trace.py")
t = importlib.util.module_from_spec(s)
s.loader.exec_module(t)
r = t.r

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--out", type=Path, required=True)
args = parser.parse_args()
root = args.out.resolve() / "baseline"
canonical = (t.match.DEFAULT_MATCH_ROOT / "scratches/quest_spawn_timeline_update/scratch.cpp").read_text()
assert r.sha(canonical.encode()) == t.probes.SOURCE_SHA
assert r.sha((r.COMPILER / "Bin/C2.DLL").read_bytes()) == t.old.C2_SHA
source_lines = canonical.splitlines()
signature = next(i for i, line in enumerate(source_lines) if "void quest_spawn_timeline_update" in line)
call_line = next(i for i, line in enumerate(source_lines) if "entry->heading);" in line) - signature
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
]
rows = []
with patch.dict(
    os.environ,
    {
        "MSVC_VER": "msvc6.5",
        "CRIMSON_MSVC_ROOT": str(r.COMPILER),
        "CRIMSON_MATCH_INCLUDE_OVERLAY": "",
        "WIBO": str(r.WIBO),
    },
):
    for mode in ["control", "reject-template-eligibility"]:
        d = root / (mode + "-late")
        d.mkdir(exist_ok=True)
        shutil.copyfile(root / "replay/replay_settings.h", d / "replay_settings.h")
        source = (
            (root / mode / "observer.c").read_text().replace("targets[16]", "targets[29]").replace("i < 16;", "i < 29;")
        )
        wrappers = ""
        for j in range(16, 16 + len(extra)):
            wrappers += """__declspec(naked) static void extra_INDEX(void) {
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
        source = source.replace(
            "static HANDLE decision_file;",
            "static HANDLE decision_file;\nstatic unsigned long late_function, late_return;",
        )
        source = source.replace(
            "(unsigned long *)registers[6]",
            "(unsigned long *)(phase >= 24 ? late_function : registers[6])",
        )
        source = source.replace(
            "    if (phase == 9) {",
            "    if (phase == 22) late_function = registers[6];\n    if (phase == 9) {",
        )
        a = source.index("__declspec(naked) static void extra_22(void)")
        b = source.index("__declspec(naked) static void extra_23(void)", a)
        source = (
            source[:a]
            + """static void __cdecl late_after(unsigned long *regs) {
    unsigned long copy[8], j;
    for (j=0; j<8; ++j) copy[j]=regs[j];
    copy[6]=late_function;
    observe(32,copy);
  }
  __declspec(naked) static void extra_22(void) {
    __asm { pushfd
     pushad
     mov eax, esp
     push eax
     push 22
     call observe
     add esp, 8
     popad
     popfd
     push eax
     mov eax, dword ptr [esp+4]
     mov late_return, eax
     mov dword ptr [esp+4], offset after_late
     pop eax
     jmp dword ptr [targets + 88]
    after_late:
     pushfd
     pushad
     mov eax, esp
     push eax
     call late_after
     add esp, 4
     popad
     popfd
     jmp dword ptr [late_return]
    }
  }
"""
            + source[b:]
        )
        for name, values in [
            ("sites", [hex(x[0]) for x in extra]),
            ("offsets", [hex(x[1]) for x in extra]),
            ("hooks", ["extra_" + str(j) for j in range(16, 29)]),
        ]:
            lines = source.splitlines()
            idx = next(i for i, x in enumerate(lines) if "static " in x and name + "[]" in x)
            lines[idx] = lines[idx].replace("};", ", " + ", ".join(values) + "};")
            source = "\n".join(lines) + "\n"
        (d / "observer.c").write_text(source)
        r.compile_driver(d, "observer.c", "observer.obj")
        r.link(d, "observer.exe", "observer.obj")
        (d / "replay.obj").unlink(missing_ok=True)
        r.run([r.WIBO, "observer.exe"], d)
        assert r.normalized_coff(d / "replay.obj") == r.normalized_coff(root / mode / "replay.obj")
        raw = (d / "phases.bin").read_bytes()
        off = 0
        snap = []
        identities = []
        while off < len(raw):
            phase, n = struct.unpack_from("<2I", raw, off)
            off += 8
            nodes = []
            ids = set()
            loads = []
            for _ in range(n):
                w = struct.unpack_from("<230I", raw, off)
                off += 920
                ids.add(hex(w[0]))
                if w[2] == 40:
                    nodes.append({"id": hex(w[0]), "opcode": hex(w[1])})
                if w[2] == call_line and w[1] == 1 and w[4] == 2 and w[7] & 255 == 6:
                    loads.append({"id": hex(w[0]), "base_symbol": hex(w[17])})
            snap.append({"phase": phase, "total_nodes": n, "pointer_line_nodes": nodes, "field_loads": loads})
            identities.append(ids)
        if mode != "control":
            before_index = next(i for i, row in enumerate(snap) if row["phase"] == 24)
            before = snap[before_index]
            after = snap[before_index + 1]
            assert after["phase"] == 25
            assert len(before["pointer_line_nodes"]) == 1
            pointer = before["pointer_line_nodes"][0]
            assert pointer["opcode"] == "0x12"
            assert pointer["id"] not in identities[before_index + 1]
            assert not after["pointer_line_nodes"]
            assert before["total_nodes"] - after["total_nodes"] == 1
            before_loads, after_loads = before["field_loads"], after["field_loads"]
            assert len(before_loads) == len(after_loads) == 2
            assert [x["id"] for x in before_loads] == [x["id"] for x in after_loads]
            assert before_loads[0]["base_symbol"] != before_loads[1]["base_symbol"]
            assert after_loads[0]["base_symbol"] == after_loads[1]["base_symbol"] == before_loads[0]["base_symbol"]
        rows.append({"mode": mode, "instrumentation_preserves_parent_coff": True, "snapshots": snap})
        print(json.dumps(rows[-1]), flush=True)
(root.parent / "late-results.json").write_text(json.dumps(rows, indent=2) + "\n")
