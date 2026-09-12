"""Diagnostic-only storage-extent intervention in the loaded compiler."""

import argparse
import importlib.util
import json
import os
import re
import shutil
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
p.add_argument("--observer", type=Path, required=True)
p.add_argument("--out", type=Path, required=True)
a = p.parse_args()
root = a.root.resolve()
out = a.out.resolve()
out.mkdir(parents=True, exist_ok=True)
assert r.sha((r.COMPILER / "Bin/C2.DLL").read_bytes()) == t.old.C2_SHA
src = (root / "scratch.cpp").read_text()
assert r.sha(src.encode()) == "5ad0be6a087969c28411fe3658c58a1dd2863f4611f4e843d684210f0a257cf9"
line = next(i for i, s in enumerate(src.splitlines()) if "for (" in s) - next(
    i for i, s in enumerate(src.splitlines()) if "void quest_spawn_timeline_update" in s
)
c = t.match.load_scratch_config(t.match.DEFAULT_MATCH_ROOT / "scratches/quest_spawn_timeline_update")
rows = []
for mode in ["control", "descriptor", "definition", "both"]:
    d = out / mode
    d.mkdir(exist_ok=True)
    shutil.copyfile(root / "replay/replay_settings.h", d / "replay_settings.h")
    code = a.observer.read_text().replace(
        "static HANDLE trace_file, layout_file;",
        "static HANDLE trace_file, layout_file;\nstatic unsigned long interventions, watched_parent;",
    )
    code = code.replace(
        "    write_block(&phase, 4);",
        """    if(phase==12) {
        for(node=first;node;node=*(unsigned long *)node) {
            unsigned long dest, parent, def;
            if(*(unsigned short *)(node+0x10)!=LINE || *(unsigned long *)(node+4)!=1)continue;
            dest=*(unsigned long *)(node+0x1c);
            if(!dest || *(unsigned char *)(dest+8)!=2)continue;
            parent=*(unsigned long *)(*(unsigned long *)(dest+0x14)+8);
            def=*(unsigned long *)parent;
            if(watched_parent || *(unsigned long *)(parent+0x20)!=8 || *(unsigned long *)(def+0x10)!=8)ExitProcess(86);
            watched_parent=parent;
            if(DESCRIPTOR) { *(unsigned long *)(parent+0x20)=4; ++interventions; }
            if(DEFINITION) { *(unsigned long *)(def+0x10)=4; ++interventions; }
        }
        if(!watched_parent)ExitProcess(85);
    }
    write_block(&phase, 4);""".replace("LINE", str(line))
        .replace("DESCRIPTOR", str(int(mode in ["descriptor", "both"])))
        .replace("DEFINITION", str(int(mode in ["definition", "both"]))),
    )
    code = code.replace(
        "    CloseHandle(layout_file);",
        "    if(!watched_parent || interventions!=EXPECTED)ExitProcess(84);\n    CloseHandle(layout_file);".replace(
            "EXPECTED",
            str({"control": 0, "descriptor": 1, "definition": 1, "both": 2}[mode]),
        ),
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
    equal = r.normalized_coff(d / "replay.obj") == r.normalized_coff(root / "replay/replay.obj")
    if mode in ["control", "definition"]:
        assert equal
    row = {
        "mode": mode,
        "whole_coff_equal_except_timestamp": equal,
        "field_writes": {"control": 0, "descriptor": 1, "definition": 1, "both": 2}[mode],
        "normalized_coff_sha256": r.sha(r.normalized_coff(d / "replay.obj")),
        "metrics": r.function_metrics(c, d / "replay.obj"),
    }
    rows.append(row)
    print(json.dumps(row), flush=True)
assert r.normalized_coff(out / "descriptor/replay.obj") == r.normalized_coff(out / "both/replay.obj")
control = (out / "control/candidate.asm").read_text().splitlines()
changed = (out / "descriptor/candidate.asm").read_text().splitlines()
# Diagnostic comparison only: validate that this intervention changes exactly
# the frame reservation and the local operands above the unused four-byte gap.
body = control.index("lea eax, dword [ebp+ebp*2]")
expected = []
sp = 0
for i, text in enumerate(control):
    if i < body:
        text = text.replace("sub esp, 0x20", "sub esp, 0x1c").replace("add esp, 0x20", "add esp, 0x1c")
    else:

        def shifted(m, sp=sp):
            off = int(m[1], 16)
            return "[esp+" + hex(off - 4 if off + sp >= 0x18 else off) + "]"

        text = re.sub(r"\[esp\+(0x[0-9a-f]+)\]", shifted, text)
        if text.startswith("push "):
            sp -= 4
        if text.startswith("pop "):
            sp += 4
        adjust = re.fullmatch(r"(add|sub) esp, (0x[0-9a-f]+)", text)
        if adjust:
            sp += int(adjust[2], 16) * (1 if adjust[1] == "add" else -1)
    expected.append(text)
assert sp == 0 and expected == changed
triplet = ["lea edi, dword [esi+0xc]", "mov dword [esp+0x10], edi", "mov dword [esp+0x10], ebx"]
assert any(changed[i : i + 3] == triplet for i in range(len(changed) - 2))
assert "mov eax, dword [edi+-0x4]" in changed and "mov edx, dword [edi]" in changed
(out / "results.json").write_text(
    json.dumps(
        {
            "source_sha256": r.sha(src.encode()),
            "c2_sha256": t.old.C2_SHA,
            "diagnostic_only": True,
            "only_frame_reservation_and_local_displacements_change": True,
            "descriptor_and_both_whole_coff_equal_except_timestamp": True,
            "modes": rows,
        },
        indent=2,
    )
    + "\n",
)
