"""Observe and selectively reject VC6 rematerialization; never a source match."""

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
parser.add_argument("--replay-root", type=Path, required=True)
parser.add_argument("--out", type=Path, required=True)
parser.add_argument("--strategy", choices=["eligibility", "conflict"], default="eligibility")
parser.add_argument("--retaining-control", action="store_true")
args = parser.parse_args()
root = args.replay_root.resolve()
out = args.out.resolve()
out.mkdir(parents=True, exist_ok=True)
source_hash = r.sha((root / "captured-source/scratch.cpp").read_bytes())
assert source_hash == (
    "b418b27e9efcafa1cc8ebecedb5b0447a651c759c2f715df84b21c738bb2ae53"
    if args.retaining_control
    else t.probes.SOURCE_SHA
)
assert r.sha((r.COMPILER / "Bin/C2.DLL").read_bytes()) == t.old.C2_SHA
modes = ["control"] if args.retaining_control else ["control", "early-only", "late-only", "early-and-late"]

config = t.match.load_scratch_config(t.match.DEFAULT_MATCH_ROOT / "scratches/quest_spawn_timeline_update")
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
    for mode in modes:
        d = out / mode
        d.mkdir(exist_ok=True)
        shutil.copyfile(root / "replay/replay_settings.h", d / "replay_settings.h")
        source = (
            (here / "decision_observer.c")
            .read_text()
            .replace("targets[16]", "targets[20]")
            .replace("return_sites[4]", "return_sites[8]")
            .replace("pending[4][12]", "pending[8][12]")
            .replace("i < 16;", "i < 20;")
        )
        source = source.replace(
            "static HANDLE decision_file;",
            "static HANDLE decision_file;\nstatic unsigned long backend_base;",
        )
        source = source.replace(
            "base = (unsigned char *)invoke - 0x57444;",
            "base = (unsigned char *)invoke - 0x57444; backend_base=(unsigned long)base;",
        )
        source = source.replace(
            "    if (index < 2) {",
            """    if (index >= 4) {
        definition = index == 5 ? regs[5] : regs[6];
        dest = *(unsigned long *)(definition+0x1c);
        temp = *(unsigned long *)(dest+0x18);
        row[4]=definition; row[5]=regs[5];
        row[6]=*(unsigned long *)(definition+4);
        row[7]=*(unsigned short *)(definition+0x10);
        row[8]=index == 4 ? regs[5] : index == 7 ? *(unsigned long *)(regs[3]+8) : *(unsigned long *)(backend_base+0xac0b4);
    } else if (index < 2) {""",
        )
        source = source.replace(
            "    pending[index][9]=regs[7];",
            """    pending[index][9]=regs[7];
    if (index==7) pending[index][8]=*(unsigned long *)pending[index][8];
    if (watched_temp && pending[index][1]==watched_temp && regs[7] &&
        ((EARLY && (index==2 || index==3)) || (LATE && index==4))) {
        regs[7]=0; pending[index][11]=1;
    }""".replace("EARLY", str(int(mode in ["early-only", "early-and-late"]))).replace(
                "LATE",
                str(int(mode in ["late-only", "early-and-late"])),
            ),
        )
        if args.strategy == "conflict":
            source = source.replace("((1 && (index==2 || index==3))", "((1 && (index==0 || index==1))")
            # Only the early conflict query returns 0 in these builds. Preserve the
            # recorded original return while changing the caller-visible value to 1.
            source = source.replace(
                "pending[index][1]==watched_temp && regs[7] &&",
                "pending[index][1]==watched_temp && ((index<2 && !regs[7]) || (index>=2 && regs[7])) &&",
            )
            source = source.replace(
                "regs[7]=0; pending[index][11]=1;",
                "regs[7]=index<2 ? 1 : 0; pending[index][11]=1;",
            )
        a = source.index("__declspec(naked) static void decision_2(void)")
        b = source.index("__declspec(naked) static void decision_3(void)", a)
        template = source[a:b]
        new = ""
        for j in [4, 5, 6, 7]:
            new += (
                template.replace("decision_2", "decision_" + str(j))
                .replace("push 2\n", "push " + str(j) + "\n")
                .replace("after_2", "after_" + str(j))
                .replace("return_sites+8", "return_sites+" + str(j * 4))
                .replace("targets+56", "targets+" + str((j + 12) * 4))
            )
        source = source.replace("void __stdcall start(void)", new + "void __stdcall start(void)")
        for name, values in [
            ("sites", ["0x5273a", "0x528e3", "0x529c1", "0x52700"]),
            ("offsets", ["0x527b2", "0x52a2b", "0x52a3d", "0x5259c"]),
            ("hooks", ["decision_4", "decision_5", "decision_6", "decision_7"]),
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
        if mode == "control":
            assert r.normalized_coff(d / "replay.obj") == r.normalized_coff(root / "replay/replay.obj")
        data = list(struct.iter_unpack("<12I", (d / "decisions.bin").read_bytes()))
        watched = [list(x) for x in data if x[1] == x[2] and x[0] < 8]
        result = t.match.run_match(
            obj_path=d / "replay.obj",
            function=config.function,
            symbol_name=config.symbol,
            reference_aliases=config.reference_aliases,
        )
        (d / "candidate.asm").write_text("\n".join(result.candidate_lines) + "\n")
        import mine

        changed = [x for x in data if x[11]]
        assert len(changed) == (
            0 if args.retaining_control or mode in ["control", "late-only"] else 1 if mode == "early-only" else 2
        )
        if mode == "late-only":
            assert r.normalized_coff(d / "replay.obj") == r.normalized_coff(root / "replay/replay.obj")
        row = {
            "mode": mode,
            "strategy": args.strategy,
            "source_sha256": source_hash,
            "watched": watched,
            "metrics": r.function_metrics(config, d / "replay.obj"),
            "screen": mine.screen(result.candidate_lines),
        }
        rows.append(row)
        print(json.dumps(row), flush=True)
(out / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
