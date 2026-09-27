"""Pinned player_update compiler decisions: preserving observation or explicit diagnostic overrides.

An intervention is never a source-matching candidate. The baseline source and C2 digest are pinned
because the tested live-range/symbol IDs belong to this exact compile.
"""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

import pefile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SOURCE_SHA = "32acad8ac4ebfa7c6af8f1cff460357473135696ed0c91435ba3493973efcd1c"
C2_SHA = "d50100ac2380d58f3f6f756961fb1319d35f5248e5fa6cafb866ca657e5dda4a"
sys.path.insert(0, str(ROOT / "scripts/c2"))
import il_stage_trace as stage
import priority_trace as pt

stage.PRESETS["spill"] = (
    (0x1072FE4D, 0x10732216, "interfere", True, 5),
    (0x1072FE73, 0x10733230, "constrain", True, 6),
    (0x10732BBC, 0x107223D5, "pressure", False, 7),
    (0x1072FE5F, 0x10732F7C, "choose", False, 8),
    (0x10736A07, 0x10737AD8, "length", True, 9),
)
# Resolve the pressure call's target from its encoded call instead of relying on labels.
compiler = ROOT / "tools/match/compilers/msvc6.5/Bin/C2.DLL"
assert hashlib.sha256(compiler.read_bytes()).hexdigest() == C2_SHA
p = pefile.PE(str(compiler))
b = p.get_data(0x32BBC, 5)
assert b[0] == 0xE8
entry = stage.PRESETS["spill"][2]
stage.PRESETS["spill"] = (
    *stage.PRESETS["spill"][:2],
    (entry[0], entry[0] + 5 + struct.unpack("<i", b[1:])[0], *entry[2:]),
    *stage.PRESETS["spill"][3:],
)
base = stage.observer_source
extra = (
    pt.EXTRA.split("static void bump(void)")[0]
    + r"""
static unsigned long length_tuple;
static void tuple(unsigned long p) { s("T ");hx(p);s(" op=");hx(W(p,4)&0xffff);s(" line=");dec(*(unsigned short *)(p+0x10));s(" dst=");chain(W(p,0x1c));s(" src=");chain(W(p,0x18));s("\n"); }

static void clear_flag_split(unsigned long set) {
 unsigned long chunk,id=157;
 if(!set)return;
 for(chunk=W(set,0);chunk;chunk=W(chunk,4)) if(W(chunk,0)==(id&~31u) && (W(chunk,8)&(1u<<(id&31)))) {
  *(unsigned long *)(chunk+8) &= ~(1u<<(id&31));
  s("INTERVENE remove normal flag from pending split set\n");
 }
}
static void watch(void) {
 unsigned long b,lr,y;
 for(b=0;b<0x400;++b) for(lr=W(compiler_base+0x9d88c,b*4);lr;lr=W(lr,0x2c)) {
  y=W(lr,0);
  if(y && W(y,0x1c)==1708) {s("WATCH ");lrline(lr);s("FLAGS ");hx(W(lr,4));s("\n");}
 }
}
"""
)


def observer(mode):
    def patched(iv):
        make = base(iv)

        def source(prof):
            t = make(prof).replace("if (phase < 12) saved_function = r[6];", "if (phase < 8) saved_function = r[6];")
            t = t.replace("static void __cdecl observe(", extra + "static void __cdecl observe(", 1)
            t = t.replace(
                '    s("END\\n");\n    flush();\n}',
                r"""    if(modes[index]==5 || modes[index]==6) {
       if(phase<100)saved_lr = modes[index]==5 ? r[5] : r[10];
       if(ENABLE_SPLIT && modes[index]==5 && phase>=100 && W(saved_lr,0) && W(W(saved_lr,0),0x1c)==5640) clear_flag_split(r[7]);
       s("CURRENT ");lrline(saved_lr);watch();
     }
     if(ENABLE_INDEX && modes[index]==8 && phase<100 && W(W(r[6],0),0x1c)==333) {
       unsigned long pref;
       for(pref=W(r[6],0x34);pref;pref=W(pref,0)) if(W(W(pref,4),0x1c)==2) { *(long *)(pref+8)=0; s("INTERVENE clear index ECX preference\n"); }
     }
     if(modes[index]==9) {
       if(phase<100)length_tuple=r[6];
       else if((W(length_tuple,4)&0xffff)==0x86) {
         s("ANGLE_ESTIMATE ");dec(r[7]);s(" ");tuple(length_tuple);
         if(ENABLE_CLONE && *(unsigned short *)(length_tuple+0x10)==587) {
           s("INTERVENE forbid demo fpatan clone\n");r[7]=22;
         }
       }
     }
     if(modes[index]==7) {s("CURRENT ");lrline(saved_lr);s("AT ");tuple(r[6]);s("LIVE ");bits(r[5]);s("\n");watch();}
     s("END\n");
     flush();
 }""",
                1,
            )
            return (
                t.replace("ENABLE_SPLIT", str(int(mode in ("split", "all"))))
                .replace("ENABLE_INDEX", str(int(mode in ("index", "all"))))
                .replace("ENABLE_CLONE", str(int(mode in ("clone", "all"))))
            )

        return source

    return patched


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--mode", choices=("observe", "index", "split", "clone", "all"), default="observe")
    args = parser.parse_args()
    scratch = HERE / "baseline"
    assert hashlib.sha256((scratch / "scratch.cpp").read_bytes()).hexdigest() == SOURCE_SHA
    stage.observer_source = observer(args.mode)
    c2, iv = stage.load_modules()
    changed = False
    try:
        result = stage.trace(c2, iv, scratch, args.out, "spill")
        metrics = result["metrics"]
    except ValueError as error:
        if args.mode == "observe" or "Observation changed the whole COFF object" not in str(error):
            raise
        changed = True
        config = c2.match.load_scratch_config((args.out / "source").resolve())
        metrics = c2.replay.function_metrics(config, args.out / "observed/replay.obj")
    assert changed == (args.mode != "observe"), (args.mode, changed)
    if args.mode == "all":
        assert metrics["exact"] and metrics["body_byte_exact"]
    obj = bytearray((args.out / "observed/replay.obj").read_bytes())
    obj[4:8] = bytes(4)
    result = {
        "kind": "preserving-c2-observation" if args.mode == "observe" else "diagnostic-c2-intervention",
        "mode": args.mode,
        "matching_credit": False,
        "source_sha256": SOURCE_SHA,
        "compiler_sha256": C2_SHA,
        "compiler_decisions_modified": changed,
        "normalized_coff_sha256": hashlib.sha256(obj).hexdigest(),
        "probe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "diagnostic_metrics": metrics,
    }
    (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
