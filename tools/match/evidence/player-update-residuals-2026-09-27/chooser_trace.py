"""Preserving trace of the pinned player_update register preferences and chooser costs."""

import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(ROOT / "scripts/c2"))
import il_stage_trace as stage
import priority_trace as priority

stage.PRESETS["chooser"] = (
    (0x1072FE5F, 0x10732F7C, "choose", True, 5),
    (0x1073321A, 0x107257E9, "propagate", False, 6),
)
EXTRA = (
    priority.EXTRA.split("static void bump(void)")[0]
    + r"""
static void prefs(unsigned long lr)
{
 unsigned long p;
 lrline(lr);
 s("PREF");
 for(p=W(lr,0x34);p;p=W(p,0)) {
  s(" "); dec(W(W(p,4),0x1c)); s("="); dec((long)W(p,8));
 }
 s("\n");
}
static unsigned long range_by_id(unsigned long id)
{
 unsigned long b,lr;
 for(b=0;b<0x400;++b)
  for(lr=W(compiler_base+0x9d88c,b*4);lr;lr=W(lr,0x2c))
   if(W(lr,0x1c)==id)return lr;
 return 0;
}
static void neighbours(unsigned long set)
{
 unsigned long chunk,b,lr;
 if(!set)return;
 for(chunk=W(set,0);chunk;chunk=W(chunk,4))
  for(b=0;b<32;++b)if(W(chunk,8)&(1u<<b)) {
   lr=range_by_id(W(chunk,0)+b);
   if(lr && (long)W(lr,0x3c)>0){s("NEIGH ");prefs(lr);}
  }
}
"""
)
base = stage.observer_source


def observer(iv):
    make = base(iv)

    def source(prof):
        t = make(prof).replace("if (phase < 12) saved_function = r[6];", "if (phase < 8) saved_function = r[6];")
        t = t.replace("static void __cdecl observe(", EXTRA + "static void __cdecl observe(", 1)
        t = t.replace(
            '    s("END\\n");\n    flush();\n}',
            r"""    if(modes[index]==5) {
      if(phase<100) { saved_lr=r[6]; prefs(saved_lr); neighbours(r[10]); }
      else { s("RESULT ");prefs(saved_lr);s("COST");for(i=0;i<9;++i){s(" ");dec(i);s("=");dec((long)W(compiler_base+0x9d868,4*i));}s("\n"); }
    }
    if(modes[index]==6) {s("FROM ");lrline(saved_lr);s("TO ");prefs(r[6]);s("REG ");dec(W(r[5],0x1c));s("\n");}
    s("END\n");
    flush();
}""",
            1,
        )
        return t

    return source


stage.observer_source = observer
c2, iv = stage.load_modules()
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--out", type=Path, required=True)
args = parser.parse_args()
scratch = HERE / "baseline"
assert (
    hashlib.sha256((scratch / "scratch.cpp").read_bytes()).hexdigest()
    == "32acad8ac4ebfa7c6af8f1cff460357473135696ed0c91435ba3493973efcd1c"
)
r = stage.trace(c2, iv, scratch, args.out, "chooser")
print(json.dumps(r["metrics"]))
