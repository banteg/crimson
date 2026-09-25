"""Show why a stack object lands in its frame slot (VC6 C2 `pack_stack_slots` 0x1074b617).

Compiles a scratch through `frame_predict.py`'s observer, then replays the local-slot packer in list
order. For every object whose name matches the pattern it prints each slot scanned (newest first),
whether the size rule (`size <= 2 * slot size`) passes, and which slot members conflict in either
direction. The first slot with no conflict is joined; otherwise a new slot is created. Use it to see
what a new aggregate must not interfere with to share a slot instead of growing the frame.

    uv run python scripts/c2/slot_scan.py <scratch-dir> --out <new-dir> --match '_turn|_previous_pos'
    uv run python scripts/c2/slot_scan.py <scratch-dir> --out <new-dir> --match _turn --source variant.cpp

Diagnostic only. Parameter slots, dead-parameter reuse, the 0x70 repack and the density sort are not
replayed; `frame_predict.py` does that and checks every offset. See
tools/match/c2/compiler/per-arm-frame-weights.md.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import frame_predict as fp


def scan(fr: fp.Frame, pattern: re.Pattern[str]) -> list[dict]:
    objs = fp.frame_objects(fr)
    name = {o.ptr: o.name for o in fr.objects}
    keys = {o["key"] for o in objs}
    interf = {o["key"]: (keys - {o["key"]}) if o["all_conflict"] else o["interf"] for o in objs}
    slots: list[dict] = []
    for o in objs:
        if o["cls"] == 5:
            continue
        watch = bool(pattern.search(name[o["key"]]))
        label = f"{name[o['key']] or '(temp)'} size={o['size']} weight={o['weight']}"
        chosen = None
        for si in range(len(slots) - 1, -1, -1):
            s = slots[si]
            size_ok = o["size"] <= 2 * s["size"]
            bad = [
                name[m["key"]] or "(temp)"
                for m in s["members"]
                if m["key"] in interf[o["key"]] or o["key"] in interf[m["key"]]
            ]
            if watch:
                more = "..." if len(bad) > 6 else ""
                print(f"  {label}: slot {si} size={s['size']} size_ok={size_ok} conflicts={bad[:6]}{more}")
            if size_ok and not bad:
                chosen = si
                break
        if chosen is None:
            slots.append({"members": [o], "size": o["size"]})
            if watch:
                print(f"  -> {label}: new slot {len(slots) - 1}")
        else:
            s = slots[chosen]
            grew = max(0, o["size"] - s["size"])
            s["members"].append(o)
            s["size"] = max(s["size"], o["size"])
            if watch:
                print(f"  -> {label}: joins slot {chosen} (grows by {grew})")
    return [{"size": s["size"], "members": [name[m["key"]] or "(temp)" for m in s["members"]]} for s in slots]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("scratch", type=Path)
    ap.add_argument("--out", type=Path, required=True, help="new work directory")
    ap.add_argument("--match", default="", help="regex of object names to trace (e.g. '_turn')")
    ap.add_argument("--source", type=Path, help="compile this source instead of the scratch's own")
    ap.add_argument("--function", default="", help="C2 function name (default: the only or scratch function)")
    args = ap.parse_args()
    frames, _ = fp.capture_and_observe(args.scratch, args.out, args.source)
    fr = next((f for f in frames if not args.function or f.name == args.function), None)
    if fr is None:
        raise SystemExit(f"function not found: {args.function}")
    slots = scan(fr, re.compile(args.match) if args.match else re.compile(r"(?!)"))
    print(f"{fr.name}: local bytes {sum(s['size'] for s in slots):#x}")
    for i, s in enumerate(slots):
        print(
            f"  [{i:2}] size={s['size']:>3}  {', '.join(s['members'][:10])}{' ...' if len(s['members']) > 10 else ''}",
        )


if __name__ == "__main__":
    main()
