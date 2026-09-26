"""What-if replay of the VC6 C2 stack packer against the native slot partition (diagnostic only).

Compiles a scratch through `native_slots.py` (the preserving observer of `frame_predict.py` plus a `/FAsc`
listing), maps every candidate stack object to its native base, and then replays `order_stack_object`
(0x1073c7e4) and `pack_stack_slots` (0x1074b617) after source-free edits:

- `--weight NAME=W` sets an object's reference count. Surplus references are dropped from the end of its
  walk; missing ones are repeated right after its last reference, so ties are broken as if the extra
  references came last.
- `--conflict A,B` adds an interference edge (a liveness change).
- `--add NAME:W:LIKE:AFTER` adds a 4-byte class-3 object of weight W (a spill home) that conflicts with
  everything LIKE conflicts with, and with LIKE; its references sit right after the first W references of
  AFTER. Its native base is taken from `--add-native` (default: unmapped).

It prints the frame size, how many mapped objects sit at their native bottom offset, and the replayed slots
with each member's weight and native base. Names are `native_slots.py` names (`_along$4702`, `$T4977`,
`anon@<offset>@<lines>`); a unique prefix is enough.

    uv run python scripts/c2/frame_whatif.py <scratch> --out <new-dir> [--source v.cpp] --weight '_half_size$4649=12'
    uv run python scripts/c2/frame_whatif.py --reuse <dir> --weight ... --conflict '_point3$4429,_half_width$4399'

`--reuse` replays an existing `--out` directory without compiling again. See
tools/match/c2/compiler/pr-spill-order.md.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import frame_predict as fp
import native_slots as ns

from crimson import match


def load(args: argparse.Namespace) -> tuple[fp.Frame, dict[int, str], dict[int, int]]:
    out = (args.reuse or args.out).resolve()
    cache = out / "whatif.json"
    if args.reuse:
        frames = fp.decode((out / "observed" / "frame.bin").read_bytes())
        data = json.loads(cache.read_text())
        fr = next(f for f in frames if f.name == data["frame"])
        return fr, {int(k): v for k, v in data["names"].items()}, {int(k): v for k, v in data["native"].items()}
    frames, info = fp.capture_and_observe(args.scratch, out, args.source)
    config = info["config"]
    fr = next(f for f in frames if (config.symbol or config.function) in f.name)
    frozen = replace(config, directory=out / "source")
    listing = match.generate_compiler_listing(frozen, output=out / "listing.cod")
    res = ns.analyze(fr, frozen, Path(info["object"]), listing.listing_path.read_bytes().decode("latin1"))
    cache.write_text(json.dumps({"frame": fr.name, "names": res["names"], "native": res["native"]}))
    return fr, res["names"], res["native"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", type=Path, nargs="?")
    parser.add_argument("--out", type=Path, help="new work directory")
    parser.add_argument("--reuse", type=Path, help="replay an existing --out directory")
    parser.add_argument("--source", type=Path, help="compile this source instead of the scratch's own")
    parser.add_argument("--weight", action="append", default=[], metavar="NAME=W")
    parser.add_argument("--conflict", action="append", default=[], metavar="A,B")
    parser.add_argument("--add", action="append", default=[], metavar="NAME:W:LIKE:AFTER")
    parser.add_argument("--add-native", type=lambda v: int(v, 0), help="native base of the --add objects")
    parser.add_argument("--size", type=int, help="print only slots of this size")
    args = parser.parse_args()
    if not args.reuse and not (args.scratch and args.out):
        parser.error("give a scratch and --out, or --reuse")
    fr, names, native = load(args)

    objs = {o["key"]: o for o in fp.frame_objects(fr)}

    def find(name: str) -> int:
        hits = [k for k, v in names.items() if v == name] or [k for k, v in names.items() if v.startswith(name)]
        if len(hits) != 1:
            raise SystemExit(f"{name!r} matches {[names[h] for h in hits]}")
        return hits[0]

    size_of = {k: o["size"] for k, o in objs.items()}
    walk = [r["obj"] for r in fr.refs if r["obj"] in size_of]
    for spec in args.weight:
        name, weight = spec.rsplit("=", 1)
        key, weight = find(name), int(weight)
        at = [i for i, k in enumerate(walk) if k == key]
        if weight < len(at):
            drop = set(at[weight:])
            walk = [k for i, k in enumerate(walk) if i not in drop]
        else:
            walk[at[-1] + 1 : at[-1] + 1] = [key] * (weight - len(at))
    for spec in args.conflict:
        a, b = (find(n) for n in spec.split(","))
        objs[a]["interf"].add(b)
        objs[b]["interf"].add(a)
    for n, spec in enumerate(args.add, start=1):
        name, weight, like, after = spec.split(":")
        key, like, after = -n, find(like), find(after)
        objs[key] = {
            "key": key,
            "cls": 3,
            "size": 4,
            "weight": 0,
            "type": 0x1004,
            "interf": set(objs[like]["interf"]) | {like},
            "all_conflict": False,
            "param_offset": 0,
        }
        for o in objs.values():
            if like in o["interf"] and o["key"] != key:
                o["interf"].add(key)
        size_of[key] = 4
        names[key] = name
        if args.add_native is not None:
            native[key] = args.add_native
        at = [i for i, k in enumerate(walk) if k == after][: int(weight)]
        for i in reversed(at):
            walk.insert(i + 1, key)

    listed = []
    for key, weight in fp.ref_order([(k, size_of[k], 1) for k in walk]):
        o = dict(objs[key])
        o["weight"] = weight
        listed.append(o)
    sim = fp.simulate(
        listed,
        fpo=bool(fr.flags & 0x10 or fr.flags & 0x600000),
        param_reuse=not (fr.flags & 0x40 or fr.flags & 0x600000),
        aligned=bool(fr.flags & 0x600000),
    )
    frame = (-sim["cursor"] + 3) & ~3
    bottom = {k: off + frame for k, off in sim["offsets"].items()}
    same = sum(1 for k, b in native.items() if bottom.get(k) == b)
    print(f"frame={frame:#x} objects at their native offset: {same}/{len(native)}")
    for s in sim["slots"][sim["nparam"] :]:
        if args.size and s["size"] != args.size:
            continue
        members = ", ".join(
            f"{names[m['key']]}(w{m['weight']}, native {native[m['key']]:#x})"
            if m["key"] in native
            else f"{names[m['key']]}(w{m['weight']})"
            for m in s["members"]
        )
        print(f"  {s['final'] + frame:#06x} size {s['size']} weight {s['weight']}: {members}")


if __name__ == "__main__":
    main()
