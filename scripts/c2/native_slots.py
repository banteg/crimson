"""Map native stack slots to the candidate's stack objects (VC6 C2 frame layout).

Compiles a scratch through `frame_predict.py`'s preserving observer (stack objects, weights,
interference, offsets) and through a `/FAsc` listing (which candidate object every `[esp+N]`
operand names), aligns candidate and native instructions, and turns each aligned frame reference
into a vote "candidate object X lives at native bottom offset B". It then prints:

- the native slot partition: every native object base, the candidate objects mapped to it, their
  candidate offsets and weights, and the candidate interference edges that forbid the grouping;
- native frame references that no candidate object explains (objects the candidate lacks);
- the packer replay in the compiler's list order, flagging each placement whose slot mates live
  in different native slots (the first flagged line is usually the one to fix).

    uv run python scripts/c2/native_slots.py tools/match/scratches/<name> --out /tmp/<new-dir>
    uv run python scripts/c2/native_slots.py <scratch> --out <dir> --source variant.cpp [--json out.json]

Offsets are bottom-relative (esp after the callee-saved pushes, before argument pushes). Diagnostic
only; see tools/match/c2/compiler/native-slot-partition.md.
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import capstone
import frame_predict as fp

from crimson import match
from crimson.match_listing_diagnostics import parse_stack_listing

STACK_OPERAND = re.compile(r"([^\s,\[\]]*)\[esp(?:\+(\d+))?\]", re.IGNORECASE)


def norm(insn) -> str:
    text = f"{insn.mnemonic} {insn.op_str}"
    text = re.sub(r"\[esp(?: \+ [0-9a-fx]+)?\]", "[S]", text)
    text = re.sub(r"0x[0-9a-f]{5,}", "A", text)
    if insn.mnemonic.startswith("j") or insn.mnemonic == "call":
        text = re.sub(r"0x[0-9a-f]+", "L", text)
    return text


def object_names(fr: fp.Frame, declarations: dict[str, int]) -> dict[int, str]:
    """Observer object -> listing alias (`_name$id`, `$Tnnnn`) or `anon@<offset>@<lines>`."""
    names = {}
    for o in fr.objects:
        if o.cls == 5:
            names[o.ptr] = f"{o.name}$"
            continue
        if o.name and f"{o.name}${o.fe_id}" in declarations:
            names[o.ptr] = f"{o.name}${o.fe_id}"
        elif o.name and f"{o.name}$" in declarations:
            names[o.ptr] = f"{o.name}$"
        elif f"$T{o.fe_id}" in declarations:
            names[o.ptr] = f"$T{o.fe_id}"
        else:
            lines = sorted({r["line"] for r in o.refs})
            names[o.ptr] = f"anon@{o.offset}@{','.join(map(str, lines[:3]))}"
    return names


def listing_operands(rows, declarations):
    """Candidate code offset -> list of (alias or None, anon offset or None) per esp operand."""
    result = {}
    for off, row in rows.items():
        ops = []
        for m in STACK_OPERAND.finditer(row.assembly):
            prefix = m.group(1).removesuffix("+").removeprefix("DWORD").removeprefix("QWORD")
            prefix = prefix.split("PTR")[-1].strip()
            if not prefix:
                ops.append((None, None))
            elif re.fullmatch(r"-?\d+", prefix):
                ops.append((None, int(prefix)))
            else:
                alias = next((d for d in declarations if prefix == d or prefix.startswith(d + "+")), None)
                ops.append((alias, None))
        result[off] = (ops, row.source_lines)
    return result


def analyze(fr: fp.Frame, config, object_path: Path, listing_text: str) -> dict:
    declarations, rows = parse_stack_listing(listing_text, symbol=config.symbol or config.function)
    names = object_names(fr, declarations)
    by_alias = {names[o.ptr]: o for o in fr.objects}
    first_line = min((ln for r in rows.values() for ln in r.source_lines), default=2)
    line_bias = first_line - 2  # observer line = source line - (function start - 1); see the note
    frames = fp.binary_frames(config, object_path)
    tf, cf = frames["target"]["frame_size"], frames["candidate"]["frame_size"]
    tref, cref = defaultdict(list), defaultdict(list)
    for a, off, _ in frames["target"]["refs"]:
        if -tf <= off < 0:
            tref[a].append(off + tf)
    for a, off, _ in frames["candidate"]["refs"]:
        if -cf <= off < 0:
            cref[a].append(off + cf)
    manifest = match.load_function_manifest(
        match.default_functions_path(config.image),
        metadata_path=match.default_metadata_path(config.image),
        image_name=match.default_image_path(config.image).name,
    )
    _, start, end = match.resolve_function(manifest, config.function, end_override=config.end_va)
    image = match.load_image(match.default_image_path(config.image), manifest.image_base)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    tins = list(md.disasm(image.function_bytes(start, end), start))
    cand = match.extract_object_function(match.parse_coff_object(object_path.read_bytes()), config.symbol)
    cins = list(md.disasm(cand.data, 0))
    ops = listing_operands(rows, declarations)
    t2c = {}
    sm = difflib.SequenceMatcher(None, [norm(i) for i in tins], [norm(i) for i in cins], autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal" or (tag == "replace" and i2 - i1 == j2 - j1):
            for k in range(i2 - i1):
                t2c[tins[i1 + k].address] = cins[j1 + k].address
    bottom = {o.ptr: o.offset + cf for o in fr.objects if o.cls != 5}
    votes: dict[int, Counter] = defaultdict(Counter)
    unexplained = []
    for insn in tins:
        if insn.address not in tref:
            continue
        ca = t2c.get(insn.address)
        crs = cref.get(ca, []) if ca is not None else []
        listing = ops.get(ca, ([], ()))
        if ca is None or len(crs) != len(tref[insn.address]) or len(listing[0]) != len(crs):
            unexplained.extend((insn.address, tb, f"{insn.mnemonic} {insn.op_str}") for tb in tref[insn.address])
            continue
        for tb, cb, (alias, _anon) in zip(tref[insn.address], crs, listing[0], strict=True):
            if alias is not None and alias in by_alias:
                owners = [by_alias[alias]]
            else:
                lines = {ln - line_bias for ln in listing[1]}
                owners = [o for o in fr.objects if o.ptr in bottom and bottom[o.ptr] <= cb < bottom[o.ptr] + o.size]
                if len(owners) > 1:
                    owners = [o for o in owners if {r["line"] for r in o.refs} & lines] or owners
            if len(owners) != 1:
                unexplained.append((insn.address, tb, f"{insn.mnemonic} {insn.op_str}"))
                continue
            o = owners[0]
            votes[o.ptr][tb - (cb - bottom[o.ptr])] += 1
    native = {p: v.most_common(1)[0][0] for p, v in votes.items()}
    return {
        "names": names,
        "native": native,
        "votes": votes,
        "unexplained": unexplained,
        "bottom": bottom,
        "tf": tf,
        "cf": cf,
    }


def report(fr: fp.Frame, res: dict) -> dict:
    names, native, bottom = res["names"], res["native"], res["bottom"]
    objs = {o.ptr: o for o in fr.objects}
    fobjs = fp.frame_objects(fr)
    keys = {o["key"] for o in fobjs}
    interf = {o["key"]: (keys - {o["key"]}) if o["all_conflict"] else o["interf"] for o in fobjs}

    def conflict(a: int, b: int) -> bool:
        return b in interf.get(a, ()) or a in interf.get(b, ())

    groups: dict[int, list[int]] = defaultdict(list)
    for p, b in native.items():
        groups[b].append(p)
    print(f"native frame {res['tf']:#x}, candidate frame {res['cf']:#x}")
    print("native base  size  members (candidate bottom, weight, native votes)  [conflicts inside the group]")
    same = 0
    rows = []
    extent = {}
    for b in sorted(groups):
        extent[b] = b + max(objs[p].size for p in groups[b])
    for b in sorted(groups):
        mem = sorted(groups[b], key=lambda p: -objs[p].weight)
        size = max(objs[p].size for p in mem)
        bad = [(names[a], names[c]) for i, a in enumerate(mem) for c in mem[i + 1 :] if conflict(a, c)]
        same += sum(bottom[p] == b for p in mem)
        desc = ", ".join(f"{names[p]}({bottom[p]:#x},w{objs[p].weight},n{sum(res['votes'][p].values())})" for p in mem)
        conf = f"  [{'; '.join(f'{a} x {c}' for a, c in bad)}]" if bad else ""
        outer = next((a for a in sorted(groups) if a < b < extent[a]), None)
        inside = f"  (field +{b - outer} of the native object at {outer:#x})" if outer is not None else ""
        print(f"  {b:#06x}  {size:>4}  {desc}{conf}{inside}")
        rows.append({"native": b, "size": size, "members": [names[p] for p in mem], "conflicts": bad})
    print(f"objects at their native offset: {same}/{len(native)}")
    if res["unexplained"]:
        print("native frame references with no candidate object:")
        for a, tb, text in res["unexplained"]:
            print(f"  {a:#x} bottom {tb:#06x}  {text}")
    print("packer replay in list order (<< = slot mates live in different native slots):")
    slots: list[list[int]] = []
    sizes: list[int] = []
    for o in fobjs:
        if o["cls"] == 5:
            continue
        k = o["key"]
        hit = next(
            (
                i
                for i in range(len(slots) - 1, -1, -1)
                if o["size"] <= 2 * sizes[i] and not any(conflict(k, m) for m in slots[i])
            ),
            None,
        )
        if hit is None:
            slots.append([k])
            sizes.append(o["size"])
            hit, act = len(slots) - 1, "new "
        else:
            slots[hit].append(k)
            sizes[hit] = max(sizes[hit], o["size"])
            act = "join"
        mates = [m for m in slots[hit] if m != k and m in native]
        flag = k in native and any(native[m] != native[k] for m in mates)
        if flag:
            nb = native[k]
            print(
                f"  << {names[k]} w{o['weight']} {act} slot {hit} (native {nb:#x}) with "
                + ", ".join(f"{names[m]}@{native[m]:#x}" for m in mates[:4]),
            )
    return {"groups": rows, "at_native_offset": same, "mapped": len(native)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", type=Path)
    parser.add_argument("--out", type=Path, required=True, help="new work directory")
    parser.add_argument("--source", type=Path, help="compile this source instead of the scratch's own")
    parser.add_argument("--json", type=Path, help="write the partition as JSON")
    args = parser.parse_args()
    frames, info = fp.capture_and_observe(args.scratch, args.out, args.source)
    config = info["config"]
    fr = next(f for f in frames if (config.symbol or config.function) in f.name)
    frozen = replace(config, directory=args.out.resolve() / "source")
    listing = match.generate_compiler_listing(frozen, output=args.out.resolve() / "listing.cod")
    text = listing.listing_path.read_bytes().decode("latin1")
    res = analyze(fr, frozen, Path(info["object"]), text)
    out = report(fr, res)
    m = info["metrics"]
    if m:
        print(f"metrics: {m['ratio'] * 100:.4f}% refs {m['references_ok']}/{m['reference_problems']}")
    if args.json:
        args.json.write_text(json.dumps(out, indent=1) + "\n")


if __name__ == "__main__":
    main()
