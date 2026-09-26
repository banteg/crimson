"""Compare a scratch with its native target by frame-bottom offsets instead of raw esp displacements (diagnostic only).

`residual_map.py`'s `stack` class says that a line differs only in an `[esp+N]` displacement. That covers two
different things: the same object reached at another push depth, and an object that lives in another slot. This
tool tracks esp through both listings (`frame_predict.binary_frames`), rewrites every `[esp+N]` operand as
`[B+off]`, where `off` is the offset from the bottom of the local frame (the lowest local byte), and then:

- prints the four `residual_map` ratios plus a `bottom` ratio: structural (labels and eax/ecx/edx masked) with the
  bottom offsets in place of the displacements. A push-depth difference pairs under `bottom`; a slot difference
  does not;
- with `--pairs`, lists every (native bottom, candidate bottom) pair taken from lines that are equal under the
  stack mask, with a count and the first native addresses. Unequal pairs are the slot differences, grouped by the
  object that should move;
- with `--dump FILE`, writes the structural diff with bottom offsets (`-` native, `+` candidate, two spaces for
  equal lines), each line prefixed with its address, for reading a region by native address.

    uv run python scripts/c2/frame_bottom_diff.py <scratch-dir> [--pairs] [--dump out.txt]

See tools/match/c2/compiler/pu-residual-map.md.
"""

from __future__ import annotations

import argparse
import difflib
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import frame_predict as fp
import residual_map as rm

from crimson import match as m

ESP = re.compile(r"\besp\+0x[0-9a-f]+\]|\besp\]")
BOTTOM = re.compile(r"B\+(0x[0-9a-f]+)")


def rewrite(lines, disassembly, frame: dict) -> list[str]:
    """Replace each esp operand of a line by its bottom offset, in operand order."""
    offsets = defaultdict(list)
    for address, offset, _text in frame["refs"]:
        offsets[address].append(offset + frame["frame_size"])
    out = []
    for line, insn in zip(lines, disassembly, strict=True):
        queue = list(offsets.get(insn.address, ()))

        def repl(match: re.Match, queue: list[int] = queue) -> str:
            return f"B+{queue.pop(0):#x}]" if queue else match.group(0)

        out.append(ESP.sub(repl, line))
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", type=Path)
    parser.add_argument("--pairs", action="store_true", help="list (native bottom, candidate bottom) pairs")
    parser.add_argument("--dump", type=Path, help="write the bottom-offset structural diff")
    args = parser.parse_args()
    result = rm.build(args.scratch)
    config = m.load_scratch_config(args.scratch)
    frames = fp.binary_frames(config, m.compile_scratch(config, m.DEFAULT_MATCH_ROOT.resolve()))
    target = rewrite(result.target_lines, result.target_disassembly, frames["target"])
    candidate = rewrite(result.candidate_lines, result.candidate_disassembly, frames["candidate"])
    a = [rm.mask(x, "structural") for x in target]
    b = [rm.mask(x, "structural") for x in candidate]
    matcher = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    scores = rm.ratios(result)
    print(" ".join(f"{k} {v:.2%}" for k, v in scores.items()), f"bottom {matcher.ratio():.2%}")
    if args.dump:
        tdis, cdis = result.target_disassembly, result.candidate_disassembly
        with args.dump.open("w") as out:
            for tag, i1, i2, j1, j2 in matcher.get_opcodes():
                if tag == "equal":
                    out.writelines(f"  {tdis[i].address:08x}  {target[i]}\n" for i in range(i1, i2))
                    continue
                out.writelines(f"- {tdis[i].address:08x}  {target[i]}\n" for i in range(i1, i2))
                out.writelines(f"+ {cdis[j].address:08x}  {candidate[j]}\n" for j in range(j1, j2))
    if args.pairs:
        sa = [rm.mask(x, "stack") for x in result.target_lines]
        sb = [rm.mask(x, "stack") for x in result.candidate_lines]
        pairs: dict[tuple[int, int], list[int]] = defaultdict(list)
        for block in difflib.SequenceMatcher(a=sa, b=sb, autojunk=False).get_matching_blocks():
            for k in range(block.size):
                i, j = block.a + k, block.b + k
                for x, y in zip(BOTTOM.findall(target[i]), BOTTOM.findall(candidate[j]), strict=False):
                    pairs[(int(x, 16), int(y, 16))].append(result.target_disassembly[i].address)
        for (x, y), where in sorted(pairs.items(), key=lambda kv: (kv[0][0] == kv[0][1], -len(kv[1]))):
            mark = "" if x == y else "  <>"
            first = " ".join(f"{w:08x}" for w in where[:4])
            print(f"  native {x:#06x} candidate {y:#06x}  {len(where):4d}{mark}  {first}")


if __name__ == "__main__":
    main()
