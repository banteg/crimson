"""Map a scratch's residual diff into regions and say what separates each one (diagnostic only; no match credit).

`crimson match` scores normalized lines with difflib. This tool scores the same listings under four masks and
then walks the labels-masked diff region by region:

- raw: the normalized lines as scored;
- labels: local branch labels masked (`jne L`), so label drift is gone;
- structural: labels plus the caller-saved registers eax/ecx/edx (`crimson match --structural`);
- stack: structural plus ESP displacements (`structural_stack_masked`).

Every labels-masked region (a run of non-equal opcodes, merged across short equal runs) is re-diffed locally
under each further mask, and each of its target lines is charged to the first mask that pairs it:

- `scratch-reg`: it pairs once eax/ecx/edx are masked;
- `stack`: it pairs once ESP displacements are masked (which object owns the slot, or the same instruction at
  another push depth; a swap of two `[esp+x]` operands also lands here);
- `saved-reg`: it pairs once every general register is masked (ebx/esi/edi/ebp choice);
- `order`: the fully masked line exists on the other side of the region, in another position;
- `moved`: the fully masked line is an unused candidate line of another region within `--window` lines
  (a block kept in another place, such as the other copy of a cross-jumped tail);
- `branch`: an unpaired jmp/jcc (branch sense or block layout);
- `code`: none of the above (a different instruction).

It prints the four ratios, the reference audit, and the regions with target address ranges, the counts per
class, and (with `--show`) the target and candidate lines side by side.

    uv run python scripts/c2/residual_map.py <scratch-dir> [--merge 2] [--window 64] [--show] [--json out.json]

See tools/match/c2/compiler/pr-residual-map.md.
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
from collections import Counter
from pathlib import Path

from crimson import match as m

LABEL = re.compile(r"\bL[0-9a-f]+\b")
STACK = re.compile(r"\besp\+0x[0-9a-f]+\b")
SCRATCH = (
    (re.compile(r"\b(?:eax|ecx|edx)\b"), "T"),
    (re.compile(r"\b(?:ax|cx|dx)\b"), "Tw"),
    (re.compile(r"\b(?:al|cl|dl|ah|ch|dh)\b"), "Tb"),
)
SAVED = re.compile(r"\b(?:ebx|esi|edi|ebp)\b")
LEVELS = ("raw", "labels", "structural", "stack")


def mask(line: str, level: str) -> str:
    if level == "raw":
        return line
    line = LABEL.sub("L", line)
    if level == "labels":
        return line
    for pattern, repl in SCRATCH:
        line = pattern.sub(repl, line)
    if level == "structural":
        return line
    line = STACK.sub("esp+S", line)
    if level == "stack":
        return line
    return SAVED.sub("R", line)


def build(directory: Path) -> m.MatchResult:
    config = m.load_scratch_config(directory)
    image_path, functions_path, metadata_path = m._paths_for_image(config.image)
    obj_path = m.compile_scratch(config, m.DEFAULT_MATCH_ROOT.resolve())
    return m.run_match(
        obj_path=obj_path,
        function=config.function,
        image_path=image_path,
        functions_path=functions_path,
        metadata_path=metadata_path,
        symbol_name=config.symbol,
        object_extent=config.archive_extent,
        object_end_symbol=config.archive_end_symbol,
        object_size=config.archive_size,
        end_va=config.end_va,
        reference_aliases=config.reference_aliases,
    )


def ratios(result: m.MatchResult) -> dict[str, float]:
    out = {}
    for level in LEVELS:
        a = [mask(x, level) for x in result.target_lines]
        b = [mask(x, level) for x in result.candidate_lines]
        out[level] = difflib.SequenceMatcher(a=a, b=b, autojunk=False).ratio()
    return out


def regions(result: m.MatchResult, merge: int) -> list[tuple[int, int, int, int]]:
    a = [mask(x, "labels") for x in result.target_lines]
    b = [mask(x, "labels") for x in result.candidate_lines]
    out: list[list[int]] = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(a=a, b=b, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        if out and i1 - out[-1][1] <= merge and j1 - out[-1][3] <= merge:
            out[-1][1], out[-1][3] = i2, j2
        else:
            out.append([i1, i2, j1, j2])
    return [tuple(r) for r in out]


def classify(target: list[str], candidate: list[str]) -> tuple[list[str], list[int]]:
    """Charge each target line of a region to the first mask that pairs it; also return unused candidate lines."""
    kinds = [""] * len(target)
    left_t = list(range(len(target)))
    left_c = list(range(len(candidate)))
    for level, name in (("labels", ""), ("structural", "scratch-reg"), ("stack", "stack"), ("all", "saved-reg")):
        a = [mask(target[i], level) for i in left_t]
        b = [mask(candidate[j], level) for j in left_c]
        paired_t, paired_c = set(), set()
        for blk in difflib.SequenceMatcher(a=a, b=b, autojunk=False).get_matching_blocks():
            for k in range(blk.size):
                paired_t.add(left_t[blk.a + k])
                paired_c.add(left_c[blk.b + k])
                kinds[left_t[blk.a + k]] = name or "label"
        left_t = [i for i in left_t if i not in paired_t]
        left_c = [j for j in left_c if j not in paired_c]
    for i in left_t:
        key = mask(target[i], "all")
        j = next((j for j in left_c if mask(candidate[j], "all") == key), None)
        if j is not None:
            left_c.remove(j)
            kinds[i] = "order"
        elif target[i].split()[0].startswith("j"):
            kinds[i] = "branch"
        else:
            kinds[i] = "code"
    return kinds, left_c


def mark_moved(result: m.MatchResult, found: list[tuple], window: int) -> None:
    """Re-charge `code`/`branch` target lines whose masked text is an unused candidate line of a nearby region."""
    unused = {j for *_, spare in found for j in spare}
    for i1, _i2, j1, _j2, kinds, _spare in found:
        for k, kind in enumerate(kinds):
            if kind not in ("code", "branch"):
                continue
            key = mask(result.target_lines[i1 + k], "all")
            near = sorted(unused, key=lambda j: abs(j - (j1 + k)))
            j = next(
                (j for j in near if abs(j - (j1 + k)) <= window and mask(result.candidate_lines[j], "all") == key),
                None,
            )
            if j is not None:
                unused.discard(j)
                kinds[k] = "moved"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", type=Path)
    parser.add_argument("--merge", type=int, default=2, help="merge regions separated by at most this many lines")
    parser.add_argument("--window", type=int, default=64, help="how far a moved line may travel (lines)")
    parser.add_argument("--show", action="store_true", help="print the lines of every region")
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    result = build(args.scratch)
    scores = ratios(result)
    audit = result.masked_operand_audit
    frame = next((x for x in result.target_lines if x.startswith("sub esp")), "?")
    cframe = next((x for x in result.candidate_lines if x.startswith("sub esp")), "?")
    print(
        f"raw {scores['raw']:.2%}  labels {scores['labels']:.2%}  structural {scores['structural']:.2%}  "
        f"stack {scores['stack']:.2%}  refs {audit.ok_count}/{audit.unresolved_count}/{audit.mismatch_count}  "
        f"insns {len(result.target_lines)}/{len(result.candidate_lines)}  frame {frame!r} vs {cframe!r}",
    )
    for entry in audit.entries:
        if entry.status != "ok":
            print(f"  ref {entry.status} {entry.target_address:08x}  {entry.instruction}")
    tdis, _cdis = result.target_disassembly, result.candidate_disassembly
    rows = []
    totals: Counter[str] = Counter()
    found = []
    for i1, i2, j1, j2 in regions(result, args.merge):
        kinds, spare = classify(list(result.target_lines[i1:i2]), list(result.candidate_lines[j1:j2]))
        found.append((i1, i2, j1, j2, kinds, [j1 + j for j in spare]))
    mark_moved(result, found, args.window)
    for i1, i2, j1, j2, kinds, _spare in found:
        t, c = list(result.target_lines[i1:i2]), list(result.candidate_lines[j1:j2])
        count = Counter(k for k in kinds if k != "label")
        totals.update(count)
        lo = tdis[i1].address if i1 < len(tdis) else tdis[-1].address
        hi = tdis[i2 - 1].address if i2 > i1 else lo
        row = {"target": [f"{lo:08x}", f"{hi:08x}"], "lines": [i1, i2, j1, j2], "kinds": dict(count)}
        rows.append(row)
        summary = " ".join(f"{k}={v}" for k, v in sorted(count.items()))
        print(f"{lo:08x}..{hi:08x}  t{i1}+{i2 - i1} c{j1}+{j2 - j1}  {summary}")
        if args.show:
            for line in difflib.ndiff(t, c):
                if not line.startswith("?"):
                    print(f"    {line}")
    print("totals: " + " ".join(f"{k}={v}" for k, v in sorted(totals.items())))
    if args.json:
        args.json.write_text(
            json.dumps(
                {
                    "scores": scores,
                    "refs": [audit.ok_count, audit.unresolved_count, audit.mismatch_count],
                    "regions": rows,
                },
                indent=1,
            ),
        )


if __name__ == "__main__":
    main()
