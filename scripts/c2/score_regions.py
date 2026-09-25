"""Explain a whole-function score change between two built scratches (diagnostic only; no match credit).

The scorer is `difflib.SequenceMatcher` over the normalized listing text, and a branch line carries its
target as a function-relative label (`jne L11ab`). A jmp/jcc therefore counts as matched only when the
candidate's byte offset of the target equals native's. A code-size change upstream can gain or lose many
branch lines far away from the edit. This tool separates those effects:

- target-line ranges matched by A but not by B, and by B but not by A (`--min` hides short ranges);
- with `--offsets`, the candidate-minus-native byte offset along B's matched blocks;
- the masked-reference problems (the refs `unresolved/mismatch` counts) of both, with their symbols.

Build each scratch first (`uv run crimson match scratch <dir>`); the newest `build/msvc6.5/*/scratch.obj`
is used, with FUNCTION, SYMBOL and REFERENCE_ALIASES from its scratch.conf.

    uv run python scripts/c2/score_regions.py <scratch-A> <scratch-B> [--min 3] [--offsets]

See tools/match/c2/compiler/slot-sharing-symbols.md §6.
"""

from __future__ import annotations

import argparse
import difflib
import shlex
from dataclasses import dataclass
from pathlib import Path

from crimson import match


@dataclass(frozen=True)
class Built:
    name: str
    target: tuple[match.DisassemblyLine, ...]
    candidate: tuple[match.DisassemblyLine, ...]
    result: match.MatchResult


def read_conf(scratch: Path) -> dict[str, str]:
    conf: dict[str, str] = {}
    for line in (scratch / "scratch.conf").read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            conf[key.strip()] = " ".join(shlex.split(value))
    return conf


def load(scratch: Path) -> Built:
    conf = read_conf(scratch)
    objs = sorted((scratch / "build").glob("*/*/scratch.obj"), key=lambda p: p.stat().st_mtime)
    if not objs:
        raise SystemExit(f"{scratch}: no build/*/*/scratch.obj; run `crimson match scratch` first")
    function = conf["FUNCTION"]
    symbol = conf.get("SYMBOL") or None
    aliases = tuple(tuple(item.rsplit(":", 1)) for item in conf.get("REFERENCE_ALIASES", "").split())
    dump = match.run_match_dump(obj_path=objs[-1], function=function, symbol_name=symbol)
    result = match.run_match(obj_path=objs[-1], function=function, symbol_name=symbol, reference_aliases=aliases)
    return Built(scratch.name, dump.target_lines, dump.candidate_lines, result)


def matcher(built: Built) -> difflib.SequenceMatcher:
    return difflib.SequenceMatcher(
        a=[line.text for line in built.target],
        b=[line.text for line in built.candidate],
        autojunk=False,
    )


def matched_targets(built: Built) -> set[int]:
    return {i for block in matcher(built).get_matching_blocks() for i in range(block.a, block.a + block.size)}


def ranges(indices: set[int]) -> list[tuple[int, int]]:
    out: list[list[int]] = []
    for i in sorted(indices):
        if out and i == out[-1][1] + 1:
            out[-1][1] = i
        else:
            out.append([i, i])
    return [(lo, hi) for lo, hi in out]


def report_ranges(a: Built, b: Built, minimum: int) -> None:
    ma, mb = matched_targets(a), matched_targets(b)
    for name, only in ((a.name, ma - mb), (b.name, mb - ma)):
        branch = sum(1 for i in only if a.target[i].text.split()[0].startswith("j"))
        print(f"== matched only by {name}: {len(only)} target lines ({branch} jmp/jcc)")
        for lo, hi in ranges(only):
            if hi - lo + 1 >= minimum:
                print(f"  {a.target[lo].address:08x}..{a.target[hi].address:08x} ({hi - lo + 1})  {a.target[lo].text}")


def report_offsets(built: Built) -> None:
    print(f"== {built.name}: candidate - native byte offset along matched blocks")
    last = None
    for block in matcher(built).get_matching_blocks():
        if not block.size:
            continue
        target, candidate = built.target[block.a], built.candidate[block.b]
        delta = candidate.offset - target.offset
        if delta != last:
            print(
                f"  {target.address:08x} +{target.offset:04x}  cand +{candidate.offset:04x}  {delta:+d}  x{block.size}",
            )
            last = delta


def report_references(built: Built) -> None:
    audit = built.result.masked_operand_audit
    print(
        f"== {built.name}: {built.result.ratio * 100:.2f}%  refs {audit.ok_count}/{audit.unresolved_count}/"
        f"{audit.mismatch_count}",
    )
    for entry in audit.entries:
        if entry.status != "ok":
            target = [sorted(r.keys) for r in entry.target_references]
            candidate = [sorted(r.keys) for r in entry.candidate_references]
            print(
                f"  {entry.status} {entry.target_address:08x} cand +{entry.candidate_offset:04x}  {entry.instruction}",
            )
            print(f"      target {target}\n      cand   {candidate}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("a", type=Path)
    parser.add_argument("b", type=Path)
    parser.add_argument("--min", type=int, default=1, help="hide ranges shorter than this")
    parser.add_argument("--offsets", action="store_true", help="print B's byte-offset deltas")
    args = parser.parse_args()
    a, b = load(args.a), load(args.b)
    report_references(a)
    report_references(b)
    report_ranges(a, b, args.min)
    if args.offsets:
        report_offsets(b)


if __name__ == "__main__":
    main()
