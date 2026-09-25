"""Separate label drift from real change in a scratch's match ratio (diagnostic only; no match credit).

`crimson match` scores normalized lines, and local branch labels are byte offsets (`jne L3f7a`).
Where the candidate's cumulative byte offset happens to equal native's, every branch into that range
matches for free; a fix that changes the byte count anywhere before it loses those lines. This tool
compiles scratches through the normal pipeline and prints:

- the drift map: for structurally matched branches (labels masked), the candidate-minus-native label
  offset, printed wherever it changes;
- with `--against`, the target lines each candidate gains or loses relative to the other, split into
  label lines and other lines, for both the raw and the label-masked comparison.

    uv run python scripts/c2/label_drift.py <scratch-dir> [--against <baseline-scratch-dir>] [--drift]
"""

from __future__ import annotations

import argparse
import difflib
import re
from pathlib import Path

from crimson import match as m

LABEL = re.compile(r"\bL([0-9a-f]+)\b")


def listing(directory: Path) -> tuple[tuple[str, ...], tuple[str, ...], float]:
    config = m.load_scratch_config(directory)
    image_path, functions_path, metadata_path = m._paths_for_image(config.image)
    obj_path = m.compile_scratch(config, m.DEFAULT_MATCH_ROOT.resolve())
    result = m.run_match(
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
    return result.target_lines, result.candidate_lines, result.ratio


def masked(lines: tuple[str, ...]) -> list[str]:
    return [LABEL.sub("L", line) for line in lines]


def matched_target_lines(target: list[str], candidate: list[str]) -> set[int]:
    matcher = difflib.SequenceMatcher(a=target, b=candidate, autojunk=False)
    lines: set[int] = set()
    for a, _b, n in matcher.get_matching_blocks():
        lines.update(range(a, a + n))
    return lines


def runs(indices: set[int]) -> list[tuple[int, int]]:
    out: list[list[int]] = []
    for index in sorted(indices):
        if out and index == out[-1][1] + 1:
            out[-1][1] = index
        else:
            out.append([index, index])
    return [(a + 1, b + 1) for a, b in out]


def print_drift(target: tuple[str, ...], candidate: tuple[str, ...]) -> None:
    matcher = difflib.SequenceMatcher(a=masked(target), b=masked(candidate), autojunk=False)
    previous = None
    for a, b, n in matcher.get_matching_blocks():
        for k in range(n):
            t_label, c_label = LABEL.search(target[a + k]), LABEL.search(candidate[b + k])
            if not (t_label and c_label):
                continue
            delta = int(c_label.group(1), 16) - int(t_label.group(1), 16)
            if delta != previous:
                print(f"  target line {a + k + 1:5d}  {target[a + k]:26s} candidate {candidate[b + k]:26s} drift {delta:+d}")
                previous = delta


def compare(name: str, base: tuple, other: tuple) -> None:
    target = list(base[0])
    for label, transform in (("raw", list), ("labels masked", masked)):
        t = transform(base[0])
        before = matched_target_lines(t, transform(base[1]))
        after = matched_target_lines(t, transform(other[1]))
        for verb, lines in (("gains", after - before), ("loses", before - after)):
            label_lines = {i for i in lines if LABEL.search(target[i])}
            print(
                f"  {label}: {name} {verb} {len(lines)} target lines "
                f"({len(label_lines)} branch-label lines): {runs(lines)[:12]}",
            )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", type=Path)
    parser.add_argument("--against", type=Path, help="baseline scratch directory to compare with")
    parser.add_argument("--drift", action="store_true", help="print the label drift map")
    args = parser.parse_args()
    candidate = listing(args.scratch)
    print(f"{args.scratch}: ratio {candidate[2]:.4%}, {len(candidate[1])} candidate lines")
    if args.drift or not args.against:
        print_drift(candidate[0], candidate[1])
    if args.against:
        base = listing(args.against)
        print(f"{args.against}: ratio {base[2]:.4%}, {len(base[1])} candidate lines")
        compare(args.scratch.name, base, candidate)


if __name__ == "__main__":
    main()
