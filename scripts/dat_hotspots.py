from __future__ import annotations

import argparse
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path


DATA_LABEL_PATTERN = re.compile(r"\b(?:_?DAT|PTR_DAT)_[0-9A-Fa-f]{8}\b")
FUNC_HEADER_PATTERN = re.compile(r"/\*\s*(?P<name>[^*]+?)\s*@\s*(?P<addr>[0-9A-Fa-f]{8})\s*\*/")


@dataclass(frozen=True)
class Sample:
    function: str
    line_number: int
    line_index: int


def iter_tokens(lines: list[str]) -> tuple[Counter[str], dict[str, list[Sample]]]:
    counts: Counter[str] = Counter()
    samples: dict[str, list[Sample]] = defaultdict(list)
    sample_funcs: dict[str, set[str]] = defaultdict(set)

    current_func = "<toplevel>"
    for line_index, line in enumerate(lines):
        header_match = FUNC_HEADER_PATTERN.match(line.strip())
        if header_match:
            current_func = header_match.group("name").strip()

        for match in DATA_LABEL_PATTERN.findall(line):
            token = match.upper()
            counts[token] += 1
            if current_func not in sample_funcs[token]:
                samples[token].append(
                    Sample(function=current_func, line_number=line_index + 1, line_index=line_index)
                )
                sample_funcs[token].add(current_func)

    return counts, samples


def format_context(lines: list[str], sample: Sample, context: int) -> list[str]:
    if context <= 0:
        return [lines[sample.line_index].rstrip()]

    start = max(0, sample.line_index - context)
    end = min(len(lines), sample.line_index + context + 1)
    return [lines[i].rstrip() for i in range(start, end)]


def report(path: Path, top: int, samples_per_token: int, context: int) -> None:
    text = path.read_text(encoding="utf-8", errors="ignore")
    lines = text.splitlines()
    counts, samples = iter_tokens(lines)

    if not counts:
        print(f"{path}: no DAT_* symbols found")
        return

    print(path)
    for token, count in counts.most_common(top):
        token_samples = samples.get(token, [])[:samples_per_token]
        if not token_samples:
            print(f"{count:>6} {token}")
            continue

        primary = token_samples[0]
        code = lines[primary.line_index].strip()
        print(f"{count:>6} {token}  {primary.function}:{primary.line_number}  {code}")

        for extra in token_samples[1:]:
            code = lines[extra.line_index].strip()
            print(f"{'':>6} {'':>11}  {extra.function}:{extra.line_number}  {code}")

        if context > 0:
            ctx_lines = format_context(lines, primary, context)
            for ctx in ctx_lines:
                print(f"{'':>6} {'':>11}  | {ctx}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="List remaining DAT_*/PTR_DAT_* tokens in Ghidra decompiled C by frequency.",
    )
    parser.add_argument(
        "inputs",
        nargs="*",
        type=Path,
        help="decompiled C files (defaults to analysis/ghidra/raw/*_decompiled.c)",
    )
    parser.add_argument("--top", type=int, default=50, help="number of tokens to show per input")
    parser.add_argument(
        "--samples",
        type=int,
        default=1,
        help="number of unique-function samples to print per token",
    )
    parser.add_argument(
        "--context",
        type=int,
        default=0,
        help="print N lines of surrounding context for the first sample",
    )
    args = parser.parse_args()

    inputs = args.inputs
    if not inputs:
        inputs = [
            Path("analysis/ghidra/raw/crimsonland.exe_decompiled.c"),
            Path("analysis/ghidra/raw/grim.dll_decompiled.c"),
        ]

    for path in inputs:
        if not path.exists():
            print(f"{path}: not found")
            continue
        report(path, top=args.top, samples_per_token=max(1, args.samples), context=args.context)
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

