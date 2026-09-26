"""Sweep a scratch's frontend-id offset and report which offsets change the compiled code (diagnostic only).

C1XX numbers declarations with one counter per translation unit (tools/match/c2/compiler/frontend-ids.md). A
translation-unit prelude (for example the real DirectX 8.1 SDK headers) shifts every id after it by the same
amount D. This tool writes copies of a scratch with an enum that consumes exactly D ids (1 for the type plus
D - 1 enumerators) in front of the source, optionally after a prelude file, compiles and scores each copy, and
groups the offsets by the resulting candidate listing. Offsets that change the listing locate frontend-id
sensitive code; see tools/match/c2/compiler/tu-prelude.md for the two C2 paths that read the ids.

    uv run python scripts/c2/fe_offset_sweep.py <scratch-dir> --out <new-dir> --deltas 0:0x10000:0x100
    uv run python scripts/c2/fe_offset_sweep.py <scratch-dir> --out <new-dir> --deltas 0:64:1 \\
        --prelude prelude.h --cflags "/IZ:/path/to/dx81"

`--deltas` takes `a:b:step` or a comma list. `--prelude` is pasted verbatim before the padding. `--cflags`
is appended to the scratch's CFLAGS (default /O2 /GB /W3 /GR-). The output directory keeps every variant
(`dXXXXX/`) and `sweep.jsonl`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import residual_map as rm

DEFAULT_CFLAGS = "/O2 /GB /W3 /GR-"


def parse_deltas(text: str) -> list[int]:
    if ":" in text:
        lo, hi, step = (int(x, 0) for x in text.split(":"))
        return list(range(lo, hi, step))
    return [int(x, 0) for x in text.split(",")]


def padding(delta: int) -> str:
    if delta == 0:
        return ""
    return "enum fe_offset_pad { " + ", ".join(f"fe_offset_pad_{i}" for i in range(delta - 1)) + " };\n"


def write_variant(scratch: Path, out: Path, delta: int, prelude: str, cflags: str) -> Path:
    conf = (scratch / "scratch.conf").read_text()
    source = re.search(r"^SOURCE=(.+)$", conf, re.MULTILINE)
    source_name = shlex.split(source.group(1))[0] if source else "scratch.cpp"
    flags = re.search(r"^CFLAGS=(.+)$", conf, re.MULTILINE)
    base_flags = shlex.split(flags.group(1))[0] if flags else DEFAULT_CFLAGS
    conf = re.sub(r"^(CFLAGS|SOURCE)=.*\n", "", conf, flags=re.MULTILINE)
    target = out / f"d{delta:05x}"
    target.mkdir(parents=True)
    text = (scratch / source_name).read_text(encoding="latin1")
    (target / "scratch.cpp").write_text(prelude + padding(delta) + text, encoding="latin1")
    all_flags = f"{base_flags} {cflags}".strip()
    (target / "scratch.conf").write_text(f'{conf}SOURCE=scratch.cpp\nCFLAGS="{all_flags}"\n')
    return target


def evaluate(directory: Path) -> dict:
    try:
        result = rm.build(directory)
    except RuntimeError as error:
        return {"variant": directory.name, "error": str(error)[-400:]}
    scores = rm.ratios(result)
    audit = result.masked_operand_audit
    listing = "\n".join(result.candidate_lines)
    return {
        "variant": directory.name,
        **{level: round(value * 100, 3) for level, value in scores.items()},
        "refs": [audit.ok_count, audit.unresolved_count, audit.mismatch_count],
        "listing": hashlib.sha1(listing.encode()).hexdigest()[:12],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scratch", type=Path)
    parser.add_argument("--out", type=Path, required=True, help="new directory for the variants")
    parser.add_argument("--deltas", default="0:64:1")
    parser.add_argument("--prelude", type=Path, help="text pasted before the padding")
    parser.add_argument("--cflags", default="", help="appended to the scratch CFLAGS")
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()
    args.out.mkdir(parents=True)
    prelude = args.prelude.read_text() if args.prelude else ""
    variants = [write_variant(args.scratch, args.out, d, prelude, args.cflags) for d in parse_deltas(args.deltas)]
    with ProcessPoolExecutor(args.jobs) as pool:
        rows = list(pool.map(evaluate, variants))
    (args.out / "sweep.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    groups: dict[str, list[dict]] = {}
    for row in rows:
        groups.setdefault(row.get("listing", "error"), []).append(row)
    for key, members in sorted(groups.items(), key=lambda item: -len(item[1])):
        first = members[0]
        deltas = ", ".join(m["variant"][1:] for m in members[:24]) + (" ..." if len(members) > 24 else "")
        summary = first.get("error") or (
            f"raw {first['raw']}% labels {first['labels']}% structural {first['structural']}% "
            f"stack {first['stack']}% refs {'/'.join(map(str, first['refs']))}"
        )
        print(f"{key}  {len(members)} offsets  {summary}\n    offsets: {deltas}")


if __name__ == "__main__":
    main()
