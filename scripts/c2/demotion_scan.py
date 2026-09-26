"""Scan scratches for block-end demotions of named locals (VC6 C2 `demote_unused_candidate_def` 0x107318e5).

`insert_upward_exposed_reloads` 0x1072e7cb passes every candidate whose last def is unused and not
live-out at a block end to 0x107318e5 (call site 0x1072eb81), which turns a local's def into a memory
store. This runs `const_trace.py` (preserving harness) on copies of the selected scratches, in
parallel, and lists each demoted def of a whole named local (`#idc4z4'name`, no `^parent+offset`)
whose source is not a constant: the stores that survive only because nothing deletes a dead memory
store after the global optimizer. Most hits are `(float)local` (read back by `fild`) or float bit
views; a store with no memory read afterwards is a dead store in the final code.

    uv run python scripts/c2/demotion_scan.py --out <new-dir> [--jobs 8] [scratch-name ...]

With no names every scratch under tools/match/scratches is scanned (about 20 minutes with 8 jobs).
Diagnostic only; see tools/match/c2/compiler/qst-dead-store.md.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRATCHES = ROOT / "tools/match/scratches"
DEMOTE = re.compile(r"DEMOTE (#\d+c4z\d+'(\S+)) T \w+ op=(\w+) ln=(\d+) \| \[1:(\w+) [^\]]*\] <= (.*)$")


def scan_one(name: str, out: Path) -> list[str]:
    source = SCRATCHES / name
    conf = (source / "scratch.conf").read_text()
    src = next(line.split("=", 1)[1].strip() for line in conf.splitlines() if line.startswith("SOURCE="))
    copy = out / "src" / name
    copy.mkdir(parents=True, exist_ok=True)
    shutil.copy(source / "scratch.conf", copy)
    shutil.copy(source / src, copy)
    trace = out / "trace" / name
    shutil.rmtree(trace, ignore_errors=True)
    subprocess.run(
        [sys.executable, str(Path(__file__).with_name("const_trace.py")), str(copy), "--out", str(trace)],
        capture_output=True,
        check=False,
        cwd=ROOT,
    )
    report = trace / "const-report.txt"
    rows = []
    if report.exists():
        for line in report.read_text().splitlines():
            m = DEMOTE.search(line)
            if m and m.group(3) == "1" and "c13=" not in m.group(6):
                rows.append(f"{name}  {m.group(1)}  type {m.group(5)}  ln {m.group(4)}  <= {m.group(6).strip()}")
    shutil.rmtree(trace, ignore_errors=True)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("names", nargs="*")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()
    names = args.names or sorted(p.parent.name for p in SCRATCHES.glob("*/scratch.conf"))
    with ThreadPoolExecutor(args.jobs) as pool:
        for rows in pool.map(lambda n: scan_one(n, args.out), names):
            for row in rows:
                print(row, flush=True)


if __name__ == "__main__":
    main()
