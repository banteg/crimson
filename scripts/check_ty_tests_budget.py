#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import subprocess
import sys


def _parse_diagnostic_count(output: str) -> int | None:
    match = re.search(r"Found\s+(\d+)\s+diagnostics", output)
    if match is None:
        return None
    return int(match.group(1))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run ty against tests and enforce a diagnostics budget.",
    )
    parser.add_argument(
        "--max-diagnostics",
        type=int,
        default=95,
        help="Maximum allowed diagnostics from `ty check tests`.",
    )
    parser.add_argument(
        "--output-format",
        default="concise",
        help="Output format passed through to `ty check`.",
    )
    args = parser.parse_args()

    command = ["ty", "check", "tests", "--output-format", str(args.output_format)]
    proc = subprocess.run(command, capture_output=True, text=True)

    output = f"{proc.stdout}{proc.stderr}"
    if output:
        sys.stdout.write(output)

    diagnostics = _parse_diagnostic_count(output)
    if diagnostics is None:
        if proc.returncode == 0:
            diagnostics = 0
        else:
            print("error: could not parse ty diagnostics count", file=sys.stderr)
            return proc.returncode or 1

    limit = int(args.max_diagnostics)
    if diagnostics > limit:
        print(
            f"error: ty tests diagnostics budget exceeded: {diagnostics} > {limit}",
            file=sys.stderr,
        )
        return 1

    print(f"ty tests diagnostics: {diagnostics} (budget: {limit})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
