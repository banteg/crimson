"""Measure CI commands without mixing their output with timing data."""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command is required")
    started = time.perf_counter()
    result = subprocess.run(command, check=False)
    measurement = {"name": args.name, "seconds": time.perf_counter() - started, "exit_code": result.returncode}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("a") as output:
        output.write(json.dumps(measurement) + "\n")
    print(json.dumps(measurement), flush=True)
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
