#!/usr/bin/env python3
"""Record and validate provenance for local persistent analysis databases."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def expected_state(args: argparse.Namespace) -> dict[str, Any]:
    binary = args.binary.resolve()
    tool_file = args.tool_file.resolve()
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": args.tool,
        "tool_version": args.tool_version,
        "tool_fingerprint": sha256_file(tool_file),
        "tool_file": str(tool_file),
        "program": args.program,
        "binary_path": str(binary),
        "binary_sha256": sha256_file(binary),
    }


def write_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(state, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def check_state(path: Path, expected: dict[str, Any]) -> list[str]:
    try:
        with path.open(encoding="utf-8") as stream:
            observed = json.load(stream)
    except FileNotFoundError:
        return [f"missing provenance file: {path}"]
    except (OSError, json.JSONDecodeError) as exc:
        return [f"invalid provenance file {path}: {exc}"]
    if not isinstance(observed, dict):
        return [f"invalid provenance file {path}: expected a JSON object"]

    mismatches = []
    for key in (
        "schema_version",
        "tool",
        "tool_version",
        "tool_fingerprint",
        "program",
        "binary_sha256",
    ):
        if observed.get(key) != expected[key]:
            mismatches.append(
                f"{key}: recorded {observed.get(key)!r}, current {expected[key]!r}",
            )
    return mismatches


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "write"))
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--tool-version", required=True)
    parser.add_argument("--tool-file", type=Path, required=True)
    parser.add_argument("--program", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    expected = expected_state(args)
    if args.command == "write":
        write_state(args.state, expected)
        print(f"Recorded analysis database provenance: {args.state}")
        return 0

    mismatches = check_state(args.state, expected)
    if mismatches:
        print("Analysis database provenance mismatch:", file=sys.stderr)
        for mismatch in mismatches:
            print(f"- {mismatch}", file=sys.stderr)
        return 1
    print(f"Analysis database provenance verified: {args.state}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
