"""Reconstruct hash-bound source experiments without changing canonical matching credit."""

import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


def recover(name=None):
    graph = json.loads((HERE / "experiments.json").read_text())
    name = name or graph["final"]
    source = (HERE / "before.cpp").read_text()
    assert sha(source.encode()) == graph["before_source_sha256"]
    path = []
    seen = set()
    while name != "before":
        assert name not in seen, "Experiment graph cycle"
        seen.add(name)
        row = graph["experiments"][name]
        path.append(row)
        name = row["parent"]
    for row in reversed(path):
        assert sha(source.encode()) == row["parent_source_sha256"]
        lines = source.splitlines(keepends=True)
        for edit in reversed(row["edits"]):
            start = edit["start_line"] - 1
            removed = edit["removed"].splitlines(keepends=True)
            assert lines[start : start + len(removed)] == removed
            lines[start : start + len(removed)] = edit["replacement"].splitlines(keepends=True)
        source = "".join(lines)
        assert sha(source.encode()) == row["source_sha256"]
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.write_text(recover(args.experiment))


if __name__ == "__main__":
    main()
