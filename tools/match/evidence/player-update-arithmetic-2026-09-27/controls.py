"""Rebuild selected recorded source controls without modifying the canonical scratch."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
spec = importlib.util.spec_from_file_location("residual_map", ROOT / "scripts/c2/residual_map.py")
residual = importlib.util.module_from_spec(spec)
spec.loader.exec_module(residual)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--name", action="append", help="repeat to select controls; omitted means all")
    args = parser.parse_args()
    recorded = json.loads((HERE / "controls.json").read_text())
    before = (HERE / "before.cpp").read_bytes()
    assert hashlib.sha256(before).hexdigest() == recorded["baseline_sha256"]
    names = {row["name"] for row in recorded["controls"]}
    assert not args.name or set(args.name) <= names
    conf = residual.m.DEFAULT_MATCH_ROOT / "scratches/player_update/scratch.conf"
    rows = []
    for row in recorded["controls"]:
        if args.name and row["name"] not in args.name:
            continue
        lines = before.decode().splitlines(keepends=True)
        for edit in reversed(row["edits"]):
            lines[edit["start"] : edit["end"]] = edit["replacement"]
        source = "".join(lines).encode()
        assert hashlib.sha256(source).hexdigest() == row["sha256"]
        directory = args.out / row["name"]
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "scratch.cpp").write_bytes(source)
        (directory / "scratch.conf").write_bytes(conf.read_bytes())
        result = residual.build(directory)
        audit = result.masked_operand_audit
        actual = {
            "scores": residual.ratios(result),
            "instructions": [len(result.target_lines), len(result.candidate_lines)],
            "refs": [audit.ok_count, audit.unresolved_count, audit.mismatch_count],
            "exact": result.exact,
        }
        assert all(actual[key] == row[key] for key in actual), (row["name"], actual)
        rows.append({"name": row["name"], **actual})
        print(row["name"], actual["scores"], flush=True)
    (args.out / "results.json").write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    main()
