"""Reconstruct and compile the recorded overlay source controls."""

import argparse
import hashlib
import json
from dataclasses import replace
from pathlib import Path

from crimson import match

HERE = Path(__file__).resolve().parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


def reconstruct(base, control):
    lines = base.splitlines(keepends=True)
    previous = len(lines)
    for edit in reversed(control["edits"]):
        start, end = edit["start"], edit["end"]
        assert 0 <= start <= end <= previous
        assert lines[start:end] == edit["old"]
        lines[start:end] = edit["new"]
        previous = start
    source = "".join(lines)
    assert sha(source.encode()) == control["source_sha256"]
    return source


def measure(config):
    obj = match.compile_scratch(config, force=True)
    result = match.run_match(
        obj_path=obj, function=config.function, symbol_name=config.symbol,
        reference_aliases=config.reference_aliases,
    )
    return {
        "ratio": result.ratio,
        "instructions": len(result.candidate_lines),
        "refs_ok": result.masked_operand_audit.ok_count,
        "refs_problems": result.masked_operand_audit.problem_count,
        "prefix": result.prefix_instructions,
        "exact": result.exact,
        "body_byte_exact": result.body_byte_exact,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    data = json.loads((HERE / "source-controls.json").read_text())
    base = (HERE / "before.cpp").read_text()
    assert sha(base.encode()) == data["before_sha256"]
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/player_render_overlays")
    rows = []
    for control in data["controls"]:
        directory = out / control["family"] / control["name"]
        directory.mkdir(parents=True, exist_ok=True)
        (directory / config.source).write_text(reconstruct(base, control))
        observed = measure(replace(config, directory=directory))
        for key in ("ratio", "instructions", "refs_ok", "refs_problems"):
            assert observed[key] == control[key], (control["name"], key, observed)
        assert not observed["exact"] and not observed["body_byte_exact"]
        rows.append({"family": control["family"], "name": control["name"], "source_sha256": control["source_sha256"], "observed": observed})
    (out / "results.json").write_text(json.dumps({
        "before_sha256": sha(base.encode()),
        "controls_sha256": sha((HERE / "source-controls.json").read_bytes()),
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "current_build_key": match._scratch_build_key(config, match.DEFAULT_MATCH_ROOT),
        "verified_controls": rows,
    }, indent=2) + "\n")
    print(f"Verified {len(rows)} reconstructed, compiling controls")


if __name__ == "__main__":
    main()
