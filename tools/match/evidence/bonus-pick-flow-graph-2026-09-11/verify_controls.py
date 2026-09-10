"""Reconstruct and measure the recorded bonus selection source controls."""

import argparse
import hashlib
import json
from dataclasses import replace
from pathlib import Path

from crimson import match

HERE = Path(__file__).resolve().parent


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def reconstruct(base, control):
    lines = base.splitlines(keepends=True)
    previous = len(lines)
    for edit in reversed(control["edits"]):
        start, stop = edit["start"], edit["stop"]
        assert 0 <= start <= stop <= previous, "Overlapping or out-of-range source edits"
        assert "".join(lines[start:stop]) == edit["old"], "Source edit no longer applies"
        lines[start:stop] = edit["new"].splitlines(keepends=True)
        previous = start
    source = "".join(lines)
    assert digest(source) == control["source_sha256"], "Reconstructed source changed"
    return source


def measure(config):
    obj = match.compile_scratch(config, force=True)
    result = match.run_match(
        obj_path=obj,
        function=config.function,
        symbol_name=config.symbol,
        reference_aliases=config.reference_aliases,
    )
    return {
        "ratio": result.ratio,
        "ins": len(result.candidate_lines),
        "prefix": result.prefix_instructions,
        "refs": result.masked_operand_audit.ok_count,
        "problems": result.masked_operand_audit.problem_count,
        "exact": result.exact,
        "body": result.body_byte_exact,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--control", action="append", help="Reproduce only this exact control name; repeatable")
    args = parser.parse_args()
    data = json.loads((HERE / "source-controls.json").read_text())
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/bonus_pick_random_type")
    base = (config.directory / config.source).read_text()
    assert digest(base) == data["baseline_sha256"], "Canonical source changed; recorded controls are historical"
    assert config.cflags == data["baseline_cflags"], "Compiler flags changed"
    assert config.compiler == data["baseline_compiler"], "Compiler changed"
    controls = data["controls"]
    if args.control:
        requested = set(args.control)
        assert requested <= {control["name"] for control in controls}, "Unknown control name"
        controls = [control for control in controls if control["name"] in requested]
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for control in controls:
        directory = out / control["name"]
        directory.mkdir(parents=True, exist_ok=True)
        (directory / config.source).write_text(reconstruct(base, control))
        observed = measure(replace(config, directory=directory, cflags=control.get("cflags", config.cflags)))
        assert observed == control["observed"], (control["name"], observed, control["observed"])
        rows.append({"name": control["name"], "source_sha256": control["source_sha256"], "observed": observed})
        print(
            f"Verified {control['name']}: {observed['ins']} instructions, encoded exact={observed['body']}",
            flush=True,
        )
    receipt = {
        "schema_version": 1,
        "baseline_sha256": digest(base),
        "normal_build_key": match._scratch_build_key(config, match.DEFAULT_MATCH_ROOT),
        "controls_sha256": digest((HERE / "source-controls.json").read_text()),
        "verifier_sha256": digest(Path(__file__).read_text()),
        "verified_controls": rows,
    }
    (out / "results.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
