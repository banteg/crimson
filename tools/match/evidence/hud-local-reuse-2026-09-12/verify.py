"""Reconstruct and recompile the bounded HUD local-reuse controls."""

import argparse
import hashlib
import json
from dataclasses import replace
from pathlib import Path

from crimson import match

HERE = Path(__file__).resolve().parent


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, help="Historical source when the canonical HUD has changed")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    data = json.loads((HERE / "source-controls.json").read_text())
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/ui_render_hud")
    base = (args.baseline or config.directory / config.source).read_text()
    assert sha(base) == data["baseline_sha256"]
    assert config.compiler == data["baseline_compiler"] and config.cflags == data["baseline_cflags"]
    rows = []
    for control in data["controls"]:
        lines = base.splitlines(keepends=True)
        previous = len(lines)
        for edit in reversed(control["edits"]):
            start, stop = edit["start"], edit["stop"]
            assert 0 <= start <= stop <= previous
            assert "".join(lines[start:stop]) == edit["old"]
            lines[start:stop] = edit["new"].splitlines(keepends=True)
            previous = start
        source = "".join(lines)
        assert sha(source) == control["source_sha256"]
        directory = out / control["name"]
        directory.mkdir(exist_ok=True)
        (directory / config.source).write_text(source)
        obj = match.compile_scratch(replace(config, directory=directory), force=True)
        result = match.run_match(
            obj_path=obj,
            function=config.function,
            symbol_name=config.symbol,
            reference_aliases=config.reference_aliases,
        )
        observed = {
            "ratio": result.ratio,
            "ins": len(result.candidate_lines),
            "prefix": result.prefix_instructions,
            "refs": result.masked_operand_audit.ok_count,
            "problems": result.masked_operand_audit.problem_count,
            "exact": result.exact,
            "body": result.body_byte_exact,
        }
        assert observed == control["observed"], (control["name"], observed)
        rows.append({"name": control["name"], "source_sha256": sha(source), "observed": observed})
    receipt = {
        "verified_controls": rows,
        "baseline_sha256": sha(base),
        "controls_sha256": sha((HERE / "source-controls.json").read_text()),
        "verifier_sha256": sha(Path(__file__).read_text()),
    }
    (out / "results.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"Verified {len(rows)} compiling controls; no exact match or canonical source change")


if __name__ == "__main__":
    main()
