"""Reconstruct and compile the bounded rocket body expression controls."""

import argparse
import importlib.util
import json
from dataclasses import replace
from pathlib import Path

from crimson import match

HERE = Path(__file__).resolve().parent
REFERENCE = HERE.parent / "bonus-pick-flow-graph-2026-09-11/verify_controls.py"
SPEC = importlib.util.spec_from_file_location("source_reconstruction", REFERENCE)
reconstruction = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reconstruction)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    data = json.loads((HERE / "source-controls.json").read_text())
    source = (HERE / "before.cpp").read_text()
    assert reconstruction.digest(source) == data["baseline_sha256"]
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/projectile_render")
    assert config.compiler == data["compiler"] and config.cflags == data["cflags"]
    records = []
    for control in data["controls"]:
        directory = out / control["name"]
        directory.mkdir(parents=True, exist_ok=True)
        text = reconstruction.reconstruct(source, control)
        (directory / config.source).write_text(text)
        status = match.evaluate_scratch(replace(config, directory=directory))
        observed = {
            "ratio": status.ratio, "ins": status.candidate_instructions,
            "refs": [status.masked_ok, status.masked_unresolved, status.masked_mismatches], "error": status.error,
        }
        assert observed == control["observed"], (control["name"], observed, control["observed"])
        if control["name"] == data["selected"]:
            assert text == (config.directory / config.source).read_text()
        records.append({"name": control["name"], "source_sha256": control["source_sha256"], "observed": observed})
    record = {
        "schema_version": 1, "baseline_sha256": data["baseline_sha256"],
        "spec_sha256": reconstruction.digest((HERE / "source-controls.json").read_text()),
        "verifier_sha256": reconstruction.digest(Path(__file__).read_text()),
        "reconstruction_sha256": reconstruction.digest(REFERENCE.read_text()), "controls": records,
    }
    (out / "controls.json").write_text(json.dumps(record, indent=2) + "\n")
    print(f"Verified {len(records)} source controls")


if __name__ == "__main__":
    main()
