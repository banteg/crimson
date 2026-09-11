"""Reconstruct the bounded muzzle component and quarter-size vector controls."""

import argparse
import importlib.util
import json
from dataclasses import replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
PARENT = HERE.parent / "overlay-size-ownership-2026-09-11" / "verify_controls.py"
spec = importlib.util.spec_from_file_location("overlay_controls", PARENT)
parent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    source = (HERE / "before.cpp").read_text()
    controls = json.loads((HERE / "source-controls.json").read_text())
    assert parent.sha(source.encode()) == controls["before_sha256"]
    config = parent.match.load_scratch_config(parent.match.DEFAULT_MATCH_ROOT / "scratches/player_render_overlays")
    rows = []
    for control in controls["controls"]:
        directory = args.out / control["family"] / control["name"]
        directory.mkdir(parents=True, exist_ok=True)
        (directory / config.source).write_text(parent.reconstruct(source, control))
        observed = parent.measure(replace(config, directory=directory))
        for key in ("ratio", "instructions", "refs_ok", "refs_problems"):
            assert observed[key] == control[key], (control["name"], key, observed)
        assert not observed["exact"] and not observed["body_byte_exact"]
        rows.append({"family": control["family"], "name": control["name"],
                     "source_sha256": control["source_sha256"], "observed": observed})
    result = {"script_sha256": parent.sha(Path(__file__).read_bytes()), "parent_verifier_sha256": parent.sha(PARENT.read_bytes()),
              "before_sha256": controls["before_sha256"], "controls_sha256": parent.sha((HERE / "source-controls.json").read_bytes()),
              "verified_controls": rows}
    (args.out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"Verified {len(rows)} reconstructed compiling controls")


if __name__ == "__main__":
    main()
