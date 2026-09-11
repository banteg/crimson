"""Reconstruct the bounded renderer ownership controls and verify their bodies."""

import argparse
import importlib.util
import json
from dataclasses import replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
PARENT = HERE.parent / "overlay-size-ownership-2026-09-11/verify_controls.py"
spec = importlib.util.spec_from_file_location("owner_controls", PARENT)
parent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parent)
match = parent.match


def reconstruct(function, name, out):
    data = json.loads((HERE / f"{function}-controls.json").read_text())
    source = (HERE / f"{function}-before.cpp").read_text()
    assert parent.sha(source.encode()) == data["before_sha256"]
    control = next(row for row in data["controls"] if row["name"] == name)
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches" / function)
    directory = out / function / name
    directory.mkdir(parents=True, exist_ok=True)
    (directory / config.source).write_text(parent.reconstruct(source, control))
    return replace(config, directory=directory), control


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    rows = []
    for function in ("projectile_render", "player_render_overlays"):
        controls_path = HERE / f"{function}-controls.json"
        data = json.loads(controls_path.read_text())
        for control in data["controls"]:
            config, _ = reconstruct(function, control["name"], args.out)
            observed = parent.measure(config)
            for key in ("ratio", "instructions", "refs_ok", "refs_problems"):
                assert observed[key] == control[key], (function, control["name"], key, observed)
            assert not observed["exact"] and not observed["body_byte_exact"]
            obj = match.compile_scratch(config)
            body = match.extract_object_function(match.parse_coff_object(obj.read_bytes()), config.symbol)
            body_sha = parent.sha(body.data)
            assert body_sha == control["body_sha256"], (function, control["name"], "body changed")
            rows.append({"function": function, "name": control["name"], "observed": observed,
                         "source_sha256": control["source_sha256"], "body_sha256": body_sha})
        print(f"Verified {function}: {len(data['controls'])} compiling controls", flush=True)
    result = {
        "schema_version": 1,
        "kind": "bounded-render-owner-source-controls",
        "new_source_matches": 0,
        "verifier_sha256": parent.sha(Path(__file__).read_bytes()),
        "parent_sha256": parent.sha(PARENT.read_bytes()),
        "control_files": {p.name: parent.sha(p.read_bytes()) for p in sorted(HERE.glob("*-controls.json"))},
        "rows": rows,
    }
    (args.out / "results.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
