"""Reconstruct and recompile every recorded creature-render owner control."""

import argparse
import importlib.util
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
PARENT = HERE.parent / "overlay-size-ownership-2026-09-11/verify_controls.py"
spec = importlib.util.spec_from_file_location("source_controls", PARENT)
parent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--jobs", type=int, default=6)
    args = parser.parse_args()
    assert args.jobs > 0
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    data = json.loads((HERE / "source-controls.json").read_text())
    before = (HERE / "before.cpp").read_text()
    assert parent.sha(before.encode()) == data["before_sha256"]
    config = parent.match.load_scratch_config(parent.match.DEFAULT_MATCH_ROOT / "scratches/creature_render_type")

    def verify(control):
        source = parent.reconstruct(before, control)
        directory = out / control["name"]
        directory.mkdir(exist_ok=True)
        (directory / config.source).write_text(source)
        observed = parent.measure(replace(config, directory=directory))
        for key, recorded in {
            "ratio": "ratio",
            "instructions": "instructions",
            "prefix": "prefix",
            "refs_ok": "refs",
            "refs_problems": "problems",
            "body_byte_exact": "body",
        }.items():
            assert observed[key] == control[recorded], (control["name"], key, observed)
        return {"name": control["name"], "source_sha256": control["source_sha256"], "observed": observed}

    rows = []
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for row in pool.map(verify, data["controls"]):
            rows.append(row)
            if len(rows) % 100 == 0:
                print(f"Reproduced {len(rows)}/{len(data['controls'])} controls", flush=True)
    result = {
        "before_sha256": data["before_sha256"],
        "controls_sha256": parent.sha((HERE / "source-controls.json").read_bytes()),
        "verifier_sha256": parent.sha(Path(__file__).read_bytes()),
        "parent_sha256": parent.sha(PARENT.read_bytes()),
        "rows": rows,
    }
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"Verified {len(rows)} reconstructed, compiling controls")


if __name__ == "__main__":
    main()
