"""Rebuild non-selected angle-storage and receiver controls; no match credit."""

import argparse
import json
import shutil
import subprocess
from pathlib import Path

from verify import HERE, ROOT, compile_control, encoded, reconstruct, sha

from crimson import match_c2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--trace", action="store_true", help="Also repeat preserving pass-boundary traces")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    data = json.loads((HERE / "followup-controls.json").read_text())
    git = shutil.which("git")
    assert git is not None
    source = subprocess.check_output(
        [
            git,
            "show",
            f"{data['baseline_commit']}:tools/match/scratches/player_update/scratch.cpp",
        ],
        cwd=ROOT,
    ).decode()
    assert sha(source.encode()) == data["baseline_source_sha256"]
    for name, digest in data["build"]["dependencies"].items():
        assert sha((ROOT / name).read_bytes()) == digest, name
    config = (HERE.parent.parent / "scratches/player_update/scratch.conf").read_text()
    baseline, row = compile_control(source, config, args.out / "baseline", data["baseline"], data["build"])
    configs = {"baseline": baseline}
    rows = [row]
    for control in data["controls"]:
        cfg, row = compile_control(
            reconstruct(source, control),
            control["config"],
            args.out / control["name"],
            control["observed"],
            data["build"],
        )
        configs[control["name"]] = cfg
        rows.append(row)
        print(json.dumps(row), flush=True)
    result = {
        "controls_sha256": sha((HERE / "followup-controls.json").read_bytes()),
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "shared_verifier_sha256": sha((HERE / "verify.py").read_bytes()),
        "compiler_controls": rows,
        "execution": "Not run: no follow-up control is selected; canonical body is unchanged.",
    }
    if args.trace:
        paths = [args.out / "trace-base", args.out / "trace-member"]
        result["traces"] = [
            match_c2.trace(configs[name].directory, out, passes_only=True)
            for name, out in zip(("baseline", "angle-storage-scratch-member"), paths, strict=True)
        ]
        result["comparison"] = match_c2.compare(*(match_c2.read_verified(path) for path in paths))
    (args.out / "results.json").write_bytes(encoded(result))


if __name__ == "__main__":
    main()
