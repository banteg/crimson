"""Reconstruct the bounded position controls and check their native witnesses."""

import argparse
import concurrent.futures
import importlib.util
import json
from dataclasses import replace
from pathlib import Path

from crimson import match

HERE = Path(__file__).resolve().parent
FIRE_PROOF = HERE.parent / "fire-overlay-lifetimes-2026-09-13/verify.py"
spec = importlib.util.spec_from_file_location("fire_position_controls", FIRE_PROOF)
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)
e = f.e


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((HERE / "source-controls.json").read_text())
    base = (FIRE_PROOF.parent / "before.cpp").read_text()
    assert e.sha(base.encode()) == manifest["baseline_sha256"]
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/projectile_render")
    assert config.compiler == manifest["compiler"] and config.cflags == manifest["cflags"]
    assert json.loads(json.dumps(config.reference_aliases)) == manifest["reference_aliases"]
    pinned = json.loads((FIRE_PROOF.parent / "results.json").read_text())
    assert e.sha(match.default_image_path().read_bytes()) == pinned["image_sha256"]

    def check(control):
        source = f.reconstruction.reconstruct(base, control)
        directory = args.out / control["name"]
        directory.mkdir(parents=True, exist_ok=True)
        (directory / config.source).write_text(source)
        program = e.Program(replace(config, directory=directory))
        native_body = program.image.function_bytes(program.native_start, program.native_end)
        assert e.sha(native_body) == pinned["native_body_sha256"]
        failed = []
        for index, case in enumerate(f.witnesses()):
            native, candidate = f.compare(program, case)
            f.oracle(case, native)
            if native["calls"] != candidate["calls"]:
                failed.append(index)
        observed = f.reconstruction.metrics(program.result)
        observed["failed"] = failed
        observed["frame"] = match.match_result_payload(program.result)["stack_frame"]
        assert observed == control["observed"], (control["name"], observed)
        print(f"{control['name']}: {26 - len(failed)}/26 witnesses agree", flush=True)
        return {
            "name": control["name"],
            "source_sha256": e.sha(source.encode()),
            "body_sha256": e.sha(program.body.data),
            "object_sha256": e.sha(program.object_path.read_bytes()),
            "observed": observed,
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        rows = list(pool.map(check, manifest["controls"]))
    receipt = {
        "controls": rows,
        "baseline_sha256": e.sha(base.encode()),
        "controls_sha256": e.sha((HERE / "source-controls.json").read_bytes()),
        "verifier_sha256": e.sha(Path(__file__).read_bytes()),
        "fire_proof_sha256": e.sha(FIRE_PROOF.read_bytes()),
        "reconstruction_sha256": e.sha(Path(f.reconstruction.__file__).read_bytes()),
        "executor_sha256": e.sha(f.EXECUTOR.read_bytes()),
        "engine_sha256": e.sha(e.ENGINE.read_bytes()),
        "image_sha256": pinned["image_sha256"],
        "native_body_sha256": pinned["native_body_sha256"],
        "unicorn_version": e.unicorn.__version__,
        "scope": "Bounded source controls and 26 Fire witnesses per control. No exact-match credit.",
    }
    (args.out / "results.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"Verified {len(rows)} controls.", flush=True)


if __name__ == "__main__":
    main()
