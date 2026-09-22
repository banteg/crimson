"""Prove the full highscore function with literal branches and positional references."""

import argparse
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

from controls import HERE, WITNESS, build, previous_module, sha, sources

from crimson import match

prior = previous_module("verify.py")
audit, reject = prior.audit, prior.reject


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    assert sha(match.default_image_path().read_bytes()) == prior.IMAGE_SHA
    image = match.load_image(match.default_image_path())
    builds, bodies, reports = {}, {}, {}
    for name in sources():
        cfg, _, body, report, metrics = build(name, out / "controls")
        frame = subprocess.run(
            [
                sys.executable,
                str(HERE.parent / "highscore-residual-decomposition-2026-09-13/frame_map.py"),
                str(cfg.directory),
            ],
            cwd=match.REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        builds[name] = {**metrics, "frame_check": frame.strip().splitlines()}
        bodies[name], reports[name] = body, report
        print("Verified stock build and frame", name, flush=True)
    body, report = bodies[WITNESS], reports[WITNESS]
    windows = ((0, prior.SIZE),)
    proof = audit(body, report, image, windows)
    assert sum(r["instructions"] for r in proof) == 2004
    assert sum(r["bytes"] for r in proof) == 8026
    partial = audit(bodies["scoped-double-x"], reports["scoped-double-x"], image, ((0, 0x1D8), (0x1E7, prior.SIZE)))
    assert sum(r["bytes"] for r in partial) == 8011
    corruptions = []
    for name, offset, mask in (
        ("separator-store-displacement", 0x1E6, 4),
        ("online-x-destination", 0xF3B, 4),
        ("status-branch-target", 0x16AD, 1),
    ):
        damaged = bytearray(body.data)
        damaged[offset] ^= mask
        corruptions.append(
            reject(name, lambda damaged=damaged: audit(replace(body, data=bytes(damaged)), report, image, windows)),
        )
    rows = list(report.candidate_disassembly)
    index = next(i for i, r in enumerate(rows) if r.offset == 0x1D8)
    rows[index] = replace(
        rows[index], masked_references=(replace(rows[index].masked_references[0], keys=("name:wrong",)),),
    )
    corruptions.append(
        reject(
            "separator-interface-reference",
            lambda: audit(body, replace(report, candidate_disassembly=tuple(rows)), image, windows),
        ),
    )
    corruptions.append(
        reject(
            "promote-partial-witness",
            lambda: audit(bodies["scoped-double-x"], reports["scoped-double-x"], image, windows),
        ),
    )
    result = {
        "schema_version": 1,
        "kind": "highscore-complete-stock-proof",
        "image_sha256": prior.IMAGE_SHA,
        "witness": WITNESS,
        "source_sha256": sources()[WITNESS][1]["source_sha256"],
        "builds": builds,
        "proof": proof,
        "excluded_windows": [],
        "proved_bytes": 8026,
        "proved_instructions": 2004,
        "full_function_match": True,
        "corruptions_rejected": corruptions,
        "inputs": {
            str(p.relative_to(match.REPO_ROOT)): sha(p.read_bytes())
            for p in (HERE / "controls.py", HERE / "controls.json", Path(__file__), Path(prior.__file__))
        },
    }
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print("Verified all 8026 bytes, full branch destinations, and positional references", flush=True)


if __name__ == "__main__":
    main()
