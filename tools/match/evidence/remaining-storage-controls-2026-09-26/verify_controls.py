"""Rebuild the bounded storage controls from the pinned Git revision."""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from crimson import match
from crimson import match_c2_replay as replay

HERE = Path(__file__).resolve().parent
ROOT = match.REPO_ROOT
sys.path.insert(0, str(ROOT / "scripts/c2"))
import frame_predict as fp
import residual_map as rm


def sha(data):
    return hashlib.sha256(data).hexdigest()


def reconstruct(base, control):
    lines = base.splitlines(keepends=True)
    previous = len(lines)
    for edit in reversed(control["edits"]):
        start, stop = edit["start"], edit["stop"]
        assert 0 <= start <= stop <= previous
        assert "".join(lines[start:stop]) == edit["old"]
        lines[start:stop] = edit["new"].splitlines(keepends=True)
        previous = start
    source = "".join(lines)
    assert sha(source.encode()) == control["source_sha256"]
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=3)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    manifest = json.loads((HERE / "controls.json").read_text())
    assert sha(match.default_image_path().read_bytes()) == manifest["image_sha256"]
    assert sha((ROOT / "tools/match/compilers/msvc6.5/Bin/C2.DLL").read_bytes()) == manifest["c2_sha256"]
    jobs = []
    git = shutil.which("git")
    assert git is not None
    for target, group in manifest["targets"].items():
        prefix = f"{manifest['base_commit']}:tools/match/scratches/{target}/"
        base = subprocess.check_output([git, "show", prefix + "scratch.cpp"], cwd=ROOT).decode()
        config = subprocess.check_output([git, "show", prefix + "scratch.conf"], cwd=ROOT).decode()
        assert sha(base.encode()) == group["source_sha256"]
        assert sha(config.encode()) == group["config_sha256"]
        jobs.extend((target, base, config, control) for control in group["controls"])

    def check(job):
        target, base, config, control = job
        directory = args.out / target / control["name"]
        directory.mkdir(parents=True)
        (directory / "scratch.conf").write_text(config)
        (directory / "scratch.cpp").write_text(reconstruct(base, control))
        cfg = match.load_scratch_config(directory)
        assert cfg.compiler == manifest["compiler"] and cfg.cflags == manifest["cflags"]
        result = rm.build(directory)
        obj = match.compile_scratch(cfg, match.DEFAULT_MATCH_ROOT.resolve())
        body = match.extract_object_function(match.parse_coff_object(obj.read_bytes()), cfg.symbol)
        audit = result.masked_operand_audit
        observed = {
            "scores": rm.ratios(result),
            "instructions": len(result.candidate_lines),
            "prefix": result.prefix_instructions,
            "audit": {
                "matched": audit.ok_count,
                "unresolved": audit.unresolved_count,
                "mismatched": audit.mismatch_count,
            },
            "frame": fp.binary_frames(cfg, obj)["candidate"]["frame_size"],
            "exact": result.exact,
            "body_byte_exact": result.body_byte_exact,
        }
        assert observed == control["expected"], (target, control["name"], observed)
        assert sha(body.data) == control["body_sha256"] and len(body.data) == control["body_bytes"]
        assert sha(replay.normalized_coff(obj)) == control["normalized_coff_sha256"]
        print(target, control["name"], "verified", flush=True)
        return {"target": target, "name": control["name"], "source_sha256": control["source_sha256"]}

    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        rows = list(pool.map(check, jobs))
    receipt = {
        "controls_sha256": sha((HERE / "controls.json").read_bytes()),
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "verified": rows,
        "new_exact_matches": 0,
    }
    (args.out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
