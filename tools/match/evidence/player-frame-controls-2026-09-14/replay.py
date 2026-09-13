"""Reconstruct and replay player_update source controls; diagnostic only."""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, replace
from pathlib import Path

from crimson import match

HERE = Path(__file__).resolve().parent
SCRATCH = Path("tools/match/scratches/player_update")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def baseline(data):
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required for the pinned baseline")
    source = subprocess.check_output(
        [git, "show", f"{data['baseline_commit']}:{SCRATCH}/scratch.cpp"],
        cwd=match.REPO_ROOT,
    )
    assert sha(source) == data["baseline_source_sha256"]
    return source.decode()


def reconstruct(source, control):
    lines = source.splitlines(keepends=True)
    previous = len(lines)
    for edit in reversed(control["edits"]):
        start, stop = edit["start"], edit["stop"]
        assert 0 <= start <= stop <= previous
        assert "".join(lines[start:stop]) == edit["old"]
        lines[start:stop] = edit["new"].splitlines(keepends=True)
        previous = start
    text = "".join(lines)
    assert sha(text.encode()) == control["observed"]["source_sha256"]
    return text


def compile_source(source, directory, build):
    directory.mkdir(parents=True, exist_ok=True)
    cfg = match.load_scratch_config(match.REPO_ROOT / SCRATCH)
    assert cfg.compiler == build["compiler"] and cfg.cflags == build["cflags"]
    (directory / cfg.source).write_text(source)
    (directory / "scratch.conf").write_bytes((cfg.directory / "scratch.conf").read_bytes())
    cfg = replace(cfg, directory=directory)
    obj = match.compile_scratch(cfg, force=True)
    receipt = json.loads((obj.parent / "scratch-build.json").read_text())
    assert receipt["key"]["toolchain"] == build["toolchain"], "toolchain inputs changed"
    body = match.extract_object_function(match.parse_coff_object(obj.read_bytes()), cfg.symbol)
    result = match.run_match(
        obj_path=obj,
        function=cfg.function,
        symbol_name=cfg.symbol,
        reference_aliases=cfg.reference_aliases,
    )
    for label, rows in [("native", result.target_disassembly), ("candidate", result.candidate_disassembly)]:
        (directory / f"{label}.json").write_text(json.dumps([asdict(row) for row in rows], indent=2) + "\n")
    audit = result.masked_operand_audit
    return {
        "source_sha256": sha(source.encode()),
        "body_sha256": sha(body.data),
        "exact": result.exact,
        "body_byte_exact": result.body_byte_exact,
        "instructions": len(result.candidate_lines),
        "target": len(result.target_lines),
        "prefix": result.prefix_instructions,
        "refs": [audit.ok_count, audit.unresolved_count, audit.mismatch_count],
        "ratio": result.ratio,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--select", default="^cough-returned-pointer$", help="Regex; .* replays all controls")
    parser.add_argument("--reconstruct-only", action="store_true", help="Check source recipes without compiling")
    parser.add_argument("--frames", action="store_true", help="Check ESP propagation for every compiled control")
    args = parser.parse_args()
    if args.reconstruct_only and args.frames:
        parser.error("--frames requires compilation")
    data = json.loads((HERE / "controls.json").read_text())
    source = baseline(data)
    selected = [c for c in data["controls"] if re.search(args.select, c["name"])]
    assert selected, "no matching controls"
    if not args.reconstruct_only:
        for name, expected in data["build"]["dependencies"].items():
            assert sha((match.REPO_ROOT / name).read_bytes()) == expected, name
    results = []
    controls = [{"name": "baseline", "observed": data["baseline"]}, *selected]
    for control in controls:
        text = source if control["name"] == "baseline" else reconstruct(source, control)
        directory = args.out.resolve() / control["name"]
        if args.reconstruct_only:
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "scratch.cpp").write_text(text)
            measured = {"source_sha256": sha(text.encode())}
        else:
            measured = compile_source(text, directory, data["build"])
        assert measured == {key: control["observed"][key] for key in measured}, control["name"]
        row = {"name": control["name"], **measured}
        if args.frames:
            subprocess.run([sys.executable, str(HERE / "frame_map.py"), str(directory)], check=True)
            row["frame"] = json.loads((directory / "frame-summary.json").read_text())
        results.append(row)
        print(json.dumps(row), flush=True)
    (args.out.resolve() / "replay-results.json").write_text(json.dumps(results, indent=2) + "\n")
    receipt = {
        "schema": 1,
        "inputs": {name: sha((HERE / name).read_bytes()) for name in ["controls.json", "replay.py", "frame_map.py"]},
        "mode": "reconstruct" if args.reconstruct_only else "compile",
        "frames_checked": args.frames,
        "results": results,
    }
    (args.out.resolve() / "results.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
