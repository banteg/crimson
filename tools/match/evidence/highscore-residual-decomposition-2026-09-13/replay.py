"""Replay source controls against the pinned highscore baseline; diagnostic only."""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from dataclasses import asdict, replace
from pathlib import Path

from crimson import match

HERE = Path(__file__).resolve().parent
SCRATCH = Path("tools/match/scratches/highscore_screen_update")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def baseline(data):
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required for the pinned baseline")
    source = subprocess.check_output(
        [git, "show", f"{data['base_commit']}:{SCRATCH}/scratch.cpp"],
        cwd=match.REPO_ROOT,
    )
    assert sha(source) == data["baseline"]["source_sha256"]
    return source.decode()


def reconstruct(source, control):
    lines = source.splitlines(keepends=True)
    previous = len(lines)
    for edit in reversed(control["edits"]):
        assert 0 <= edit["start"] <= edit["end"] <= previous
        lines[edit["start"] : edit["end"]] = edit["lines"]
        previous = edit["start"]
    text = "".join(lines)
    assert sha(text.encode()) == control["source_sha256"]
    return text


def compile_source(source, directory):
    directory.mkdir(parents=True, exist_ok=True)
    cfg = match.load_scratch_config(match.REPO_ROOT / SCRATCH)
    (directory / cfg.source).write_text(source)
    (directory / "scratch.conf").write_bytes((cfg.directory / "scratch.conf").read_bytes())
    cfg = replace(cfg, directory=directory)
    obj = match.compile_scratch(cfg, force=True)
    body = match.extract_object_function(match.parse_coff_object(obj.read_bytes()), cfg.symbol)
    result = match.run_match(
        obj_path=obj,
        function=cfg.function,
        symbol_name=cfg.symbol,
        reference_aliases=cfg.reference_aliases,
    )
    for label, rows in [("native", result.target_disassembly), ("candidate", result.candidate_disassembly)]:
        (directory / f"{label}.json").write_text(json.dumps([asdict(row) for row in rows], indent=2) + "\n")
    return body, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--select", default="^date-signed$", help="Regex; use .* to replay every control")
    args = parser.parse_args()
    data = json.loads((HERE / "controls.json").read_text())
    source = baseline(data)
    selected = [c for c in data["controls"] if re.search(args.select, c["name"])]
    assert selected, "no matching controls"
    for control in [data["baseline"], *selected]:
        text = source if control["name"] == "baseline" else reconstruct(source, control)
        body, result = compile_source(text, args.out.resolve() / control["name"])
        audit = result.masked_operand_audit
        measured = {
            "source_sha256": sha(text.encode()),
            "body_sha256": sha(body.data),
            "exact": result.exact,
            "body_byte_exact": result.body_byte_exact,
            "instructions": len(result.candidate_lines),
            "target": len(result.target_lines),
            "prefix": result.prefix_instructions,
            "refs": [audit.ok_count, audit.unresolved_count, audit.mismatch_count],
            "ratio": result.ratio,
        }
        assert measured == {key: control[key] for key in measured}, control["name"]
        print(json.dumps({"name": control["name"], **measured}), flush=True)


if __name__ == "__main__":
    main()
