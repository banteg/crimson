"""Reconstruct and independently compile the bounded filter-storage controls."""

import argparse
import hashlib
import json
import shutil
import subprocess
from dataclasses import asdict, replace
from pathlib import Path

from crimson import match

HERE = Path(__file__).resolve().parent
SCRATCH = Path("tools/match/scratches/highscore_screen_update")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def sources():
    data = json.loads((HERE / "controls.json").read_text())
    git = shutil.which("git")
    assert git is not None
    baseline = subprocess.check_output(
        [git, "show", f"{data['base_commit']}:{SCRATCH}/scratch.cpp"],
        cwd=match.REPO_ROOT,
    )
    assert sha(baseline) == data["base_source_sha256"]
    result = {}
    for row in data["controls"]:
        lines = baseline.decode().splitlines(keepends=True)
        previous = len(lines)
        for edit in reversed(row["edits"]):
            assert 0 <= edit["start"] <= edit["end"] <= previous
            lines[edit["start"] : edit["end"]] = edit["lines"]
            previous = edit["start"]
        source = "".join(lines)
        assert sha(source.encode()) == row["source_sha256"]
        result[row["name"]] = source, row
    return result


def build(name, root):
    source, expected = sources()[name]
    cfg = match.load_scratch_config(match.REPO_ROOT / SCRATCH)
    assert cfg.compiler == "msvc6.5" and cfg.cflags == "/O2 /GB /W3 /GR-"
    directory = root / name
    directory.mkdir(parents=True, exist_ok=True)
    (directory / cfg.source).write_text(source)
    (directory / "scratch.conf").write_bytes((cfg.directory / "scratch.conf").read_bytes())
    cfg = replace(cfg, directory=directory)
    obj = match.compile_scratch(cfg, force=True)
    body = match.extract_object_function(match.parse_coff_object(obj.read_bytes()), cfg.symbol)
    r = match.run_match(
        obj_path=obj,
        function=cfg.function,
        symbol_name=cfg.symbol,
        reference_aliases=cfg.reference_aliases,
    )
    audit = r.masked_operand_audit
    actual = {
        "body_sha256": sha(body.data),
        "instructions": len(r.candidate_lines),
        "ratio": r.ratio,
        "prefix": r.prefix_instructions,
        "references": [audit.ok_count, audit.unresolved_count, audit.mismatch_count],
        "exact": r.exact,
        "body_byte_exact": r.body_byte_exact,
    }
    assert actual == {key: expected[key] for key in actual}, name
    for label, rows in [("native", r.target_disassembly), ("candidate", r.candidate_disassembly)]:
        (directory / f"{label}.json").write_text(json.dumps([asdict(row) for row in rows], indent=2) + "\n")
        (directory / f"{label}.asm").write_text("\n".join(f"{x.address:#x}: {x.text}" for x in rows) + "\n")
    return cfg, obj, body, r


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    for name in sources():
        build(name, args.out)
        print("Verified", name, flush=True)
