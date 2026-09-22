"""Rebuild highscore quest and operand-ordering source controls."""

import argparse
import importlib.util
import json
from dataclasses import asdict, replace
from pathlib import Path

from crimson import match

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "label_controls",
    HERE.parent / "highscore-label-bitcopy-2026-09-22/controls.py",
)
previous = importlib.util.module_from_spec(spec)
spec.loader.exec_module(previous)
sha = previous.sha
WITNESS = "quest-arm-direct"


def sources():
    parents = {k: v[0] for k, v in previous.sources().items()}
    result = {}
    for row in json.loads((HERE / "controls.json").read_text())["controls"]:
        source = parents[row["parent"]]
        assert sha(source.encode()) == row["parent_source_sha256"]
        lines = source.splitlines(keepends=True)
        boundary = len(lines)
        for edit in reversed(row["edits"]):
            assert 0 <= edit["start"] <= edit["end"] <= boundary
            lines[edit["start"] : edit["end"]] = edit["lines"]
            boundary = edit["start"]
        source = "".join(lines)
        assert sha(source.encode()) == row["source_sha256"]
        assert row["name"] not in parents
        parents[row["name"]] = source
        result[row["name"]] = source, row
    return result


def measure(obj, cfg):
    body = match.extract_object_function(match.parse_coff_object(obj.read_bytes()), cfg.symbol)
    r = match.run_match(
        obj_path=obj,
        function=cfg.function,
        symbol_name=cfg.symbol,
        reference_aliases=cfg.reference_aliases,
    )
    audit = r.masked_operand_audit
    coff = bytearray(obj.read_bytes())
    coff[4:8] = bytes(4)
    measured = {
        "normalized_coff_sha256": sha(coff),
        "body_sha256": sha(body.data),
        "instructions": len(r.candidate_lines),
        "ratio": r.ratio,
        "prefix": r.prefix_instructions,
        "references": [audit.ok_count, audit.unresolved_count, audit.mismatch_count],
        "exact": r.exact,
        "body_byte_exact": r.body_byte_exact,
    }
    return body, r, measured


def build(name, root):
    source, expected = sources()[name]
    cfg = match.load_scratch_config(match.REPO_ROOT / "tools/match/scratches/highscore_screen_update")
    assert cfg.compiler == "msvc6.5" and cfg.cflags == "/O2 /GB /W3 /GR-"
    directory = root / name
    directory.mkdir(parents=True, exist_ok=True)
    (directory / cfg.source).write_text(source)
    (directory / "scratch.conf").write_bytes((cfg.directory / "scratch.conf").read_bytes())
    cfg = replace(cfg, directory=directory)
    obj = match.compile_scratch(cfg, force=True)
    body, r, measured = measure(obj, cfg)
    assert measured == {k: expected[k] for k in measured}, name
    assert not r.exact and not r.body_byte_exact
    for kind, rows in [("native", r.target_disassembly), ("candidate", r.candidate_disassembly)]:
        (directory / f"{kind}.json").write_text(json.dumps([asdict(v) for v in rows], indent=2) + "\n")
    return cfg, obj, body, r, measured


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    root = parser.parse_args().out.resolve()
    root.mkdir(parents=True, exist_ok=False)
    results = {}
    for name in sources():
        results[name] = build(name, root)[-1]
        print("Verified", name, flush=True)
    (root / "results.json").write_text(json.dumps(results, indent=2) + "\n")
