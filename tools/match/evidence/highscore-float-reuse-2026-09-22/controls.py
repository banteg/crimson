"""Rebuild the bounded float-expression ownership controls; none is promoted."""

import argparse
import importlib.util
import json
from dataclasses import asdict, replace
from pathlib import Path

from crimson import match

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "filter_controls",
    HERE.parent / "highscore-filter-storage-2026-09-22/controls.py",
)
previous = importlib.util.module_from_spec(spec)
spec.loader.exec_module(previous)
sha = previous.sha


def sources():
    data = json.loads((HERE / "controls.json").read_text())
    base, _ = previous.sources()[data["base_control"]]
    assert sha(base.encode()) == data["base_source_sha256"]
    canonical = previous.sources()["baseline"][0]
    assert sha(canonical.encode()) == "e214b927b4836da4ac731f80e24380580d324421e58945dc987c8b2f4e971abd"
    result = {"baseline": (base, None), "canonical": (canonical, None)}
    for row in data["controls"]:
        lines = base.splitlines(keepends=True)
        boundary = len(lines)
        for edit in reversed(row["edits"]):
            assert 0 <= edit["start"] <= edit["end"] <= boundary
            lines[edit["start"] : edit["end"]] = edit["lines"]
            boundary = edit["start"]
        source = "".join(lines)
        assert sha(source.encode()) == row["source_sha256"]
        result[row["name"]] = source, row
    return result


def measure(obj, cfg, directory):
    body = match.extract_object_function(match.parse_coff_object(obj.read_bytes()), cfg.symbol)
    r = match.run_match(
        obj_path=obj,
        function=cfg.function,
        symbol_name=cfg.symbol,
        reference_aliases=cfg.reference_aliases,
    )
    audit = r.masked_operand_audit
    measured = {
        "body_sha256": sha(body.data),
        "instructions": len(r.candidate_lines),
        "ratio": r.ratio,
        "prefix": r.prefix_instructions,
        "refs": [audit.ok_count, audit.unresolved_count, audit.mismatch_count],
        "exact": r.exact,
        "body_byte_exact": r.body_byte_exact,
    }
    for name, rows in [("native", r.target_disassembly), ("candidate", r.candidate_disassembly)]:
        (directory / f"{name}.json").write_text(json.dumps([asdict(v) for v in rows], indent=2) + "\n")
    return body, r, measured


def build(name, root):
    source, expected = sources()[name]
    cfg = match.load_scratch_config(match.REPO_ROOT / previous.SCRATCH)
    assert cfg.compiler == "msvc6.5" and cfg.cflags == "/O2 /GB /W3 /GR-"
    directory = root / name
    directory.mkdir(parents=True, exist_ok=True)
    (directory / cfg.source).write_text(source)
    (directory / "scratch.conf").write_bytes((cfg.directory / "scratch.conf").read_bytes())
    cfg = replace(cfg, directory=directory)
    obj = match.compile_scratch(cfg, force=True)
    body, result, measured = measure(obj, cfg, directory)
    if expected is None:
        assert (
            measured["body_sha256"]
            == {
                "baseline": "9e60f1b6688db4c84699d44b280e46f0afce439b0cbb6c19280ae2adc84178e3",
                "canonical": "68b5c4a6e7eaf848be291652e8e47e673eef6dea746719daf74df017c207c392",
            }[name]
        )
    else:
        assert all(measured[k] == expected[k] for k in measured if k in expected), name
    assert not measured["exact"] and not measured["body_byte_exact"]
    return cfg, obj, body, result, measured


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
