"""Rebuild the float ownership controls culminating in a complete stock match."""

import importlib.util
import json
import sys
from dataclasses import asdict, replace
from pathlib import Path

from crimson import match

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "state_controls",
    HERE.parent / "highscore-state-owners-2026-09-22/controls.py",
)
previous = importlib.util.module_from_spec(spec)
spec.loader.exec_module(previous)
sha = previous.sha
measure = previous.measure
WITNESS = "separator-double-center"


def previous_module(filename):
    """Load a historical verifier with its own controls, not this package's."""
    saved = {key: sys.modules.get(key) for key in ("controls", "verify")}
    try:
        sys.modules["controls"] = previous
        if filename == "verify_compiler.py":
            sys.modules["verify"] = previous_module("verify.py")
        spec = importlib.util.spec_from_file_location("state_" + filename[:-3], previous.HERE / filename)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for key, value in saved.items():
            if value is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = value


def sources():
    parent = previous.sources()[previous.WITNESS][0]
    result = {}
    for row in json.loads((HERE / "controls.json").read_text())["controls"]:
        assert row["parent"] == previous.WITNESS
        assert sha(parent.encode()) == row["parent_source_sha256"]
        lines = parent.splitlines(keepends=True)
        boundary = len(lines)
        for edit in reversed(row["edits"]):
            assert 0 <= edit["start"] <= edit["end"] <= boundary
            lines[edit["start"] : edit["end"]] = edit["lines"]
            boundary = edit["start"]
        source = "".join(lines)
        assert sha(source.encode()) == row["source_sha256"]
        assert row["name"] not in result
        result[row["name"]] = source, row
    return result


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
    body, report, measured = measure(obj, cfg)
    assert measured == {k: expected[k] for k in measured}, name
    assert report.exact == report.body_byte_exact == (name == WITNESS)
    for kind, rows in (("native", report.target_disassembly), ("candidate", report.candidate_disassembly)):
        (directory / f"{kind}.json").write_text(json.dumps([asdict(v) for v in rows], indent=2) + "\n")
    return cfg, obj, body, report, measured
