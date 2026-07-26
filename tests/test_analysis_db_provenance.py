from __future__ import annotations

import importlib.util
import sys
from argparse import Namespace
from pathlib import Path


def _load_provenance():
    path = Path(__file__).parents[1] / "scripts" / "analysis_db_provenance.py"
    spec = importlib.util.spec_from_file_location("analysis_db_provenance_test", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _args(tmp_path: Path) -> Namespace:
    binary = tmp_path / "program.exe"
    binary.write_bytes(b"program")
    tool_file = tmp_path / "tool"
    tool_file.write_bytes(b"tool")
    return Namespace(
        binary=binary,
        tool_file=tool_file,
        tool="ida",
        tool_version="9.4",
        program="program.exe",
    )


def test_round_trip_accepts_matching_database_provenance(tmp_path: Path) -> None:
    provenance = _load_provenance()
    args = _args(tmp_path)
    state_path = tmp_path / "program.i64.provenance.json"

    expected = provenance.expected_state(args)
    provenance.write_state(state_path, expected)

    assert provenance.check_state(state_path, expected) == []


def test_check_rejects_changed_binary_and_tool(tmp_path: Path) -> None:
    provenance = _load_provenance()
    args = _args(tmp_path)
    state_path = tmp_path / "program.i64.provenance.json"
    provenance.write_state(state_path, provenance.expected_state(args))

    args.binary.write_bytes(b"changed program")
    args.tool_file.write_bytes(b"changed tool")
    mismatches = provenance.check_state(state_path, provenance.expected_state(args))

    assert any(row.startswith("binary_sha256:") for row in mismatches)
    assert any(row.startswith("tool_fingerprint:") for row in mismatches)


def test_check_rejects_missing_or_invalid_state(tmp_path: Path) -> None:
    provenance = _load_provenance()
    args = _args(tmp_path)
    expected = provenance.expected_state(args)
    state_path = tmp_path / "missing.json"

    assert provenance.check_state(state_path, expected) == [
        f"missing provenance file: {state_path}",
    ]

    state_path.write_text("{", encoding="utf-8")
    mismatches = provenance.check_state(state_path, expected)
    assert len(mismatches) == 1
    assert mismatches[0].startswith(f"invalid provenance file {state_path}:")
