from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

from crimson.cli import app
from crimson.native_link import NativeAuditArtifacts


def _audit(*, closed: bool):
    return SimpleNamespace(
        object_manifest={
            "abi_assertions": {"status": "passed"},
            "object_count": 137,
            "states": {"match": 130, "wip": 7},
        },
        symbol_closure={
            "summary": {
                "all_references_closed": False,
                "function_closure": True,
                "game_function_debt": {},
                "game_owned_closure": closed,
                "hard_duplicate_by_section": {},
                "hard_duplicate_symbols": 0,
                "resolved_symbols": 39,
                "unresolved_by_category": {"game_data": 154},
                "unresolved_symbols": 154,
            },
        },
        data_manifest={
            "summary": {
                "entry_count": 273,
                "explicit_alignment_entries": 0,
                "explicit_initializer_entries": 0,
                "explicit_size_entries": 0,
                "typed_entries": 182,
            },
        },
    )


def test_native_audit_cli_reports_artifacts(monkeypatch, tmp_path: Path) -> None:
    audit = _audit(closed=False)
    artifacts = NativeAuditArtifacts(
        object_manifest=tmp_path / "objects.json",
        object_list=tmp_path / "objects.txt",
        export_definition=tmp_path / "exports.def",
        symbol_closure=tmp_path / "closure.json",
        data_manifest=tmp_path / "data.json",
    )
    monkeypatch.setattr("crimson.cli.native.native_link.build_native_audit", lambda *args, **kwargs: audit)
    monkeypatch.setattr("crimson.cli.native.native_link.write_native_audit", lambda *args, **kwargs: artifacts)

    completed = CliRunner().invoke(
        app,
        ["native", "audit", "--image", "grim.dll", "--out-dir", str(tmp_path)],
    )

    assert completed.exit_code == 0
    assert "objects=137 states={'match': 130, 'wip': 7} abi=passed" in completed.stdout
    assert "function_closed=True game_owned_closed=False" in completed.stdout
    assert "function_debt={} duplicate_sections={}" in completed.stdout
    assert f"symbol_closure={tmp_path / 'closure.json'}" in completed.stdout


def test_native_audit_cli_can_require_full_game_closure(monkeypatch, tmp_path: Path) -> None:
    audit = _audit(closed=False)
    artifacts = NativeAuditArtifacts(
        object_manifest=tmp_path / "objects.json",
        object_list=tmp_path / "objects.txt",
        export_definition=tmp_path / "exports.def",
        symbol_closure=tmp_path / "closure.json",
        data_manifest=tmp_path / "data.json",
    )
    monkeypatch.setattr("crimson.cli.native.native_link.build_native_audit", lambda *args, **kwargs: audit)
    monkeypatch.setattr("crimson.cli.native.native_link.write_native_audit", lambda *args, **kwargs: artifacts)

    completed = CliRunner().invoke(
        app,
        [
            "native",
            "audit",
            "--image",
            "grim.dll",
            "--out-dir",
            str(tmp_path),
            "--require-game-closure",
        ],
    )

    assert completed.exit_code == 1
