from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

from crimson.cli.app import app
from crimson_re.match import NativeLinkStatus
from crimson_re.native_link import NativeAuditArtifacts


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


def test_native_audit_cli_can_require_full_game_closure(monkeypatch, tmp_path: Path) -> None:
    audit = _audit(closed=False)
    artifacts = NativeAuditArtifacts(
        object_manifest=tmp_path / "objects.json",
        object_list=tmp_path / "objects.txt",
        export_definition=tmp_path / "exports.def",
        symbol_closure=tmp_path / "closure.json",
        data_manifest=tmp_path / "data.json",
    )
    monkeypatch.setattr("crimson_re.cli.native.native_link.build_native_audit", lambda *args, **kwargs: audit)
    monkeypatch.setattr("crimson_re.cli.native.native_link.write_native_audit", lambda *args, **kwargs: artifacts)

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


def test_native_verify_cli_rejects_stale_artifacts_before_gate(monkeypatch) -> None:
    monkeypatch.setattr(
        "crimson_re.cli.native.matchlib.collect_native_link_statuses",
        lambda **kwargs: [
            NativeLinkStatus(
                image="grim.dll",
                artifact_state="stale",
                artifact_note="recorded input changed",
                game_owned_closure=True,
            ),
        ],
    )

    completed = CliRunner().invoke(
        app,
        [
            "native",
            "verify",
            "--image",
            "grim.dll",
            "--require-game-closure",
        ],
    )

    assert completed.exit_code == 2
    assert "artifact_note=recorded input changed" in completed.stdout


def test_native_verify_cli_rejects_open_game_closure(monkeypatch) -> None:
    monkeypatch.setattr(
        "crimson_re.cli.native.matchlib.collect_native_link_statuses",
        lambda **kwargs: [
            NativeLinkStatus(
                image="grim.dll",
                artifact_state="current",
                artifact_note="verified",
                game_owned_closure=False,
            ),
        ],
    )

    completed = CliRunner().invoke(
        app,
        [
            "native",
            "verify",
            "--image",
            "grim.dll",
            "--require-game-closure",
        ],
    )

    assert completed.exit_code == 1
