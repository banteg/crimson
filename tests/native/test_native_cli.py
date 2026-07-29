from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

from crimson.cli import app
from crimson.match import NativeLinkStatus
from crimson.native_link import NativeAuditArtifacts, NativeLinkedImageArtifacts


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


def test_native_link_cli_reports_structural_artifacts(monkeypatch, tmp_path: Path) -> None:
    audit = _audit(closed=True)
    config = object()
    artifacts = NativeLinkedImageArtifacts(
        image=tmp_path / "grim.dll",
        import_library=tmp_path / "grim.lib",
        map_file=tmp_path / "grim.dll.map",
        response_file=tmp_path / "link.rsp",
        log=tmp_path / "link.log",
        manifest=tmp_path / "link.json",
    )
    manifest = {
        "mode": "structural",
        "providers": [{}, {}],
        "runnable": False,
        "status": "linked",
        "summary": {
            "archive_symbols": 32,
            "covered_symbols": 53,
            "generated_import_symbols": 5,
            "import_symbols": 20,
            "link_dependency_symbols": 24,
            "placeholder_symbols": 16,
        },
    }
    monkeypatch.setattr(
        "crimson.cli.native.native_link.build_native_audit",
        lambda *args, **kwargs: audit,
    )
    monkeypatch.setattr(
        "crimson.cli.native.native_link.write_native_audit",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        "crimson.cli.native.native_link.load_native_provider_config",
        lambda *args, **kwargs: config,
    )
    monkeypatch.setattr(
        "crimson.cli.native.native_link.link_native_image",
        lambda *args, **kwargs: (artifacts, manifest),
    )

    completed = CliRunner().invoke(
        app,
        ["native", "link", "--image", "grim.dll", "--out-dir", str(tmp_path)],
    )

    assert completed.exit_code == 0
    assert "image=grim.dll mode=structural status=linked" in completed.stdout
    assert (
        "providers=2 covered=53 imports=20 archives=32 generated_imports=5 "
        "link_deps=24 placeholders=16 runnable=False"
    ) in completed.stdout
    assert f"linked_image={tmp_path / 'grim.dll'}" in completed.stdout


def test_native_verify_cli_gates_both_checked_in_images(monkeypatch) -> None:
    captured = {}

    def collect(**kwargs):
        captured.update(kwargs)
        return [
            NativeLinkStatus(
                image=image,
                artifact_state="current",
                artifact_note="verified",
                function_closure=True,
                game_owned_closure=True,
                all_references_closed=False,
            )
            for image in ("crimsonland.exe", "grim.dll")
        ]

    monkeypatch.setattr(
        "crimson.cli.native.matchlib.collect_native_link_statuses",
        collect,
    )

    completed = CliRunner().invoke(
        app,
        [
            "native",
            "verify",
            "--require-game-closure",
            "--allow-absent-toolchain",
        ],
    )

    assert completed.exit_code == 0
    assert captured["images"] == ("crimsonland.exe", "grim.dll")
    assert captured["allow_absent_toolchain"] is True
    assert "image=crimsonland.exe artifacts=current" in completed.stdout
    assert "image=grim.dll artifacts=current" in completed.stdout


def test_native_verify_cli_rejects_stale_artifacts_before_gate(monkeypatch) -> None:
    monkeypatch.setattr(
        "crimson.cli.native.matchlib.collect_native_link_statuses",
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
        "crimson.cli.native.matchlib.collect_native_link_statuses",
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
