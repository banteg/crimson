from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from crimson_re.cli.match import match_app
from crimson_re.library_provenance import (
    load_library_provenance,
    validate_library_provenance,
)


def test_library_provenance_reports_artifact_hash_drift(tmp_path: Path) -> None:
    payload = load_library_provenance()
    payload["artifacts"][0]["sha256"] = "00" * 32
    manifest = tmp_path / "library_provenance.json"
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    report = validate_library_provenance(manifest)

    assert not report.ok
    assert any(
        check.artifact == "crimsonland.exe" and check.kind == "sha256" and not check.passed for check in report.failed
    )


def test_library_provenance_reports_synced_file_drift(tmp_path: Path) -> None:
    payload = load_library_provenance()
    jpeg = next(source for source in payload["source_artifacts"] if source["id"] == "ijg-libjpeg-6a")
    jpeg["members"][0]["sha256"] = "00" * 32
    manifest = tmp_path / "library_provenance.json"
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    report = validate_library_provenance(manifest)

    assert any(
        check.artifact == "third_party/headers/jinclude.h"
        and check.kind == "source-member"
        and not check.passed
        for check in report.failed
    )


def test_library_provenance_cli_check() -> None:
    result = CliRunner().invoke(match_app, ["provenance", "--check"])

    assert result.exit_code == 0, result.output
    assert result.output.startswith("provenance=ok")
    assert "crimsonland.exe:d3dx8 ok" in result.output
    assert "grim.dll:libjpeg ok" in result.output


def test_artifact_paths_follow_symlinked_game_bins_but_not_parent_escapes(tmp_path: Path) -> None:
    from crimson_re.library_provenance import _artifact_path

    outside = tmp_path / "outside"
    (outside / "crimsonland").mkdir(parents=True)
    (outside / "crimsonland" / "crimsonland.exe").write_bytes(b"MZ")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "game_bins").symlink_to(outside)

    assert _artifact_path(repo, "game_bins/crimsonland/crimsonland.exe").read_bytes() == b"MZ"
    for escape in ("../outside/crimsonland/crimsonland.exe", "game_bins/../../outside", "/etc/passwd"):
        with pytest.raises(ValueError, match="escapes repository"):
            _artifact_path(repo, escape)
