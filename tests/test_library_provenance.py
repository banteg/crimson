from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from crimson.cli.match import match_app
from crimson.library_provenance import (
    DEFAULT_PROVENANCE_PATH,
    load_library_provenance,
    render_provenance_report,
    validate_library_provenance,
)


def test_library_provenance_manifest_validates_current_binaries() -> None:
    report = validate_library_provenance()

    assert report.ok
    assert not report.failed
    assert any(check.component == "libjpeg" and check.kind == "fingerprint" and check.passed for check in report.checks)
    assert sum(check.component == "d3dx8" and check.kind == "cross-image" for check in report.checks) == 3


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


def test_library_provenance_cli_check() -> None:
    result = CliRunner().invoke(match_app, ["provenance", "--check"])

    assert result.exit_code == 0, result.output
    assert result.output.startswith("provenance=ok")
    assert "crimsonland.exe:d3dx8 ok" in result.output
    assert "grim.dll:libjpeg ok" in result.output


def test_render_library_provenance_report_is_concise() -> None:
    report = validate_library_provenance(DEFAULT_PROVENANCE_PATH)

    rendered = render_provenance_report(report)

    assert "failed=0" in rendered
    assert "crimsonland.exe<->grim.dll:d3dx8 ok checks=3" in rendered
