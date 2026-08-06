from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from crimson.cli.match import match_app
from crimson.library_provenance import (
    DEFAULT_PROVENANCE_PATH,
    load_library_provenance,
    render_provenance_report,
    validate_library_provenance,
)


def test_library_provenance_manifest_validates_current_binaries() -> None:
    payload = load_library_provenance()
    report = validate_library_provenance()

    assert report.ok
    assert not report.failed
    directx = next(source for source in payload["source_artifacts"] if source["id"] == "directx-8.1-sdk-full")
    assert directx["members"][0]["sha256"] == "39a8e21889a7c1f0b966f04a9e7d392de14ddebb3e091dfa1e5ce3e19564fc28"
    xiph = next(
        source for source in payload["source_artifacts"] if source["id"] == "xiph-ogg-vorbis-win32sdk-1.0"
    )
    assert xiph["sha256"] == "e40f25803224ce4fee102e74d97c1bf77231986a9acc33eb613232e860fee7fe"
    assert len(xiph["members"]) == 3
    vc6 = next(source for source in payload["source_artifacts"] if source["id"] == "visual-cpp-6-sp6-media")
    assert vc6["members"][-2]["sha256"] == "a541c95e5ffdd6d5573d1976f5e5d0038f2c4fb0bcb02975c68948bf1d6e452a"
    assert vc6["members"][-1]["sha256"] == "3efc3ddf045a459a2b6403f0b821be2cb7c316ffca67dddddb346cea7a9e4f63"
    derived = {artifact["id"]: artifact for artifact in payload["derived_artifacts"]}
    assert derived["ijg-libjpeg-6a-vc6-jaz-provider"]["sha256"] == (
        "c0bf240e27e8684357c676030e3cb8913d04e6b1e14f8000f069b43b17de6869"
    )
    assert derived["zlib-1.1.3-vc6-provider"]["sha256"] == (
        "6b44ac2a8a67123b929cb9286c343730af5f6777609a54e12e402e5ac7e503b0"
    )
    archive_match = payload["archive_matches"][0]
    assert [target["artifact"] for target in archive_match["targets"]] == ["crimsonland.exe", "grim.dll"]
    crt_match = next(match for match in payload["archive_matches"] if match["component"] == "msvc6-crt")
    assert [target["artifact"] for target in crt_match["targets"]] == ["crimsonland.exe", "grim.dll"]
    assert crt_match["targets"][1]["start"] == "0x1000A8D0"
    dll_crt_match = next(
        match
        for match in payload["archive_matches"]
        if match["component"] == "msvc6-dll-crt"
    )
    assert dll_crt_match["targets"][0]["artifact"] == "grim.dll"
    assert dll_crt_match["targets"][0]["unique_functions"] == 4
    assert any(check.component == "libjpeg" and check.kind == "fingerprint" and check.passed for check in report.checks)
    assert (
        sum(
            check.kind == "source-member"
            and check.artifact in {"ogg.dll", "vorbis.dll", "vorbisfile.dll"}
            and check.passed
            for check in report.checks
        )
        == 3
    )
    assert sum(check.component == "ijg-libjpeg-6a" and check.passed for check in report.checks) == 8
    assert sum(check.component == "zlib-1.1.3" and check.passed for check in report.checks) == 14
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


def test_library_provenance_rejects_unknown_source_artifact(tmp_path: Path) -> None:
    payload = load_library_provenance()
    payload["artifacts"][0]["components"][0]["source_artifact"] = "missing-sdk"
    manifest = tmp_path / "library_provenance.json"
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="unknown source artifact"):
        load_library_provenance(manifest)


def test_library_provenance_reports_source_member_drift(tmp_path: Path) -> None:
    payload = load_library_provenance()
    xiph = next(
        source for source in payload["source_artifacts"] if source["id"] == "xiph-ogg-vorbis-win32sdk-1.0"
    )
    xiph["members"][0]["sha256"] = "00" * 32
    manifest = tmp_path / "library_provenance.json"
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    report = validate_library_provenance(manifest)

    assert any(
        check.artifact == "ogg.dll" and check.kind == "source-member" and not check.passed
        for check in report.failed
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


def test_render_library_provenance_report_is_concise() -> None:
    report = validate_library_provenance(DEFAULT_PROVENANCE_PATH)

    rendered = render_provenance_report(report)

    assert "failed=0" in rendered
    assert "crimsonland.exe<->grim.dll:d3dx8 ok checks=3" in rendered
