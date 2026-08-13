from __future__ import annotations

import hashlib
import json
import shutil
import struct
from pathlib import Path

from typer.testing import CliRunner

from crimson.cli.match import match_app
from crimson.match import (
    DEFAULT_IMAGE_PATH,
    IMAGE_REL_I386_REL32,
    LoadedImage,
    ObjectFunction,
    ObjectRelocationReference,
)
from crimson.mod_sdk import (
    DEFAULT_MOD_SDK_MANIFEST,
    _find_masked_fingerprint_hits,
    _pe_linker_version,
    _resolve_oracle_addresses,
    _rich_records,
    load_mod_sdk_manifest,
    mod_sdk_report_payload,
    render_mod_sdk_report,
    validate_mod_sdk,
)


def _write_manifest(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "sdk"
    root.mkdir()
    source = root / "source.cpp"
    source.write_text("extern \"C\" int example() { return 1; }\n", encoding="ascii")
    binary = root / "sample.dll"
    shutil.copyfile(DEFAULT_IMAGE_PATH, binary)
    binary_data = binary.read_bytes()
    rich = _rich_records(binary_data)
    product, count = next(iter(rich.items()))
    linker = _pe_linker_version(binary_data)

    def artifact(path: Path) -> dict[str, object]:
        data = path.read_bytes()
        return {
            "path": path.name,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    payload = {
        "schema": 1,
        "kind": "crimsonland-mod-sdk-provenance",
        "package": {
            "name": "fixture",
            "release": "2003-08-14",
            "root": "sdk",
            "archive": {
                "filename": "sdk.zip",
                "size": 1,
                "sha256": "00" * 32,
            },
            "artifacts": [artifact(source), artifact(binary)],
        },
        "projects": [
            {
                "name": "sample",
                "binary": binary.name,
                "source": source.name,
                "source_files": [source.name],
                "compiler": {
                    "profile": "msvc6.5pp",
                    "product_id": 49,
                    "build": 9044,
                    "flags": ["/O2"],
                    "defines": [],
                },
                "linker_version": list(linker),
                "rich_records": [
                    {
                        "product_id": product[0],
                        "build": product[1],
                        "count": count,
                    },
                ],
                "exports": [{"name": "example", "symbol": "_example"}],
            },
        ],
        "calibration": {
            "oracle_scope": ["fixture source style"],
            "excluded_claims": ["fixture is not game provenance"],
        },
    }
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    return manifest, root


def test_mod_sdk_manifest_pins_source_binary_pair() -> None:
    payload = load_mod_sdk_manifest(DEFAULT_MOD_SDK_MANIFEST)

    assert payload["package"]["release"] == "2003-08-14"
    assert payload["package"]["archive"]["sha256"] == (
        "f81cc70ebe29cf9576b251e8723802dedd7abdd7b6b00a8d15c503ed8ceb786c"
    )
    projects = {project["name"]: project for project in payload["projects"]}
    assert projects["cl_nullmod"]["compiler"]["build"] == 9044
    assert projects["cl_crimsonroks"]["rich_records"][0] == {
        "product_id": 49,
        "build": 9044,
        "count": 2,
    }
    assert projects["cl_crimsonroks"]["oracle"] == {
        "source": "cl_crimsonroks/src/r_roks.cpp",
        "symbol_prefix": "?r",
        "expected_functions": 25,
    }
    assert "Linux ports" in payload["calibration"]["excluded_claims"][-1]


def test_sdk_oracle_fingerprint_masks_linker_words() -> None:
    function = ObjectFunction(
        name="?example@@YAXXZ",
        data=b"\x55\x8b\xec\xe8\x00\x00\x00\x00\xc3",
        relocation_offsets=frozenset({4}),
        relocation_references=(
            ObjectRelocationReference(
                offset=4,
                symbol_name="?callee@@YAXXZ",
                key=None,
                explained=False,
                relocation_type=IMAGE_REL_I386_REL32,
            ),
        ),
    )
    segment = (
        b"\x90"
        + b"\x55\x8b\xec\xe8\x11\x22\x33\x44\xc3"
        + b"\x90"
        + b"\x55\x8b\xec\xe8\xaa\xbb\xcc\xdd\xc3"
    )

    assert _find_masked_fingerprint_hits(function, ((0x1000, segment),)) == (
        0x1001,
        0x100B,
    )


def test_sdk_oracle_uses_caller_xref_to_split_identical_bodies() -> None:
    callee_symbol = "?callee@@YAXXZ"
    caller = ObjectFunction(
        name="?caller@@YAXXZ",
        data=b"\xe8\x00\x00\x00\x00\xc3",
        relocation_offsets=frozenset({1}),
        relocation_references=(
            ObjectRelocationReference(
                offset=1,
                symbol_name=callee_symbol,
                key=None,
                explained=False,
                relocation_type=IMAGE_REL_I386_REL32,
            ),
        ),
    )
    callee = ObjectFunction(name=callee_symbol, data=b"\xc3", relocation_offsets=frozenset())
    mapped = bytearray(0x100)
    caller_va = 0x1010
    callee_va = 0x1040
    struct.pack_into("<i", mapped, caller_va - 0x1000 + 1, callee_va - (caller_va + 5))
    image = LoadedImage(mapped=bytes(mapped), image_base=0x1000, size_of_image=len(mapped))

    resolved, evidence = _resolve_oracle_addresses(
        {caller.name: caller, callee.name: callee},
        {caller.name: (caller_va,), callee.name: (0x1030, callee_va)},
        image,
    )

    assert resolved[callee.name] == callee_va
    assert evidence[callee.name] == "masked-fingerprint+caller-xref"


def test_mod_sdk_provenance_validates_directory_and_reports_drift(tmp_path: Path) -> None:
    manifest, root = _write_manifest(tmp_path)

    report = validate_mod_sdk(root, manifest_path=manifest, compile_exports=False)

    assert report.ok
    assert mod_sdk_report_payload(report)["summary"]["failed"] == 0
    assert "sample ok" in render_mod_sdk_report(report)
    assert "fixture is not game provenance" in render_mod_sdk_report(report)

    (root / "source.cpp").write_text("drift\n", encoding="ascii")
    drifted = validate_mod_sdk(root, manifest_path=manifest, compile_exports=False)
    assert not drifted.ok
    assert any(check.component == "source.cpp" and check.kind == "sha256" for check in drifted.failed)


def test_mod_sdk_cli_provenance_only(tmp_path: Path) -> None:
    manifest, root = _write_manifest(tmp_path)

    result = CliRunner().invoke(
        match_app,
        [
            "mod-sdk",
            "--sdk",
            str(root),
            "--manifest",
            str(manifest),
            "--provenance-only",
            "--check",
        ],
    )

    assert result.exit_code == 0, result.output
    assert result.output.startswith("mod-sdk=ok release=2003-08-14")
    assert "excluded claims:" in result.output
