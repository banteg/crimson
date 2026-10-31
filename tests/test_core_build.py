"""crimson-core/build.py's choices that need no compiler."""

import importlib
from pathlib import Path

import pytest

from scripts.build_identity import write_manifest

ROOT = Path(__file__).resolve().parents[1]


def test_only_the_module_its_manifest_records_is_kept(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "crimson-core"))
    build = importlib.import_module("build")
    module = tmp_path / "core.wasm"
    module.write_bytes(b"\0asm linked")

    # Ninja would keep any module newer than its objects: one without a manifest links again.
    assert not build.recorded(module)
    write_manifest(module.with_name("core.wasm.build.json"), {}, [module])
    assert build.recorded(module)
    # So does one whose bytes are no longer the ones the build recorded.
    module.write_bytes(b"\0asm\1\0\0\0")
    assert not build.recorded(module)
