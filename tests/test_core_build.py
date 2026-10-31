"""crimson-core/build.py's choices that need no compiler."""

import importlib
from pathlib import Path

import pytest

from scripts.build_identity import write_manifest

ROOT = Path(__file__).resolve().parents[1]


def test_only_the_module_its_manifest_records_for_these_inputs_is_kept(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "crimson-core"))
    build = importlib.import_module("build")
    module = tmp_path / "core.wasm"
    module.write_bytes(b"\0asm linked")

    # Ninja would keep any module newer than its objects: one without a manifest links again.
    assert not build.recorded(module, "inputs")
    write_manifest(build.manifest(module), {"fingerprint": "inputs"}, [module])
    assert build.recorded(module, "inputs")
    # So does one the build recorded from other inputs, such as an older module restored with its manifest.
    assert not build.recorded(module, "edited inputs")
    # And one whose bytes are no longer the ones the build recorded.
    module.write_bytes(b"\0asm\1\0\0\0")
    assert not build.recorded(module, "inputs")

    # A module that goes takes its manifest with it, and a manifest left alone vouches for nothing.
    build.discard(module)
    assert not module.exists()
    assert not build.manifest(module).exists()
    write_manifest(build.manifest(module), {"fingerprint": "inputs"}, [])
    assert not build.recorded(module, "inputs")
