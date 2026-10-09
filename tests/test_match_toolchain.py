from __future__ import annotations

import os
from pathlib import Path

import pytest

from crimson_re import match as matchlib
from crimson_re.match_toolchain import tree_set_sha256


@pytest.mark.parametrize("dependency", ["Include/sdk.h", "runner"])
def test_build_and_epoch_track_actual_compiler_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    dependency: str,
) -> None:
    root = tmp_path / "match"
    bundle = root / "compilers/msvc6.5"
    (bundle / "Bin").mkdir(parents=True)
    (bundle / "Include").mkdir()
    (bundle / "Bin/CL.EXE").write_bytes(b"compiler")
    (bundle / "Bin/C2.DLL").write_bytes(b"backend-a")
    (bundle / "Include/sdk.h").write_text("#define VALUE 1\n")
    (root / "cl.sh").write_text("wrapper\n")
    runner = tmp_path / "wibo"
    runner.write_bytes(b"runner-a")
    runner.chmod(0o755)
    monkeypatch.setenv("WIBO", str(runner))
    scratch = root / "scratches/foo"
    scratch.mkdir(parents=True)
    (scratch / "scratch.cpp").write_text("#include <sdk.h>\nint foo(void) { return VALUE; }\n")
    (scratch / "scratch.conf").write_text("FUNCTION=game_is_full_version\n")
    config = matchlib.ScratchConfig(
        scratch,
        "game_is_full_version",
        "crimsonland.exe",
        "msvc6.5",
        "/O2",
        "scratch.cpp",
        None,
        None,
        "",
    )
    key = matchlib._scratch_build_key(config, root)
    epoch = matchlib.scratch_experiment_epoch(config, root)
    path = runner if dependency == "runner" else bundle / dependency
    old = path.stat()
    path.write_bytes(path.read_bytes().replace(b"a", b"b").replace(b"1", b"2"))
    os.utime(path, ns=(old.st_atime_ns, old.st_mtime_ns))
    assert matchlib._scratch_build_key(config, root) != key
    assert matchlib.scratch_experiment_epoch(config, root) != epoch


def test_tree_fingerprint_ignores_hidden_entries(tmp_path: Path) -> None:
    (tmp_path / "Include").mkdir()
    (tmp_path / "Include/windows.h").write_text("int x;")
    clean = tree_set_sha256(tmp_path, ("Include",))
    (tmp_path / "Include/.DS_Store").write_bytes(b"finder")
    (tmp_path / "Include/.claude").mkdir()
    (tmp_path / "Include/.claude/state").write_text("tool")
    assert tree_set_sha256(tmp_path, ("Include",)) == clean
    (tmp_path / "Include/windows.h").write_text("int y;")
    assert tree_set_sha256(tmp_path, ("Include",)) != clean
