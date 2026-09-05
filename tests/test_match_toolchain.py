from __future__ import annotations

import os
from pathlib import Path

import pytest

from crimson import match as matchlib
from crimson.match_toolchain import file_sha256


@pytest.mark.parametrize("dependency", ["Bin/C2.DLL", "Include/sdk.h", "runner"])
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


def test_content_fingerprint_detects_preserved_mtime(tmp_path: Path) -> None:
    source = tmp_path / "source.cpp"
    source.write_text("return 1;")
    initial = file_sha256(source)
    stat = source.stat()
    source.write_text("return 2;")
    os.utime(source, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    assert file_sha256(source) != initial


@pytest.mark.parametrize("artifact_state", ["current", "stale"])
def test_ci_uses_recorded_epoch_only_from_verified_current_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_state: str,
) -> None:
    import json

    root = tmp_path / "tools/match"
    scratch = root / "scratches/foo"
    scratch.mkdir(parents=True)
    (scratch / "scratch.conf").write_text("FUNCTION=game_is_full_version\n")
    (scratch / "scratch.cpp").write_text("int game_is_full_version(void) { return 1; }\n")
    artifact_root = tmp_path / "analysis/native"
    image = artifact_root / "crimsonland.exe"
    image.mkdir(parents=True)
    recorded = "a" * 64
    (image / "objects.json").write_text(
        json.dumps(
            {
                "objects": [
                    {
                        "functions": [
                            {
                                "canonical_scratch": "tools/match/scratches/foo",
                                "experiment_epoch": recorded,
                            },
                        ],
                    },
                ],
            },
        ),
    )
    monkeypatch.setattr(matchlib, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(matchlib, "DEFAULT_MATCH_ROOT", root)
    monkeypatch.setattr(matchlib, "DEFAULT_NATIVE_ANALYSIS_ROOT", artifact_root)
    monkeypatch.setattr(
        matchlib, "_compiler_executable_path", lambda config, match_root: tmp_path / "missing/Bin/CL.EXE",
    )
    monkeypatch.setattr(
        matchlib,
        "collect_native_link_statuses",
        lambda **kwargs: [
            matchlib.NativeLinkStatus("crimsonland.exe", artifact_state, "verified by test fixture"),
        ],
    )
    epochs = matchlib.scratch_experiment_epochs(root, directories=[scratch])
    assert (epochs[scratch.resolve()] == recorded) is (artifact_state == "current")
