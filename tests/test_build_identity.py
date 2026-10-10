"""Build inputs, compatibility and deployment provenance must remain distinct."""

import json
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from scripts import build_identity as build


@pytest.fixture
def source(tmp_path: Path) -> Path:
    files = {
        "pyproject.toml": '[project]\nname = "crimsonland"\nversion = "1.2.3"\n',
        "uv.lock": "locked dependencies",
        "scripts/build_identity.py": "build planner",
        "src/crimson/game_version.py": "REPLAY_RULES = 1",
        "src/crimson/sim/world.py": "Python simulation",
        "src/grim/geom.py": "geometry",
        "crimson-core/build.py": "compiler flags",
        "crimson-core/sources.json": '["decomp/1.9/crimsonland/gameplay/step.cpp"]',
        "decomp/1.9/crimsonland/gameplay/step.cpp": "gameplay",
        "crimson-core/client/main.cpp": "client",
        "docs/readme.md": "documentation",
    }
    for name, contents in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
    git = shutil.which("git")
    assert git is not None
    subprocess.run([git, "init", "-q", str(tmp_path)], check=True)
    commit(tmp_path)
    return tmp_path


def commit(root: Path) -> None:
    git = shutil.which("git")
    assert git is not None
    subprocess.run([git, "add", "."], cwd=root, check=True)
    subprocess.run([git, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "--allow-empty", "-qm", "test"], cwd=root, check=True)


def game_module(root: Path) -> dict:
    module = root / "crimson-core/build/game/game.wasm"
    module.parent.mkdir(parents=True)
    module.write_bytes(b"\0asm fixture")
    identity = build.runtime_identity("game", root)
    build.write_manifest(module.with_name(module.name + ".build.json"), identity, [module])
    return identity


@pytest.mark.parametrize("target", ["wasm", "game"])
def test_optimization_patches_change_runtime_identity(source: Path, target: str) -> None:
    before = build.runtime_identity(target, source)
    patch = source / "crimson-core/optimizations/survival.patch"
    patch.parent.mkdir(parents=True)
    patch.write_text("optimization patch")
    added = build.runtime_identity(target, source)
    assert added["fingerprint"] != before["fingerprint"]
    assert added["origin"]["dirty"] is True
    commit(source)
    patch.write_text("updated optimization patch")
    assert build.runtime_identity(target, source)["fingerprint"] != added["fingerprint"]


def test_unrelated_commits_and_tags_preserve_identity_but_record_new_provenance(source: Path) -> None:
    before = build.runtime_identity("game", source)
    (source / "docs/readme.md").write_text("another document")
    commit(source)
    git = shutil.which("git")
    assert git is not None
    subprocess.run([git, "tag", "v1.2.3"], cwd=source, check=True)
    after = build.runtime_identity("game", source)
    assert after["fingerprint"] == before["fingerprint"]
    assert after["version"] == before["version"]
    assert after["origin"]["commit"] != before["origin"]["commit"]
    assert after["origin"]["dirty"] is False


@pytest.mark.parametrize("path", ["decomp/1.9/crimsonland/gameplay/step.cpp", "crimson-core/host/new.inc", "crimson-core/game/changes/new.patch", "src/crimson/game_version.py", "crimson-core/build.py"])
def test_edits_and_new_untracked_game_inputs_change_the_identity(source: Path, path: str) -> None:
    before = build.runtime_identity("game", source)
    changed = source / path
    changed.parent.mkdir(parents=True, exist_ok=True)
    changed.write_text("new input")
    after = build.runtime_identity("game", source)
    assert after["fingerprint"] != before["fingerprint"]
    assert after["origin"]["dirty"] is True
    changed.write_text("another edit")
    assert build.runtime_identity("game", source)["fingerprint"] != after["fingerprint"]


def test_python_content_tracks_its_sources_and_dependency_lock(source: Path) -> None:
    before = build.python_identity(source)
    game = build.runtime_identity("game", source)
    (source / "src/crimson/sim/world.py").write_text("changed Python simulation")
    assert build.python_identity(source)["fingerprint"] != before["fingerprint"]
    assert build.runtime_identity("game", source)["fingerprint"] == game["fingerprint"]
    before = build.python_identity(source)
    (source / "uv.lock").write_text("another dependency version")
    assert build.python_identity(source)["fingerprint"] != before["fingerprint"]


def test_toolchain_change_invalidates_game_and_client_inputs(source: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    before = build.runtime_identity("game", source)
    monkeypatch.setattr(build, "ZIG_VERSION", "next-compiler")
    assert build.runtime_identity("game", source)["fingerprint"] != before["fingerprint"]
    game_module(source)
    before = build.client_identity("web", source, wabt="1.0.42", emscripten="6.0.10")
    for wabt, emscripten in [("1.0.43", "6.0.10"), ("1.0.42", "6.0.11")]:
        assert build.client_identity("web", source, wabt=wabt, emscripten=emscripten)["fingerprint"] != before["fingerprint"]


def test_client_edit_reuses_game_and_records_its_own_build(source: Path) -> None:
    game = game_module(source)
    before = build.client_identity("web", source, wabt="1.0.42", emscripten="6.0.10")
    (source / "crimson-core/client/main.cpp").write_text("another client")
    after = build.client_identity("web", source, wabt="1.0.42", emscripten="6.0.10")
    assert build.runtime_identity("game", source)["fingerprint"] == game["fingerprint"]
    assert after["fingerprint"] != before["fingerprint"]
    assert after["version"] != game["version"]
    assert after["game"]["origin"] == game["origin"]


def test_tampered_cached_binary_or_manifest_is_rejected(source: Path) -> None:
    game_module(source)
    module = source / "crimson-core/build/game/game.wasm"
    module.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="Changed build artifact"):
        build.client_identity("web", source, wabt="1.0.42", emscripten="6.0.10")
    manifest = module.with_name(module.name + ".build.json")
    data = json.loads(manifest.read_text())
    data["recipe"]["zig"] = "another compiler"
    manifest.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="Invalid build identity"):
        build.read_manifest(manifest)


def test_node_accepts_the_python_fingerprint_and_original_build_commit(source: Path) -> None:
    # Includes non-ASCII strings to exercise Python/JS canonical JSON agreement.
    (source / "crimson-core/host/é.inc").parent.mkdir(parents=True)
    (source / "crimson-core/host/é.inc").write_text("content")
    commit(source)
    identity = game_module(source)
    node = shutil.which("node")
    assert node is not None
    checker = Path(__file__).resolve().parents[1] / "service/scripts/deploy-checks.mjs"
    script = f"import {{ requireBuildIdentity }} from {json.dumps(checker.as_uri())}; import {{ readFileSync }} from 'node:fs'; requireBuildIdentity(JSON.parse(readFileSync(0, 'utf8')), 'game');"
    subprocess.run([node, "--input-type=module", "-e", script], input=json.dumps(identity), text=True, check=True)


def test_ignored_but_consumed_inputs_are_still_modified_sources(source: Path) -> None:
    (source / ".gitignore").write_text("*.inc\n")
    commit(source)
    ignored = source / "crimson-core/host/ignored.inc"
    ignored.parent.mkdir(parents=True)
    ignored.write_text("compiled even though git ignores it")
    assert build.runtime_identity("game", source)["origin"]["dirty"] is True


def test_an_unrelated_parent_repo_is_not_package_provenance(source: Path) -> None:
    extracted = source / "extracted"
    extracted.mkdir()
    (extracted / "pyproject.toml").write_text('[project]\nversion = "1.2.3"\n')
    (extracted / "src/crimson").mkdir(parents=True)
    (extracted / "src/crimson/game_version.py").write_text("unpacked package")
    assert build.python_identity(extracted)["origin"] == {"commit": None, "dirty": None}


def test_wheel_from_sdist_retains_identity_and_source_provenance_without_git(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    source = tmp_path / "source"
    source.mkdir()
    for name in ("pyproject.toml", "uv.lock", "pypi.md", "build_backend.py"):
        shutil.copy2(root / name, source / name)
    for name in ("src", "crimson-re/src"):
        shutil.copytree(root / name, source / name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "_build.json"))
    shutil.copy2(root / "crimson-re/pyproject.toml", source / "crimson-re/pyproject.toml")
    (source / "scripts").mkdir()
    shutil.copy2(root / "scripts/build_identity.py", source / "scripts/build_identity.py")
    git = shutil.which("git")
    uv = shutil.which("uv")
    assert git is not None and uv is not None
    subprocess.run([git, "init", "-q", str(source)], check=True)
    commit(source)
    expected = build.python_identity(source)
    distributions = tmp_path / "dist"
    # uv's default builds the wheel from the sdist, exercising both PEP 517 hooks.
    subprocess.run([uv, "build", "--out-dir", str(distributions)], cwd=source, check=True, capture_output=True)
    with tarfile.open(next(distributions.glob("*.tar.gz"))) as archive:
        member = next(item for item in archive.getmembers() if item.name.endswith("/src/crimson/_build.json"))
        extracted = archive.extractfile(member)
        assert extracted is not None
        assert json.loads(extracted.read())["fingerprint"] == expected["fingerprint"]
    installation = tmp_path / "installed"
    with zipfile.ZipFile(next(distributions.glob("*.whl"))) as archive:
        metadata = json.loads(archive.read("crimson/_build.json"))
        archive.extractall(installation)
    assert metadata["fingerprint"] == expected["fingerprint"]
    assert metadata["origin"] == expected["origin"]
    assert not (source / "src/crimson/_build.json").exists()
    # Only this wheel and the standard library; no Git executable on PATH.
    script = "from crimson.game_version import current_replay_game_version; print(current_replay_game_version())"
    result = subprocess.check_output([sys.executable, "-S", "-c", script], cwd=tmp_path, env={**os.environ, "PYTHONPATH": str(installation), "PATH": ""}, text=True)
    assert result.strip() == expected["version"]
