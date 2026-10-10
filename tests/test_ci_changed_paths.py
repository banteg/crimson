"""Keep required CI gates aligned with the paths their suites cover."""

import shutil
import subprocess
from pathlib import Path

import pytest

from scripts.ci_changed_paths import changed_paths, relevant, version_bump_only


def test_rename_checks_both_old_and_new_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    git = shutil.which("git")
    assert git is not None

    def run(*args: str) -> None:
        subprocess.run([git, *args], cwd=tmp_path, check=True, capture_output=True)

    run("init", "-q")
    (tmp_path / "src").mkdir()
    (tmp_path / "src/a.py").write_text("same contents\n")
    run("add", "src/a.py")
    run("-c", "user.name=CI", "-c", "user.email=ci@example.invalid", "commit", "-qm", "base")
    base = subprocess.check_output([git, "rev-parse", "HEAD"], cwd=tmp_path, text=True).strip()

    (tmp_path / "docs").mkdir()
    run("mv", "src/a.py", "docs/a.md")
    run("-c", "user.name=CI", "-c", "user.email=ci@example.invalid", "commit", "-qam", "rename")

    monkeypatch.chdir(tmp_path)
    assert set(changed_paths(base)) == {"src/a.py", "docs/a.md"}
    assert not relevant("pytest", ["docs/a.md"])
    assert relevant("pytest", changed_paths(base))


def test_a_release_version_bump_is_not_a_change(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    git = shutil.which("git")
    assert git is not None

    def commit(pyproject: str, lock: str) -> str:
        (tmp_path / "pyproject.toml").write_text(pyproject)
        (tmp_path / "uv.lock").write_text(lock)
        subprocess.run([git, "add", "."], cwd=tmp_path, check=True)
        subprocess.run(
            [git, "-c", "user.name=CI", "-c", "user.email=ci@example.invalid", "commit", "-qm", "c"],
            cwd=tmp_path,
            check=True,
        )
        return subprocess.check_output([git, "rev-parse", "HEAD"], cwd=tmp_path, text=True).strip()

    def files(version: str, dependency: str) -> tuple[str, str]:
        pyproject = f'[project]\nname = "crimsonland"\nversion = "{version}"\ndependencies = ["{dependency}"]\n'
        lock = (
            f'[[package]]\nname = "crimsonland"\nversion = "{version}"\nsource = {{ editable = "." }}\n\n'
            f'[[package]]\nname = "{dependency}"\nversion = "1.0"\nsource = {{ registry = "https://pypi.org/simple" }}\n'
        )
        return pyproject, lock

    subprocess.run([git, "init", "-q"], cwd=tmp_path, check=True)
    base = commit(*files("0.14.0", "msgspec"))
    monkeypatch.chdir(tmp_path)

    commit(*files("0.14.1", "msgspec"))
    assert version_bump_only(base, "pyproject.toml")
    assert version_bump_only(base, "uv.lock")

    commit(*files("0.14.1", "zstandard"))
    assert not version_bump_only(base, "pyproject.toml")
    assert not version_bump_only(base, "uv.lock")


def test_a_suite_runs_for_the_code_its_checks_import(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(Path(__file__).resolve().parents[1])

    # The gate steps the simulation; the menus never run in it.
    assert relevant("core-gate", ["src/crimson/sim/world_state.py"])
    assert not relevant("core-gate", ["src/crimson/screens/actions.py"])
    # The decomp report runs the matching tools, not the trace debugger.
    assert relevant("decomp", ["crimson-re/src/crimson_re/match.py"])
    assert not relevant("decomp", ["crimson-re/src/crimson_re/dbg/trace.py"])
    # The game build compiles in the version, format and rules, and imports nothing else of the port.
    assert relevant("client", ["src/crimson/game_version.py"])
    assert not relevant("client", ["src/crimson/sim/world_state.py"])


@pytest.mark.parametrize(
    "path",
    [
        "crimson-core/host/session.inc",
        "crimson-core/host/watch.inc",
        "crimson-core/host/keyframes.inc",
        "crimson-core/game.py",
        "third_party/sources/zlib/inflate.c",
    ],
)
def test_game_only_inputs_do_not_rebuild_or_replay_the_verifier(path: str) -> None:
    assert relevant("game-build", [path])
    assert relevant("core-game", [path])
    assert relevant("client", [path])
    for suite in ("core-build", "core-corpus", "core-gate", "core-oracles", "service"):
        assert not relevant(suite, [path]), suite


@pytest.mark.parametrize(
    "path",
    ["decomp/1.9/crimsonland/gameplay/player_update_heading.cpp", "crimson-core/optimizations/new-optimization.patch"],
)
def test_a_compiled_gameplay_source_reaches_every_runtime_consumer(path: str) -> None:
    for suite in (
        "core-build",
        "game-build",
        "core-corpus",
        "core-gate",
        "core-game",
        "core-oracles",
        "client",
        "service",
    ):
        assert relevant(suite, [path]), suite


def test_new_presentation_sources_and_headers_keep_build_coverage() -> None:
    assert relevant("game-build", ["decomp/1.9/grim/render/new_renderer.cpp"])
    assert not relevant("core-build", ["decomp/1.9/grim/render/new_renderer.cpp"])
    assert relevant("core-build", ["tools/match/include/new_header.h"])
    assert relevant("core-build", ["crimson-core/abi/new-repair.patch"])
    assert relevant("core-build", ["crimson-core/optimizations/new-optimization.patch"])
    assert relevant("core-build", ["crimson-core/seams/new-input.patch"])
    assert not relevant("core-build", ["crimson-core/game/changes/new-host.patch"])


def test_native_oracle_does_not_import_unused_parent_fixtures() -> None:
    assert not relevant("native-oracle", ["tests/conftest.py"])
    assert not relevant("native-oracle", ["src/crimson/modes/replay_playback_mode.py"])
    assert relevant("native-oracle", ["src/crimson/sim/world_state.py"])


def test_matching_suites_cover_every_pinned_report_input() -> None:
    from crimson_re.match_report import _input_path
    from scripts.ci_changed_paths import tracked_files

    for path in tracked_files():
        if _input_path(path):
            assert relevant("decomp", [path]), path
            assert relevant("re-audits", [path]), path


@pytest.mark.parametrize("suite", ["decomp", "re-audits"])
def test_unconsumed_analysis_notes_do_not_start_matching_checks(suite: str) -> None:
    assert not relevant(suite, ["analysis/frida/readme.md"])
    assert not relevant(suite, ["analysis/historical/readme.md"])
    assert relevant(suite, ["analysis/decomp/new-build/new-image/native.json"])
    assert relevant(suite, ["analysis/native/grim.dll/closure.json"])
    assert relevant(suite, ["analysis/ida/raw/grim.dll/segments.json"])


def test_deployment_workflow_checks_both_published_components() -> None:
    path = ".github/workflows/deploy.yml"
    assert relevant("client", [path])
    assert relevant("service", [path])
    assert not relevant("core-build", [path])


def test_shared_game_art_action_invalidates_its_consumers() -> None:
    path = ".github/actions/game-art/action.yml"
    assert relevant("service", [path])
    assert relevant("pytest", [path])
    assert not relevant("client", [path])
