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
            [git, "-c", "user.name=CI", "-c", "user.email=ci@example.invalid", "commit", "-qm", "c"], cwd=tmp_path, check=True,
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
