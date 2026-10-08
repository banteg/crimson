"""Keep required CI gates aligned with the paths their suites cover."""

import shutil
import subprocess
from pathlib import Path

import pytest

from scripts.ci_changed_paths import changed_paths, relevant


@pytest.mark.parametrize(
    ("category", "path"),
    [
        ("core", "third_party/sources/zlib/adler32.c"),
        ("client", "src/crimson/replay/types.py"),
        ("client", "pyproject.toml"),
        ("client", "uv.lock"),
        ("decomp", "src/crimson/cli/__init__.py"),
        ("service", "src/grim/assets.py"),
        ("service", "tests/fixtures/replays/run.crd"),
    ],
)
def test_external_suite_inputs_run_their_consumers(category: str, path: str) -> None:
    assert relevant(category, [path])


@pytest.mark.parametrize("category", ["core", "client", "decomp", "service"])
def test_filter_change_runs_every_suite(category: str) -> None:
    assert relevant(category, ["scripts/ci_changed_paths.py"])
    assert relevant(category, ["crimson-re/pyproject.toml"])
    assert not relevant(category, ["README.md", "docs/index.md"])


def test_docs_only_requires_all_paths_to_be_docs() -> None:
    assert relevant("docs-only", ["README.md", "docs/image.png"])
    assert not relevant("docs-only", ["README.md", "src/crimson/game.py"])
    assert not relevant("docs-only", ["docs/javascripts/weapons-widgets.js"])
    assert not relevant("docs-only", ["tests/fixtures/readme.md"])
    assert not relevant("docs-only", [])


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
    assert not relevant("docs-only", changed_paths(base))
    assert relevant("core", changed_paths(base))
