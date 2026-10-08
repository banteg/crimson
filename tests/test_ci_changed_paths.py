"""Keep required CI gates aligned with the paths their suites cover."""

import pytest

from scripts.ci_changed_paths import relevant


@pytest.mark.parametrize(
    ("category", "path", "expected"),
    [
        ("core", "src/crimson/game.py", True),
        ("core", "tests/fixtures/replays/rush.json", True),
        ("core", "docs/index.md", False),
        ("client", "crimson-core/client/build.py", True),
        ("client", "third_party/SDL3/header.h", True),
        ("client", "src/crimson/game.py", False),
        ("decomp", "analysis/decomp/1.9.93.json", True),
        ("decomp", "tools/match/report.py", True),
        ("decomp", "docs/index.md", False),
    ],
)
def test_suite_paths(category: str, path: str, expected: bool) -> None:
    assert relevant(category, [path]) is expected


@pytest.mark.parametrize("category", ["core", "client", "decomp"])
def test_filter_change_runs_every_suite(category: str) -> None:
    assert relevant(category, ["scripts/ci_changed_paths.py"])


def test_docs_only_requires_all_paths_to_be_docs() -> None:
    assert relevant("docs-only", ["README.md", "docs/image.png"])
    assert not relevant("docs-only", ["README.md", "src/crimson/game.py"])
    assert not relevant("docs-only", ["docs/javascripts/weapons-widgets.js"])
    assert not relevant("docs-only", ["tests/fixtures/readme.md"])
    assert not relevant("docs-only", [])
