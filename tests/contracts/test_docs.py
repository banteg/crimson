from __future__ import annotations

from pathlib import Path

import pytest

from crimson.dbg.frida_finalize import FRIDA_CAPTURE_FORMAT_VERSION, FRIDA_EVIDENCE_FORMAT_VERSION
from crimson.dbg.schema import TRACE_FORMAT_VERSION, TRACE_SCHEMA_VERSION
from crimson.replay.types import REPLAY_FORMAT_VERSION
from scripts.check_docs import find_broken_markdown_links, find_broken_source_paths


def test_source_references_accept_files_directories_and_symbol_suffixes(tmp_path: Path) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    source = tmp_path / "src" / "game.py"
    source.parent.mkdir()
    source.touch()
    page = docs / "index.md"
    page.write_text("`src/` `src/game.py` `src/game.py:12` `src/game.py:run_game`\n")

    assert find_broken_source_paths(tmp_path, docs, [page]) == []


def test_source_references_report_deleted_modules_and_moved_tests(tmp_path: Path) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    page = docs / "index.md"
    page.write_text("# Reference\n`src/game_world.py:GameWorld`\n`tests/net/`\n")

    assert find_broken_source_paths(tmp_path, docs, [page]) == [
        "index.md:2: missing source path 'src/game_world.py'",
        "index.md:3: missing source path 'tests/net/'",
    ]


def test_source_references_skip_examples_but_check_fixture_files(tmp_path: Path) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    page = docs / "index.md"
    page.write_text(
        "`src/<module>.py` `tests/test_*.py` `scripts/example.py --out out.json`\n"
        "`tests/fixtures/captures/` `tools/match/bin/` `tools/match/compilers/`\n"
        "`tests/fixtures/missing.json`\n",
    )

    assert find_broken_source_paths(tmp_path, docs, [page]) == [
        "index.md:3: missing source path 'tests/fixtures/missing.json'",
    ]


@pytest.mark.parametrize("target", ["/Users/person/game.py", "/home/person/game.py", "~/game.py", "file:///tmp/game.py"])
def test_docs_reject_machine_local_links(tmp_path: Path, target: str) -> None:
    page = tmp_path / "index.md"
    page.write_text(f"[Source]({target})\n")

    assert find_broken_markdown_links(tmp_path, [page]) == [f"index.md: nonportable link '{target}'"]


def test_docs_links_cannot_escape_to_a_sibling_with_the_same_prefix(tmp_path: Path) -> None:
    docs = tmp_path / "docs"
    sibling = tmp_path / "docs-old"
    docs.mkdir()
    sibling.mkdir()
    (sibling / "old.md").touch()
    (docs / "current.md").touch()
    page = docs / "index.md"
    page.write_text("[Old](../docs-old/old.md) [Current](current.md#details)\n")

    assert find_broken_markdown_links(docs, [page]) == ["index.md: broken link '../docs-old/old.md'"]


def test_documented_format_matrix_matches_current_versions() -> None:
    page = Path(__file__).resolve().parents[2] / "docs/rewrite/trace-format-alignment.md"
    rows = {
        cells[1].strip(): cells[2].strip()
        for line in page.read_text().splitlines()
        if line.startswith("|") and len(cells := line.split("|")) >= 4
    }

    assert {name: rows[name] for name in (
        "Frida raw JSONL", "Frida evidence sidecar", "CDT container", "CDT payload schema", "CRD replay",
    )} == {
        "Frida raw JSONL": str(FRIDA_CAPTURE_FORMAT_VERSION),
        "Frida evidence sidecar": str(FRIDA_EVIDENCE_FORMAT_VERSION),
        "CDT container": str(TRACE_FORMAT_VERSION),
        "CDT payload schema": str(TRACE_SCHEMA_VERSION),
        "CRD replay": str(REPLAY_FORMAT_VERSION),
    }
