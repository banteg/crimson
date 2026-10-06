from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from crimson_re.cli.match import match_app
from crimson_re.name_audit import (
    collect_resolved_name_references,
    render_resolved_name_reference_summary,
    rewrite_resolved_name_references,
)


def test_collect_resolved_name_references_covers_text_and_native_initializers(
    tmp_path: Path,
) -> None:
    docs_root = tmp_path / "docs"
    docs_root.mkdir()
    docs_root.joinpath("recovered.md").write_text(
        "`known_function` (`FUN_00401000`) reads `known_table` (`DAT_00405000`).\n",
        encoding="utf-8",
    )
    source_root = tmp_path / "src"
    source_root.mkdir()
    source_root.joinpath("notes.py").write_text(
        "# FUN_00401000 reads DAT_00405000\n"
        "# _DAT_00405000 is the same recovered table\n"
        "# former_function has a stronger curated identity\n"
        "# data_406000 and sub_00409999 remain unresolved\n",
        encoding="utf-8",
    )
    definitions_root = tmp_path / "tools" / "native" / "data_definitions"
    definitions_root.mkdir(parents=True)
    definitions_root.joinpath("grim.dll.json").write_text(
        json.dumps(
            {
                "image": "grim.dll",
                "entries": [
                    {
                        "initializer_symbols": [
                            ["0x0", "0x10002000", "nullsub_3"],
                        ],
                    },
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    name_map = tmp_path / "name_map.json"
    name_map.write_text(
        json.dumps(
            [
                {
                    "program": "crimsonland.exe",
                    "address": "0x00401000",
                    "name": "known_function",
                    "formerly": ["former_function"],
                },
                {
                    "program": "grim.dll",
                    "address": "0x10002000",
                    "name": "known_noop",
                },
            ],
        )
        + "\n",
        encoding="utf-8",
    )
    data_map = tmp_path / "data_map.json"
    data_map.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "program": "crimsonland.exe",
                        "address": "0x00405000",
                        "name": "known_table",
                    },
                    {
                        "program": "crimsonland.exe",
                        "address": "0x00406000",
                        "name": "data_406000",
                    },
                ],
            },
        )
        + "\n",
        encoding="utf-8",
    )

    rows = collect_resolved_name_references(
        repo_root=tmp_path,
        name_map_path=name_map,
        data_map_path=data_map,
    )

    assert {
        (row.source, row.token, row.image, row.address, row.canonical_names)
        for row in rows
    } == {
        ("text", "FUN_00401000", "crimsonland.exe", 0x00401000, ("known_function",)),
        ("text", "DAT_00405000", "crimsonland.exe", 0x00405000, ("known_table",)),
        ("text", "_DAT_00405000", "crimsonland.exe", 0x00405000, ("known_table",)),
        (
            "superseded-identity",
            "former_function",
            "crimsonland.exe",
            0x00401000,
            ("known_function",),
        ),
        ("native-initializer", "nullsub_3", "grim.dll", 0x10002000, ("known_noop",)),
    }
    assert [row.path for row in rows if row.path.startswith("docs/")] == [
        "docs/recovered.md",
        "docs/recovered.md",
    ]
    assert render_resolved_name_reference_summary(rows) == (
        "rows=7; sources=native-initializer:1,superseded-identity:1,text:5"
    )

    completed = CliRunner().invoke(
        match_app,
        [
            "resolved-name-audit",
            "--root",
            str(tmp_path),
            "--name-map",
            str(name_map),
            "--data-map",
            str(data_map),
            "--json",
            "--check",
        ],
    )

    assert completed.exit_code == 1
    payload = json.loads(completed.output)
    assert payload["summary"] == {
        "row_count": 7,
        "sources": {"native-initializer": 1, "superseded-identity": 1, "text": 5},
    }

    rewrite_result = rewrite_resolved_name_references(rows, repo_root=tmp_path)

    assert rewrite_result == {
        "files_updated": 3,
        "references_updated": 7,
        "rows_skipped": 0,
    }
    assert docs_root.joinpath("recovered.md").read_text(encoding="utf-8") == (
        "`known_function` (`0x00401000`) reads `known_table` (`0x00405000`).\n"
    )
    assert source_root.joinpath("notes.py").read_text(encoding="utf-8") == (
        "# known_function reads known_table\n"
        "# known_table is the same recovered table\n"
        "# known_function has a stronger curated identity\n"
        "# data_406000 and sub_00409999 remain unresolved\n"
    )
    rewritten_payload = json.loads(
        definitions_root.joinpath("grim.dll.json").read_text(encoding="utf-8"),
    )
    assert rewritten_payload["entries"][0]["initializer_symbols"][0][2] == "known_noop"
    assert collect_resolved_name_references(
        repo_root=tmp_path,
        name_map_path=name_map,
        data_map_path=data_map,
    ) == []


def test_collect_resolved_name_references_keeps_identity_canonical_elsewhere(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "src"
    source_root.mkdir()
    source_root.joinpath("notes.py").write_text(
        "# wrapper calls shared_identity\n",
        encoding="utf-8",
    )
    name_map = tmp_path / "name_map.json"
    name_map.write_text(
        "["
        '{"program":"crimsonland.exe","address":"0x00401000",'
        '"name":"shared_identity"},'
        '{"program":"crimsonland.exe","address":"0x00401010",'
        '"name":"body_identity","formerly":["shared_identity"]}'
        "]\n",
        encoding="utf-8",
    )
    data_map = tmp_path / "data_map.json"
    data_map.write_text('{"entries":[]}\n', encoding="utf-8")

    assert collect_resolved_name_references(
        repo_root=tmp_path,
        name_map_path=name_map,
        data_map_path=data_map,
    ) == []


def test_history_and_marked_lines_keep_their_names(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "page.md").write_text("old_name\nold_name  # name-audit: keep\n", encoding="utf-8")
    evidence = tmp_path / "tools" / "match" / "evidence" / "probe-2026-09-11"
    evidence.mkdir(parents=True)
    (evidence / "notes.md").write_text("old_name\n", encoding="utf-8")
    (tmp_path / "tools" / "match" / "EXACT-MATCHES-2026-09-07.md").write_text("old_name\n", encoding="utf-8")
    scratch = tmp_path / "tools" / "match" / "scratches" / "new_name"
    scratch.mkdir(parents=True)
    (scratch / "NOTES.md").write_text("old_name\n", encoding="utf-8")
    (scratch / "scratch.conf").write_text("FUNCTION=old_name\n", encoding="utf-8")
    name_map = tmp_path / "name_map.json"
    name_map.write_text(
        '[{"program":"crimsonland.exe","address":"0x00401000","name":"new_name","formerly":["old_name"]}]\n',
        encoding="utf-8",
    )
    data_map = tmp_path / "data_map.json"
    data_map.write_text('{"entries":[]}\n', encoding="utf-8")

    rows = collect_resolved_name_references(repo_root=tmp_path, name_map_path=name_map, data_map_path=data_map)

    assert [(row.path, row.line) for row in rows] == [
        ("docs/page.md", 1),
        ("tools/match/scratches/new_name/scratch.conf", 1),
    ]
