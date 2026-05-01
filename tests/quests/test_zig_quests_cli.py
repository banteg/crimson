from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any, cast

import pytest

import crimson.dbg.record as dbg_record
from crimson.quests import quest_by_level
from crimson.quests.level import QuestLevel
from crimson.quests.runtime import build_quest_spawn_table
from crimson.quests.types import QuestContext, SpawnEntry
from grim.rand import Crand


def test_zig_quests_json_matches_python_spawn_table() -> None:
    level = QuestLevel(2, 5)
    seed = 0x1234
    width = 1600
    height = 900
    player_count = 3
    quest = quest_by_level(level)
    assert quest is not None
    expected_entries = build_quest_spawn_table(
        quest,
        QuestContext(width=width, height=height, player_count=player_count),
        rng=Crand(seed),
        hardcore=False,
        full_version=True,
    )

    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    result = dbg_record._run_process(
        [
            str(dbg_record._ZIG_BIN),
            "quests",
            level.text,
            "--format",
            "json",
            "--width",
            str(width),
            "--height",
            str(height),
            "--player-count",
            str(player_count),
            "--seed",
            str(seed),
        ],
        cwd=dbg_record._REPO_ROOT,
    )

    assert result.returncode == 0, dbg_record._command_detail(result)
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == 1
    assert payload["status"] == "ok"
    assert payload["level"] == level.text
    assert payload["level_key"] == 205
    assert payload["start_weapon_id"] == int(quest.start_weapon_id)
    assert payload["entry_count"] == len(expected_entries)
    payload_entries = cast("list[dict[str, Any]]", payload["entries"])
    for actual, expected in zip(_payload_entries(payload_entries), _expected_entries(expected_entries), strict=True):
        assert actual[0:3] == pytest.approx(expected[0:3], abs=1e-4)
        assert actual[3:] == expected[3:]


def test_zig_quests_human_output_reports_unknown_level() -> None:
    build_run = dbg_record._run_process(["zig", "build"], cwd=dbg_record._ZIG_ROOT)
    assert build_run.returncode == 0, dbg_record._command_detail(build_run)

    result = dbg_record._run_process(
        [str(dbg_record._ZIG_BIN), "quests", "9.9"],
        cwd=dbg_record._REPO_ROOT,
    )

    assert result.returncode == 1
    assert "invalid quests args: invalid quest level" in result.stderr


def _payload_entries(entries: list[dict[str, Any]]) -> list[tuple[float, float, float, int, int, int]]:
    rows: list[tuple[float, float, float, int, int, int]] = []
    for entry in entries:
        pos = cast("dict[str, Any]", entry["pos"])
        rows.append(
            (
                float(pos["x"]),
                float(pos["y"]),
                float(entry["heading"]),
                int(entry["spawn_id"]),
                int(entry["trigger_ms"]),
                int(entry["count"]),
            ),
        )
    return rows


def _expected_entries(entries: Sequence[SpawnEntry]) -> list[tuple[float, float, float, int, int, int]]:
    return [
        (
            float(entry.pos.x),
            float(entry.pos.y),
            float(entry.heading),
            int(entry.spawn_id),
            int(entry.trigger_ms),
            int(entry.count),
        )
        for entry in entries
    ]
