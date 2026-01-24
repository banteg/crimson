from __future__ import annotations

import pytest

from crimson.quests.timeline import tick_quest_spawn_timeline
from crimson.quests.types import SpawnEntry


def test_tick_quest_spawn_timeline_no_trigger_resets_idle_timer_when_creatures_active() -> None:
    entries = (
        SpawnEntry(x=512.0, y=512.0, heading=0.0, spawn_id=0x12, trigger_ms=1000, count=1),
    )
    updated, creatures_none_active, idle_ms, spawns = tick_quest_spawn_timeline(
        entries,
        quest_spawn_timeline_ms=0.0,
        frame_dt_ms=16.0,
        terrain_width=1024.0,
        creatures_none_active=False,
        no_creatures_timer_ms=123.0,
    )

    assert updated == entries
    assert creatures_none_active is False
    assert idle_ms == pytest.approx(0.0, abs=1e-9)
    assert spawns == ()


def test_tick_quest_spawn_timeline_triggers_horizontal_spread_when_on_screen() -> None:
    entries = (
        SpawnEntry(x=512.0, y=512.0, heading=1.25, spawn_id=0x12, trigger_ms=1000, count=3),
    )
    updated, creatures_none_active, idle_ms, spawns = tick_quest_spawn_timeline(
        entries,
        quest_spawn_timeline_ms=1001.0,
        frame_dt_ms=16.0,
        terrain_width=1024.0,
        creatures_none_active=True,
        no_creatures_timer_ms=0.0,
    )

    assert updated[0].count == 0
    assert creatures_none_active is False
    assert idle_ms == pytest.approx(16.0, abs=1e-9)
    assert len(spawns) == 3
    assert [(s.pos[0], s.pos[1]) for s in spawns] == [
        (pytest.approx(512.0, abs=1e-9), pytest.approx(512.0, abs=1e-9)),
        (pytest.approx(472.0, abs=1e-9), pytest.approx(512.0, abs=1e-9)),
        (pytest.approx(592.0, abs=1e-9), pytest.approx(512.0, abs=1e-9)),
    ]
    for spawn in spawns:
        assert spawn.heading == pytest.approx(1.25, abs=1e-9)


def test_tick_quest_spawn_timeline_triggers_vertical_spread_when_offscreen_x() -> None:
    entries = (
        SpawnEntry(x=-50.0, y=512.0, heading=0.25, spawn_id=0x12, trigger_ms=1000, count=3),
    )
    _, _, _, spawns = tick_quest_spawn_timeline(
        entries,
        quest_spawn_timeline_ms=1001.0,
        frame_dt_ms=0.0,
        terrain_width=1024.0,
        creatures_none_active=True,
        no_creatures_timer_ms=0.0,
    )

    assert [(s.pos[0], s.pos[1]) for s in spawns] == [
        (pytest.approx(-50.0, abs=1e-9), pytest.approx(512.0, abs=1e-9)),
        (pytest.approx(-50.0, abs=1e-9), pytest.approx(472.0, abs=1e-9)),
        (pytest.approx(-50.0, abs=1e-9), pytest.approx(592.0, abs=1e-9)),
    ]


def test_tick_quest_spawn_timeline_fires_only_one_trigger_group_per_tick() -> None:
    entries = (
        SpawnEntry(x=512.0, y=512.0, heading=0.0, spawn_id=0x12, trigger_ms=500, count=1),
        SpawnEntry(x=512.0, y=512.0, heading=0.0, spawn_id=0x2B, trigger_ms=500, count=1),
        SpawnEntry(x=512.0, y=512.0, heading=0.0, spawn_id=0x3A, trigger_ms=600, count=1),
    )
    updated, _, _, spawns = tick_quest_spawn_timeline(
        entries,
        quest_spawn_timeline_ms=10_000.0,
        frame_dt_ms=0.0,
        terrain_width=1024.0,
        creatures_none_active=True,
        no_creatures_timer_ms=0.0,
    )

    assert [e.count for e in updated] == [0, 0, 1]
    assert [s.template_id for s in spawns] == [0x12, 0x2B]


def test_tick_quest_spawn_timeline_force_fires_after_idle_timeout() -> None:
    entries = (
        SpawnEntry(x=512.0, y=512.0, heading=0.0, spawn_id=0x12, trigger_ms=999_999, count=1),
    )
    updated, creatures_none_active, idle_ms, spawns = tick_quest_spawn_timeline(
        entries,
        quest_spawn_timeline_ms=2000.0,  # > 0x6A4
        frame_dt_ms=0.0,
        terrain_width=1024.0,
        creatures_none_active=True,
        no_creatures_timer_ms=3001.0,  # > 3000
    )

    assert updated[0].count == 0
    assert creatures_none_active is False
    assert idle_ms == pytest.approx(3001.0, abs=1e-9)
    assert len(spawns) == 1
