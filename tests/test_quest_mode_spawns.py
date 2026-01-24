from __future__ import annotations

import pytest

from crimson.quests.timeline import tick_quest_mode_spawns
from crimson.quests.types import SpawnEntry


def test_tick_quest_mode_spawns_advances_timeline_when_creatures_active() -> None:
    entries: tuple[SpawnEntry, ...] = ()
    updated, timeline_ms, creatures_none_active, idle_ms, spawns = tick_quest_mode_spawns(
        entries,
        quest_spawn_timeline_ms=1000.0,
        frame_dt_ms=16.0,
        terrain_width=1024.0,
        creatures_none_active=False,
        no_creatures_timer_ms=123.0,
    )

    assert updated == ()
    assert timeline_ms == pytest.approx(1016.0, abs=1e-9)
    assert creatures_none_active is False
    assert idle_ms == pytest.approx(0.0, abs=1e-9)
    assert spawns == ()


def test_tick_quest_mode_spawns_advances_timeline_when_table_not_empty() -> None:
    entries = (
        SpawnEntry(x=512.0, y=512.0, heading=0.0, spawn_id=0x12, trigger_ms=10_000, count=1),
    )
    updated, timeline_ms, creatures_none_active, idle_ms, spawns = tick_quest_mode_spawns(
        entries,
        quest_spawn_timeline_ms=1000.0,
        frame_dt_ms=16.0,
        terrain_width=1024.0,
        creatures_none_active=True,
        no_creatures_timer_ms=0.0,
    )

    assert updated == entries
    assert timeline_ms == pytest.approx(1016.0, abs=1e-9)
    assert creatures_none_active is True
    assert idle_ms == pytest.approx(16.0, abs=1e-9)
    assert spawns == ()


def test_tick_quest_mode_spawns_freezes_timeline_when_idle_complete() -> None:
    entries: tuple[SpawnEntry, ...] = ()
    updated, timeline_ms, creatures_none_active, idle_ms, spawns = tick_quest_mode_spawns(
        entries,
        quest_spawn_timeline_ms=1000.0,
        frame_dt_ms=16.0,
        terrain_width=1024.0,
        creatures_none_active=True,
        no_creatures_timer_ms=0.0,
    )

    assert updated == ()
    assert timeline_ms == pytest.approx(1000.0, abs=1e-9)
    assert creatures_none_active is True
    assert idle_ms == pytest.approx(16.0, abs=1e-9)
    assert spawns == ()


def test_tick_quest_mode_spawns_can_fire_entries_after_timeline_advance() -> None:
    entries = (
        SpawnEntry(x=512.0, y=512.0, heading=0.25, spawn_id=0x12, trigger_ms=1000, count=1),
    )
    updated, timeline_ms, creatures_none_active, idle_ms, spawns = tick_quest_mode_spawns(
        entries,
        quest_spawn_timeline_ms=999.0,
        frame_dt_ms=2.0,
        terrain_width=1024.0,
        creatures_none_active=True,
        no_creatures_timer_ms=0.0,
    )

    assert timeline_ms == pytest.approx(1001.0, abs=1e-9)
    assert updated[0].count == 0
    assert creatures_none_active is False
    assert idle_ms == pytest.approx(2.0, abs=1e-9)
    assert len(spawns) == 1
    assert spawns[0].template_id == 0x12

