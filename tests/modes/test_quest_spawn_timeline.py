from __future__ import annotations

from crimson.creatures.spawn import SpawnId
from crimson.quests.timeline import tick_quest_spawn_timeline
from crimson.quests.types import SpawnEntry
from grim.geom import Vec2
from tests.support.helpers import assert_float_close


def test_tick_quest_spawn_timeline_no_trigger_resets_idle_timer_when_creatures_active() -> None:
    entries = (
        SpawnEntry(
            pos=Vec2(512.0, 512.0),
            heading=0.0,
            spawn_id=SpawnId.FORMATION_RING_ALIEN_8_12,
            trigger_ms=1000,
            count=1,
        ),
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
    assert_float_close(idle_ms, 0.0)
    assert spawns == ()


def test_tick_quest_spawn_timeline_triggers_horizontal_spread_when_on_screen() -> None:
    entries = (
        SpawnEntry(
            pos=Vec2(512.0, 512.0),
            heading=1.25,
            spawn_id=SpawnId.FORMATION_RING_ALIEN_8_12,
            trigger_ms=1000,
            count=3,
        ),
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
    assert_float_close(idle_ms, 16.0)
    assert len(spawns) == 3
    for spawn, (expected_x, expected_y) in zip(spawns, ((512.0, 512.0), (472.0, 512.0), (592.0, 512.0))):
        assert_float_close(spawn.pos.x, expected_x)
        assert_float_close(spawn.pos.y, expected_y)
    for spawn in spawns:
        assert_float_close(spawn.heading, 1.25)


def test_tick_quest_spawn_timeline_triggers_vertical_spread_when_offscreen_x() -> None:
    entries = (
        SpawnEntry(
            pos=Vec2(-50.0, 512.0),
            heading=0.25,
            spawn_id=SpawnId.FORMATION_RING_ALIEN_8_12,
            trigger_ms=1000,
            count=3,
        ),
    )
    _, _, _, spawns = tick_quest_spawn_timeline(
        entries,
        quest_spawn_timeline_ms=1001.0,
        frame_dt_ms=0.0,
        terrain_width=1024.0,
        creatures_none_active=True,
        no_creatures_timer_ms=0.0,
    )

    for spawn, (expected_x, expected_y) in zip(spawns, ((-50.0, 512.0), (-50.0, 472.0), (-50.0, 592.0))):
        assert_float_close(spawn.pos.x, expected_x)
        assert_float_close(spawn.pos.y, expected_y)


def test_tick_quest_spawn_timeline_fires_only_one_trigger_group_per_tick() -> None:
    entries = (
        SpawnEntry(
            pos=Vec2(512.0, 512.0),
            heading=0.0,
            spawn_id=SpawnId.FORMATION_RING_ALIEN_8_12,
            trigger_ms=500,
            count=1,
        ),
        SpawnEntry(
            pos=Vec2(512.0, 512.0),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_DEADLY_FAST_2B,
            trigger_ms=500,
            count=1,
        ),
        SpawnEntry(
            pos=Vec2(512.0, 512.0),
            heading=0.0,
            spawn_id=SpawnId.SPIDER_BOSS_3A,
            trigger_ms=600,
            count=1,
        ),
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
    assert [s.template_id for s in spawns] == [SpawnId.FORMATION_RING_ALIEN_8_12, SpawnId.ALIEN_DEADLY_FAST_2B]


def test_tick_quest_spawn_timeline_force_fires_after_idle_timeout() -> None:
    entries = (
        SpawnEntry(
            pos=Vec2(512.0, 512.0),
            heading=0.0,
            spawn_id=SpawnId.FORMATION_RING_ALIEN_8_12,
            trigger_ms=999_999,
            count=1,
        ),
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
    assert_float_close(idle_ms, 3001.0)
    assert len(spawns) == 1
