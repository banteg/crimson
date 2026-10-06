from __future__ import annotations

from crimson.creatures.spawn import SpawnId
from crimson.quests.helpers import spawn
from crimson.quests.level import QuestLevel
from crimson.quests.timeline import quest_spawn_timeline_update
from crimson.sim.mode_updates import QuestSpawnState, quest_mode_update
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from tests.support.builders.session import make_world


def _active(world: WorldState) -> list[tuple[float, float, float]]:
    return [(creature.pos.x, creature.pos.y, creature.heading) for creature in world.creatures.entries if creature.active]


def _occupy_one_slot(world: WorldState) -> None:
    world.creatures.spawn_template(SpawnId.ALIEN_SMALL_GRAY_26, Vec2(0.0, 0.0), 0.0, state=world.state, detail_preset=5)


def test_no_due_group_resets_the_stall_timer_while_creatures_are_active() -> None:
    world = make_world()
    _occupy_one_slot(world)
    quest = QuestSpawnState(
        spawn_entries=(spawn(Vec2(512.0, 512.0), SpawnId.ALIEN_SMALL_GRAY_26, 1000, 1),),
        no_creatures_timer_ms=123.0,
    )

    quest_spawn_timeline_update(world, quest, dt_ms=16.0)

    assert quest.no_creatures_timer_ms == 0.0
    assert quest.spawn_entries[0].count == 1
    assert len(_active(world)) == 1


def test_due_group_spreads_along_x_and_zeroes_the_entry() -> None:
    world = make_world()
    quest = QuestSpawnState(
        spawn_entries=(spawn(Vec2(512.0, 512.0), SpawnId.ALIEN_SMALL_GRAY_26, 1000, 3, heading=1.25),),
        spawn_timeline_ms=1001.0,
        creatures_none_active=True,
    )

    quest_spawn_timeline_update(world, quest, dt_ms=16.0)

    assert quest.spawn_entries[0].count == 0
    assert quest.no_creatures_timer_ms == 16.0
    assert _active(world) == [(512.0, 512.0, 1.25), (472.0, 512.0, 1.25), (592.0, 512.0, 1.25)]


def test_group_off_the_side_spreads_along_y() -> None:
    world = make_world()
    quest = QuestSpawnState(
        spawn_entries=(spawn(Vec2(-50.0, 512.0), SpawnId.ALIEN_SMALL_GRAY_26, 1000, 3),),
        spawn_timeline_ms=1001.0,
    )

    quest_spawn_timeline_update(world, quest, dt_ms=0.0)

    assert [(x, y) for x, y, _ in _active(world)] == [(-50.0, 512.0), (-50.0, 472.0), (-50.0, 592.0)]


def test_only_the_first_trigger_group_spawns_per_update() -> None:
    world = make_world()
    quest = QuestSpawnState(
        spawn_entries=(
            spawn(Vec2(100.0, 100.0), SpawnId.ALIEN_SMALL_GRAY_26, 500, 1),
            spawn(Vec2(200.0, 100.0), SpawnId.ALIEN_DEADLY_FAST_2B, 500, 1),
            spawn(Vec2(300.0, 100.0), SpawnId.SPIDER_BOSS_3A, 600, 1),
        ),
        spawn_timeline_ms=10_000.0,
    )

    quest_spawn_timeline_update(world, quest, dt_ms=0.0)

    assert [entry.count for entry in quest.spawn_entries] == [0, 0, 1]
    assert [x for x, _, _ in _active(world)] == [100.0, 200.0]


def test_next_group_spawns_early_after_three_idle_seconds() -> None:
    world = make_world()
    quest = QuestSpawnState(
        spawn_entries=(spawn(Vec2(512.0, 512.0), SpawnId.ALIEN_SMALL_GRAY_26, 999_999, 1),),
        spawn_timeline_ms=2000.0,  # > 0x6A4
        no_creatures_timer_ms=3001.0,  # > 3000
        creatures_none_active=True,
    )

    quest_spawn_timeline_update(world, quest, dt_ms=0.0)

    assert quest.spawn_entries[0].count == 0
    assert len(_active(world)) == 1
    # Spawning a group clears the cached flag, as native does.
    assert not quest.creatures_none_active


def test_timeline_advances_while_creatures_are_active_or_entries_remain() -> None:
    world = make_world()
    _occupy_one_slot(world)
    quest = QuestSpawnState(spawn_timeline_ms=1000.0)

    quest_mode_update(world, quest, dt_ms=16.0)

    assert quest.spawn_timeline_ms == 1016.0

    idle = make_world()
    pending = QuestSpawnState(
        spawn_entries=(spawn(Vec2(512.0, 512.0), SpawnId.ALIEN_SMALL_GRAY_26, 999_999, 1),),
        spawn_timeline_ms=1000.0,
    )
    quest_mode_update(idle, pending, dt_ms=16.0)

    assert pending.spawn_timeline_ms == 1016.0


def test_timeline_holds_once_the_quest_is_idle_complete_but_the_stage_banner_runs_on() -> None:
    world = make_world(quest_level=QuestLevel(1, 1))
    quest = QuestSpawnState(spawn_timeline_ms=1000.0, stage_banner_timer_ms=1000.0)

    quest_mode_update(world, quest, dt_ms=16.0)

    assert (quest.spawn_timeline_ms, quest.stage_banner_timer_ms) == (1000.0, 1016.0)
