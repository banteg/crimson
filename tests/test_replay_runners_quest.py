from __future__ import annotations

import msgspec
import pytest

from crimson.creatures.spawn import CreatureFlags, CreatureTypeId, SpawnId
from crimson.game_modes import GameMode
from crimson.perks import PerkId
from crimson.quests.types import SpawnEntry
from crimson.replay import (
    CaptureCreatureSpawnAddedHeadRow,
    CaptureCreatureSpawnEvent,
    CaptureCreatureSpawnRow,
    CapturePerkApplyEvent,
    CaptureStateTransitionEvent,
    CaptureStateTransitionRow,
    ReplayGameVersionWarning,
    ReplayHeader,
    ReplayRecorder,
)
from crimson.sim.driver.replay_events import apply_replay_tick_events
from crimson.sim.driver.replay_runner import run_quest_replay
from crimson.sim.driver.setup import reset_players
from crimson.sim.input import PlayerInput
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from tests.helpers import assert_float_close
from tests.replay_runner_helpers import (
    _blank_quest_replay,
    _quest_spawn_entries,
    _strict_bootstrap_event,
    _strict_bootstrap_payload,
    _strict_bootstrap_player_payload,
)


def test_quest_runner_is_deterministic() -> None:
    _header, rec = _blank_quest_replay(ticks=10, seed=101, game_version="0.0.0")
    replay = rec.finish()
    spawn_entries = _quest_spawn_entries(
        "1.1", player_count=int(replay.header.player_count), seed=int(replay.header.seed),
    )

    with pytest.warns(ReplayGameVersionWarning):
        result0 = run_quest_replay(
            replay,
            spawn_entries=tuple(spawn_entries),
        )
    with pytest.warns(ReplayGameVersionWarning):
        result1 = run_quest_replay(
            replay,
            spawn_entries=tuple(spawn_entries),
        )

    assert result0 == result1
    assert result0.game_mode_id == int(GameMode.QUESTS)
    assert result0.ticks == 10
    assert result0.elapsed_ms >= 0
    assert result0.score_xp == 0
    assert result0.creature_kill_count == 0


def test_quest_runner_applies_original_capture_bootstrap_session_timers() -> None:
    _header, rec = _blank_quest_replay(ticks=20, seed=101, game_version="0.0.0")
    replay_base = rec.finish()
    base_entry = _quest_spawn_entries("1.3", player_count=1, seed=int(replay_base.header.seed))[0]
    spawn_entries = (msgspec.structs.replace(base_entry, trigger_ms=5000, count=1),)
    dt_overrides = {tick: 0.1 for tick in range(20)}

    baseline_checkpoints = []
    with pytest.warns(ReplayGameVersionWarning):
        run_quest_replay(
            replay_base,
            spawn_entries=spawn_entries,
            dt_frame_overrides=dt_overrides,
            checkpoints_out=baseline_checkpoints,
            checkpoint_ticks={19},
        )
    assert len(baseline_checkpoints) == 1
    assert int(baseline_checkpoints[0].creature_count) == 0

    replay_bootstrapped = rec.finish()
    bootstrap_payload = _strict_bootstrap_payload(tick_index=0)
    bootstrap_payload["quest_session"] = {
        "spawn_timeline_ms": 1701.0,
        "no_creatures_timer_ms": 3100.0,
        "completion_transition_ms": -1.0,
    }
    replay_bootstrapped.events.append(_strict_bootstrap_event(bootstrap_payload))
    bootstrapped_checkpoints = []
    with pytest.warns(ReplayGameVersionWarning):
        run_quest_replay(
            replay_bootstrapped,
            spawn_entries=spawn_entries,
            dt_frame_overrides=dt_overrides,
            checkpoints_out=bootstrapped_checkpoints,
            checkpoint_ticks={19},
        )
    assert len(bootstrapped_checkpoints) == 1
    assert int(bootstrapped_checkpoints[0].creature_count) > 0


def test_quest_runner_uses_capture_creature_spawn_events_for_original_capture_replay() -> None:
    _header, rec = _blank_quest_replay(ticks=1, seed=101, game_version="0.0.0")
    replay = rec.finish()
    bootstrap_payload = _strict_bootstrap_payload(tick_index=0)
    bootstrap_payload["quest_session"] = {
        "spawn_timeline_ms": 0.0,
        "no_creatures_timer_ms": 0.0,
        "completion_transition_ms": -1.0,
    }
    replay.events.append(_strict_bootstrap_event(bootstrap_payload))
    replay.events.append(
        CaptureCreatureSpawnEvent(
            tick_index=0,
            spawns=[
                CaptureCreatureSpawnRow(
                    template_id=int(SpawnId.ALIEN_AI7_ORBITER_36),
                    pos_x=434.3393859863281,
                    pos_y=455.56573486328125,
                    heading=-4.083981990814209,
                ),
            ],
            added_head=[],
        ),
    )
    spawn_entries = (
        SpawnEntry(
            pos=Vec2(900.0, 900.0),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_AI7_ORBITER_36,
            trigger_ms=0,
            count=1,
        ),
    )

    checkpoints = []
    with pytest.warns(ReplayGameVersionWarning):
        run_quest_replay(
            replay,
            spawn_entries=spawn_entries,
            checkpoints_out=checkpoints,
            checkpoint_ticks={0},
        )
    assert len(checkpoints) == 1
    assert int(checkpoints[0].creature_count) == 1


def test_quest_runner_disables_runtime_spawn_slot_ticks_when_capture_spawns_are_authoritative() -> None:
    _header, rec = _blank_quest_replay(ticks=40, seed=101, game_version="0.0.0")
    replay = rec.finish()
    bootstrap_payload = _strict_bootstrap_payload(tick_index=0)
    bootstrap_payload["quest_session"] = {
        "spawn_timeline_ms": 0.0,
        "no_creatures_timer_ms": 0.0,
        "completion_transition_ms": -1.0,
    }
    replay.events.append(_strict_bootstrap_event(bootstrap_payload))
    replay.events.append(
        CaptureCreatureSpawnEvent(
            tick_index=0,
            spawns=[
                CaptureCreatureSpawnRow(
                    template_id=int(SpawnId.ALIEN_SPAWNER_CHILD_32_SLOW_0A),
                    pos_x=900.0,
                    pos_y=900.0,
                    heading=0.0,
                ),
            ],
            added_head=[],
        ),
    )
    dt_overrides = {tick: 0.1 for tick in range(40)}

    checkpoints = []
    with pytest.warns(ReplayGameVersionWarning):
        run_quest_replay(
            replay,
            spawn_entries=(),
            dt_frame_overrides=dt_overrides,
            checkpoints_out=checkpoints,
            checkpoint_ticks={39},
        )
    assert len(checkpoints) == 1
    # Capture spawn hooks are authoritative in original-capture quest replays.
    # Local runtime spawn-slot ticking must stay disabled to avoid duplicate children.
    assert int(checkpoints[0].creature_count) == 1


def test_capture_creature_spawn_event_applies_added_head_overrides() -> None:
    world = WorldState.build(
        world_size=1024.0,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=1,
    )
    reset_players(world.players, world_size=1024.0, player_count=1)
    event = CaptureCreatureSpawnEvent(
        tick_index=0,
        spawns=[
            CaptureCreatureSpawnRow(
                template_id=int(SpawnId.FORMATION_GRID_ALIEN_BRONZE_18),
                pos_x=-256.0,
                pos_y=256.0,
                heading=-4.083981990814209,
            ),
        ],
        added_head=[
            CaptureCreatureSpawnAddedHeadRow(
                index=1,
                heading=1.1278764009475708,
                target_heading=0.621416449546814,
                ai_mode=3,
                link_index=0,
                hp=123.5,
                lifecycle_stage=9.5,
                orbit_angle=0.25,
                orbit_radius=0.75,
                flags=17,
                type_id=int(CreatureTypeId.TROOPER),
                pos_x=12.25,
                pos_y=34.5,
            ),
        ],
    )
    apply_replay_tick_events(
        [event],
        tick_index=0,
        dt_frame=1.0 / 60.0,
        world=world,
        game_mode_id=int(GameMode.QUESTS),
        strict_events=True,
    )
    creature = world.creatures.entries[1]
    assert creature.active
    assert_float_close(float(creature.heading), 1.1278764009475708)
    assert_float_close(float(creature.target_heading), 0.621416449546814)
    assert int(creature.ai_mode) == 3
    assert int(creature.link_index) == 0
    assert_float_close(float(creature.hp), 123.5)
    assert_float_close(float(creature.lifecycle_stage), 9.5)
    assert_float_close(float(creature.orbit_angle), 0.25)
    assert_float_close(float(creature.orbit_radius), 0.75)
    assert int(creature.flags) == 17
    assert creature.type_id == CreatureTypeId.TROOPER
    assert_float_close(float(creature.pos.x), 12.25)
    assert_float_close(float(creature.pos.y), 34.5)


def test_capture_creature_spawn_event_applies_added_head_without_spawn_rows() -> None:
    world = WorldState.build(
        world_size=1024.0,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=1,
    )
    reset_players(world.players, world_size=1024.0, player_count=1)
    spawned, _ = world.creatures.spawn_template(
        int(SpawnId.ALIEN_AI7_ORBITER_36),
        Vec2(256.0, 256.0),
        0.0,
        world.state.rng,
        rand=world.state.rng.rand,
    )
    assert spawned
    idx = int(spawned[0])

    event = CaptureCreatureSpawnEvent(
        tick_index=0,
        spawns=[],
        added_head=[
            CaptureCreatureSpawnAddedHeadRow(
                index=idx,
                heading=0.28999999165534973,
                target_heading=0.521416425704956,
                ai_mode=0,
                link_index=1,
                hp=None,
                lifecycle_stage=None,
                orbit_angle=None,
                orbit_radius=1.25,
                flags=5,
                type_id=None,
                pos_x=None,
                pos_y=None,
            ),
        ],
    )
    apply_replay_tick_events(
        [event],
        tick_index=0,
        dt_frame=1.0 / 60.0,
        world=world,
        game_mode_id=int(GameMode.QUESTS),
        strict_events=True,
    )
    creature = world.creatures.entries[idx]
    assert creature.active
    assert_float_close(float(creature.heading), 0.28999999165534973)
    assert_float_close(float(creature.target_heading), 0.521416425704956)
    assert int(creature.ai_mode) == 0
    assert int(creature.link_index) == 1
    assert_float_close(float(creature.orbit_radius), 1.25)
    assert int(creature.flags) == 5


def test_capture_creature_spawn_event_backfills_ai7_rollover_rng_draw_for_spawned_rows() -> None:
    def _rng_state_after(event: CaptureCreatureSpawnEvent) -> tuple[int, WorldState]:
        world = WorldState.build(
            world_size=1024.0,
            demo_mode_active=False,
            hardcore=False,
            difficulty_level=1,
        )
        reset_players(world.players, world_size=1024.0, player_count=1)
        world.state.rng.srand(0x1234ABCD)
        apply_replay_tick_events(
            [event],
            tick_index=0,
            dt_frame=1.0 / 60.0,
            world=world,
            game_mode_id=int(GameMode.QUESTS),
            strict_events=True,
        )
        return int(world.state.rng.state), world

    base_event = CaptureCreatureSpawnEvent(
        tick_index=0,
        spawns=[
            CaptureCreatureSpawnRow(
                template_id=int(SpawnId.SPIDER_SP1_RANDOM_32),
                pos_x=256.0,
                pos_y=256.0,
                heading=-100.0,
            ),
        ],
        added_head=[],
    )
    with_rollover_event = CaptureCreatureSpawnEvent(
        tick_index=0,
        spawns=list(base_event.spawns),
        added_head=[
            CaptureCreatureSpawnAddedHeadRow(
                index=0,
                heading=None,
                target_heading=None,
                ai_mode=None,
                link_index=-975,
                hp=None,
                lifecycle_stage=None,
                orbit_angle=None,
                orbit_radius=None,
                flags=int(CreatureFlags.AI7_LINK_TIMER),
                type_id=None,
                pos_x=None,
                pos_y=None,
            ),
        ],
    )

    state_without_rollover, _ = _rng_state_after(base_event)
    state_with_rollover, world_with_rollover = _rng_state_after(with_rollover_event)

    probe = WorldState.build(
        world_size=1024.0,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=1,
    )
    probe.state.rng.srand(state_without_rollover)
    probe.state.rng.rand()
    assert state_with_rollover == int(probe.state.rng.state)
    assert int(world_with_rollover.creatures.entries[0].link_index) == -975


def test_quest_runner_disables_world_dt_steps_for_original_capture_dt_overrides() -> None:
    def _run(*, include_reflex_boosted: bool, dt_overrides: dict[int, float] | None) -> tuple[float, float]:
        header = ReplayHeader(
            game_mode_id=int(GameMode.QUESTS),
            seed=101,
            tick_rate=60,
            player_count=1,
            game_version="0.0.0",
        )
        rec = ReplayRecorder(header)
        rec.record_tick([PlayerInput(move=Vec2(1.0, 0.0), aim=Vec2(700.0, 512.0))])
        replay = rec.finish()
        bootstrap_payload = _strict_bootstrap_payload(tick_index=0)
        replay.events.append(_strict_bootstrap_event(bootstrap_payload))
        if include_reflex_boosted:
            replay.events.append(
                CapturePerkApplyEvent(
                    tick_index=0,
                    perk_id=int(PerkId.REFLEX_BOOSTED),
                    outside_before=True,
                    pending_before=None,
                    pending_after=None,
                ),
            )

        checkpoints = []
        with pytest.warns(ReplayGameVersionWarning):
            run_quest_replay(
                replay,
                spawn_entries=(),
                dt_frame_overrides=dt_overrides,
                checkpoints_out=checkpoints,
                checkpoint_ticks={0},
            )
        assert len(checkpoints) == 1
        player = checkpoints[0].players[0]
        return float(player.pos.x), float(player.pos.y)

    no_override_without_perk = _run(include_reflex_boosted=False, dt_overrides=None)
    no_override_with_perk = _run(include_reflex_boosted=True, dt_overrides=None)
    assert abs(no_override_with_perk[0] - no_override_without_perk[0]) > 1e-6

    dt_overrides = {0: 0.1}
    override_without_perk = _run(include_reflex_boosted=False, dt_overrides=dt_overrides)
    override_with_perk = _run(include_reflex_boosted=True, dt_overrides=dt_overrides)
    assert_float_close(override_with_perk[0], override_without_perk[0])
    assert_float_close(override_with_perk[1], override_without_perk[1])


def test_quest_runner_resets_run_on_capture_state_transition_to_12() -> None:
    _header, rec = _blank_quest_replay(ticks=2, seed=101, game_version="0.0.0")
    replay = rec.finish()
    replay.inputs[1][0] = [0.0, 0.0, 700.0, 512.0, 1]
    bootstrap_payload = _strict_bootstrap_payload(tick_index=0)
    bootstrap_payload["players"] = [
        _strict_bootstrap_player_payload(
            weapon_id=17,
            ammo=6.0,
            experience=11581,
            level=4,
            health=0.0,
        ),
    ]
    bootstrap_payload["score_xp"] = 11581
    bootstrap_payload["bonus_timers_ms"] = {"9": 1769}
    bootstrap_payload["perk"] = {
        "pending_count": 0,
        "choices_dirty": False,
        "choices": [],
        "player_nonzero_counts": [[[12, 1], [34, 1], [44, 1]]],
    }
    replay.events.append(_strict_bootstrap_event(bootstrap_payload))
    replay.events.append(
        CaptureStateTransitionEvent(
            tick_index=0,
            transitions=[
                CaptureStateTransitionRow(target_state=12, before_state=9, after_state=12),
            ],
        ),
    )

    checkpoints = []
    with pytest.warns(ReplayGameVersionWarning):
        run_quest_replay(
            replay,
            spawn_entries=(),
            dt_frame_overrides={0: 0.1, 1: 0.1},
            checkpoints_out=checkpoints,
            checkpoint_ticks={1},
        )
    assert len(checkpoints) == 1
    checkpoint = checkpoints[0]
    player = checkpoint.players[0]
    assert int(player.weapon_id) == 1
    assert_float_close(float(player.ammo), 11.0)
    assert int(player.experience) == 0
    assert int(player.level) == 1
    assert int(checkpoint.score_xp) == 0
    assert int(checkpoint.creature_count) == 0
    assert int(checkpoint.bonus_timers.get("9", 0)) == 0
    assert checkpoint.perk.player_nonzero_counts[0] == []
