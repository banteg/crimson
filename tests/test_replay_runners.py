from __future__ import annotations

from dataclasses import replace

import pytest

from crimson.creatures.spawn import SpawnId
from crimson.game_modes import GameMode
from crimson.original.capture import (
    CAPTURE_BOOTSTRAP_EVENT_KIND,
    CAPTURE_CREATURE_SPAWN_EVENT_KIND,
    CAPTURE_PERK_APPLY_EVENT_KIND,
    CAPTURE_STATE_TRANSITION_EVENT_KIND,
)
from crimson.perks import PerkId
from crimson.quests import quest_by_level
from crimson.quests.runtime import build_quest_spawn_table
from crimson.quests.types import QuestContext, SpawnEntry
from crimson.replay import ReplayGameVersionWarning, ReplayHeader, ReplayRecorder, UnknownEvent
from crimson.sim.driver.replay_events import apply_replay_tick_events
from crimson.sim.driver.replay_runner import run_quest_replay, run_rush_replay, run_survival_replay
from crimson.sim.driver.setup import ReplayRunnerError, reset_players
from crimson.sim.input import PlayerInput
from crimson.sim.world_state import WorldState
from grim.geom import Vec2


def _blank_survival_replay(*, ticks: int, seed: int = 0xBEEF, game_version: str = "0.0.0") -> tuple[ReplayHeader, ReplayRecorder]:
    header = ReplayHeader(
        game_mode_id=int(GameMode.SURVIVAL),
        seed=int(seed),
        tick_rate=60,
        player_count=1,
        game_version=game_version,
    )
    rec = ReplayRecorder(header)
    for _ in range(int(ticks)):
        rec.record_tick([PlayerInput(aim=Vec2(512.0, 512.0))])
    return header, rec


def _blank_rush_replay(*, ticks: int, seed: int = 0xBEEF, game_version: str = "0.0.0") -> tuple[ReplayHeader, ReplayRecorder]:
    header = ReplayHeader(
        game_mode_id=int(GameMode.RUSH),
        seed=int(seed),
        tick_rate=60,
        player_count=1,
        game_version=game_version,
    )
    rec = ReplayRecorder(header)
    for _ in range(int(ticks)):
        rec.record_tick([PlayerInput(aim=Vec2(512.0, 512.0))])
    return header, rec


def _blank_quest_replay(*, ticks: int, seed: int = 101, game_version: str = "0.0.0") -> tuple[ReplayHeader, ReplayRecorder]:
    header = ReplayHeader(
        game_mode_id=int(GameMode.QUESTS),
        seed=int(seed),
        tick_rate=60,
        player_count=1,
        game_version=game_version,
    )
    rec = ReplayRecorder(header)
    for _ in range(int(ticks)):
        rec.record_tick([PlayerInput(aim=Vec2(512.0, 512.0))])
    return header, rec


def _quest_spawn_entries(level: str = "1.1", *, player_count: int = 1, seed: int = 101):
    quest = quest_by_level(level)
    assert quest is not None
    ctx = QuestContext(width=1024, height=1024, player_count=int(player_count))
    return build_quest_spawn_table(
        quest,
        ctx,
        seed=int(seed),
        hardcore=False,
        full_version=True,
    )


def test_survival_runner_is_deterministic() -> None:
    _header, rec = _blank_survival_replay(ticks=10, seed=0x1234, game_version="0.0.0")
    replay = rec.finish()

    with pytest.warns(ReplayGameVersionWarning):
        result0 = run_survival_replay(replay)
    with pytest.warns(ReplayGameVersionWarning):
        result1 = run_survival_replay(replay)

    assert result0 == result1
    assert result0.game_mode_id == int(GameMode.SURVIVAL)
    assert result0.ticks == 10
    assert result0.elapsed_ms == int(10 * (1000.0 / 60.0))
    assert result0.score_xp == 0
    assert result0.creature_kill_count == 0
    assert result0.most_used_weapon_id == 1
    assert result0.shots_fired == 0
    assert result0.shots_hit == 0


def test_quest_runner_is_deterministic() -> None:
    _header, rec = _blank_quest_replay(ticks=10, seed=101, game_version="0.0.0")
    replay = rec.finish()
    spawn_entries = _quest_spawn_entries("1.1", player_count=int(replay.header.player_count), seed=int(replay.header.seed))

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
    spawn_entries = (replace(base_entry, trigger_ms=5000, count=1),)
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
    replay_bootstrapped.events.append(
        UnknownEvent(
            tick_index=0,
            kind=CAPTURE_BOOTSTRAP_EVENT_KIND,
            payload=[
                {
                    "quest_session": {
                        "spawn_timeline_ms": 1701.0,
                        "no_creatures_timer_ms": 3100.0,
                        "completion_transition_ms": -1.0,
                    },
                },
            ],
        ),
    )
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
    replay.events.append(
        UnknownEvent(
            tick_index=0,
            kind=CAPTURE_BOOTSTRAP_EVENT_KIND,
            payload=[{"quest_session": {"spawn_timeline_ms": 0.0, "no_creatures_timer_ms": 0.0}}],
        ),
    )
    replay.events.append(
        UnknownEvent(
            tick_index=0,
            kind=CAPTURE_CREATURE_SPAWN_EVENT_KIND,
            payload=[
                {
                    "spawns": [
                        {
                            "template_id": int(SpawnId.ALIEN_AI7_ORBITER_36),
                            "pos": {"x": 434.3393859863281, "y": 455.56573486328125},
                            "heading": -4.083981990814209,
                        },
                    ],
                },
            ],
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


def test_capture_creature_spawn_event_applies_added_head_overrides() -> None:
    world = WorldState.build(
        world_size=1024.0,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=1,
    )
    reset_players(world.players, world_size=1024.0, player_count=1)
    event = UnknownEvent(
        tick_index=0,
        kind=CAPTURE_CREATURE_SPAWN_EVENT_KIND,
        payload=[
            {
                "spawns": [
                    {
                        "template_id": int(SpawnId.FORMATION_GRID_ALIEN_BRONZE_18),
                        "pos": {"x": -256.0, "y": 256.0},
                        "heading": -4.083981990814209,
                    },
                ],
                "added_head": [
                    {
                        "index": 1,
                        "heading": 1.1278764009475708,
                        "target_heading": 0.621416449546814,
                        "ai_mode": 3,
                        "link_index": 0,
                        "hp": 123.5,
                        "hitbox_size": 9.5,
                        "orbit_angle": 0.25,
                        "orbit_radius": 0.75,
                        "flags": 17,
                        "type_id": 7,
                        "pos": {"x": 12.25, "y": 34.5},
                    },
                ],
            },
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
    assert float(creature.heading) == pytest.approx(1.1278764009475708, abs=1e-6)
    assert float(creature.target_heading) == pytest.approx(0.621416449546814, abs=1e-6)
    assert int(creature.ai_mode) == 3
    assert int(creature.link_index) == 0
    assert float(creature.hp) == pytest.approx(123.5, abs=1e-6)
    assert float(creature.hitbox_size) == pytest.approx(9.5, abs=1e-6)
    assert float(creature.orbit_angle) == pytest.approx(0.25, abs=1e-6)
    assert float(creature.orbit_radius) == pytest.approx(0.75, abs=1e-6)
    assert int(creature.flags) == 17
    assert int(creature.type_id) == 7
    assert float(creature.pos.x) == pytest.approx(12.25, abs=1e-6)
    assert float(creature.pos.y) == pytest.approx(34.5, abs=1e-6)


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

    event = UnknownEvent(
        tick_index=0,
        kind=CAPTURE_CREATURE_SPAWN_EVENT_KIND,
        payload=[
            {
                "spawns": [],
                "added_head": [
                    {
                        "index": idx,
                        "heading": 0.28999999165534973,
                        "target_heading": 0.521416425704956,
                        "ai_mode": 0,
                        "link_index": 1,
                        "orbit_radius": 1.25,
                        "flags": 5,
                    },
                ],
            },
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
    assert float(creature.heading) == pytest.approx(0.28999999165534973, abs=1e-6)
    assert float(creature.target_heading) == pytest.approx(0.521416425704956, abs=1e-6)
    assert int(creature.ai_mode) == 0
    assert int(creature.link_index) == 1
    assert float(creature.orbit_radius) == pytest.approx(1.25, abs=1e-6)
    assert int(creature.flags) == 5


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
        replay.events.append(
            UnknownEvent(
                tick_index=0,
                kind=CAPTURE_BOOTSTRAP_EVENT_KIND,
                payload=[{"tick_index": 0}],
            ),
        )
        if include_reflex_boosted:
            replay.events.append(
                UnknownEvent(
                    tick_index=0,
                    kind=CAPTURE_PERK_APPLY_EVENT_KIND,
                    payload=[{"perk_id": int(PerkId.REFLEX_BOOSTED), "outside_before": True}],
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
    assert no_override_with_perk[0] != pytest.approx(no_override_without_perk[0], abs=1e-4)

    dt_overrides = {0: 0.1}
    override_without_perk = _run(include_reflex_boosted=False, dt_overrides=dt_overrides)
    override_with_perk = _run(include_reflex_boosted=True, dt_overrides=dt_overrides)
    assert override_with_perk[0] == pytest.approx(override_without_perk[0], abs=1e-6)
    assert override_with_perk[1] == pytest.approx(override_without_perk[1], abs=1e-6)


def test_quest_runner_resets_run_on_capture_state_transition_to_12() -> None:
    _header, rec = _blank_quest_replay(ticks=2, seed=101, game_version="0.0.0")
    replay = rec.finish()
    replay.inputs[1][0] = [0.0, 0.0, [700.0, 512.0], 1]
    replay.events.append(
        UnknownEvent(
            tick_index=0,
            kind=CAPTURE_BOOTSTRAP_EVENT_KIND,
            payload=[
                {
                    "players": [
                        {
                            "weapon_id": 17,
                            "ammo": 6.0,
                            "experience": 11581,
                            "level": 4,
                            "health": 0.0,
                        },
                    ],
                    "score_xp": 11581,
                    "bonus_timers_ms": {"9": 1769},
                    "perk": {
                        "pending_count": 0,
                        "choices_dirty": False,
                        "choices": [],
                        "player_nonzero_counts": [[[12, 1], [34, 1], [44, 1]]],
                    },
                },
            ],
        ),
    )
    replay.events.append(
        UnknownEvent(
            tick_index=0,
            kind=CAPTURE_STATE_TRANSITION_EVENT_KIND,
            payload=[{"transitions": [{"target_state": 12, "before_state": 9, "after_state": 12}]}],
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
    assert float(player.ammo) == pytest.approx(11.0, abs=1e-6)
    assert int(player.experience) == 0
    assert int(player.level) == 1
    assert int(checkpoint.score_xp) == 0
    assert int(checkpoint.creature_count) == 0
    assert int(checkpoint.bonus_timers.get("9", 0)) == 0
    assert checkpoint.perk.player_nonzero_counts[0] == []


def test_survival_runner_honors_dt_frame_overrides_for_elapsed_ms() -> None:
    _header, rec = _blank_survival_replay(ticks=1, seed=0x1234, game_version="0.0.0")
    replay = rec.finish()

    with pytest.warns(ReplayGameVersionWarning):
        result = run_survival_replay(
            replay,
            dt_frame_overrides={0: 0.5},
        )

    assert result.elapsed_ms == 500


def test_survival_runner_inter_tick_rand_draws_shift_rng_state() -> None:
    _header, rec = _blank_survival_replay(ticks=3, seed=0x1234, game_version="0.0.0")
    replay = rec.finish()

    with pytest.warns(ReplayGameVersionWarning):
        baseline = run_survival_replay(replay)
    with pytest.warns(ReplayGameVersionWarning):
        shifted = run_survival_replay(replay, inter_tick_rand_draws=1)
    with pytest.warns(ReplayGameVersionWarning):
        shifted_again = run_survival_replay(replay, inter_tick_rand_draws=1)

    assert baseline.ticks == shifted.ticks == shifted_again.ticks == 3
    assert shifted == shifted_again
    assert shifted.rng_state != baseline.rng_state


def test_survival_runner_rejects_invalid_perk_pick_event() -> None:
    _header, rec = _blank_survival_replay(ticks=1, seed=0x1234, game_version="0.0.0")
    rec.record_perk_pick(player_index=0, choice_index=0, tick_index=0)
    replay = rec.finish()

    with pytest.warns(ReplayGameVersionWarning):
        with pytest.raises(ReplayRunnerError, match="perk_pick failed"):
            run_survival_replay(replay)


def test_survival_runner_checkpoints_capture_rng_marks() -> None:
    _header, rec = _blank_survival_replay(ticks=3, seed=0x1234, game_version="0.0.0")
    replay = rec.finish()
    checkpoints = []

    with pytest.warns(ReplayGameVersionWarning):
        run_survival_replay(
            replay,
            strict_events=False,
            checkpoints_out=checkpoints,
            checkpoint_ticks={0, 2},
        )

    assert [int(ckpt.tick_index) for ckpt in checkpoints] == [0, 2]
    for ckpt in checkpoints:
        assert len(ckpt.command_hash) == 16
        assert {
            "before_world_step",
            "gw_begin",
            "gw_after_weapon_refresh",
            "gw_after_perks_rebuild",
            "gw_after_time_scale",
            "after_world_step",
            "after_stage_spawns",
            "after_wave_spawns",
        }.issubset(ckpt.rng_marks.keys())
        assert {
            "ws_begin",
            "ws_after_particles_update",
            "ws_after_sprite_effects",
            "ws_after_projectiles",
            "ws_after_bonus_update",
            "ws_after_sfx_queue_merge",
            "ws_after_player_damage_sfx",
            "ws_after_sfx",
        }.issubset(ckpt.rng_marks.keys())
        assert isinstance(ckpt.events.hit_count, int)
        assert isinstance(ckpt.events.pickup_count, int)
        assert isinstance(ckpt.events.sfx_count, int)
        assert isinstance(ckpt.deaths, list)


def test_survival_runner_trace_rng_captures_presentation_marks() -> None:
    _header, rec = _blank_survival_replay(ticks=1, seed=0x1234, game_version="0.0.0")
    replay = rec.finish()
    checkpoints = []

    with pytest.warns(ReplayGameVersionWarning):
        run_survival_replay(
            replay,
            strict_events=False,
            trace_rng=True,
            checkpoints_out=checkpoints,
            checkpoint_ticks={0},
        )

    assert [int(ckpt.tick_index) for ckpt in checkpoints] == [0]
    assert checkpoints[0].rng_marks["ps_draws_total"] >= 0


def test_survival_runner_can_skip_invalid_perk_pick_event_non_strict() -> None:
    _header, rec = _blank_survival_replay(ticks=3, seed=0x1234, game_version="0.0.0")
    rec.record_perk_pick(player_index=0, choice_index=0, tick_index=0)
    replay = rec.finish()

    with pytest.warns(ReplayGameVersionWarning):
        result = run_survival_replay(replay, strict_events=False)

    assert result.ticks == 3


def test_survival_runner_applies_terminal_tick_events() -> None:
    _header, rec = _blank_survival_replay(ticks=3, seed=0x1234, game_version="0.0.0")
    rec.record_perk_menu_open(player_index=0, tick_index=3)
    replay_with_terminal_event = rec.finish()

    _header, rec = _blank_survival_replay(ticks=3, seed=0x1234, game_version="0.0.0")
    replay_without_terminal_event = rec.finish()

    with pytest.warns(ReplayGameVersionWarning):
        with_terminal_event = run_survival_replay(replay_with_terminal_event)
    with pytest.warns(ReplayGameVersionWarning):
        without_terminal_event = run_survival_replay(replay_without_terminal_event)

    assert with_terminal_event.rng_state != without_terminal_event.rng_state


def test_survival_runner_can_capture_terminal_tick_checkpoint() -> None:
    _header, rec = _blank_survival_replay(ticks=3, seed=0x1234, game_version="0.0.0")
    rec.record_perk_menu_open(player_index=0, tick_index=3)
    replay = rec.finish()
    checkpoints = []

    with pytest.warns(ReplayGameVersionWarning):
        run_survival_replay(
            replay,
            strict_events=True,
            checkpoints_out=checkpoints,
            checkpoint_ticks={3},
        )

    assert [int(ckpt.tick_index) for ckpt in checkpoints] == [3]
    assert checkpoints[0].rng_marks == {}


def test_survival_runner_applies_original_capture_bootstrap_event() -> None:
    _header, rec = _blank_survival_replay(ticks=1, seed=0x1234, game_version="0.0.0")
    replay = rec.finish()
    replay.events.append(
        UnknownEvent(
            tick_index=0,
            kind=CAPTURE_BOOTSTRAP_EVENT_KIND,
            payload=[
                {
                    "elapsed_ms": 2000,
                    "perk_pending": 2,
                    "bonus_timers_ms": {"4": 1500},
                    "players": [
                        {
                            "pos": {"x": 600.0, "y": 600.0},
                            "health": 75.0,
                            "weapon_id": 9,
                            "ammo": 4.0,
                            "experience": 321,
                            "level": 5,
                        },
                    ],
                },
            ],
        ),
    )

    with pytest.warns(ReplayGameVersionWarning):
        result = run_survival_replay(replay, strict_events=True, max_ticks=1)

    assert result.ticks == 1
    assert result.score_xp == 321


def test_survival_runner_bootstrap_player_shot_cooldown_blocks_first_tick_fire() -> None:
    def _run(*, include_shot_cooldown: bool) -> float:
        header = ReplayHeader(
            game_mode_id=int(GameMode.SURVIVAL),
            seed=0x1234,
            tick_rate=60,
            player_count=1,
            game_version="0.0.0",
        )
        recorder = ReplayRecorder(header)
        recorder.record_tick([PlayerInput(aim=Vec2(700.0, 512.0), fire_down=True)])
        replay = recorder.finish()
        bootstrap_player: dict[str, object] = {
            "weapon_id": 1,
            "ammo": 12.0,
            "reload_active": False,
            "reload_timer": 0.0,
            "reload_timer_max": 1.0,
            "spread_heat": 0.0,
        }
        if include_shot_cooldown:
            bootstrap_player["shot_cooldown"] = 0.5
        replay.events.append(
            UnknownEvent(
                tick_index=0,
                kind=CAPTURE_BOOTSTRAP_EVENT_KIND,
                payload=[{"players": [bootstrap_player]}],
            ),
        )

        checkpoints = []
        with pytest.warns(ReplayGameVersionWarning):
            run_survival_replay(
                replay,
                strict_events=True,
                max_ticks=1,
                checkpoints_out=checkpoints,
                checkpoint_ticks={0},
            )
        assert len(checkpoints) == 1
        return float(checkpoints[0].players[0].ammo)

    ammo_without_shot_cooldown = _run(include_shot_cooldown=False)
    ammo_with_shot_cooldown = _run(include_shot_cooldown=True)
    assert ammo_without_shot_cooldown < ammo_with_shot_cooldown
    assert ammo_with_shot_cooldown == pytest.approx(12.0, abs=1e-6)


def test_survival_runner_bootstrap_perk_counts_enable_alternate_weapon_swap() -> None:
    def _run(*, include_perk_counts: bool) -> tuple[int, float]:
        header = ReplayHeader(
            game_mode_id=int(GameMode.SURVIVAL),
            seed=0x1234,
            tick_rate=60,
            player_count=1,
            game_version="0.0.0",
        )
        rec = ReplayRecorder(header)
        rec.record_tick([PlayerInput(aim=Vec2(512.0, 512.0), reload_pressed=True)])
        replay = rec.finish()
        payload: dict[str, object] = {
            "players": [
                {
                    "weapon_id": 11,
                    "ammo": 0.0,
                    "reload_active": False,
                    "reload_timer": 0.0,
                    "reload_timer_max": 1.0,
                    "alt_weapon": {
                        "weapon_id": 1,
                        "clip_size": 12,
                        "ammo": 12.0,
                        "reload_active": False,
                        "reload_timer": 0.0,
                        "shot_cooldown": 0.0,
                        "reload_timer_max": 1.2,
                    },
                },
            ],
        }
        if include_perk_counts:
            payload["perk"] = {
                "pending_count": 0,
                "choices_dirty": False,
                "choices": [],
                "player_nonzero_counts": [[[int(PerkId.ALTERNATE_WEAPON), 1]]],
            }
        replay.events.append(
            UnknownEvent(
                tick_index=0,
                kind=CAPTURE_BOOTSTRAP_EVENT_KIND,
                payload=[payload],
            ),
        )

        checkpoints = []
        with pytest.warns(ReplayGameVersionWarning):
            run_survival_replay(
                replay,
                strict_events=True,
                max_ticks=1,
                checkpoints_out=checkpoints,
                checkpoint_ticks={0},
            )
        assert len(checkpoints) == 1
        player = checkpoints[0].players[0]
        return int(player.weapon_id), float(player.ammo)

    weapon_without_perk, ammo_without_perk = _run(include_perk_counts=False)
    weapon_with_perk, ammo_with_perk = _run(include_perk_counts=True)
    assert weapon_without_perk == 11
    assert ammo_without_perk == pytest.approx(0.0, abs=1e-6)
    assert weapon_with_perk == 1
    assert ammo_with_perk == pytest.approx(12.0, abs=1e-6)


def test_survival_runner_does_not_stop_early_on_death_for_original_capture_replay() -> None:
    _header, rec = _blank_survival_replay(ticks=3, seed=0x1234, game_version="0.0.0")
    replay = rec.finish()
    replay.events.append(
        UnknownEvent(
            tick_index=0,
            kind=CAPTURE_BOOTSTRAP_EVENT_KIND,
            payload=[{"players": [{"health": -1.0}]}],
        ),
    )

    with pytest.warns(ReplayGameVersionWarning):
        result = run_survival_replay(replay, strict_events=True)

    assert result.ticks == 3


def test_survival_runner_skips_world_dt_perk_steps_for_original_capture_dt_overrides() -> None:
    def _run(*, include_bootstrap: bool) -> float:
        header = ReplayHeader(
            game_mode_id=int(GameMode.SURVIVAL),
            seed=0x1234,
            tick_rate=60,
            player_count=1,
            game_version="0.0.0",
        )
        recorder = ReplayRecorder(header)
        recorder.record_tick([PlayerInput(move=Vec2(1.0, 0.0), aim=Vec2(600.0, 512.0))])
        replay = recorder.finish()
        if include_bootstrap:
            replay.events.append(
                UnknownEvent(
                    tick_index=0,
                    kind=CAPTURE_BOOTSTRAP_EVENT_KIND,
                    payload=[{"digital_move_enabled_by_player": [True]}],
                ),
            )
        replay.events.append(
            UnknownEvent(
                tick_index=0,
                kind=CAPTURE_PERK_APPLY_EVENT_KIND,
                payload=[{"perk_id": int(PerkId.REFLEX_BOOSTED), "outside_before": False}],
            ),
        )

        checkpoints = []
        with pytest.warns(ReplayGameVersionWarning):
            run_survival_replay(
                replay,
                max_ticks=1,
                checkpoints_out=checkpoints,
                checkpoint_ticks={0},
                dt_frame_overrides={0: 0.1},
            )
        assert len(checkpoints) == 1
        return float(checkpoints[0].players[0].pos.x)

    orig_capture_x = _run(include_bootstrap=True)
    plain_replay_x = _run(include_bootstrap=False)
    assert orig_capture_x > plain_replay_x


def test_survival_runner_original_capture_reflex_scaled_dt_ms_uses_scaled_float_dt() -> None:
    _header, rec = _blank_survival_replay(ticks=1, seed=0x1234, game_version="0.0.0")
    replay = rec.finish()
    replay.events.append(
        UnknownEvent(
            tick_index=0,
            kind=CAPTURE_BOOTSTRAP_EVENT_KIND,
            payload=[
                {
                    "bonus_timers_ms": {"9": 124},
                    "digital_move_enabled_by_player": [True],
                },
            ],
        ),
    )

    with pytest.warns(ReplayGameVersionWarning):
        result = run_survival_replay(
            replay,
            max_ticks=1,
            dt_frame_overrides={0: 0.0468},
            dt_frame_ms_i32_overrides={0: 46},
        )

    # With Reflex Boost active, native scaled frame_dt_ms is derived from the
    # scaled float dt path (~42.12ms -> 42), not from integer base-ms scaling.
    assert result.elapsed_ms == 42


def test_survival_runner_original_capture_uses_packed_move_vector_for_turn_only_keys() -> None:
    header = ReplayHeader(
        game_mode_id=int(GameMode.SURVIVAL),
        seed=0x1234,
        tick_rate=60,
        player_count=1,
        game_version="0.0.0",
    )
    recorder = ReplayRecorder(header)
    recorder.record_tick([PlayerInput(move=Vec2(1.0, 0.0), aim=Vec2(600.0, 512.0))])
    replay = recorder.finish()
    replay.events.append(
        UnknownEvent(
            tick_index=0,
            kind=CAPTURE_BOOTSTRAP_EVENT_KIND,
            payload=[{"digital_move_enabled_by_player": [True]}],
        ),
    )

    checkpoints = []
    with pytest.warns(ReplayGameVersionWarning):
        run_survival_replay(
            replay,
            max_ticks=1,
            checkpoints_out=checkpoints,
            checkpoint_ticks={0},
        )

    assert len(checkpoints) == 1
    assert float(checkpoints[0].players[0].pos.x) > 512.0


def test_rush_runner_is_deterministic() -> None:
    _header, rec = _blank_rush_replay(ticks=10, seed=0x1234, game_version="0.0.0")
    replay = rec.finish()

    with pytest.warns(ReplayGameVersionWarning):
        result0 = run_rush_replay(replay)
    with pytest.warns(ReplayGameVersionWarning):
        result1 = run_rush_replay(replay)

    assert result0 == result1
    assert result0.game_mode_id == int(GameMode.RUSH)
    assert result0.ticks == 10
    assert result0.elapsed_ms == int(10 * (1000.0 / 60.0))
    assert result0.score_xp == 0
    assert result0.creature_kill_count == 0
    assert result0.most_used_weapon_id == 2
    assert result0.shots_fired == 0
    assert result0.shots_hit == 0


def test_rush_runner_honors_dt_frame_overrides_for_elapsed_ms() -> None:
    _header, rec = _blank_rush_replay(ticks=1, seed=0x1234, game_version="0.0.0")
    replay = rec.finish()

    with pytest.warns(ReplayGameVersionWarning):
        result = run_rush_replay(
            replay,
            dt_frame_overrides={0: 0.5},
        )

    assert result.elapsed_ms == 500


def test_rush_runner_inter_tick_rand_draws_shift_rng_state() -> None:
    _header, rec = _blank_rush_replay(ticks=3, seed=0x1234, game_version="0.0.0")
    replay = rec.finish()

    with pytest.warns(ReplayGameVersionWarning):
        baseline = run_rush_replay(replay)
    with pytest.warns(ReplayGameVersionWarning):
        shifted = run_rush_replay(replay, inter_tick_rand_draws=1)
    with pytest.warns(ReplayGameVersionWarning):
        shifted_again = run_rush_replay(replay, inter_tick_rand_draws=1)

    assert baseline.ticks == shifted.ticks == shifted_again.ticks == 3
    assert shifted == shifted_again
    assert shifted.rng_state != baseline.rng_state


def test_rush_runner_rejects_events() -> None:
    _header, rec = _blank_rush_replay(ticks=1, seed=0x1234, game_version="0.0.0")
    rec.record_perk_pick(player_index=0, choice_index=0, tick_index=0)
    replay = rec.finish()

    with pytest.warns(ReplayGameVersionWarning):
        with pytest.raises(ReplayRunnerError, match="does not support events"):
            run_rush_replay(replay)


def test_rush_runner_applies_original_capture_bootstrap_event() -> None:
    _header, rec = _blank_rush_replay(ticks=1, seed=0x1234, game_version="0.0.0")
    replay = rec.finish()
    replay.events.append(
        UnknownEvent(
            tick_index=0,
            kind=CAPTURE_BOOTSTRAP_EVENT_KIND,
            payload=[
                {
                    "elapsed_ms": 3000,
                    "players": [
                        {
                            "pos": {"x": 400.0, "y": 450.0},
                            "health": 90.0,
                            "weapon_id": 2,
                            "ammo": 8.0,
                            "experience": 77,
                            "level": 3,
                        },
                    ],
                },
            ],
        ),
    )

    with pytest.warns(ReplayGameVersionWarning):
        result = run_rush_replay(replay, max_ticks=1)

    assert result.ticks == 1
    assert result.score_xp == 77


def test_rush_runner_original_capture_uses_packed_move_vector_for_turn_only_keys() -> None:
    header = ReplayHeader(
        game_mode_id=int(GameMode.RUSH),
        seed=0x1234,
        tick_rate=60,
        player_count=1,
        game_version="0.0.0",
    )
    recorder = ReplayRecorder(header)
    recorder.record_tick([PlayerInput(move=Vec2(1.0, 0.0), aim=Vec2(600.0, 512.0))])
    replay = recorder.finish()
    replay.events.append(
        UnknownEvent(
            tick_index=0,
            kind=CAPTURE_BOOTSTRAP_EVENT_KIND,
            payload=[{"digital_move_enabled_by_player": [True]}],
        ),
    )

    checkpoints = []
    with pytest.warns(ReplayGameVersionWarning):
        run_rush_replay(
            replay,
            max_ticks=1,
            checkpoints_out=checkpoints,
            checkpoint_ticks={0},
        )

    assert len(checkpoints) == 1
    assert float(checkpoints[0].players[0].pos.x) > 512.0


def test_rush_runner_checkpoints_capture_rng_marks() -> None:
    _header, rec = _blank_rush_replay(ticks=3, seed=0x1234, game_version="0.0.0")
    replay = rec.finish()
    checkpoints = []

    with pytest.warns(ReplayGameVersionWarning):
        run_rush_replay(
            replay,
            checkpoints_out=checkpoints,
            checkpoint_ticks={0, 2},
        )

    assert [int(ckpt.tick_index) for ckpt in checkpoints] == [0, 2]
    for ckpt in checkpoints:
        assert len(ckpt.command_hash) == 16
        assert {
            "before_world_step",
            "gw_begin",
            "gw_after_weapon_refresh",
            "gw_after_perks_rebuild",
            "gw_after_time_scale",
            "after_world_step",
            "after_rush_spawns",
        }.issubset(ckpt.rng_marks.keys())
        assert {
            "ws_begin",
            "ws_after_particles_update",
            "ws_after_sprite_effects",
            "ws_after_projectiles",
            "ws_after_bonus_update",
            "ws_after_sfx_queue_merge",
            "ws_after_player_damage_sfx",
            "ws_after_sfx",
        }.issubset(ckpt.rng_marks.keys())
        assert isinstance(ckpt.events.hit_count, int)
        assert isinstance(ckpt.events.pickup_count, int)
        assert isinstance(ckpt.events.sfx_count, int)
        assert isinstance(ckpt.deaths, list)


def test_rush_runner_trace_rng_captures_presentation_marks() -> None:
    _header, rec = _blank_rush_replay(ticks=1, seed=0x1234, game_version="0.0.0")
    replay = rec.finish()
    checkpoints = []

    with pytest.warns(ReplayGameVersionWarning):
        run_rush_replay(
            replay,
            trace_rng=True,
            checkpoints_out=checkpoints,
            checkpoint_ticks={0},
        )

    assert [int(ckpt.tick_index) for ckpt in checkpoints] == [0]
    assert checkpoints[0].rng_marks["ps_draws_total"] >= 0
