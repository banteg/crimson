from __future__ import annotations

import msgspec
import pytest

from crimson.perks import PerkId
from crimson.replay.driver.playback_driver import PlaybackDriver, build_verify_playback_driver
from crimson.replay.driver.setup import ReplayRunnerError
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.bootstrap import advance_unlock_terrain
from crimson.sim.input_providers import PerkMenuOpenCommand, PerkPickCommand
from crimson.sim.run_result import PlayerRunResult, RunOutcome
from crimson.sim.run_spec import WORLD_SIZE
from crimson.weapons import WeaponId
from grim.rand import CallerStatic, Crand
from tests.support.replay_runner_helpers import (
    ReplayRngTraceRecorder,
    _blank_survival_replay,
    _run_verify_playback,
    finish_replay,
)


def test_survival_runner_is_deterministic() -> None:
    replay = finish_replay(_blank_survival_replay(ticks=10, seed=0x1234))

    result0 = _run_verify_playback(replay)
    result1 = _run_verify_playback(replay)

    assert result0 == result1 == replay.result
    assert result0.outcome == RunOutcome.INCOMPLETE
    assert result0.elapsed_ms == 10 * int(1000.0 / 60.0)
    assert result0.kills == 0
    assert result0.quest_final_ms is None
    assert result0.players == (
        PlayerRunResult(experience=0, health=100.0, shots_fired=0, shots_hit=0, most_used_weapon_id=WeaponId.PISTOL),
    )


def test_survival_runner_uses_header_seed_for_startup_terrain_prelude() -> None:
    replay = finish_replay(_blank_survival_replay(ticks=0, seed=0x1234))
    driver = build_verify_playback_driver(replay)

    rng = Crand(int(replay.run.seed))
    terrain = advance_unlock_terrain(
        rng,
        unlock_index=int(replay.run.status.quest_unlock_index),
        width=int(WORLD_SIZE),
        height=int(WORLD_SIZE),
    )

    terrain_setup = driver.terrain_setup
    assert terrain_setup is not None
    assert terrain_setup.terrain_slots == terrain.terrain_slots
    assert terrain_setup.terrain_seed == int(terrain.terrain_seed)
    assert int(driver.world.state.rng.state) == int(rng.state)


def test_survival_runner_checkpoints_capture_debug_fields() -> None:
    replay = finish_replay(_blank_survival_replay(ticks=3, seed=0x1234))
    checkpoints = []

    _run_verify_playback(
        replay,
        checkpoints_out=checkpoints,
        checkpoint_ticks={0, 2},
    )

    assert [int(ckpt.tick_index) for ckpt in checkpoints] == [0, 2]
    for ckpt in checkpoints:
        assert isinstance(ckpt.events.hit_count, int)
        assert isinstance(ckpt.events.pickup_count, int)
        assert isinstance(ckpt.events.sfx_count, int)
        assert isinstance(ckpt.deaths, list)


def test_survival_runner_tick_rng_trace_observer_emits_rows_for_first_tick() -> None:
    replay = finish_replay(_blank_survival_replay(ticks=1, seed=0x1234))
    observer = ReplayRngTraceRecorder(rows_by_tick={})

    _run_verify_playback(
        replay,
        trace_rng=True,
        observer=observer,
    )

    assert sorted(observer.rows_by_tick.keys()) == [0]
    assert observer.rows_by_tick[0]


def test_survival_runner_tick_rng_trace_observer_emits_draw_rows() -> None:
    replay = finish_replay(_blank_survival_replay(ticks=3, seed=0x1234))
    observer = ReplayRngTraceRecorder(rows_by_tick={})

    _run_verify_playback(
        replay,
        trace_rng=True,
        observer=observer,
    )

    assert sorted(observer.rows_by_tick.keys()) == [0, 1, 2]
    tagged_by_tick: dict[int, list[CallerStatic]] = {}
    for tick_index, draws in sorted(observer.rows_by_tick.items()):
        tagged_callers: list[CallerStatic] = []
        for state_before_u32, value_15, state_after_u32, caller in draws:
            expected_after = (int(state_before_u32) * 214013 + 2531011) & 0xFFFFFFFF
            assert int(state_after_u32) == int(expected_after)
            assert int(value_15) == ((int(state_after_u32) >> 16) & 0x7FFF)
            if caller is not None:
                tagged_callers.append(caller)
        tagged_by_tick[int(tick_index)] = tagged_callers

    assert tagged_by_tick == {
        0: [
            RngCallerStatic.SURVIVAL_UPDATE_MAIN_SPAWN_EDGE,
            RngCallerStatic.SURVIVAL_UPDATE_MAIN_SPAWN_TOP_X,
            RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_TYPE_ROLL,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_RARE_OVERRIDE,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_SIZE,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_HEADING,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_HEALTH,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_LOW_TINT_G,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_LOW_TINT_B,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_REWARD_BONUS,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_RARE_RED,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_RARE_GREEN,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_RARE_BLUE,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_RARE_PURPLE,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_RARE_YELLOW,
        ],
        1: [],
        2: [],
    }


def test_playback_driver_run_matches_verify_driver_factory() -> None:
    replay = finish_replay(_blank_survival_replay(ticks=4, seed=0x1234))
    driver = PlaybackDriver(replay)

    driver_result = driver.run()
    wrapper_result = build_verify_playback_driver(replay).run()

    assert driver_result == wrapper_result


def _with_commands(replay, commands):
    replay.ticks[0] = msgspec.structs.replace(replay.ticks[0], commands=list(commands))
    return replay


@pytest.mark.parametrize(
    "commands",
    [
        [PerkPickCommand(player_index=0, choice_index=0)],
        [PerkMenuOpenCommand(player_index=0)],
    ],
)
def test_survival_runner_rejects_perk_commands_without_pending_perk(commands) -> None:
    replay = _with_commands(finish_replay(_blank_survival_replay(ticks=1, seed=0x1234)), commands)

    with pytest.raises(ReplayRunnerError, match="without a pending perk"):
        _run_verify_playback(replay)


def test_survival_runner_rejects_unoffered_perk_choice() -> None:
    replay = _with_commands(
        finish_replay(_blank_survival_replay(ticks=1, seed=0x1234)),
        [PerkPickCommand(player_index=0, choice_index=6)],
    )
    driver = PlaybackDriver(replay)
    perk = driver.world.state.perk_selection
    perk.pending_count = 1
    perk.choices_dirty = False
    perk.choices = [PerkId.BANDAGE] * 3

    with pytest.raises(ReplayRunnerError, match="not an offered choice"):
        driver.step_tick(0)


def test_survival_runner_menu_open_allows_same_tick_perk_pick() -> None:
    replay = _with_commands(
        finish_replay(_blank_survival_replay(ticks=1, seed=0x1234)),
        [PerkMenuOpenCommand(player_index=0), PerkPickCommand(player_index=0, choice_index=0)],
    )
    driver = PlaybackDriver(replay)
    driver.world.state.perk_selection.pending_count = 1

    driver.step_tick(0)

    assert driver.world.state.perk_selection.pending_count == 0


def test_survival_runner_rejects_ticks_after_run_end() -> None:
    replay = finish_replay(_blank_survival_replay(ticks=3, seed=0x1234))
    driver = PlaybackDriver(replay)
    for player in driver.world.players:
        player.health = 0.0
        player.death_timer = 0.0

    with pytest.raises(ReplayRunnerError, match=r"run ended \(death\) at tick 0 but the replay has 3 ticks"):
        driver.run()


def test_survival_runner_reports_death_on_final_tick() -> None:
    replay = finish_replay(_blank_survival_replay(ticks=1, seed=0x1234))
    driver = PlaybackDriver(replay)
    for player in driver.world.players:
        player.health = 0.0
        player.death_timer = 0.0

    result = driver.run()

    assert result.outcome == RunOutcome.DEATH


def test_survival_runner_rejects_perk_commands_after_every_player_died() -> None:
    replay = _with_commands(
        finish_replay(_blank_survival_replay(ticks=1, seed=0x1234)),
        [PerkMenuOpenCommand(player_index=0)],
    )
    driver = PlaybackDriver(replay)
    driver.world.state.perk_selection.pending_count = 1
    for player in driver.world.players:
        player.health = 0.0

    with pytest.raises(ReplayRunnerError, match="every player is dead"):
        driver.step_tick(0)
