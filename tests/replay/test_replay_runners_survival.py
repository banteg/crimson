from __future__ import annotations

import msgspec

from crimson.game_modes import GameMode
from crimson.perks import PerkId
from crimson.replay.driver.playback_driver import PlaybackDriver, build_verify_playback_driver
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.bootstrap import advance_unlock_terrain
from crimson.sim.input_providers import (
    GameFrameRngAdvanceOperation,
    PerkMenuOpenCommand,
    PerkPickCommand,
)
from grim.rand import CallerStatic, Crand, CrtRand
from tests.support.replay_runner_helpers import (
    ReplayRngTraceRecorder,
    _blank_survival_replay,
    _run_verify_playback,
)


def test_survival_runner_is_deterministic() -> None:
    _header, rec = _blank_survival_replay(ticks=10, seed=0x1234)
    replay = rec.finish()

    result0 = _run_verify_playback(replay)
    result1 = _run_verify_playback(replay)

    assert result0 == result1
    assert result0.game_mode_id == int(GameMode.SURVIVAL)
    assert result0.ticks == 10
    assert result0.elapsed_ms == 10 * int(1000.0 / 60.0)
    assert result0.score_xp == 0
    assert result0.creature_kill_count == 0
    assert result0.most_used_weapon_id == 1
    assert result0.shots_fired == 0
    assert result0.shots_hit == 0


def test_survival_runner_uses_replay_dt_rows_for_elapsed_ms() -> None:
    _header, rec = _blank_survival_replay(ticks=1, seed=0x1234)
    replay = rec.finish()
    replay.ticks[0] = msgspec.structs.replace(replay.ticks[0], dt=0.5)

    result = _run_verify_playback(replay)

    assert result.elapsed_ms == 500


def test_survival_runner_game_frame_rng_advance_prelude_shifts_rng_state() -> None:
    _header, rec = _blank_survival_replay(ticks=3, seed=0x1234)
    replay = rec.finish()

    baseline = _run_verify_playback(replay)
    shifted_replay = msgspec.structs.replace(
        replay,
        ticks=[
            msgspec.structs.replace(tick, prelude=[GameFrameRngAdvanceOperation(frames=1)]) for tick in replay.ticks
        ],
    )
    shifted = _run_verify_playback(shifted_replay)
    shifted_again = _run_verify_playback(shifted_replay)

    assert baseline.ticks == shifted.ticks == shifted_again.ticks == 3
    assert shifted == shifted_again
    assert shifted.rng_state != baseline.rng_state


def test_survival_replay_prelude_finishes_before_tick_rng_trace() -> None:
    _header, rec = _blank_survival_replay(ticks=1, seed=0x1234)
    replay = rec.finish()
    replay.ticks[0] = msgspec.structs.replace(
        replay.ticks[0],
        prelude=[
            GameFrameRngAdvanceOperation(frames=1),
            PerkPickCommand(player_index=0, choice_index=0),
            GameFrameRngAdvanceOperation(frames=3),
        ],
    )
    driver = PlaybackDriver(replay, trace_rng=True, strict_rng_trace=True)
    perk = driver.world.state.perk_selection
    perk.pending_count = 1
    perk.choices_dirty = False
    perk.choices = [PerkId.BANDAGE] * 7
    prelude_draws: list[tuple[int, int, int, CallerStatic | None]] = []

    def _trace(state_before: int, state_after: int, value_15: int, caller: CallerStatic | None) -> None:
        prelude_draws.append((state_before, state_after, value_15, caller))

    rng = driver.world.state.rng
    assert isinstance(rng, CrtRand)
    rng.set_trace_sink(_trace, require_caller=True)
    driver.step_tick(0)

    callers = [row[3] for row in prelude_draws]
    assert callers[0] == RngCallerStatic.GAME_FRAME_UPDATE_DISCARDED
    assert RngCallerStatic.PERK_APPLY_BANDAGE_HEAL in callers
    assert callers[-3:] == [RngCallerStatic.GAME_FRAME_UPDATE_DISCARDED] * 3
    assert driver._last_tick_rng_rows
    assert int(driver._last_tick_rng_rows[0][0]) == int(prelude_draws[-1][1])


def test_survival_replay_postlude_appends_menu_rng_after_simulation() -> None:
    _header, recorder = _blank_survival_replay(ticks=1, seed=0x1234)
    baseline_replay = recorder.finish()
    postlude_replay = msgspec.structs.replace(
        baseline_replay,
        ticks=[
            msgspec.structs.replace(
                baseline_replay.ticks[0],
                postlude=[PerkMenuOpenCommand(player_index=0)],
            ),
        ],
    )
    baseline = PlaybackDriver(baseline_replay, trace_rng=True, strict_rng_trace=True)
    postlude = PlaybackDriver(postlude_replay, trace_rng=True, strict_rng_trace=True)

    baseline.step_tick(0)
    postlude.step_tick(0)

    baseline_rows = list(baseline._last_tick_rng_rows)
    postlude_rows = list(postlude._last_tick_rng_rows)
    assert postlude_rows[: len(baseline_rows)] == baseline_rows
    assert len(postlude_rows) > len(baseline_rows)
    assert RngCallerStatic.PERK_SELECT_RANDOM in [row[3] for row in postlude_rows[len(baseline_rows) :]]
    assert len(postlude.world.state.perk_selection.choices) == 7
    assert postlude.world.state.perk_selection.choices_dirty is False


def test_survival_runner_uses_header_seed_for_startup_terrain_prelude() -> None:
    _header, rec = _blank_survival_replay(ticks=0, seed=0x1234)
    replay = rec.finish()
    driver = build_verify_playback_driver(replay)

    rng = Crand(int(replay.header.seed))
    terrain = advance_unlock_terrain(
        rng,
        unlock_index=int(replay.header.status.quest_unlock_index),
        width=int(replay.header.world_size),
        height=int(replay.header.world_size),
    )

    terrain_setup = driver.terrain_setup
    assert terrain_setup is not None
    assert terrain_setup.terrain_slots == terrain.terrain_slots
    assert terrain_setup.terrain_seed == int(terrain.terrain_seed)
    assert int(driver.world.state.rng.state) == int(rng.state)


def test_survival_runner_ignores_stale_perk_pick_command() -> None:
    _header, rec = _blank_survival_replay(ticks=1, seed=0x1234)
    replay = rec.finish()
    replay.ticks[0] = msgspec.structs.replace(
        replay.ticks[0],
        prelude=[PerkPickCommand(player_index=0, choice_index=0)],
    )

    result = _run_verify_playback(replay)
    assert result.ticks == 1


def test_survival_runner_menu_open_allows_same_tick_perk_pick() -> None:
    _header, rec = _blank_survival_replay(ticks=1, seed=0x1234)
    replay = rec.finish()
    replay.ticks[0] = msgspec.structs.replace(
        replay.ticks[0],
        prelude=[PerkMenuOpenCommand(player_index=0), PerkPickCommand(player_index=0, choice_index=0)],
    )

    result = _run_verify_playback(replay)

    assert result.game_mode_id == int(GameMode.SURVIVAL)
    assert result.ticks == 1


def test_survival_runner_checkpoints_capture_debug_fields() -> None:
    _header, rec = _blank_survival_replay(ticks=3, seed=0x1234)
    replay = rec.finish()
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
    _header, rec = _blank_survival_replay(ticks=1, seed=0x1234)
    replay = rec.finish()
    observer = ReplayRngTraceRecorder(rows_by_tick={})

    _run_verify_playback(
        replay,
        trace_rng=True,
        observer=observer,
    )

    assert sorted(observer.rows_by_tick.keys()) == [0]
    assert observer.rows_by_tick[0]


def test_survival_runner_tick_rng_trace_observer_emits_draw_rows() -> None:
    _header, rec = _blank_survival_replay(ticks=3, seed=0x1234)
    replay = rec.finish()
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
    _header, rec = _blank_survival_replay(ticks=4, seed=0x1234)
    replay = rec.finish()
    driver = PlaybackDriver(replay)

    driver_result = driver.run()
    wrapper_result = build_verify_playback_driver(replay).run()

    assert driver_result == wrapper_result
