from __future__ import annotations

import msgspec

from crimson.game_modes import GameMode
from crimson.quests import quest_by_level
from crimson.sim.driver.replay_info import run_replay_info
from crimson.sim.driver.replay_runner import run_replay
from crimson.sim.input_providers import PerkPickCommand
from crimson.weapons import WEAPON_BY_ID
from tests.replay_runner_helpers import _blank_quest_replay, _quest_spawn_entries


def test_quest_runner_is_deterministic() -> None:
    _header, rec = _blank_quest_replay(ticks=10, seed=101)
    replay = rec.finish()
    spawn_entries = tuple(
        _quest_spawn_entries("1.1", player_count=int(replay.header.player_count), seed=int(replay.header.seed)),
    )

    result0 = run_replay(replay, spawn_entries=spawn_entries)
    result1 = run_replay(replay, spawn_entries=spawn_entries)

    assert result0 == result1
    assert result0.game_mode_id == int(GameMode.QUESTS)
    assert result0.ticks == 10
    assert result0.elapsed_ms >= 0


def test_quest_runner_uses_replay_dt_rows_for_elapsed_ms() -> None:
    _header, rec = _blank_quest_replay(ticks=1, seed=101)
    replay = rec.finish()
    replay.ticks[0] = msgspec.structs.replace(replay.ticks[0], dt=0.5)
    spawn_entries = tuple(
        _quest_spawn_entries("1.1", player_count=int(replay.header.player_count), seed=int(replay.header.seed)),
    )

    result = run_replay(
        replay,
        spawn_entries=spawn_entries,
    )

    assert result.elapsed_ms == 500


def test_quest_runner_inter_tick_rand_draws_shift_rng_state() -> None:
    _header, rec = _blank_quest_replay(ticks=3, seed=101)
    replay = rec.finish()

    baseline = run_replay(replay, spawn_entries=())
    shifted = run_replay(replay, spawn_entries=(), inter_tick_rand_draws=1)
    shifted_again = run_replay(replay, spawn_entries=(), inter_tick_rand_draws=1)

    assert baseline.ticks == shifted.ticks == shifted_again.ticks == 3
    assert shifted == shifted_again
    assert shifted.rng_state != baseline.rng_state


def test_quest_runner_replays_start_weapon_reload_sfx_at_tick_zero() -> None:
    _header, rec = _blank_quest_replay(ticks=1, seed=101)
    replay = rec.finish()
    checkpoints = []

    run_replay(
        replay,
        checkpoints_out=checkpoints,
        checkpoint_ticks={0},
    )

    assert len(checkpoints) == 1
    tick0 = checkpoints[0]
    assert int(tick0.events.sfx_count) == 1

    quest = quest_by_level("1.1")
    assert quest is not None
    weapon = WEAPON_BY_ID[quest.start_weapon_id]
    expected_reload_sfx = weapon.reload_sound
    assert tick0.events.sfx_head == [expected_reload_sfx]


def test_quest_runner_ignores_stale_perk_pick_command() -> None:
    _header, rec = _blank_quest_replay(ticks=1, seed=101)
    replay = rec.finish()
    replay.ticks[0] = msgspec.structs.replace(
        replay.ticks[0],
        commands=(PerkPickCommand(player_index=0, choice_index=0),),
    )

    result = run_replay(replay, spawn_entries=())
    assert result.ticks == 1


def test_quest_replay_info_elapsed_matches_run_replay() -> None:
    _header, rec = _blank_quest_replay(ticks=1, seed=101)
    replay = rec.finish()
    replay.ticks[0] = msgspec.structs.replace(replay.ticks[0], dt=0.5)

    run_result = run_replay(replay)
    info = run_replay_info(replay)

    assert int(info.elapsed_ms) == int(run_result.elapsed_ms)
