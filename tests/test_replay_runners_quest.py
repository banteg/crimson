from __future__ import annotations

import pytest

from crimson.game_modes import GameMode
from crimson.replay import ReplayGameVersionWarning
from crimson.sim.driver.replay_runner import run_replay
from crimson.sim.driver.setup import ReplayRunnerError
from tests.replay_runner_helpers import _blank_quest_replay, _quest_spawn_entries


def test_quest_runner_is_deterministic() -> None:
    _header, rec = _blank_quest_replay(ticks=10, seed=101, game_version="0.0.0")
    replay = rec.finish()
    spawn_entries = tuple(
        _quest_spawn_entries("1.1", player_count=int(replay.header.player_count), seed=int(replay.header.seed)),
    )

    with pytest.warns(ReplayGameVersionWarning):
        result0 = run_replay(replay, spawn_entries=spawn_entries)
    with pytest.warns(ReplayGameVersionWarning):
        result1 = run_replay(replay, spawn_entries=spawn_entries)

    assert result0 == result1
    assert result0.game_mode_id == int(GameMode.QUESTS)
    assert result0.ticks == 10
    assert result0.elapsed_ms >= 0


def test_quest_runner_honors_dt_frame_overrides_for_elapsed_ms() -> None:
    _header, rec = _blank_quest_replay(ticks=1, seed=101, game_version="0.0.0")
    replay = rec.finish()
    spawn_entries = tuple(
        _quest_spawn_entries("1.1", player_count=int(replay.header.player_count), seed=int(replay.header.seed)),
    )

    with pytest.warns(ReplayGameVersionWarning):
        result = run_replay(
            replay,
            spawn_entries=spawn_entries,
            dt_frame_overrides={0: 0.5},
        )

    assert result.elapsed_ms == 500


def test_quest_runner_inter_tick_rand_draws_shift_rng_state() -> None:
    _header, rec = _blank_quest_replay(ticks=3, seed=101, game_version="0.0.0")
    replay = rec.finish()

    with pytest.warns(ReplayGameVersionWarning):
        baseline = run_replay(replay, spawn_entries=())
    with pytest.warns(ReplayGameVersionWarning):
        shifted = run_replay(replay, spawn_entries=(), inter_tick_rand_draws=1)
    with pytest.warns(ReplayGameVersionWarning):
        shifted_again = run_replay(replay, spawn_entries=(), inter_tick_rand_draws=1)

    assert baseline.ticks == shifted.ticks == shifted_again.ticks == 3
    assert shifted == shifted_again
    assert shifted.rng_state != baseline.rng_state


def test_quest_runner_rejects_invalid_perk_pick_event() -> None:
    _header, rec = _blank_quest_replay(ticks=1, seed=101, game_version="0.0.0")
    rec.record_perk_pick(player_index=0, choice_index=0, tick_index=0)
    replay = rec.finish()

    with pytest.warns(ReplayGameVersionWarning):
        with pytest.raises(ReplayRunnerError, match="perk_pick failed"):
            run_replay(replay, spawn_entries=())


def test_quest_runner_can_skip_invalid_perk_pick_event_non_strict() -> None:
    _header, rec = _blank_quest_replay(ticks=3, seed=101, game_version="0.0.0")
    rec.record_perk_pick(player_index=0, choice_index=0, tick_index=0)
    replay = rec.finish()

    with pytest.warns(ReplayGameVersionWarning):
        result = run_replay(replay, spawn_entries=(), strict_events=False)

    assert result.ticks == 3
