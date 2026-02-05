from __future__ import annotations

import pytest

from crimson.game_modes import GameMode
from crimson.gameplay import PlayerInput
from crimson.replay import ReplayGameVersionWarning, ReplayHeader, ReplayRecorder
from crimson.sim.runners import ReplayRunnerError, run_rush_replay, run_survival_replay


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
        rec.record_tick([PlayerInput(aim_x=512.0, aim_y=512.0)])
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
        rec.record_tick([PlayerInput(aim_x=512.0, aim_y=512.0)])
    return header, rec


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


def test_survival_runner_rejects_invalid_perk_pick_event() -> None:
    _header, rec = _blank_survival_replay(ticks=1, seed=0x1234, game_version="0.0.0")
    rec.record_perk_pick(player_index=0, choice_index=0, tick_index=0)
    replay = rec.finish()

    with pytest.warns(ReplayGameVersionWarning):
        with pytest.raises(ReplayRunnerError, match="perk_pick failed"):
            run_survival_replay(replay)


def test_survival_runner_can_skip_invalid_perk_pick_event_non_strict() -> None:
    _header, rec = _blank_survival_replay(ticks=3, seed=0x1234, game_version="0.0.0")
    rec.record_perk_pick(player_index=0, choice_index=0, tick_index=0)
    replay = rec.finish()

    with pytest.warns(ReplayGameVersionWarning):
        result = run_survival_replay(replay, strict_events=False)

    assert result.ticks == 3


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


def test_rush_runner_rejects_events() -> None:
    _header, rec = _blank_rush_replay(ticks=1, seed=0x1234, game_version="0.0.0")
    rec.record_perk_pick(player_index=0, choice_index=0, tick_index=0)
    replay = rec.finish()

    with pytest.warns(ReplayGameVersionWarning):
        with pytest.raises(ReplayRunnerError, match="does not support events"):
            run_rush_replay(replay)
