from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest

from crimson.game_modes import GameMode
from crimson.modes.replay_playback_mode import ReplayPlaybackMode
from crimson.sim.driver.replay_benchmark import ReplayBenchmarkError, _run_result_for_replay_mode
from crimson.weapons import WeaponId


def test_run_result_for_replay_mode_delegates_to_driver_build_run_result() -> None:
    build_run_result_calls: list[int] = []
    mode = SimpleNamespace(
        _driver=SimpleNamespace(
            build_run_result=lambda *, ticks: build_run_result_calls.append(int(ticks)) or SimpleNamespace(
                game_mode_id=GameMode.SURVIVAL,
                ticks=int(ticks),
                elapsed_ms=777,
                score_xp=456,
                creature_kill_count=12,
                most_used_weapon_id=WeaponId.PISTOL,
                shots_fired=11,
                shots_hit=5,
                rng_state=12345,
            ),
        ),
        tick_index=88,
    )

    result = _run_result_for_replay_mode(mode=cast(ReplayPlaybackMode, mode))

    assert build_run_result_calls == [88]
    assert result.game_mode_id == GameMode.SURVIVAL
    assert result.ticks == 88
    assert result.elapsed_ms == 777
    assert result.score_xp == 456
    assert result.creature_kill_count == 12
    assert result.most_used_weapon_id == WeaponId.PISTOL
    assert result.shots_fired == 11
    assert result.shots_hit == 5
    assert result.rng_state == 12345


def test_run_result_for_replay_mode_requires_driver() -> None:
    mode = SimpleNamespace(
        _driver=None,
        tick_index=88,
    )

    with pytest.raises(ReplayBenchmarkError, match="replay driver was not available"):
        _run_result_for_replay_mode(mode=cast(ReplayPlaybackMode, mode))
