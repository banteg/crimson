from __future__ import annotations

from types import SimpleNamespace
from typing import cast

from crimson.game_modes import GameMode
from crimson.modes.replay_playback_mode import ReplayPlaybackMode
from crimson.replay import Replay
from crimson.sim.driver.replay_benchmark import _run_result_from_replay_mode
from crimson.weapons import WeaponId


def test_run_result_from_replay_mode_reads_sim_world_state(monkeypatch) -> None:
    monkeypatch.setattr(
        "crimson.sim.driver.replay_benchmark.player0_shots",
        lambda _state: (11, 5),
    )
    monkeypatch.setattr(
        "crimson.sim.driver.replay_benchmark.player0_most_used_weapon_id",
        lambda _state, _players: WeaponId.PISTOL,
    )

    sim_world = SimpleNamespace(
        elapsed_ms=777,
        state=SimpleNamespace(rng=SimpleNamespace(state=12345)),
        players=[SimpleNamespace(experience=456)],
        creatures=SimpleNamespace(kill_count=12),
    )
    # Intentionally omit legacy facade attributes (`state`, `players`, `creatures`)
    # at mode root. The replay benchmark must read from `mode._runtime.sim_world`.
    mode = SimpleNamespace(
        _runtime=SimpleNamespace(sim_world=sim_world),
        _quest_spawn_timeline_ms=999,
        tick_index=88,
    )
    replay = SimpleNamespace(header=SimpleNamespace(game_mode_id=int(GameMode.SURVIVAL), tick_rate=60))

    result = _run_result_from_replay_mode(
        mode=cast(ReplayPlaybackMode, mode),
        replay=cast(Replay, replay),
    )

    assert result.game_mode_id == GameMode.SURVIVAL
    assert result.ticks == 88
    assert result.elapsed_ms == 777
    assert result.score_xp == 456
    assert result.creature_kill_count == 12
    assert result.most_used_weapon_id == WeaponId.PISTOL
    assert result.shots_fired == 11
    assert result.shots_hit == 5
    assert result.rng_state == 12345
