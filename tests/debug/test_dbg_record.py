from __future__ import annotations

from pathlib import Path

import pytest

import crimson_re.dbg.record as dbg_record
from crimson.game_modes import GameMode
from crimson.replay import REPLAY_TICK_DT, REPLAY_TICK_RATE
from crimson_re.dbg.canonical_channels import (
    ReplayStepSnapshot,
    bonus_timer_ms,
)
from crimson_re.dbg.trace import load_trace
from tests.replay.cli._helpers import build_replay


def test_bonus_timer_ms_matches_frida_nearest_millisecond_encoding() -> None:
    assert bonus_timer_ms(8.811999320983887) == 8812
    assert bonus_timer_ms(0.0005) == 1
    assert bonus_timer_ms(-1.0) == 0


def test_canonical_elapsed_ms_uses_unscaled_replay_clock() -> None:
    steps = [
        ReplayStepSnapshot(dt=dt, inputs=[], prelude=[], postlude=[], commands=[]) for dt in (0.1, 0.09, 0.087)
    ]

    assert dbg_record._canonical_elapsed_ms_by_tick(steps) == [100, 190, 277]


def test_quest_recording_preserves_scaled_simulation_clock(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from crimson.replay.codec import dump_replay_file
    from crimson.replay.driver.playback_driver import build_verify_playback_driver

    replay_path, out_path = tmp_path / "quest.crd", tmp_path / "quest.cdt"
    dump_replay_file(replay_path, build_replay(mode=GameMode.QUESTS, ticks=2, quest_level="1.1"))

    def boosted_driver(*args, **kwargs):
        driver = build_verify_playback_driver(*args, **kwargs)
        driver.world.state.bonuses.reflex_boost = 5.0
        driver.world.state.time_scale_active = True
        return driver

    monkeypatch.setattr(dbg_record, "build_verify_playback_driver", boosted_driver)
    dbg_record.record_replay_to_trace(replay_path=replay_path, out_path=out_path)
    _, ticks, _ = load_trace(out_path)
    assert [tick.elapsed_ms for tick in ticks] == [5, 10]
    assert [tick.channels.checkpoint.elapsed_ms for tick in ticks] == [5, 10]
    assert [tick.dt_ms_i32 for tick in ticks] == [16, 16]


def test_port_replay_trace_reports_the_fixed_step_boundary(tmp_path: Path) -> None:
    from crimson.replay.codec import dump_replay_file
    from tests.replay.cli._helpers import build_typo_submit_replay

    replay = build_typo_submit_replay(word="ab")
    replay_path, out_path = tmp_path / "typo.crd", tmp_path / "typo.cdt"
    dump_replay_file(replay_path, replay)
    dbg_record.record_replay_to_trace(replay_path=replay_path, out_path=out_path)

    meta, ticks, _ = load_trace(out_path)
    assert meta.source.tick_rate == REPLAY_TICK_RATE
    assert meta.status == replay.run.status.as_status_data()
    steps = [tick.channels.replay_step for tick in ticks]
    assert [step.commands for step in steps] == [list(tick.commands) for tick in replay.ticks]
    assert all(step.dt == REPLAY_TICK_DT and not step.prelude and not step.postlude for step in steps)
    assert {tick.dt_ms_i32 for tick in ticks} == {16}
