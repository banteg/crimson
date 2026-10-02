from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import crimson_re.dbg.record as dbg_record
from crimson.game_modes import GameMode
from crimson.replay import REPLAY_TICK_DT, REPLAY_TICK_RATE
from crimson.replay.checkpoints import (
    ReplayCheckpoint,
    ReplayCheckpointVec2,
    ReplayEventSummary,
    ReplayPerkSnapshot,
    ReplayPlayerCheckpoint,
)
from crimson.weapons import WeaponId
from crimson_re.dbg.canonical_channels import (
    EntitySamplesSnapshot,
    ReplayStepSnapshot,
    SimStateSnapshot,
    SnapshotBonusTimers,
    SnapshotGameplay,
    SnapshotPlayer,
    SnapshotVec2,
    SnapshotWeapon,
    bonus_timer_ms,
)
from crimson_re.dbg.schema import TRACE_SCHEMA_VERSION
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


def test_record_replay_to_trace_python_writes_unattributed_rows(
    monkeypatch,
    tmp_path: Path,
) -> None:
    replay_path = tmp_path / "sample.crd"
    replay_path.write_bytes(b"fake")
    replay = build_replay(mode=GameMode.SURVIVAL, ticks=1)

    class _FakeDriver:
        def build_checkpoint(self, *, tick_result) -> ReplayCheckpoint:
            return ReplayCheckpoint(
                tick_index=int(tick_result.tick_index),
                rng_state=0,
                rng_callers_crc32=0,
                elapsed_ms=0,
                score_xp=0,
                kills=0,
                creature_count=0,
                perk_pending=0,
                players=[
                    ReplayPlayerCheckpoint(
                        pos=ReplayCheckpointVec2(0.0, 0.0),
                        health=100.0,
                        weapon_id=WeaponId.PISTOL,
                        ammo=0.0,
                        experience=0,
                        level=1,
                    ),
                ],
                bonus_timers={},
                deaths=[],
                perk=ReplayPerkSnapshot(
                    pending_count=0,
                    choices_dirty=False,
                    choices=[0] * 7,
                    player_nonzero_counts=[[]],
                ),
                events=ReplayEventSummary(
                    hit_count=0,
                    pickup_count=0,
                    sfx_count=0,
                    sfx_head=[],
                    hit_head=[],
                ),
                tutorial=None,
                typo=None,
            )

        def run(self, *, observer):
            tick_result = SimpleNamespace(tick_index=0)
            world = SimpleNamespace(
                state=SimpleNamespace(
                    time_scale_active=False,
                    bonuses=SimpleNamespace(reflex_boost=0.0),
                ),
            )
            observer.before_tick(0, world, REPLAY_TICK_DT)
            observer.after_tick(tick_result, world)
            observer.rng_trace(
                tick_result,
                ((0x90ABCDEF, 23203, 0x5AA3B0F6, None),),
            )
            return SimpleNamespace()

    monkeypatch.setattr(
        dbg_record,
        "_load_recording",
        lambda _path: (dbg_record._replay_recording(replay), _FakeDriver()),
    )
    monkeypatch.setattr(
        dbg_record,
        "_entity_samples_for_world",
        lambda *_args, **_kwargs: EntitySamplesSnapshot(
            creatures=[],
            projectiles=[],
            secondary_projectiles=[],
            bonuses=[],
        ),
    )
    monkeypatch.setattr(
        dbg_record,
        "_sim_state_from_world",
        lambda *_args, **_kwargs: SimStateSnapshot(
            gameplay=SnapshotGameplay(
                mode_id=int(GameMode.SURVIVAL),
                quest_stage_major=0,
                quest_stage_minor=0,
                perk_pending_count=0,
                perk_choices_dirty=False,
                bonus_timers=SnapshotBonusTimers(
                    weapon_power_up_ms=0,
                    reflex_boost_ms=0,
                    energizer_ms=0,
                    double_experience_ms=0,
                    freeze_ms=0,
                ),
            ),
            players=[
                SnapshotPlayer(
                    index=0,
                    pos=SnapshotVec2(x=0.0, y=0.0),
                    heading=0.0,
                    move_speed=0.0,
                    move_phase=0.0,
                    aim=SnapshotVec2(x=0.0, y=0.0),
                    aim_heading=0.0,
                    health=100.0,
                    weapon=SnapshotWeapon(
                        weapon_id=int(WeaponId.PISTOL),
                        ammo=0.0,
                        clip_size=0,
                        reload_active=False,
                        reload_timer=0.0,
                        reload_timer_max=0.0,
                        shot_cooldown=0.0,
                    ),
                    experience=0,
                    level=1,
                ),
            ],
        ),
    )

    summary = dbg_record.record_replay_to_trace(
        replay_path=replay_path,
        out_path=tmp_path / "sample.cdt",
    )

    assert summary.meta.trace_schema_version == TRACE_SCHEMA_VERSION
    meta, ticks, footer = load_trace(tmp_path / "sample.cdt")
    assert meta.trace_schema_version == TRACE_SCHEMA_VERSION
    assert meta.status == replay.run.status.as_status_data()
    assert footer.tick_count == 1
    assert ticks[0].channels.rng_stream[0].caller is None
    assert len(ticks[0].channels.timing_samples) == 1
    assert ticks[0].channels.timing_samples[0].phase == "gpur_enter"


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
