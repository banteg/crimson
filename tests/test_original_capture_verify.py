from __future__ import annotations

from dataclasses import replace

from grim.geom import Vec2

from crimson.game_modes import GameMode
from crimson.gameplay import PlayerInput
from crimson.replay import ReplayHeader, ReplayRecorder
from crimson.replay.checkpoints import ReplayCheckpoint
from crimson.replay.original_capture import (
    ORIGINAL_CAPTURE_FORMAT_VERSION,
    OriginalCaptureSidecar,
    OriginalCaptureTick,
)
from crimson.replay.original_capture_verify import verify_original_capture
from crimson.sim.runners import run_survival_replay


def _single_tick_survival_checkpoint(*, seed: int = 0xBEEF):
    header = ReplayHeader(
        game_mode_id=int(GameMode.SURVIVAL),
        seed=int(seed),
        tick_rate=60,
        player_count=1,
    )
    rec = ReplayRecorder(header)
    rec.record_tick([PlayerInput(aim=Vec2(512.0, 512.0))])
    replay = rec.finish()

    checkpoints = []
    run_survival_replay(
        replay,
        strict_events=True,
        checkpoint_use_world_step_creature_count=True,
        checkpoints_out=checkpoints,
        checkpoint_ticks={0},
    )
    assert len(checkpoints) == 1
    return checkpoints[0]


def _capture_from_checkpoint(*, checkpoint: ReplayCheckpoint) -> OriginalCaptureSidecar:
    ckpt = checkpoint
    tick = OriginalCaptureTick(
        tick_index=int(ckpt.tick_index),
        state_hash="orig-state-hash",
        command_hash="orig-command-hash",
        rng_state=int(ckpt.rng_state),
        elapsed_ms=int(ckpt.elapsed_ms) + 5000,
        score_xp=int(ckpt.score_xp),
        kills=int(ckpt.kills),
        creature_count=int(ckpt.creature_count),
        perk_pending=int(ckpt.perk_pending),
        players=list(ckpt.players),
        bonus_timers=dict(ckpt.bonus_timers),
        rng_marks=dict(ckpt.rng_marks),
        deaths=list(ckpt.deaths),
        perk=ckpt.perk,
        events=ckpt.events,
        game_mode_id=int(GameMode.SURVIVAL),
        mode_hint="survival_update",
        input_approx=[],
    )
    return OriginalCaptureSidecar(
        version=ORIGINAL_CAPTURE_FORMAT_VERSION,
        sample_rate=1,
        ticks=[tick],
    )


def test_verify_original_capture_matches_state_ignoring_hash_domains() -> None:
    checkpoint = _single_tick_survival_checkpoint(seed=0xCAFE)
    capture = _capture_from_checkpoint(checkpoint=checkpoint)

    result, run_result = verify_original_capture(
        capture,
        seed=0xCAFE,
        strict_events=True,
    )

    assert result.ok is True
    assert result.failure is None
    assert result.checked_count == 1
    assert result.elapsed_baseline_tick == 0
    assert result.elapsed_offset_ms is not None
    assert run_result.ticks == 1


def test_verify_original_capture_accepts_world_step_latched_creature_count() -> None:
    checkpoint = _single_tick_survival_checkpoint(seed=0xB00B)
    capture = _capture_from_checkpoint(checkpoint=checkpoint)
    capture = replace(capture, ticks=[replace(capture.ticks[0], creature_count=0)])

    result, _run_result = verify_original_capture(
        capture,
        seed=0xB00B,
        strict_events=True,
    )

    assert result.ok is True
    assert result.failure is None


def test_verify_original_capture_surfaces_first_field_mismatch() -> None:
    checkpoint = _single_tick_survival_checkpoint(seed=0x1234)
    capture = _capture_from_checkpoint(checkpoint=checkpoint)
    modified_tick = replace(capture.ticks[0], creature_count=int(capture.ticks[0].creature_count) + 3)
    capture = replace(capture, ticks=[modified_tick])

    result, _run_result = verify_original_capture(
        capture,
        seed=0x1234,
        strict_events=True,
    )

    assert result.ok is False
    assert result.failure is not None
    assert result.failure.kind == "state_mismatch"
    assert result.failure.tick_index == 0
    assert any(diff.field == "creature_count" for diff in result.failure.field_diffs)


def test_verify_original_capture_float_tolerance_defaults_to_1e3_abs() -> None:
    header = ReplayHeader(
        game_mode_id=int(GameMode.SURVIVAL),
        seed=0xBEEF,
        tick_rate=60,
        player_count=1,
    )
    rec = ReplayRecorder(header)
    rec.record_tick([PlayerInput(aim=Vec2(512.0, 512.0))])
    rec.record_tick([PlayerInput(aim=Vec2(512.0, 512.0))])
    replay = rec.finish()

    checkpoints: list[ReplayCheckpoint] = []
    run_survival_replay(
        replay,
        strict_events=True,
        checkpoint_use_world_step_creature_count=True,
        checkpoints_out=checkpoints,
        checkpoint_ticks={0, 1},
    )
    assert len(checkpoints) == 2

    capture0 = _capture_from_checkpoint(checkpoint=checkpoints[0]).ticks[0]
    capture1 = _capture_from_checkpoint(checkpoint=checkpoints[1]).ticks[0]
    capture = OriginalCaptureSidecar(
        version=ORIGINAL_CAPTURE_FORMAT_VERSION,
        sample_rate=1,
        ticks=[capture0, capture1],
    )

    player0 = capture.ticks[1].players[0]
    adjusted_player0 = replace(player0, health=float(player0.health) + 0.0005)
    adjusted_tick1 = replace(capture.ticks[1], players=[adjusted_player0])
    adjusted_capture = replace(capture, ticks=[capture.ticks[0], adjusted_tick1])

    relaxed, _ = verify_original_capture(
        adjusted_capture,
        seed=0xBEEF,
        strict_events=True,
    )
    strict, _ = verify_original_capture(
        adjusted_capture,
        seed=0xBEEF,
        strict_events=True,
        float_abs_tol=0.0001,
    )

    assert relaxed.ok is True
    assert strict.ok is False
    assert strict.failure is not None
    assert any(diff.field == "players[0].health" for diff in strict.failure.field_diffs)
