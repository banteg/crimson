from __future__ import annotations

from dataclasses import replace

import pytest

from crimson.game_modes import GameMode
from crimson.original.capture import convert_capture_to_replay
from crimson.original.diff import ReplayFieldDiff
from crimson.original.schema import (
    CaptureCheckpoint,
    CaptureDeath,
    CaptureEventSummary,
    CaptureFile,
    CapturePerkSnapshot,
    CapturePlayerCheckpoint,
    CaptureRngMarks,
    CaptureStatusSnapshot,
    CaptureTick,
    CaptureVec2,
)
from crimson.original.verify import _allow_capture_sample_creature_count, _allow_one_tick_kills_lag, verify_capture
from crimson.replay import ReplayHeader, ReplayRecorder
from crimson.replay.checkpoints import ReplayCheckpoint
from crimson.replay.types import ReplayStatusSnapshot
from crimson.sim.driver.replay_runner import run_quest_replay, run_survival_replay
from crimson.sim.input import PlayerInput
from grim.geom import Vec2


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
        checkpoint_use_world_step_creature_count=False,
        checkpoints_out=checkpoints,
        checkpoint_ticks={0},
    )
    assert len(checkpoints) == 1
    return checkpoints[0]


def _single_tick_quest_checkpoint(*, quest_level: str = "1.1", seed: int = 0xBEEF) -> ReplayCheckpoint:
    header = ReplayHeader(
        game_mode_id=int(GameMode.QUESTS),
        seed=int(seed),
        quest_level=str(quest_level),
        tick_rate=60,
        player_count=1,
    )
    rec = ReplayRecorder(header)
    rec.record_tick([PlayerInput(aim=Vec2(512.0, 512.0))])
    replay = rec.finish()

    checkpoints: list[ReplayCheckpoint] = []
    run_quest_replay(
        replay,
        strict_events=True,
        checkpoint_use_world_step_creature_count=False,
        checkpoints_out=checkpoints,
        checkpoint_ticks={0},
    )
    assert len(checkpoints) == 1
    return checkpoints[0]


def _capture_from_checkpoint(
    *,
    checkpoint: ReplayCheckpoint,
    game_mode_id: int = int(GameMode.SURVIVAL),
    mode_hint: str = "survival_update",
    quest_stage_major: int = -1,
    quest_stage_minor: int = -1,
    status: ReplayStatusSnapshot | None = None,
) -> CaptureFile:
    ckpt = checkpoint
    replay_status = status or ReplayStatusSnapshot()
    capture_players = [
        CapturePlayerCheckpoint(
            pos=CaptureVec2(float(player.pos.x), float(player.pos.y)),
            health=float(player.health),
            weapon_id=int(player.weapon_id),
            ammo=float(player.ammo),
            experience=int(player.experience),
            level=int(player.level),
        )
        for player in ckpt.players
    ]
    capture_deaths = [
        CaptureDeath(
            creature_index=int(death.creature_index),
            type_id=int(death.type_id),
            reward_value=float(death.reward_value),
            xp_awarded=int(death.xp_awarded),
            owner_id=int(death.owner_id),
        )
        for death in ckpt.deaths
    ]
    capture_perk = CapturePerkSnapshot(
        pending_count=int(ckpt.perk.pending_count),
        choices_dirty=bool(ckpt.perk.choices_dirty),
        choices=[int(value) for value in ckpt.perk.choices],
        player_nonzero_counts=[
            [[int(pair[0]), int(pair[1])] for pair in pairs if isinstance(pair, (list, tuple)) and len(pair) == 2]
            for pairs in ckpt.perk.player_nonzero_counts
        ],
    )
    capture_events = CaptureEventSummary(
        hit_count=int(ckpt.events.hit_count),
        pickup_count=int(ckpt.events.pickup_count),
        sfx_count=int(ckpt.events.sfx_count),
        sfx_head=[str(value) for value in ckpt.events.sfx_head],
    )
    rng_marks = CaptureRngMarks(
        rand_calls=int(ckpt.rng_marks.get("rand_calls", 0)),
        rand_last=int(ckpt.rng_marks.get("rand_last", 0)) if "rand_last" in ckpt.rng_marks else None,
    )
    capture_checkpoint = CaptureCheckpoint(
        tick_index=int(ckpt.tick_index),
        state_hash="orig-state-hash",
        command_hash="orig-command-hash",
        rng_state=int(ckpt.rng_state),
        elapsed_ms=int(ckpt.elapsed_ms) + 5000,
        score_xp=int(ckpt.score_xp),
        kills=int(ckpt.kills),
        creature_count=int(ckpt.creature_count),
        perk_pending=int(ckpt.perk_pending),
        players=capture_players,
        status=CaptureStatusSnapshot(
            quest_unlock_index=int(replay_status.quest_unlock_index),
            quest_unlock_index_full=int(replay_status.quest_unlock_index_full),
            weapon_usage_counts=[int(value) for value in replay_status.weapon_usage_counts],
        ),
        bonus_timers={str(key): int(value) for key, value in ckpt.bonus_timers.items()},
        rng_marks=rng_marks,
        deaths=capture_deaths,
        perk=capture_perk,
        events=capture_events,
    )
    tick = CaptureTick(
        tick_index=int(ckpt.tick_index),
        gameplay_frame=int(ckpt.tick_index) + 1,
        mode_hint=str(mode_hint),
        game_mode_id=int(game_mode_id),
        quest_stage_major=int(quest_stage_major),
        quest_stage_minor=int(quest_stage_minor),
        checkpoint=capture_checkpoint,
    )
    return CaptureFile(
        script="gameplay_diff_capture",
        session_id="test-session",
        out_path="capture.json",
        ticks=[tick],
    )


def test_verify_capture_matches_state_ignoring_hash_domains() -> None:
    checkpoint = _single_tick_survival_checkpoint(seed=0xCAFE)
    capture = _capture_from_checkpoint(checkpoint=checkpoint)

    result, run_result = verify_capture(
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


def test_verify_capture_supports_quest_mode() -> None:
    checkpoint = _single_tick_quest_checkpoint(quest_level="1.1", seed=0xCAFE)
    capture = _capture_from_checkpoint(
        checkpoint=checkpoint,
        game_mode_id=int(GameMode.QUESTS),
        mode_hint="quest_mode_update",
        quest_stage_major=1,
        quest_stage_minor=1,
    )

    result, run_result = verify_capture(
        capture,
        seed=0xCAFE,
        strict_events=True,
    )

    assert result.ok is True
    assert result.failure is None
    assert result.checked_count == 1
    assert run_result.game_mode_id == int(GameMode.QUESTS)
    assert run_result.ticks == 1


def test_verify_capture_supports_quest_mode_nonzero_start_tick() -> None:
    checkpoint = _single_tick_quest_checkpoint(quest_level="1.1", seed=0xCAFE)
    checkpoint = replace(checkpoint, tick_index=123)
    capture = _capture_from_checkpoint(
        checkpoint=checkpoint,
        game_mode_id=int(GameMode.QUESTS),
        mode_hint="quest_mode_update",
        quest_stage_major=1,
        quest_stage_minor=1,
    )

    result, run_result = verify_capture(
        capture,
        seed=0xCAFE,
        strict_events=True,
    )

    assert result.ok is True
    assert result.failure is None
    assert result.checked_count == 1
    assert result.elapsed_baseline_tick == 123
    assert run_result.game_mode_id == int(GameMode.QUESTS)
    assert run_result.ticks == 124


def test_verify_capture_quest_nonzero_start_tick_bootstraps_perk_choices() -> None:
    checkpoint = _single_tick_quest_checkpoint(quest_level="1.1", seed=0xCAFE)
    checkpoint = replace(
        checkpoint,
        tick_index=123,
        perk=replace(
            checkpoint.perk,
            pending_count=0,
            choices_dirty=False,
            choices=[11, 22, 33, 44, 55, 66, 77],
        ),
    )
    capture = _capture_from_checkpoint(
        checkpoint=checkpoint,
        game_mode_id=int(GameMode.QUESTS),
        mode_hint="quest_mode_update",
        quest_stage_major=1,
        quest_stage_minor=1,
    )

    result, run_result = verify_capture(
        capture,
        seed=0xCAFE,
        strict_events=True,
    )

    assert result.ok is True
    assert result.failure is None
    assert result.checked_count == 1
    assert result.elapsed_baseline_tick == 123
    assert run_result.game_mode_id == int(GameMode.QUESTS)
    assert run_result.ticks == 124


def test_verify_capture_quest_uses_capture_inter_tick_rand_draw_overrides(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint = _single_tick_quest_checkpoint(quest_level="1.1", seed=0xCAFE)
    capture = _capture_from_checkpoint(
        checkpoint=checkpoint,
        game_mode_id=int(GameMode.QUESTS),
        mode_hint="quest_mode_update",
        quest_stage_major=1,
        quest_stage_minor=1,
    )

    seen: dict[str, object] = {}

    class _Stop(RuntimeError):
        pass

    def _fake_run_quest_replay(*_args: object, **kwargs: object):
        seen.update(kwargs)
        raise _Stop("stop after capturing kwargs")

    monkeypatch.setattr(
        "crimson.original.verify.build_capture_inter_tick_rand_draws_overrides",
        lambda _capture: {0: 0, 1: 1},
    )
    monkeypatch.setattr("crimson.original.verify.run_quest_replay", _fake_run_quest_replay)

    with pytest.raises(_Stop):
        verify_capture(
            capture,
            seed=0xCAFE,
            strict_events=True,
        )

    assert int(seen.get("inter_tick_rand_draws", -1)) == 1
    assert seen.get("inter_tick_rand_draws_by_tick") == {0: 0, 1: 1}


def test_allow_capture_sample_creature_count_prefers_sample_stream() -> None:
    checkpoint = _single_tick_survival_checkpoint(seed=0xD00D)
    expected = replace(checkpoint, tick_index=5, creature_count=31)
    actual = replace(checkpoint, tick_index=5, creature_count=32)
    allowed = _allow_capture_sample_creature_count(
        tick=5,
        field_diffs=[ReplayFieldDiff(field="creature_count", expected=31, actual=32)],
        expected_by_tick={5: expected},
        actual_by_tick={5: actual},
        capture_sample_creature_counts={5: 32},
    )

    assert allowed is True


def test_allow_capture_sample_creature_count_allows_corpse_despawn_sampling_lag() -> None:
    checkpoint = _single_tick_survival_checkpoint(seed=0xFACE)
    expected = replace(checkpoint, tick_index=9, creature_count=51)
    actual = replace(checkpoint, tick_index=9, creature_count=50)
    allowed = _allow_capture_sample_creature_count(
        tick=9,
        field_diffs=[ReplayFieldDiff(field="creature_count", expected=51, actual=50)],
        expected_by_tick={9: expected},
        actual_by_tick={9: actual},
        capture_sample_creature_counts={9: 51},
        capture_active_corpse_below_despawn_ticks={9},
    )
    blocked = _allow_capture_sample_creature_count(
        tick=9,
        field_diffs=[ReplayFieldDiff(field="creature_count", expected=51, actual=50)],
        expected_by_tick={9: expected},
        actual_by_tick={9: actual},
        capture_sample_creature_counts={9: 51},
        capture_active_corpse_below_despawn_ticks=set(),
    )

    assert allowed is True
    assert blocked is False


def test_allow_capture_sample_creature_count_allows_one_tick_sample_lead_lag() -> None:
    checkpoint = _single_tick_survival_checkpoint(seed=0x5178)
    expected_by_tick = {
        5178: replace(checkpoint, tick_index=5178, creature_count=52),
        5179: replace(checkpoint, tick_index=5179, creature_count=52),
    }
    actual_by_tick = {
        5178: replace(checkpoint, tick_index=5178, creature_count=51),
        5179: replace(checkpoint, tick_index=5179, creature_count=51),
    }
    allowed = _allow_capture_sample_creature_count(
        tick=5178,
        field_diffs=[ReplayFieldDiff(field="creature_count", expected=52, actual=51)],
        expected_by_tick=expected_by_tick,
        actual_by_tick=actual_by_tick,
        capture_sample_creature_counts={5178: 52, 5179: 51},
    )

    assert allowed is True


def test_allow_one_tick_kills_lag_allows_isolated_blip() -> None:
    checkpoint = _single_tick_survival_checkpoint(seed=0xA11CE)
    expected_by_tick = {
        9: replace(checkpoint, tick_index=9, kills=486),
        10: replace(checkpoint, tick_index=10, kills=487),
        11: replace(checkpoint, tick_index=11, kills=487),
    }
    actual_by_tick = {
        9: replace(checkpoint, tick_index=9, kills=486),
        10: replace(checkpoint, tick_index=10, kills=486),
        11: replace(checkpoint, tick_index=11, kills=487),
    }
    allowed = _allow_one_tick_kills_lag(
        tick=10,
        field_diffs=[ReplayFieldDiff(field="kills", expected=487, actual=486)],
        expected_by_tick=expected_by_tick,
        actual_by_tick=actual_by_tick,
    )
    blocked = _allow_one_tick_kills_lag(
        tick=10,
        field_diffs=[ReplayFieldDiff(field="kills", expected=487, actual=486)],
        expected_by_tick=expected_by_tick,
        actual_by_tick={
            9: replace(checkpoint, tick_index=9, kills=485),
            10: replace(checkpoint, tick_index=10, kills=486),
            11: replace(checkpoint, tick_index=11, kills=487),
        },
    )

    assert allowed is True
    assert blocked is False


def test_verify_capture_surfaces_first_field_mismatch() -> None:
    checkpoint = _single_tick_survival_checkpoint(seed=0x1234)
    capture = _capture_from_checkpoint(checkpoint=checkpoint)
    capture.ticks[0].checkpoint.creature_count = int(capture.ticks[0].checkpoint.creature_count) + 3

    result, _run_result = verify_capture(
        capture,
        seed=0x1234,
        strict_events=True,
    )

    assert result.ok is False
    assert result.failure is not None
    assert result.failure.kind == "state_mismatch"
    assert result.failure.tick_index == 0
    assert any(diff.field == "creature_count" for diff in result.failure.field_diffs)


def test_verify_capture_float_tolerance_defaults_to_1e3_abs() -> None:
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
        checkpoint_use_world_step_creature_count=False,
        checkpoints_out=checkpoints,
        checkpoint_ticks={0, 1},
    )
    assert len(checkpoints) == 2

    adjusted_capture = _capture_from_checkpoint(checkpoint=checkpoints[0])
    adjusted_capture.ticks.append(_capture_from_checkpoint(checkpoint=checkpoints[1]).ticks[0])
    adjusted_capture.ticks[1].checkpoint.players[0].health = (
        float(adjusted_capture.ticks[1].checkpoint.players[0].health) + 0.0005
    )

    relaxed, _ = verify_capture(
        adjusted_capture,
        seed=0xBEEF,
        strict_events=True,
    )
    strict, _ = verify_capture(
        adjusted_capture,
        seed=0xBEEF,
        strict_events=True,
        float_abs_tol=0.0001,
    )

    assert relaxed.ok is True
    assert strict.ok is False
    assert strict.failure is not None
    assert any(diff.field == "players[0].health" for diff in strict.failure.field_diffs)


def test_convert_capture_to_replay_runs_with_minimal_capture() -> None:
    checkpoint = _single_tick_survival_checkpoint(seed=0xCAFE)
    capture = _capture_from_checkpoint(checkpoint=checkpoint)
    replay = convert_capture_to_replay(capture, seed=0xCAFE)
    assert replay.inputs
