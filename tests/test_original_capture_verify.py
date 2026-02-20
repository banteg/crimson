from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest

import crimson.original.verify as original_verify
from crimson.game_modes import GameMode
from crimson.original.capture import convert_capture_to_replay
from crimson.original.diff import ReplayFieldDiff
from crimson.original.schema import (
    CaptureCheckpoint,
    CaptureCheckpointDebug,
    CaptureCheckpointDebugStatus,
    CaptureConfig,
    CaptureDeath,
    CaptureDiagnostics,
    CaptureEventCounts,
    CaptureEventSummary,
    CaptureFile,
    CaptureInputQueries,
    CaptureInputQueryCounter,
    CaptureInputQueryStats,
    CapturePerkApplyOutsideBefore,
    CapturePerkSnapshot,
    CapturePlayerCheckpoint,
    CapturePlayerFireDiagnostics,
    CaptureRngDiagnostics,
    CaptureRngMarks,
    CaptureRngSummary,
    CaptureSamples,
    CaptureSnapshot,
    CaptureSnapshotGlobals,
    CaptureSnapshotInput,
    CaptureSnapshotInputAimScreen,
    CaptureSnapshotInputBindingAlternateSingle,
    CaptureSnapshotInputBindingPlayer,
    CaptureSnapshotInputBindings,
    CaptureSnapshotStatus,
    CaptureSpawnDiagnostics,
    CaptureStatusSnapshot,
    CaptureTick,
    CaptureTimingDiagnostics,
    CaptureVec2,
    ModuleInfo,
    ProcessInfo,
    SessionFingerprint,
)


def _empty_snapshot() -> CaptureSnapshot:
    return CaptureSnapshot(
        globals=CaptureSnapshotGlobals(
            config_game_mode=int(GameMode.SURVIVAL),
            config_player_mode_flags=[0],
            config_aim_scheme=[None],
            game_state_prev=0,
            game_state_id=0,
            game_state_pending=0,
            frame_dt=None,
            frame_dt_ms_i32=None,
            frame_dt_ms_f32=None,
            time_played_ms=0,
            creature_active_count=0,
            creature_kill_count=0,
            perk_pending_count=0,
            perk_choices_dirty=0,
            shock_chain_links_left=0,
            shock_chain_projectile_id=0,
            quest_spawn_timeline=0,
            quest_stage_major=-1,
            quest_stage_minor=-1,
            quest_spawn_stall_timer_ms=0,
            quest_transition_timer_ms=0,
            quest_stage_banner_timer_ms=0,
            ui_elements_timeline=0.0,
            ui_transition_direction=0,
            ui_transition_alpha=0.0,
            pause_keybind_help_alpha_ms=0,
            player_alt_weapon_swap_cooldown_ms=0,
            perk_jinxed_proc_timer_s=0.0,
            perk_lean_mean_exp_tick_timer_s=0.0,
            perk_doctor_target_creature_id=-1,
            bonus_reflex_boost_timer=0.0,
            bonus_freeze_timer=0.0,
            bonus_weapon_power_up_timer=0.0,
            bonus_energizer_timer=0.0,
            bonus_double_xp_timer=0.0,
        ),
        status=CaptureSnapshotStatus(
            quest_unlock_index=0,
            quest_unlock_index_full=0,
            weapon_usage_counts=[],
        ),
        player_count=1,
        players=[],
        input=CaptureSnapshotInput(
            console_open=0,
            primary_latch=0,
            mouse_x=0.0,
            mouse_y=0.0,
            aim_screen=[CaptureSnapshotInputAimScreen(player_index=0, x=0.0, y=0.0)],
        ),
        input_bindings=CaptureSnapshotInputBindings(
            players=[
                CaptureSnapshotInputBindingPlayer(
                    player_index=0,
                    move_forward=0,
                    move_backward=0,
                    turn_left=0,
                    turn_right=0,
                    fire=0,
                    aim_left=0,
                    aim_right=0,
                    axis_aim_x=0,
                    axis_aim_y=0,
                    axis_move_x=0,
                    axis_move_y=0,
                ),
            ],
            alternate_single=CaptureSnapshotInputBindingAlternateSingle(
                move_forward=0,
                move_backward=0,
                turn_left=0,
                turn_right=0,
                fire=0,
            ),
        ),
    )

def _empty_samples() -> CaptureSamples:
    return CaptureSamples(creatures=[], projectiles=[], secondary_projectiles=[], bonuses=[])

def _empty_debug() -> CaptureCheckpointDebug:
    return CaptureCheckpointDebug(
        sampling_phase="",
        timing=CaptureTimingDiagnostics(
            gameplay_frame=0,
            gameplay_frame_delta_prev_tick=None,
            elapsed_ms_before=0,
            elapsed_ms_after=0,
            elapsed_delta_in_tick_ms=0,
            elapsed_delta_prev_tick_ms=None,
            frame_dt_before=None,
            frame_dt_after=None,
            frame_dt_ms_before_i32=None,
            frame_dt_ms_after_i32=None,
            frame_dt_ms_before_f32=None,
            frame_dt_ms_after_f32=None,
            frame_dt_source_before="none",
            frame_dt_source_after="none",
            mode_tick_event_count=0,
            mode_tick_sample_count=0,
            mode_tick_mode_fn_head=[],
            mode_tick_present=False,
        ),
        spawn=CaptureSpawnDiagnostics(
            before_creature_count=0,
            after_creature_count=0,
            creature_count_delta=0,
            event_count_template=0,
            event_count_low_level=0,
            event_count_creature_damage=0,
            event_count_projectile_find_query=0,
            event_count_projectile_find_hit=0,
            event_count_projectile_find_query_miss=0,
            event_count_projectile_find_query_owner_collision=0,
            event_count_death=0,
            top_template_callers=[],
            top_low_level_callers=[],
            top_low_level_sources=[],
            top_creature_damage_callers=[],
            top_projectile_find_query_callers=[],
            top_projectile_find_hit_callers=[],
            top_death_callers=[],
            event_count_blood_splatter=0,
            blood_splatter_rng_draws=0,
            blood_splatter_projectile_update_calls=0,
            top_blood_splatter_callers=[],
            top_blood_splatter_rng_draw_callers=[],
            event_count_bonus_spawn=0,
            top_bonus_spawn_callers=[],
            mode_samples=[],
        ),
        rng=CaptureRngDiagnostics(
            seq_first=None,
            seq_last=None,
            seed_epoch_enter=None,
            seed_epoch_last=None,
            outside_before_calls=0,
            outside_before_dropped=0,
            outside_before_head=[],
            mirror_mismatch_total_enter=0,
            mirror_mismatch_total_leave=0,
            mirror_unknown_total_enter=0,
            mirror_unknown_total_leave=0,
            roll_log_emitted_total=0,
            roll_log_dropped_total=0,
        ),
        perk_apply_outside_before=CapturePerkApplyOutsideBefore(calls=0, dropped=0, head=[]),
        creature_lifecycle=None,
        player_fire=CapturePlayerFireDiagnostics(
            event_count_player_fire=0,
            top_direct_events_by_player=[],
            top_fallback_events_by_player=[],
            top_player_projectile_spawns_by_player=[],
        ),
        before_players=[],
        before_status=CaptureCheckpointDebugStatus(quest_unlock_index=0, quest_unlock_index_full=0),
    )

def _empty_event_counts() -> CaptureEventCounts:
    return CaptureEventCounts(
        state_transition=0, player_fire=0, weapon_assign=0, bonus_apply=0, bonus_spawn=0,
        projectile_spawn=0, projectile_find_query=0, projectile_find_hit=0, secondary_projectile_spawn=0,
        player_damage=0, creature_damage=0, creature_spawn=0, creature_spawn_low=0, creature_death=0,
        creature_lifecycle=0, creature_update_micro=0, perk_apply=0, sfx=0, perk_delta=0,
        quest_timeline_delta=0, mode_tick=0, input_primary_edge=0, input_primary_down=0, input_any_key=0,
    )

def _empty_input_queries() -> CaptureInputQueries:
    return CaptureInputQueries(
        stats=CaptureInputQueryStats(
            primary_edge=CaptureInputQueryCounter(0,0),
            primary_down=CaptureInputQueryCounter(0,0),
            any_key=CaptureInputQueryCounter(0,0),
        ),
        query_hash="",
    )

def _empty_rng_summary() -> CaptureRngSummary:
    return CaptureRngSummary(
        calls=0, last_value=None, hash="", head=[], callers=[], caller_overflow=0,
        seq_first=None, seq_last=None, seed_epoch_enter=None, seed_epoch_last=None,
        outside_before_calls=0, outside_before_dropped=0, outside_before_head=[],
        mirror_mismatch_total=0, mirror_unknown_total=0,
    )

def _empty_diagnostics() -> CaptureDiagnostics:
    return CaptureDiagnostics(
        sampling_phase="", timing=_empty_debug().timing, spawn=_empty_debug().spawn, rng=_empty_debug().rng,
        perk_apply_outside_before=CapturePerkApplyOutsideBefore(calls=0, dropped=0, head=[]),
        creature_lifecycle=None, player_fire=_empty_debug().player_fire,
    )

def _empty_config() -> CaptureConfig:
    return CaptureConfig(
        out_path="", split_quest_files=True, quest_out_dir="", quest_out_prefix="", capture_profile="",
        config_env_overrides=[], log_mode="truncate", console_all_events=False, console_events=[],
        include_caller=True, include_backtrace=False, emit_ticks_outside_tracked_states=False, tracked_states=[],
        player_count_override=0, focus_tick=-1, focus_radius=0, heartbeat_ms=1000, max_head_per_kind=-1,
        max_events_per_tick=-1, max_rng_head_per_tick=-1, max_rng_caller_kinds=-1, enable_rng_state_mirror=True,
        max_creature_delta_ids=32, creature_sample_limit=-1, projectile_sample_limit=-1,
        secondary_projectile_sample_limit=-1, bonus_sample_limit=-1, enable_input_hooks=True,
        enable_rng_hooks=True, enable_sfx_hooks=True, enable_damage_hooks=True, enable_effect_hooks=True,
        creature_damage_projectile_only=True, enable_spawn_hooks=True, enable_creature_spawn_hook=True,
        enable_creature_death_hook=True, enable_bonus_spawn_hook=True, enable_creature_lifecycle_digest=True,
        enable_creature_micro_hooks=True, creature_micro_slots=[], creature_micro_tick_start=-1,
        creature_micro_tick_end=-1, creature_micro_max_head_per_tick=256,
    )

def _empty_session_fingerprint() -> SessionFingerprint:
    return SessionFingerprint(session_id="", module_hash=None, ptrs_hash=None)

def _empty_process_info() -> ProcessInfo:
    return ProcessInfo(pid=0, platform="", arch="", frida_version="", runtime="")

def _empty_module_info() -> ModuleInfo:
    return ModuleInfo(base="", size=0, path="")

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
            bonus_timers={},
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
        rng_call_count=0,
        input_true_count=0,
    )
    rng_marks = CaptureRngMarks(
        rand_calls=int(ckpt.rng_marks.get("rand_calls", 0)),
        rand_hash="",
        rand_last=int(ckpt.rng_marks.get("rand_last", 0)) if "rand_last" in ckpt.rng_marks else None,
        rand_head=[], rand_callers=[], rand_caller_overflow=0, rand_seq_first=None, rand_seq_last=None,
        rand_seed_epoch_enter=None, rand_seed_epoch_last=None, rand_outside_before_calls=0,
        rand_outside_before_dropped=0, rand_outside_before_head=[], rand_mirror_mismatch_total=0,
        rand_mirror_unknown_total=0,
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
        debug=_empty_debug(),
    )
    tick = CaptureTick(
        tick_index=int(ckpt.tick_index),
        gameplay_frame=int(ckpt.tick_index) + 1,
        before=_empty_snapshot(),
        after=_empty_snapshot(),
        samples=_empty_samples(),
        mode_hint=str(mode_hint),
        game_mode_id=int(game_mode_id),
        quest_stage_major=int(quest_stage_major),
        quest_stage_minor=int(quest_stage_minor),
        checkpoint=capture_checkpoint,
        focus_tick=False,
        state_id_enter=None,
        state_id_leave=None,
        state_pending_enter=None,
        state_pending_leave=None,
        ts_enter_ms=0,
        ts_leave_ms=0,
        duration_ms=0,
        event_counts=_empty_event_counts(),
        event_overflow=False,
        event_heads=[],
        phase_markers=[],
        input_queries=_empty_input_queries(),
        input_player_keys=[],
        perk_apply_outside_before=CapturePerkApplyOutsideBefore(calls=0, dropped=0, head=[]),
        perk_apply_in_tick=[],
        rng=_empty_rng_summary(),
        diagnostics=_empty_diagnostics(),
        input_approx=[],
        frame_dt_ms=None,
        frame_dt_ms_i32=None,
        creature_lifecycle=None,
    )
    return CaptureFile(
        script="gameplay_diff_capture",
        session_id="test-session",
        out_path="capture.json",
        capture_format_version=5,
        config=_empty_config(),
        session_fingerprint=_empty_session_fingerprint(),
        process=_empty_process_info(),
        exe=_empty_module_info(),
        grim=None,
        pointers_resolved={},
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
    mocker,
) -> None:
    checkpoint = _single_tick_quest_checkpoint(quest_level="1.1", seed=0xCAFE)
    capture = _capture_from_checkpoint(
        checkpoint=checkpoint,
        game_mode_id=int(GameMode.QUESTS),
        mode_hint="quest_mode_update",
        quest_stage_major=1,
        quest_stage_minor=1,
    )

    seen_inter_tick_rand_draws = -1
    seen_inter_tick_rand_draws_by_tick: dict[int, int] = {}

    class _Stop(RuntimeError):
        pass

    def _fake_run_quest_replay(*_args: object, **kwargs: object):
        nonlocal seen_inter_tick_rand_draws, seen_inter_tick_rand_draws_by_tick
        inter_tick_draws_obj = kwargs.get("inter_tick_rand_draws", -1)
        seen_inter_tick_rand_draws = int(inter_tick_draws_obj) if isinstance(inter_tick_draws_obj, int) else -1
        seen_inter_tick_rand_draws_by_tick = cast("dict[int, int]", kwargs.get("inter_tick_rand_draws_by_tick", {}))
        raise _Stop("stop after capturing kwargs")

    mocker.patch.object(
        original_verify,
        "build_capture_inter_tick_rand_draws_overrides",
        side_effect=lambda _capture: {0: 0, 1: 1},
    )
    mocker.patch.object(original_verify, "run_quest_replay", side_effect=_fake_run_quest_replay)

    with pytest.raises(_Stop):
        verify_capture(
            capture,
            seed=0xCAFE,
            strict_events=True,
        )

    assert seen_inter_tick_rand_draws == 1
    assert seen_inter_tick_rand_draws_by_tick == {0: 0, 1: 1}


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
