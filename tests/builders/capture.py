from __future__ import annotations

from pathlib import Path

import msgspec

from crimson.game_modes import GameMode
from crimson.original.schema import (
    CAPTURE_FORMAT_VERSION,
    CaptureBonusSample,
    CaptureCheckpoint,
    CaptureCheckpointDebug,
    CaptureCheckpointDebugStatus,
    CaptureConfig,
    CaptureCounterEntry,
    CaptureCreatureLifecycleDigest,
    CaptureCreatureLifecycleEntry,
    CaptureCreatureSample,
    CaptureDiagnostics,
    CaptureEventCounts,
    CaptureEventHead,
    CaptureEventSummary,
    CaptureFile,
    CaptureInputApprox,
    CaptureInputPlayerKeys,
    CaptureInputQueries,
    CaptureInputQueryCounter,
    CaptureInputQueryStats,
    CapturePerkApplyEntry,
    CapturePerkApplyOutsideBefore,
    CapturePerkSnapshot,
    CapturePhaseMarker,
    CapturePlayerCheckpoint,
    CapturePlayerFireDiagnostics,
    CaptureProjectileSample,
    CaptureRngDiagnostics,
    CaptureRngHeadEntry,
    CaptureRngMarks,
    CaptureRngSummary,
    CaptureSamples,
    CaptureSecondaryProjectileSample,
    CaptureSnapshot,
    CaptureSnapshotGlobals,
    CaptureSnapshotInput,
    CaptureSnapshotInputAimScreen,
    CaptureSnapshotInputBindingAlternateSingle,
    CaptureSnapshotInputBindingPlayer,
    CaptureSnapshotInputBindings,
    CaptureSnapshotPlayer,
    CaptureSnapshotPlayerAltWeapon,
    CaptureSnapshotPlayerBonusTimers,
    CaptureSnapshotPlayerPerkTimers,
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


def build_capture_config() -> CaptureConfig:
    return CaptureConfig(
        out_path="",
        split_quest_files=True,
        quest_out_dir="",
        quest_out_prefix="",
        capture_profile="",
        config_env_overrides=[],
        log_mode="truncate",
        console_all_events=False,
        console_events=[],
        include_caller=True,
        include_backtrace=False,
        emit_ticks_outside_tracked_states=False,
        tracked_states=[],
        player_count_override=0,
        focus_tick=-1,
        focus_radius=0,
        heartbeat_ms=1000,
        max_head_per_kind=-1,
        max_events_per_tick=-1,
        max_rng_head_per_tick=-1,
        max_rng_caller_kinds=-1,
        enable_rng_state_mirror=True,
        max_creature_delta_ids=32,
        creature_sample_limit=-1,
        projectile_sample_limit=-1,
        secondary_projectile_sample_limit=-1,
        bonus_sample_limit=-1,
        enable_input_hooks=True,
        enable_rng_hooks=True,
        enable_sfx_hooks=True,
        enable_damage_hooks=True,
        enable_effect_hooks=True,
        creature_damage_projectile_only=True,
        enable_spawn_hooks=True,
        enable_creature_spawn_hook=True,
        enable_creature_death_hook=True,
        enable_bonus_spawn_hook=True,
        enable_creature_lifecycle_digest=True,
        enable_creature_micro_hooks=True,
        creature_micro_slots=[],
        creature_micro_tick_start=-1,
        creature_micro_tick_end=-1,
        creature_micro_max_head_per_tick=256,
    )


def build_capture_snapshot() -> CaptureSnapshot:
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


def build_capture_rng_head_entry() -> CaptureRngHeadEntry:
    return CaptureRngHeadEntry(
        seq=None,
        seed_epoch=None,
        tick_index=None,
        tick_call_index=None,
        outside_tick=None,
        value=None,
        value_u32=None,
        value_15=None,
        branch_id=None,
        caller=None,
        caller_static=None,
        state_before_u32=None,
        state_after_u32=None,
        state_before_hex=None,
        state_after_hex=None,
        expected_value_15=None,
        mirror_match=None,
    )


def build_capture_counter_entry(*, key: str = "", count: int = 0) -> CaptureCounterEntry:
    return CaptureCounterEntry(key=str(key), count=int(count))


def build_capture_perk_apply_entry(
    *,
    perk_id: int | None = None,
    pending_before: int | None = None,
    pending_after: int | None = None,
    caller: str | None = None,
    caller_static: str | None = None,
    backtrace: list[str] | None = None,
) -> CapturePerkApplyEntry:
    return CapturePerkApplyEntry(
        perk_id=None if perk_id is None else int(perk_id),
        pending_before=None if pending_before is None else int(pending_before),
        pending_after=None if pending_after is None else int(pending_after),
        caller=caller,
        caller_static=caller_static,
        backtrace=None if backtrace is None else list(backtrace),
    )


def build_capture_perk_apply_outside_before(
    *,
    calls: int = 0,
    dropped: int = 0,
    head: list[CapturePerkApplyEntry] | None = None,
) -> CapturePerkApplyOutsideBefore:
    return CapturePerkApplyOutsideBefore(
        calls=int(calls),
        dropped=int(dropped),
        head=[] if head is None else list(head),
    )


def build_capture_input_player_keys(
    *,
    player_index: int = 0,
    move_forward_pressed: bool | None = None,
    move_backward_pressed: bool | None = None,
    turn_left_pressed: bool | None = None,
    turn_right_pressed: bool | None = None,
    fire_down: bool | None = None,
    fire_pressed: bool | None = None,
    reload_pressed: bool | None = None,
) -> CaptureInputPlayerKeys:
    return CaptureInputPlayerKeys(
        player_index=int(player_index),
        move_forward_pressed=move_forward_pressed,
        move_backward_pressed=move_backward_pressed,
        turn_left_pressed=turn_left_pressed,
        turn_right_pressed=turn_right_pressed,
        fire_down=fire_down,
        fire_pressed=fire_pressed,
        reload_pressed=reload_pressed,
    )


def build_capture_input_approx(
    *,
    player_index: int = 0,
    move_dx: float = 0.0,
    move_dy: float = 0.0,
    aim_x: float = 0.0,
    aim_y: float = 0.0,
    aim_heading: float | None = None,
    move_mode: int | None = None,
    aim_scheme: int | None = None,
    fired_events: int = 0,
    moving: bool | None = None,
    reload_active: bool | None = False,
    weapon_id: int | None = None,
    move_forward_pressed: bool | None = None,
    move_backward_pressed: bool | None = None,
    turn_left_pressed: bool | None = None,
    turn_right_pressed: bool | None = None,
    fire_down: bool | None = None,
    fire_pressed: bool | None = None,
    reload_pressed: bool | None = None,
) -> CaptureInputApprox:
    return CaptureInputApprox(
        player_index=int(player_index),
        move_dx=float(move_dx),
        move_dy=float(move_dy),
        aim_x=float(aim_x),
        aim_y=float(aim_y),
        aim_heading=None if aim_heading is None else float(aim_heading),
        move_mode=None if move_mode is None else int(move_mode),
        aim_scheme=None if aim_scheme is None else int(aim_scheme),
        fired_events=int(fired_events),
        moving=moving,
        reload_active=reload_active,
        weapon_id=None if weapon_id is None else int(weapon_id),
        move_forward_pressed=move_forward_pressed,
        move_backward_pressed=move_backward_pressed,
        turn_left_pressed=turn_left_pressed,
        turn_right_pressed=turn_right_pressed,
        fire_down=fire_down,
        fire_pressed=fire_pressed,
        reload_pressed=reload_pressed,
    )


def build_capture_snapshot_player(*, index: int = 0) -> CaptureSnapshotPlayer:
    return CaptureSnapshotPlayer(
        index=int(index),
        pos_x=None,
        pos_y=None,
        move_dx=None,
        move_dy=None,
        health=None,
        aim_x=None,
        aim_y=None,
        aim_heading=None,
        weapon_id=None,
        clip_size_i32=None,
        clip_size_f32=None,
        ammo_i32=None,
        ammo_f32=None,
        reload_active_i32=None,
        reload_active_f32=None,
        reload_timer=None,
        reload_timer_max=None,
        shot_cooldown=None,
        spread_heat=None,
        experience=None,
        level=None,
        perk_timers=CaptureSnapshotPlayerPerkTimers(
            hot_tempered=None,
            man_bomb=None,
            living_fortress=None,
            fire_cough=None,
        ),
        bonus_timers=CaptureSnapshotPlayerBonusTimers(
            speed_bonus=None,
            shield=None,
            fire_bullets=None,
        ),
        alt_weapon=CaptureSnapshotPlayerAltWeapon(
            weapon_id=None,
            clip_size_i32=None,
            reload_active_i32=None,
            ammo_i32=None,
            reload_timer=None,
            shot_cooldown=None,
            reload_timer_max=None,
        ),
    )


def build_capture_creature_sample(*, index: int = 5) -> CaptureCreatureSample:
    return CaptureCreatureSample(
        index=int(index),
        active=1,
        state_flag=1,
        collision_flag=1,
        hitbox_size=16.0,
        pos=CaptureVec2(x=256.0, y=128.0),
        hp=100.0,
        type_id=2,
        target_player=0,
        flags=0,
        link_index=None,
        ai_mode=None,
        heading=None,
        target_heading=None,
        orbit_angle=None,
        orbit_radius=None,
        ai7_timer_ms=None,
    )


def build_capture_projectile_sample(*, index: int = 7) -> CaptureProjectileSample:
    return CaptureProjectileSample(
        index=int(index),
        active=1,
        angle=0.0,
        pos=CaptureVec2(x=10.0, y=20.0),
        vel=CaptureVec2(x=1.0, y=0.5),
        type_id=4,
        life_timer=1.5,
        speed_scale=1.0,
        damage_pool=22.0,
        hit_radius=8.0,
        base_damage=15.0,
        owner_id=0,
    )


def build_capture_secondary_projectile_sample(*, index: int = 9) -> CaptureSecondaryProjectileSample:
    return CaptureSecondaryProjectileSample(
        index=int(index),
        active=1,
        pos=CaptureVec2(x=30.0, y=40.0),
        life_timer=0.5,
        angle=0.0,
        vel=CaptureVec2(x=0.2, y=0.3),
        trail_timer=0.0,
        type_id=3,
        target_id=1,
    )


def build_capture_bonus_sample(*, index: int = 2) -> CaptureBonusSample:
    return CaptureBonusSample(
        index=int(index),
        bonus_id=3,
        state=1,
        time_left=4.0,
        time_max=5.0,
        pos=CaptureVec2(x=300.0, y=310.0),
        amount_f32=1.0,
        amount_i32=1,
    )


def build_capture_creature_lifecycle_entry(*, index: int = -1, active: bool = True) -> CaptureCreatureLifecycleEntry:
    return CaptureCreatureLifecycleEntry(
        index=int(index),
        active=bool(active),
        active_flag=None,
        state_flag=None,
        type_id=None,
        hp=None,
        hitbox_size=None,
        pos=CaptureVec2(x=0.0, y=0.0),
        flags=None,
        link_index=None,
        ai_mode=None,
        heading=None,
        target_heading=None,
        orbit_angle=None,
        orbit_radius=None,
        ai7_timer_ms=None,
    )


def build_capture_event_head(*, event_type: str, data: dict[str, object]) -> CaptureEventHead:
    return msgspec.convert(
        {"type": str(event_type), "data": dict(data)},
        type=CaptureEventHead,
        strict=True,
    )


def build_capture_event_head_projectile_spawn(
    *,
    owner_id: int = -100,
    requested_type_id: int = 0,
    actual_type_id: int | None = None,
    index: int = -1,
    angle_f32: float | None = None,
    pos: CaptureVec2 | None = None,
    type_overridden: bool | None = None,
    caller: str | None = None,
    caller_static: str | None = None,
) -> CaptureEventHead:
    spawn_pos = pos if pos is not None else CaptureVec2(x=0.0, y=0.0)
    return build_capture_event_head(
        event_type="projectile_spawn",
        data={
            "index": int(index),
            "requested_type_id": int(requested_type_id),
            "actual_type_id": None if actual_type_id is None else int(actual_type_id),
            "spawned": None,
            "owner_id": int(owner_id),
            "angle_f32": angle_f32,
            "pos": spawn_pos,
            "type_overridden": type_overridden,
            "caller": caller,
            "caller_static": caller_static,
        },
    )


def build_capture_event_head_secondary_projectile_spawn(
    *,
    requested_type_id: int = 0,
    actual_type_id: int | None = None,
    index: int = -1,
    angle_f32: float | None = None,
    pos: CaptureVec2 | None = None,
    type_overridden: bool | None = None,
    caller: str | None = None,
) -> CaptureEventHead:
    spawn_pos = pos if pos is not None else CaptureVec2(x=0.0, y=0.0)
    return build_capture_event_head(
        event_type="secondary_projectile_spawn",
        data={
            "index": int(index),
            "requested_type_id": int(requested_type_id),
            "actual_type_id": None if actual_type_id is None else int(actual_type_id),
            "spawned": None,
            "angle_f32": angle_f32,
            "pos": spawn_pos,
            "type_overridden": type_overridden,
            "caller": caller,
        },
    )


def build_capture_event_head_player_fire(
    *,
    player_index: int | None = 0,
    owner_id: int | None = -100,
    weapon_before: int | None = None,
    weapon_after: int | None = None,
    ammo_before: float | None = None,
    ammo_after: float | None = None,
    shot_cooldown_after: float | None = None,
    requested_type_id: int | None = None,
    actual_type_id: int | None = None,
    source: str | None = None,
    caller: str | None = None,
    caller_static: str | None = None,
) -> CaptureEventHead:
    return build_capture_event_head(
        event_type="player_fire",
        data={
            "player_index": player_index,
            "owner_id": owner_id,
            "weapon_before": weapon_before,
            "weapon_after": weapon_after,
            "ammo_before": ammo_before,
            "ammo_after": ammo_after,
            "shot_cooldown_after": shot_cooldown_after,
            "requested_type_id": requested_type_id,
            "actual_type_id": actual_type_id,
            "source": source,
            "caller": caller,
            "caller_static": caller_static,
        },
    )


def build_capture_event_head_state_transition(
    *,
    target_state: int = -1,
    before_prev: int | None = None,
    before_id: int | None = None,
    before_pending: int | None = None,
    after_prev: int | None = None,
    after_id: int | None = None,
    after_pending: int | None = None,
    caller: str | None = None,
    backtrace: list[str] | None = None,
) -> CaptureEventHead:
    return build_capture_event_head(
        event_type="state_transition",
        data={
            "target_state": int(target_state),
            "before": {"prev": before_prev, "id": before_id, "pending": before_pending},
            "after": {"prev": after_prev, "id": after_id, "pending": after_pending},
            "caller": caller,
            "backtrace": None if backtrace is None else list(backtrace),
        },
    )


def build_capture_event_head_bonus_apply(
    *,
    player_index: int | None = 0,
    bonus_id: int | None = None,
    entry_state: int | None = None,
    amount_i32: int | None = None,
    amount_f32: float | None = None,
    caller: str | None = None,
) -> CaptureEventHead:
    return build_capture_event_head(
        event_type="bonus_apply",
        data={
            "player_index": player_index,
            "bonus_id": bonus_id,
            "entry_state": entry_state,
            "amount_i32": amount_i32,
            "amount_f32": amount_f32,
            "caller": caller,
        },
    )


def build_capture_event_head_weapon_assign(
    *,
    player_index: int | None = 0,
    weapon_id: int | None = None,
    weapon_before: int | None = None,
    weapon_after: int | None = None,
    caller: str | None = None,
) -> CaptureEventHead:
    return build_capture_event_head(
        event_type="weapon_assign",
        data={
            "player_index": player_index,
            "weapon_id": weapon_id,
            "weapon_before": weapon_before,
            "weapon_after": weapon_after,
            "caller": caller,
        },
    )


def build_capture_event_head_projectile_find_query(
    *,
    result_kind: str = "miss",
    result_creature_index: int | None = None,
    start_index: int | None = None,
    radius_f32: float | None = None,
    query_pos: CaptureVec2 | None = None,
    projectile_index: int | None = None,
    projectile_owner_id: int | None = None,
    projectile_type_id: int | None = None,
    projectile_hit_radius: float | None = None,
    owner_collision: bool = False,
    player_find_skipped: bool = False,
    shock_chain_projectile_id: int | None = None,
    shock_chain_links_left: int | None = None,
    caller: str | None = None,
    caller_static: str | None = None,
    backtrace: list[str] | None = None,
) -> CaptureEventHead:
    pos = query_pos if query_pos is not None else CaptureVec2(x=0.0, y=0.0)
    return build_capture_event_head(
        event_type="projectile_find_query",
        data={
            "result_creature_index": result_creature_index,
            "result_kind": str(result_kind),
            "start_index": start_index,
            "radius_f32": radius_f32,
            "query_pos": pos,
            "projectile_index": projectile_index,
            "projectile_owner_id": projectile_owner_id,
            "projectile_type_id": projectile_type_id,
            "projectile_hit_radius": projectile_hit_radius,
            "owner_collision": bool(owner_collision),
            "player_find_skipped": bool(player_find_skipped),
            "shock_chain_projectile_id": shock_chain_projectile_id,
            "shock_chain_links_left": shock_chain_links_left,
            "caller": caller,
            "caller_static": caller_static,
            "backtrace": None if backtrace is None else list(backtrace),
        },
    )


def build_capture_event_head_projectile_find_hit(
    *,
    creature_index: int,
    result_kind: str = "hit",
    result_creature_index: int | None = None,
    start_index: int | None = None,
    radius_f32: float | None = None,
    query_pos: CaptureVec2 | None = None,
    projectile_index: int | None = None,
    projectile_owner_id: int | None = None,
    projectile_type_id: int | None = None,
    projectile_hit_radius: float | None = None,
    owner_collision: bool = False,
    player_find_skipped: bool = False,
    shock_chain_projectile_id: int | None = None,
    shock_chain_links_left: int | None = None,
    caller: str | None = None,
    caller_static: str | None = None,
    backtrace: list[str] | None = None,
    creature: CaptureCreatureLifecycleEntry | None = None,
    corpse_hit: bool | None = None,
) -> CaptureEventHead:
    pos = query_pos if query_pos is not None else CaptureVec2(x=0.0, y=0.0)
    return build_capture_event_head(
        event_type="projectile_find_hit",
        data={
            "result_creature_index": result_creature_index,
            "result_kind": str(result_kind),
            "start_index": start_index,
            "radius_f32": radius_f32,
            "query_pos": pos,
            "projectile_index": projectile_index,
            "projectile_owner_id": projectile_owner_id,
            "projectile_type_id": projectile_type_id,
            "projectile_hit_radius": projectile_hit_radius,
            "owner_collision": bool(owner_collision),
            "player_find_skipped": bool(player_find_skipped),
            "shock_chain_projectile_id": shock_chain_projectile_id,
            "shock_chain_links_left": shock_chain_links_left,
            "caller": caller,
            "caller_static": caller_static,
            "backtrace": None if backtrace is None else list(backtrace),
            "creature_index": int(creature_index),
            "creature": creature,
            "corpse_hit": corpse_hit,
        },
    )


def build_capture_event_head_creature_spawn(
    *,
    template_id: int,
    pos: CaptureVec2 | None = None,
    heading: float | None = None,
    ret_ptr: str | None = None,
    caller: str | None = None,
    caller_static: str | None = None,
) -> CaptureEventHead:
    spawn_pos = pos if pos is not None else CaptureVec2(x=0.0, y=0.0)
    return build_capture_event_head(
        event_type="creature_spawn",
        data={
            "template_id": int(template_id),
            "pos": spawn_pos,
            "heading": heading,
            "ret_ptr": ret_ptr,
            "caller": caller,
            "caller_static": caller_static,
        },
    )


def build_capture_event_head_creature_lifecycle(
    *,
    before_count: int | None = None,
    after_count: int | None = None,
    before_hash: str | None = None,
    after_hash: str | None = None,
    added_head: list[CaptureCreatureLifecycleEntry] | None = None,
    removed_head: list[CaptureCreatureLifecycleEntry] | None = None,
    added_ids: list[int] | None = None,
    removed_ids: list[int] | None = None,
    added_overflow: int = 0,
    removed_overflow: int = 0,
) -> CaptureEventHead:
    added_rows = [] if added_head is None else list(added_head)
    removed_rows = [] if removed_head is None else list(removed_head)
    digest = CaptureCreatureLifecycleDigest(
        before_count=before_count,
        after_count=after_count,
        before_hash=before_hash,
        after_hash=after_hash,
        added_total=len(added_rows),
        removed_total=len(removed_rows),
        added_ids=[int(v) for v in (added_ids if added_ids is not None else [row.index for row in added_rows])],
        removed_ids=[int(v) for v in (removed_ids if removed_ids is not None else [row.index for row in removed_rows])],
        added_overflow=int(added_overflow),
        removed_overflow=int(removed_overflow),
        added_head=added_rows,
        removed_head=removed_rows,
    )
    return msgspec.convert(
        {"type": "creature_lifecycle", "data": digest},
        type=CaptureEventHead,
        strict=True,
    )


def build_capture_event_head_perk_delta(
    *,
    perk_jinxed_proc_timer_s: float | None = None,
    perk_lean_mean_exp_tick_timer_s: float | None = None,
    perk_doctor_target_creature_id: int | None = None,
    perk_pending_count: int | None = None,
) -> CaptureEventHead:
    return build_capture_event_head(
        event_type="perk_delta",
        data={
            "perk_jinxed_proc_timer_s": perk_jinxed_proc_timer_s,
            "perk_lean_mean_exp_tick_timer_s": perk_lean_mean_exp_tick_timer_s,
            "perk_doctor_target_creature_id": perk_doctor_target_creature_id,
            "perk_pending_count": perk_pending_count,
        },
    )


def build_capture_event_head_quest_timeline_delta(
    *,
    quest_spawn_timeline: int | None = None,
    quest_spawn_stall_timer_ms: int | None = None,
    creature_active_count: int | None = None,
    quest_transition_timer_ms: int | None = None,
) -> CaptureEventHead:
    return build_capture_event_head(
        event_type="quest_timeline_delta",
        data={
            "quest_spawn_timeline": quest_spawn_timeline,
            "quest_spawn_stall_timer_ms": quest_spawn_stall_timer_ms,
            "creature_active_count": creature_active_count,
            "quest_transition_timer_ms": quest_transition_timer_ms,
        },
    )


def build_capture_event_head_sfx(
    *,
    kind: str | None = None,
    id_i32: int | None = None,
    caller: str | None = None,
    backtrace: list[str] | None = None,
) -> CaptureEventHead:
    return build_capture_event_head(
        event_type="sfx",
        data={
            "kind": kind,
            "id_i32": id_i32,
            "caller": caller,
            "backtrace": None if backtrace is None else list(backtrace),
        },
    )


def build_capture_event_head_creature_update_micro(*, data: dict[str, object]) -> CaptureEventHead:
    return build_capture_event_head(event_type="creature_update_micro", data=data)


def build_capture_event_head_creature_update_micro_angle_approach(*, slot: int) -> CaptureEventHead:
    return build_capture_event_head(
        event_type="creature_update_micro",
        data={
            "event_kind": "angle_approach",
            "slot": int(slot),
            "angle_ptr": None,
            "angle_in": None,
            "angle_out": None,
            "target": None,
            "target_effective": None,
            "rate": None,
            "delta_to_target_direct": None,
            "delta_to_target_effective": None,
            "step_delta": None,
            "branch": None,
            "before": None,
            "after": None,
        },
    )


def build_capture_event_head_creature_update_micro_window(*, slot: int) -> CaptureEventHead:
    return build_capture_event_head(
        event_type="creature_update_micro",
        data={
            "event_kind": "creature_update_window",
            "slot": int(slot),
            "before": None,
            "after": None,
        },
    )


def build_capture_checkpoint(*, tick_index: int, elapsed_ms: int, score_xp: int = 0, perk_pending: int = 0) -> CaptureCheckpoint:
    return CaptureCheckpoint(
        tick_index=int(tick_index),
        state_hash=f"state-{int(tick_index)}",
        command_hash=f"cmd-{int(tick_index)}",
        rng_state=0,
        elapsed_ms=int(elapsed_ms),
        score_xp=int(score_xp),
        kills=0,
        creature_count=0,
        perk_pending=int(perk_pending),
        players=[
            CapturePlayerCheckpoint(
                pos=CaptureVec2(512.0, 512.0),
                health=100.0,
                weapon_id=1,
                ammo=12.0,
                experience=0,
                level=1,
                bonus_timers={},
            ),
        ],
        status=CaptureStatusSnapshot(
            quest_unlock_index=0,
            quest_unlock_index_full=0,
            weapon_usage_counts=[],
        ),
        bonus_timers={},
        rng_marks=CaptureRngMarks(
            rand_calls=0,
            rand_hash="",
            rand_last=None,
            rand_head=[],
            rand_callers=[],
            rand_caller_overflow=0,
            rand_seq_first=None,
            rand_seq_last=None,
            rand_seed_epoch_enter=None,
            rand_seed_epoch_last=None,
            rand_outside_before_calls=0,
            rand_outside_before_dropped=0,
            rand_outside_before_head=[],
            rand_mirror_mismatch_total=0,
            rand_mirror_unknown_total=0,
        ),
        deaths=[],
        perk=CapturePerkSnapshot(pending_count=int(perk_pending), choices_dirty=False, choices=[], player_nonzero_counts=[]),
        events=CaptureEventSummary(hit_count=-1, pickup_count=-1, sfx_count=-1, sfx_head=[], rng_call_count=0, input_true_count=0),
        debug=CaptureCheckpointDebug(
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
        ),
    )


def build_capture_tick(
    *,
    tick_index: int,
    elapsed_ms: int,
    score_xp: int = 0,
    perk_pending: int = 0,
    event_heads: list[CaptureEventHead] | None = None,
    phase_markers: list[CapturePhaseMarker] | None = None,
) -> CaptureTick:
    checkpoint = build_capture_checkpoint(
        tick_index=int(tick_index),
        elapsed_ms=int(elapsed_ms),
        score_xp=int(score_xp),
        perk_pending=int(perk_pending),
    )
    return CaptureTick(
        tick_index=int(tick_index),
        gameplay_frame=int(tick_index) + 1,
        before=build_capture_snapshot(),
        after=build_capture_snapshot(),
        samples=CaptureSamples(creatures=[], projectiles=[], secondary_projectiles=[], bonuses=[]),
        focus_tick=False,
        state_id_enter=None,
        state_id_leave=None,
        state_pending_enter=None,
        state_pending_leave=None,
        mode_hint="survival_update",
        game_mode_id=int(GameMode.SURVIVAL),
        quest_stage_major=-1,
        quest_stage_minor=-1,
        ts_enter_ms=0,
        ts_leave_ms=0,
        duration_ms=0,
        checkpoint=checkpoint,
        event_counts=CaptureEventCounts(
            state_transition=0,
            player_fire=0,
            weapon_assign=0,
            bonus_apply=0,
            bonus_spawn=0,
            projectile_spawn=0,
            projectile_find_query=0,
            projectile_find_hit=0,
            secondary_projectile_spawn=0,
            player_damage=0,
            creature_damage=0,
            creature_spawn=0,
            creature_spawn_low=0,
            creature_death=0,
            creature_lifecycle=0,
            creature_update_micro=0,
            perk_apply=0,
            sfx=0,
            perk_delta=0,
            quest_timeline_delta=0,
            mode_tick=0,
            input_primary_edge=0,
            input_primary_down=0,
            input_any_key=0,
        ),
        event_overflow=False,
        event_heads=[] if event_heads is None else list(event_heads),
        phase_markers=[] if phase_markers is None else list(phase_markers),
        input_queries=CaptureInputQueries(
            stats=CaptureInputQueryStats(
                primary_edge=CaptureInputQueryCounter(calls=0, true_calls=0),
                primary_down=CaptureInputQueryCounter(calls=0, true_calls=0),
                any_key=CaptureInputQueryCounter(calls=0, true_calls=0),
            ),
            query_hash="",
        ),
        input_player_keys=[
            CaptureInputPlayerKeys(
                player_index=0,
                move_forward_pressed=None,
                move_backward_pressed=None,
                turn_left_pressed=None,
                turn_right_pressed=None,
                fire_down=None,
                fire_pressed=None,
                reload_pressed=None,
            ),
        ],
        perk_apply_outside_before=CapturePerkApplyOutsideBefore(calls=0, dropped=0, head=[]),
        perk_apply_in_tick=[],
        rng=CaptureRngSummary(
            calls=0,
            last_value=None,
            hash="",
            head=[],
            callers=[],
            caller_overflow=0,
            seq_first=None,
            seq_last=None,
            seed_epoch_enter=None,
            seed_epoch_last=None,
            outside_before_calls=0,
            outside_before_dropped=0,
            outside_before_head=[],
            mirror_mismatch_total=0,
            mirror_unknown_total=0,
        ),
        diagnostics=CaptureDiagnostics(
            sampling_phase="",
            timing=checkpoint.debug.timing,
            spawn=checkpoint.debug.spawn,
            rng=checkpoint.debug.rng,
            perk_apply_outside_before=CapturePerkApplyOutsideBefore(calls=0, dropped=0, head=[]),
            creature_lifecycle=None,
            player_fire=checkpoint.debug.player_fire,
        ),
        input_approx=[
            CaptureInputApprox(
                player_index=0,
                move_dx=0.0,
                move_dy=0.0,
                aim_x=0.0,
                aim_y=0.0,
                aim_heading=None,
                move_mode=None,
                aim_scheme=None,
                fired_events=0,
                moving=None,
                reload_active=False,
                weapon_id=None,
                move_forward_pressed=None,
                move_backward_pressed=None,
                turn_left_pressed=None,
                turn_right_pressed=None,
                fire_down=None,
                fire_pressed=None,
                reload_pressed=None,
            ),
        ],
        frame_dt_ms=None,
        frame_dt_ms_i32=None,
        creature_lifecycle=None,
    )


def build_capture_file(*, ticks: list[CaptureTick], session_id: str = "session-1") -> CaptureFile:
    return CaptureFile(
        script="gameplay_diff_capture",
        session_id=session_id,
        out_path="capture.json",
        capture_format_version=int(CAPTURE_FORMAT_VERSION),
        config=build_capture_config(),
        session_fingerprint=SessionFingerprint(session_id=session_id, module_hash="deadbeef", ptrs_hash="feedface"),
        process=ProcessInfo(pid=123, platform="windows", arch="x86", frida_version="16.0.0", runtime="v8"),
        exe=ModuleInfo(base="0x00400000", size=1, path="crimsonland.exe"),
        grim=None,
        pointers_resolved={},
        ticks=ticks,
    )


def capture_file_to_dict(capture: CaptureFile) -> dict[str, object]:
    return msgspec.json.decode(msgspec.json.encode(capture))


def capture_value_to_builtins(value: object) -> object:
    return msgspec.json.decode(msgspec.json.encode(value))


def write_capture_json(path: Path, capture: CaptureFile) -> None:
    path.write_text(msgspec.json.encode(capture).decode("utf-8"), encoding="utf-8")
