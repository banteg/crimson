from __future__ import annotations

from typing import Literal, TypeAlias

import msgspec

CAPTURE_FORMAT_VERSION = 5


class CaptureConfig(msgspec.Struct, forbid_unknown_fields=True):
    out_path: str
    split_quest_files: bool
    quest_out_dir: str
    quest_out_prefix: str
    capture_profile: str
    config_env_overrides: list[str]
    log_mode: str
    console_all_events: bool
    console_events: list[str]
    include_caller: bool
    include_backtrace: bool
    emit_ticks_outside_tracked_states: bool
    tracked_states: list[int]
    player_count_override: int
    focus_tick: int
    focus_radius: int
    heartbeat_ms: int
    max_head_per_kind: int
    max_events_per_tick: int
    max_rng_head_per_tick: int
    max_rng_caller_kinds: int
    enable_rng_state_mirror: bool
    max_creature_delta_ids: int
    creature_sample_limit: int
    projectile_sample_limit: int
    secondary_projectile_sample_limit: int
    bonus_sample_limit: int
    enable_input_hooks: bool
    enable_rng_hooks: bool
    enable_sfx_hooks: bool
    enable_damage_hooks: bool
    enable_effect_hooks: bool
    creature_damage_projectile_only: bool
    enable_spawn_hooks: bool
    enable_creature_spawn_hook: bool
    enable_creature_death_hook: bool
    enable_bonus_spawn_hook: bool
    enable_creature_lifecycle_digest: bool
    enable_creature_micro_hooks: bool
    creature_micro_slots: list[int]
    creature_micro_tick_start: int
    creature_micro_tick_end: int
    creature_micro_max_head_per_tick: int


class SessionFingerprint(msgspec.Struct, forbid_unknown_fields=True):
    session_id: str
    module_hash: str | None
    ptrs_hash: str | None


class ProcessInfo(msgspec.Struct, forbid_unknown_fields=True):
    pid: int
    platform: str
    arch: str
    frida_version: str
    runtime: str


class ModuleInfo(msgspec.Struct, forbid_unknown_fields=True):
    base: str
    size: int
    path: str


class CaptureVec2(msgspec.Struct, forbid_unknown_fields=True):
    x: float
    y: float


class CapturePlayerCheckpoint(msgspec.Struct, forbid_unknown_fields=True):
    pos: CaptureVec2
    health: float
    weapon_id: int
    ammo: float
    experience: int
    level: int
    bonus_timers: dict[str, int]


class CaptureDeath(msgspec.Struct, forbid_unknown_fields=True):
    creature_index: int
    type_id: int
    reward_value: float
    xp_awarded: int
    owner_id: int


class CapturePerkSnapshot(msgspec.Struct, forbid_unknown_fields=True):
    pending_count: int
    choices_dirty: bool
    choices: list[int]
    player_nonzero_counts: list[list[list[int]]]


class CaptureEventSummary(msgspec.Struct, forbid_unknown_fields=True):
    hit_count: int
    pickup_count: int
    sfx_count: int
    sfx_head: list[str]
    rng_call_count: int
    input_true_count: int


class CaptureStatusSnapshot(msgspec.Struct, forbid_unknown_fields=True):
    quest_unlock_index: int
    quest_unlock_index_full: int
    weapon_usage_counts: list[int]


class CaptureRngHeadEntry(msgspec.Struct, forbid_unknown_fields=True):
    seq: int | None
    seed_epoch: int | None
    tick_index: int | None
    tick_call_index: int | None
    outside_tick: bool | None
    value: int | None
    value_u32: int | None
    value_15: int | None
    branch_id: str | None
    caller: str | None
    caller_static: str | None
    state_before_u32: int | None
    state_after_u32: int | None
    state_before_hex: str | None
    state_after_hex: str | None
    expected_value_15: int | None
    mirror_match: bool | None


class CaptureRngCallerCount(msgspec.Struct, forbid_unknown_fields=True):
    caller_static: str
    calls: int


class CaptureRngMarks(msgspec.Struct, forbid_unknown_fields=True):
    rand_calls: int
    rand_hash: str
    rand_last: int | None
    rand_head: list[CaptureRngHeadEntry]
    rand_callers: list[CaptureRngCallerCount]
    rand_caller_overflow: int
    rand_seq_first: int | None
    rand_seq_last: int | None
    rand_seed_epoch_enter: int | None
    rand_seed_epoch_last: int | None
    rand_outside_before_calls: int
    rand_outside_before_dropped: int
    rand_outside_before_head: list[CaptureRngHeadEntry]
    rand_mirror_mismatch_total: int
    rand_mirror_unknown_total: int


class CapturePerkApplyEntry(msgspec.Struct, forbid_unknown_fields=True):
    perk_id: int | None
    pending_before: int | None
    pending_after: int | None
    caller: str | None
    caller_static: str | None
    backtrace: list[str] | None


class CapturePerkApplyOutsideBefore(msgspec.Struct, forbid_unknown_fields=True):
    calls: int
    dropped: int
    head: list[CapturePerkApplyEntry]


class CaptureCheckpointDebugStatus(msgspec.Struct, forbid_unknown_fields=True):
    quest_unlock_index: int
    quest_unlock_index_full: int


class CaptureCounterEntry(msgspec.Struct, forbid_unknown_fields=True):
    key: str
    count: int


class CaptureModeTickSamplePoint(msgspec.Struct, forbid_unknown_fields=True):
    creature_active_count: int | None
    time_played_ms: int | None
    frame_dt_ms_i32: int | None
    frame_dt_ms_f32: float | None
    quest_spawn_timeline: int | None
    quest_spawn_stall_timer_ms: int | None


class CaptureModeTickSampleDelta(msgspec.Struct, forbid_unknown_fields=True):
    creature_active_count: int | None
    time_played_ms: int | None


class CaptureModeTickSample(msgspec.Struct, forbid_unknown_fields=True):
    mode_fn: str
    before: CaptureModeTickSamplePoint
    after: CaptureModeTickSamplePoint
    delta: CaptureModeTickSampleDelta


class CaptureTimingDiagnostics(msgspec.Struct, forbid_unknown_fields=True):
    gameplay_frame: int
    gameplay_frame_delta_prev_tick: int | None
    elapsed_ms_before: int | None
    elapsed_ms_after: int | None
    elapsed_delta_in_tick_ms: int | None
    elapsed_delta_prev_tick_ms: int | None
    frame_dt_before: float | None
    frame_dt_after: float | None
    frame_dt_ms_before_i32: int | None
    frame_dt_ms_after_i32: int | None
    frame_dt_ms_before_f32: float | None
    frame_dt_ms_after_f32: float | None
    frame_dt_source_before: str
    frame_dt_source_after: str
    mode_tick_event_count: int
    mode_tick_sample_count: int
    mode_tick_mode_fn_head: list[str]
    mode_tick_present: bool


class CaptureSpawnDiagnostics(msgspec.Struct, forbid_unknown_fields=True):
    before_creature_count: int | None
    after_creature_count: int | None
    creature_count_delta: int | None
    event_count_template: int
    event_count_low_level: int
    event_count_creature_damage: int
    event_count_projectile_find_query: int
    event_count_projectile_find_hit: int
    event_count_projectile_find_query_miss: int
    event_count_projectile_find_query_owner_collision: int
    event_count_death: int
    top_template_callers: list[CaptureCounterEntry]
    top_low_level_callers: list[CaptureCounterEntry]
    top_low_level_sources: list[CaptureCounterEntry]
    top_creature_damage_callers: list[CaptureCounterEntry]
    top_projectile_find_query_callers: list[CaptureCounterEntry]
    top_projectile_find_hit_callers: list[CaptureCounterEntry]
    top_death_callers: list[CaptureCounterEntry]
    event_count_blood_splatter: int
    blood_splatter_rng_draws: int
    blood_splatter_projectile_update_calls: int
    top_blood_splatter_callers: list[CaptureCounterEntry]
    top_blood_splatter_rng_draw_callers: list[CaptureCounterEntry]
    event_count_bonus_spawn: int
    top_bonus_spawn_callers: list[CaptureCounterEntry]
    mode_samples: list[CaptureModeTickSample]


class CaptureRngDiagnostics(msgspec.Struct, forbid_unknown_fields=True):
    seq_first: int | None
    seq_last: int | None
    seed_epoch_enter: int | None
    seed_epoch_last: int | None
    outside_before_calls: int
    outside_before_dropped: int
    outside_before_head: list[CaptureRngHeadEntry]
    mirror_mismatch_total_enter: int
    mirror_mismatch_total_leave: int
    mirror_unknown_total_enter: int
    mirror_unknown_total_leave: int
    roll_log_emitted_total: int
    roll_log_dropped_total: int


class CapturePlayerFireDiagnostics(msgspec.Struct, forbid_unknown_fields=True):
    event_count_player_fire: int
    top_direct_events_by_player: list[CaptureCounterEntry]
    top_fallback_events_by_player: list[CaptureCounterEntry]
    top_player_projectile_spawns_by_player: list[CaptureCounterEntry]


class CaptureCreatureLifecycleEntry(msgspec.Struct, forbid_unknown_fields=True):
    index: int
    active: bool
    active_flag: int | None
    state_flag: int | None
    type_id: int | None
    hp: float | None
    hitbox_size: float | None
    pos: CaptureVec2
    flags: int | None
    link_index: int | None
    ai_mode: int | None
    heading: float | None
    target_heading: float | None
    orbit_angle: float | None
    orbit_radius: float | None
    ai7_timer_ms: int | None


class CaptureCreatureLifecycleDigest(msgspec.Struct, forbid_unknown_fields=True):
    before_count: int | None
    after_count: int | None
    before_hash: str | None
    after_hash: str | None
    added_total: int
    removed_total: int
    added_ids: list[int]
    removed_ids: list[int]
    added_overflow: int
    removed_overflow: int
    added_head: list[CaptureCreatureLifecycleEntry]
    removed_head: list[CaptureCreatureLifecycleEntry]


class CaptureCheckpointDebug(msgspec.Struct, forbid_unknown_fields=True):
    sampling_phase: str
    timing: CaptureTimingDiagnostics
    spawn: CaptureSpawnDiagnostics
    rng: CaptureRngDiagnostics
    perk_apply_outside_before: CapturePerkApplyOutsideBefore
    creature_lifecycle: CaptureCreatureLifecycleDigest | None
    player_fire: CapturePlayerFireDiagnostics | None
    before_players: list[CapturePlayerCheckpoint]
    before_status: CaptureCheckpointDebugStatus


class CaptureCheckpoint(msgspec.Struct, forbid_unknown_fields=True):
    tick_index: int
    state_hash: str
    command_hash: str
    rng_state: int
    elapsed_ms: int
    score_xp: int
    kills: int
    creature_count: int
    perk_pending: int
    players: list[CapturePlayerCheckpoint]
    status: CaptureStatusSnapshot
    bonus_timers: dict[str, int]
    rng_marks: CaptureRngMarks
    deaths: list[CaptureDeath]
    perk: CapturePerkSnapshot
    events: CaptureEventSummary
    debug: CaptureCheckpointDebug


class CaptureInputQueryCounter(msgspec.Struct, forbid_unknown_fields=True):
    calls: int
    true_calls: int


class CaptureInputQueryStats(msgspec.Struct, forbid_unknown_fields=True):
    primary_edge: CaptureInputQueryCounter
    primary_down: CaptureInputQueryCounter
    any_key: CaptureInputQueryCounter


class CaptureInputQueries(msgspec.Struct, forbid_unknown_fields=True):
    stats: CaptureInputQueryStats
    query_hash: str


class CaptureInputPlayerKeys(msgspec.Struct, forbid_unknown_fields=True):
    player_index: int
    move_forward_pressed: bool | None
    move_backward_pressed: bool | None
    turn_left_pressed: bool | None
    turn_right_pressed: bool | None
    fire_down: bool | None
    fire_pressed: bool | None
    reload_pressed: bool | None


class CaptureInputApprox(msgspec.Struct, forbid_unknown_fields=True):
    player_index: int
    move_dx: float
    move_dy: float
    aim_x: float
    aim_y: float
    aim_heading: float | None
    move_mode: int | None
    aim_scheme: int | None
    fired_events: int
    moving: bool | None
    reload_active: bool | None
    weapon_id: int | None
    move_forward_pressed: bool | None
    move_backward_pressed: bool | None
    turn_left_pressed: bool | None
    turn_right_pressed: bool | None
    fire_down: bool | None
    fire_pressed: bool | None
    reload_pressed: bool | None


class CaptureVec2Nullable(msgspec.Struct, forbid_unknown_fields=True):
    x: float | None
    y: float | None


class CaptureEventHeadModeTickData(msgspec.Struct, forbid_unknown_fields=True):
    mode_fn: str | None


class CaptureEventHeadStateTransitionSnapshot(msgspec.Struct, forbid_unknown_fields=True):
    prev: int | None
    id: int | None
    pending: int | None


class CaptureEventHeadStateTransitionData(msgspec.Struct, forbid_unknown_fields=True):
    target_state: int
    before: CaptureEventHeadStateTransitionSnapshot
    after: CaptureEventHeadStateTransitionSnapshot
    caller: str | None
    backtrace: list[str] | None


class CaptureEventHeadStateTransition(msgspec.Struct, tag="state_transition", forbid_unknown_fields=True):
    data: CaptureEventHeadStateTransitionData


class CaptureEventHeadModeTick(msgspec.Struct, tag="mode_tick", forbid_unknown_fields=True):
    data: CaptureEventHeadModeTickData


class CaptureEventHeadInputQueryData(msgspec.Struct, forbid_unknown_fields=True):
    query: str
    pressed: bool
    arg0: int | None
    caller: str | None
    caller_static: str | None
    backtrace: list[str] | None
    console_open: int | None
    primary_latch: int | None


class CaptureEventHeadInputPrimaryEdge(msgspec.Struct, tag="input_primary_edge", forbid_unknown_fields=True):
    data: CaptureEventHeadInputQueryData


class CaptureEventHeadInputPrimaryDown(msgspec.Struct, tag="input_primary_down", forbid_unknown_fields=True):
    data: CaptureEventHeadInputQueryData


class CaptureEventHeadInputAnyKey(msgspec.Struct, tag="input_any_key", forbid_unknown_fields=True):
    data: CaptureEventHeadInputQueryData


class CaptureEventHeadPlayerFireData(msgspec.Struct, forbid_unknown_fields=True):
    player_index: int | None
    weapon_before: int | None
    weapon_after: int | None
    ammo_before: float | None
    ammo_after: float | None
    shot_cooldown_after: float | None
    owner_id: int | None
    requested_type_id: int | None
    actual_type_id: int | None
    source: str | None
    caller: str | None
    caller_static: str | None


class CaptureEventHeadPlayerFire(msgspec.Struct, tag="player_fire", forbid_unknown_fields=True):
    data: CaptureEventHeadPlayerFireData


class CaptureEventHeadWeaponAssignData(msgspec.Struct, forbid_unknown_fields=True):
    player_index: int | None
    weapon_id: int | None
    weapon_before: int | None
    weapon_after: int | None
    caller: str | None


class CaptureEventHeadWeaponAssign(msgspec.Struct, tag="weapon_assign", forbid_unknown_fields=True):
    data: CaptureEventHeadWeaponAssignData


class CaptureEventHeadBonusApplyData(msgspec.Struct, forbid_unknown_fields=True):
    player_index: int | None
    bonus_id: int | None
    entry_state: int | None
    amount_i32: int | None
    amount_f32: float | None
    caller: str | None


class CaptureEventHeadBonusApply(msgspec.Struct, tag="bonus_apply", forbid_unknown_fields=True):
    data: CaptureEventHeadBonusApplyData


class CaptureEventHeadBonusSpawnData(msgspec.Struct, forbid_unknown_fields=True):
    pos: CaptureVec2 | None
    caller: str | None
    caller_static: str | None
    backtrace: list[str] | None
    before_active_count: int | None
    after_active_count: int | None
    active_delta: int | None
    changed_slots_total: int | None
    changed_slots_head: list[dict[str, object]]
    changed_slots_overflow: int | None
    spawned_slots_total: int | None
    spawned_slots: list[dict[str, object]]
    spawned_slots_overflow: int | None
    removed_slots_total: int | None
    removed_slots: list[dict[str, object]]
    removed_slots_overflow: int | None
    before_live_head: list[dict[str, object]]
    after_live_head: list[dict[str, object]]
    spawned_head: list[dict[str, object]]


class CaptureEventHeadBonusSpawn(msgspec.Struct, tag="bonus_spawn", forbid_unknown_fields=True):
    data: CaptureEventHeadBonusSpawnData


class CaptureEventHeadSecondaryProjectileSpawnData(msgspec.Struct, forbid_unknown_fields=True):
    index: int
    requested_type_id: int
    actual_type_id: int | None
    spawned: CaptureSecondaryProjectileSample | None
    angle_f32: float | None
    pos: CaptureVec2
    type_overridden: bool | None
    caller: str | None


class CaptureEventHeadSecondaryProjectileSpawn(
    msgspec.Struct,
    tag="secondary_projectile_spawn",
    forbid_unknown_fields=True,
):
    data: CaptureEventHeadSecondaryProjectileSpawnData


class CaptureEventHeadProjectileSpawnData(msgspec.Struct, forbid_unknown_fields=True):
    index: int
    requested_type_id: int
    actual_type_id: int | None
    spawned: CaptureProjectileSample | None
    owner_id: int
    angle_f32: float | None
    pos: CaptureVec2
    type_overridden: bool | None
    caller: str | None
    caller_static: str | None


class CaptureEventHeadProjectileSpawn(msgspec.Struct, tag="projectile_spawn", forbid_unknown_fields=True):
    data: CaptureEventHeadProjectileSpawnData


class CaptureEventHeadProjectileFindQueryData(msgspec.Struct, forbid_unknown_fields=True):
    result_creature_index: int | None
    result_kind: str
    start_index: int | None
    radius_f32: float | None
    query_pos: CaptureVec2
    projectile_index: int | None
    projectile_owner_id: int | None
    projectile_type_id: int | None
    projectile_hit_radius: float | None
    owner_collision: bool
    player_find_skipped: bool
    shock_chain_projectile_id: int | None
    shock_chain_links_left: int | None
    caller: str | None
    caller_static: str | None
    backtrace: list[str] | None


class CaptureEventHeadProjectileFindQuery(msgspec.Struct, tag="projectile_find_query", forbid_unknown_fields=True):
    data: CaptureEventHeadProjectileFindQueryData


class CaptureEventHeadProjectileFindHitData(msgspec.Struct, forbid_unknown_fields=True):
    result_creature_index: int | None
    result_kind: str
    start_index: int | None
    radius_f32: float | None
    query_pos: CaptureVec2
    projectile_index: int | None
    projectile_owner_id: int | None
    projectile_type_id: int | None
    projectile_hit_radius: float | None
    owner_collision: bool
    player_find_skipped: bool
    shock_chain_projectile_id: int | None
    shock_chain_links_left: int | None
    caller: str | None
    caller_static: str | None
    backtrace: list[str] | None
    creature_index: int
    creature: CaptureCreatureLifecycleEntry | None
    corpse_hit: bool | None


class CaptureEventHeadProjectileFindHit(msgspec.Struct, tag="projectile_find_hit", forbid_unknown_fields=True):
    data: CaptureEventHeadProjectileFindHitData


class CaptureEventHeadCreatureDamageData(msgspec.Struct, forbid_unknown_fields=True):
    creature_index: int
    damage_f32: float | None
    damage_type: int | None
    impulse_x: float | None
    impulse_y: float | None
    hp_before: float | None
    hp_after: float | None
    hp_delta: float | None
    killed: bool | None
    kill_return: int | None
    active_before: bool | None
    active_after: bool | None
    caller: str | None
    caller_static: str | None
    backtrace: list[str] | None


class CaptureEventHeadCreatureDamage(msgspec.Struct, tag="creature_damage", forbid_unknown_fields=True):
    data: CaptureEventHeadCreatureDamageData


class CaptureEventHeadPlayerDamageData(msgspec.Struct, forbid_unknown_fields=True):
    player_index: int
    damage_f32: float | None
    health_before: float | None
    health_after: float | None
    health_delta: float | None
    caller: str | None


class CaptureEventHeadPlayerDamage(msgspec.Struct, tag="player_damage", forbid_unknown_fields=True):
    data: CaptureEventHeadPlayerDamageData


class CaptureEventHeadCreatureDeathData(msgspec.Struct, forbid_unknown_fields=True):
    creature_index: int
    keep_corpse: bool | None
    active_before: bool | None
    active_after: bool | None
    before: CaptureCreatureLifecycleEntry | None
    after: CaptureCreatureLifecycleEntry | None
    caller: str | None
    caller_static: str | None
    backtrace: list[str] | None


class CaptureEventHeadCreatureDeath(msgspec.Struct, tag="creature_death", forbid_unknown_fields=True):
    data: CaptureEventHeadCreatureDeathData


class CaptureEventHeadCreatureSpawnData(msgspec.Struct, forbid_unknown_fields=True):
    template_id: int
    pos: CaptureVec2
    heading: float | None
    ret_ptr: str | None
    caller: str | None
    caller_static: str | None


class CaptureEventHeadCreatureSpawn(msgspec.Struct, tag="creature_spawn", forbid_unknown_fields=True):
    data: CaptureEventHeadCreatureSpawnData


class CaptureEventHeadCreatureSpawnLowTint(msgspec.Struct, forbid_unknown_fields=True):
    r: float | None
    g: float | None
    b: float | None
    a: float | None


class CaptureEventHeadCreatureSpawnLowSurvivalData(
    msgspec.Struct,
    tag="survival_spawn_creature",
    tag_field="source",
    forbid_unknown_fields=True,
):
    pos: CaptureVec2
    creature_count_before: int | None
    creature_count_after: int | None
    creature_count_delta: int | None
    caller: str | None
    caller_static: str | None


class CaptureEventHeadCreatureSpawnLowCreatureSpawnData(
    msgspec.Struct,
    tag="creature_spawn",
    tag_field="source",
    forbid_unknown_fields=True,
):
    index: int
    type_id: int
    pos: CaptureVec2
    tint: CaptureEventHeadCreatureSpawnLowTint
    spawned: CaptureCreatureSample | None
    caller: str | None
    caller_static: str | None


class CaptureEventHeadCreatureSpawnLowCreatureSpawnTintedData(
    msgspec.Struct,
    tag="creature_spawn_tinted",
    tag_field="source",
    forbid_unknown_fields=True,
):
    index: int
    type_id: int
    pos: CaptureVec2
    tint: CaptureEventHeadCreatureSpawnLowTint
    spawned: CaptureCreatureSample | None
    caller: str | None
    caller_static: str | None


CaptureEventHeadCreatureSpawnLowData: TypeAlias = (
    CaptureEventHeadCreatureSpawnLowSurvivalData
    | CaptureEventHeadCreatureSpawnLowCreatureSpawnData
    | CaptureEventHeadCreatureSpawnLowCreatureSpawnTintedData
)


class CaptureEventHeadCreatureSpawnLow(msgspec.Struct, tag="creature_spawn_low", forbid_unknown_fields=True):
    data: CaptureEventHeadCreatureSpawnLowData


class CaptureEventHeadPerkDeltaData(msgspec.Struct, forbid_unknown_fields=True):
    perk_jinxed_proc_timer_s: float | None
    perk_lean_mean_exp_tick_timer_s: float | None
    perk_doctor_target_creature_id: int | None
    perk_pending_count: int | None


class CaptureEventHeadPerkDelta(msgspec.Struct, tag="perk_delta", forbid_unknown_fields=True):
    data: CaptureEventHeadPerkDeltaData


class CaptureEventHeadQuestTimelineDeltaData(msgspec.Struct, forbid_unknown_fields=True):
    quest_spawn_timeline: int | None
    quest_spawn_stall_timer_ms: int | None
    creature_active_count: int | None
    quest_transition_timer_ms: int | None


class CaptureEventHeadQuestTimelineDelta(msgspec.Struct, tag="quest_timeline_delta", forbid_unknown_fields=True):
    data: CaptureEventHeadQuestTimelineDeltaData


class CaptureEventHeadSfxData(msgspec.Struct, forbid_unknown_fields=True):
    kind: str | None
    id_i32: int | None
    caller: str | None
    backtrace: list[str] | None


class CaptureEventHeadSfx(msgspec.Struct, tag="sfx", forbid_unknown_fields=True):
    data: CaptureEventHeadSfxData


class CaptureEventHeadCreatureLifecycle(msgspec.Struct, tag="creature_lifecycle", forbid_unknown_fields=True):
    data: CaptureCreatureLifecycleDigest


class CaptureEventHeadCreatureUpdateMicroState(msgspec.Struct, forbid_unknown_fields=True):
    index: int
    active: bool
    active_flag: int | None
    state_flag: int | None
    ai_mode: int | None
    flags: int | None
    link_index: int | None
    target_player: int | None
    hitbox_size: float | None
    hp: float | None
    force_target: int | None
    ai7_timer_ms: int | None
    heading: float | None
    target_heading: float | None
    orbit_angle: float | None
    orbit_radius: float | None
    target_x: float | None
    target_y: float | None
    pos: CaptureVec2Nullable
    vel: CaptureVec2Nullable
    move_speed: float | None
    dt_frame: float | None
    dist_to_target: float | None
    dist_bucket: str | None
    link_active_flag: int | None
    link_pos: CaptureVec2Nullable
    dist_to_link: float | None
    link_dist_bucket: str | None
    move_scale_estimate: float | None


class CaptureEventHeadCreatureUpdateMicroWindowData(
    msgspec.Struct,
    tag="creature_update_window",
    tag_field="event_kind",
    forbid_unknown_fields=True,
):
    slot: int
    before: CaptureEventHeadCreatureUpdateMicroState | None
    after: CaptureEventHeadCreatureUpdateMicroState | None


class CaptureEventHeadCreatureUpdateMicroAngleApproachData(
    msgspec.Struct,
    tag="angle_approach",
    tag_field="event_kind",
    forbid_unknown_fields=True,
):
    slot: int
    angle_ptr: str | None
    angle_in: float | None
    angle_out: float | None
    target: float | None
    target_effective: float | None
    rate: float | None
    delta_to_target_direct: float | None
    delta_to_target_effective: float | None
    step_delta: float | None
    branch: str | None
    before: CaptureEventHeadCreatureUpdateMicroState | None
    after: CaptureEventHeadCreatureUpdateMicroState | None


CaptureEventHeadCreatureUpdateMicroData: TypeAlias = (
    CaptureEventHeadCreatureUpdateMicroWindowData | CaptureEventHeadCreatureUpdateMicroAngleApproachData
)


class CaptureEventHeadCreatureUpdateMicro(msgspec.Struct, tag="creature_update_micro", forbid_unknown_fields=True):
    data: CaptureEventHeadCreatureUpdateMicroData


class CaptureEventHeadPerkApply(
    msgspec.Struct,
    tag="perk_apply",
    forbid_unknown_fields=True,
):
    perk_id: int | None
    pending_before: int | None
    pending_after: int | None
    caller: str | None
    caller_static: str | None
    backtrace: list[str] | None


CaptureEventHead: TypeAlias = (
    CaptureEventHeadStateTransition
    | CaptureEventHeadModeTick
    | CaptureEventHeadInputPrimaryEdge
    | CaptureEventHeadInputPrimaryDown
    | CaptureEventHeadInputAnyKey
    | CaptureEventHeadPlayerFire
    | CaptureEventHeadWeaponAssign
    | CaptureEventHeadBonusApply
    | CaptureEventHeadBonusSpawn
    | CaptureEventHeadSecondaryProjectileSpawn
    | CaptureEventHeadProjectileSpawn
    | CaptureEventHeadProjectileFindQuery
    | CaptureEventHeadProjectileFindHit
    | CaptureEventHeadCreatureDamage
    | CaptureEventHeadPlayerDamage
    | CaptureEventHeadCreatureDeath
    | CaptureEventHeadCreatureSpawn
    | CaptureEventHeadCreatureSpawnLow
    | CaptureEventHeadPerkDelta
    | CaptureEventHeadQuestTimelineDelta
    | CaptureEventHeadSfx
    | CaptureEventHeadCreatureLifecycle
    | CaptureEventHeadCreatureUpdateMicro
    | CaptureEventHeadPerkApply
)


class _CapturePhaseMarkerData(msgspec.Struct, forbid_unknown_fields=True):
    data: dict[str, object]


class CapturePhaseMarkerStateEnter(
    msgspec.Struct,
    tag="state_enter",
    forbid_unknown_fields=True,
):
    state_id: int | None
    state_pending: int | None


class CapturePhaseMarkerStateLeave(
    _CapturePhaseMarkerData,
    tag="state_leave",
):
    pass


class CapturePhaseMarkerModeHint(_CapturePhaseMarkerData, tag="mode_hint"):
    pass


class CapturePhaseMarkerInputPrimaryEdge(
    _CapturePhaseMarkerData,
    tag="input_primary_edge",
):
    pass


class CapturePhaseMarkerRngActivity(
    _CapturePhaseMarkerData,
    tag="rng_activity",
):
    pass


class CapturePhaseMarkerStateSetCall(
    _CapturePhaseMarkerData,
    tag="state_set_call",
):
    pass


class CapturePhaseMarkerModeEnter(
    _CapturePhaseMarkerData,
    tag="mode_enter",
):
    pass


class CapturePhaseMarkerCreatureCountIncreaseWithoutSpawnHook(
    _CapturePhaseMarkerData,
    tag="creature_count_increase_without_spawn_hook",
):
    pass


class CapturePhaseMarkerCreatureCountDropWithoutDeathHook(
    _CapturePhaseMarkerData,
    tag="creature_count_drop_without_death_hook",
):
    pass


class CapturePhaseMarkerCreatureLifecycleDeltaMismatch(
    _CapturePhaseMarkerData,
    tag="creature_lifecycle_delta_mismatch",
):
    pass


CapturePhaseMarker: TypeAlias = (
    CapturePhaseMarkerStateEnter
    | CapturePhaseMarkerStateLeave
    | CapturePhaseMarkerModeHint
    | CapturePhaseMarkerInputPrimaryEdge
    | CapturePhaseMarkerRngActivity
    | CapturePhaseMarkerStateSetCall
    | CapturePhaseMarkerModeEnter
    | CapturePhaseMarkerCreatureCountIncreaseWithoutSpawnHook
    | CapturePhaseMarkerCreatureCountDropWithoutDeathHook
    | CapturePhaseMarkerCreatureLifecycleDeltaMismatch
)


class CaptureRngSummary(msgspec.Struct, forbid_unknown_fields=True):
    calls: int
    last_value: int | None
    hash: str
    head: list[CaptureRngHeadEntry]
    callers: list[CaptureRngCallerCount]
    caller_overflow: int
    seq_first: int | None
    seq_last: int | None
    seed_epoch_enter: int | None
    seed_epoch_last: int | None
    outside_before_calls: int
    outside_before_dropped: int
    outside_before_head: list[CaptureRngHeadEntry]
    mirror_mismatch_total: int
    mirror_unknown_total: int


class CaptureDiagnostics(msgspec.Struct, forbid_unknown_fields=True):
    sampling_phase: str
    timing: CaptureTimingDiagnostics
    spawn: CaptureSpawnDiagnostics
    rng: CaptureRngDiagnostics
    perk_apply_outside_before: CapturePerkApplyOutsideBefore
    creature_lifecycle: CaptureCreatureLifecycleDigest | None
    player_fire: CapturePlayerFireDiagnostics | None


class CaptureSnapshotGlobals(msgspec.Struct, forbid_unknown_fields=True):
    config_game_mode: int | None
    config_player_mode_flags: list[int | None]
    config_aim_scheme: list[int | None]
    game_state_prev: int | None
    game_state_id: int | None
    game_state_pending: int | None
    frame_dt: float | None
    frame_dt_ms_i32: int | None
    frame_dt_ms_f32: float | None
    time_played_ms: int | None
    creature_active_count: int | None
    creature_kill_count: int | None
    perk_pending_count: int | None
    perk_choices_dirty: int | None
    shock_chain_links_left: int | None
    shock_chain_projectile_id: int | None
    quest_spawn_timeline: int | None
    quest_stage_major: int | None
    quest_stage_minor: int | None
    quest_spawn_stall_timer_ms: int | None
    quest_transition_timer_ms: int | None
    quest_stage_banner_timer_ms: int | None
    ui_elements_timeline: float | None
    ui_transition_direction: int | None
    ui_transition_alpha: float | None
    pause_keybind_help_alpha_ms: int | None
    player_alt_weapon_swap_cooldown_ms: int | None
    perk_jinxed_proc_timer_s: float | None
    perk_lean_mean_exp_tick_timer_s: float | None
    perk_doctor_target_creature_id: int | None
    bonus_reflex_boost_timer: float | None
    bonus_freeze_timer: float | None
    bonus_weapon_power_up_timer: float | None
    bonus_energizer_timer: float | None
    bonus_double_xp_timer: float | None


class CaptureSnapshotStatus(msgspec.Struct, forbid_unknown_fields=True):
    quest_unlock_index: int | None
    quest_unlock_index_full: int | None
    weapon_usage_counts: list[int]


class CaptureSnapshotPlayerPerkTimers(msgspec.Struct, forbid_unknown_fields=True):
    hot_tempered: float | None
    man_bomb: float | None
    living_fortress: float | None
    fire_cough: float | None


class CaptureSnapshotPlayerBonusTimers(msgspec.Struct, forbid_unknown_fields=True):
    speed_bonus: float | None
    shield: float | None
    fire_bullets: float | None


class CaptureSnapshotPlayerAltWeapon(msgspec.Struct, forbid_unknown_fields=True):
    weapon_id: int | None
    clip_size_i32: int | None
    reload_active_i32: int | None
    ammo_i32: int | None
    reload_timer: float | None
    shot_cooldown: float | None
    reload_timer_max: float | None


class CaptureSnapshotPlayer(msgspec.Struct, forbid_unknown_fields=True):
    index: int
    pos_x: float | None
    pos_y: float | None
    move_dx: float | None
    move_dy: float | None
    health: float | None
    aim_x: float | None
    aim_y: float | None
    aim_heading: float | None
    weapon_id: int | None
    clip_size_i32: int | None
    clip_size_f32: float | None
    ammo_i32: int | None
    ammo_f32: float | None
    reload_active_i32: int | None
    reload_active_f32: float | None
    reload_timer: float | None
    reload_timer_max: float | None
    shot_cooldown: float | None
    spread_heat: float | None
    experience: int | None
    level: int | None
    perk_timers: CaptureSnapshotPlayerPerkTimers
    bonus_timers: CaptureSnapshotPlayerBonusTimers
    alt_weapon: CaptureSnapshotPlayerAltWeapon


class CaptureSnapshotInputAimScreen(msgspec.Struct, forbid_unknown_fields=True):
    player_index: int
    x: float | None
    y: float | None


class CaptureSnapshotInput(msgspec.Struct, forbid_unknown_fields=True):
    console_open: int | None
    primary_latch: int | None
    mouse_x: float | None
    mouse_y: float | None
    aim_screen: list[CaptureSnapshotInputAimScreen]


class CaptureSnapshotInputBindingPlayer(msgspec.Struct, forbid_unknown_fields=True):
    player_index: int
    move_forward: int | None
    move_backward: int | None
    turn_left: int | None
    turn_right: int | None
    fire: int | None
    aim_left: int | None
    aim_right: int | None
    axis_aim_x: int | None
    axis_aim_y: int | None
    axis_move_x: int | None
    axis_move_y: int | None


class CaptureSnapshotInputBindingAlternateSingle(msgspec.Struct, forbid_unknown_fields=True):
    move_forward: int | None
    move_backward: int | None
    turn_left: int | None
    turn_right: int | None
    fire: int | None


class CaptureSnapshotInputBindings(msgspec.Struct, forbid_unknown_fields=True):
    players: list[CaptureSnapshotInputBindingPlayer]
    alternate_single: CaptureSnapshotInputBindingAlternateSingle


class CaptureSnapshot(msgspec.Struct, forbid_unknown_fields=True):
    globals: CaptureSnapshotGlobals
    status: CaptureSnapshotStatus
    player_count: int
    players: list[CaptureSnapshotPlayer]
    input: CaptureSnapshotInput
    input_bindings: CaptureSnapshotInputBindings


class CaptureCreatureSample(msgspec.Struct, forbid_unknown_fields=True):
    index: int
    active: int
    state_flag: int
    collision_flag: int
    hitbox_size: float
    pos: CaptureVec2
    hp: float
    type_id: int
    target_player: int
    flags: int
    link_index: int | None
    ai_mode: int | None
    heading: float | None
    target_heading: float | None
    orbit_angle: float | None
    orbit_radius: float | None
    ai7_timer_ms: int | None


class CaptureProjectileSample(msgspec.Struct, forbid_unknown_fields=True):
    index: int
    active: int
    angle: float
    pos: CaptureVec2
    vel: CaptureVec2
    type_id: int
    life_timer: float
    speed_scale: float
    damage_pool: float
    hit_radius: float
    base_damage: float
    owner_id: int


class CaptureSecondaryProjectileSample(msgspec.Struct, forbid_unknown_fields=True):
    index: int
    active: int
    pos: CaptureVec2
    life_timer: float
    angle: float
    vel: CaptureVec2
    trail_timer: float
    type_id: int
    target_id: int


class CaptureBonusSample(msgspec.Struct, forbid_unknown_fields=True):
    index: int
    bonus_id: int
    state: int
    time_left: float
    time_max: float
    pos: CaptureVec2
    amount_f32: float
    amount_i32: int


class CaptureSamples(msgspec.Struct, forbid_unknown_fields=True):
    creatures: list[CaptureCreatureSample]
    projectiles: list[CaptureProjectileSample]
    secondary_projectiles: list[CaptureSecondaryProjectileSample]
    bonuses: list[CaptureBonusSample]


class CaptureEventCounts(msgspec.Struct, forbid_unknown_fields=True):
    state_transition: int
    player_fire: int
    weapon_assign: int
    bonus_apply: int
    bonus_spawn: int
    projectile_spawn: int
    projectile_find_query: int
    projectile_find_hit: int
    secondary_projectile_spawn: int
    player_damage: int
    creature_damage: int
    creature_spawn: int
    creature_spawn_low: int
    creature_death: int
    creature_lifecycle: int
    creature_update_micro: int
    perk_apply: int
    sfx: int
    perk_delta: int
    quest_timeline_delta: int
    mode_tick: int
    input_primary_edge: int
    input_primary_down: int
    input_any_key: int


class CaptureTick(msgspec.Struct, forbid_unknown_fields=True):
    tick_index: int
    gameplay_frame: int
    before: CaptureSnapshot
    after: CaptureSnapshot
    samples: CaptureSamples
    focus_tick: bool
    state_id_enter: int | None
    state_id_leave: int | None
    state_pending_enter: int | None
    state_pending_leave: int | None
    mode_hint: str
    game_mode_id: int
    quest_stage_major: int
    quest_stage_minor: int
    ts_enter_ms: int
    ts_leave_ms: int
    duration_ms: int
    checkpoint: CaptureCheckpoint
    event_counts: CaptureEventCounts
    event_overflow: bool
    event_heads: list[CaptureEventHead]
    phase_markers: list[CapturePhaseMarker]
    input_queries: CaptureInputQueries
    input_player_keys: list[CaptureInputPlayerKeys]
    perk_apply_outside_before: CapturePerkApplyOutsideBefore
    perk_apply_in_tick: list[CapturePerkApplyEntry]
    rng: CaptureRngSummary
    diagnostics: CaptureDiagnostics
    input_approx: list[CaptureInputApprox]
    frame_dt_ms: float | None
    frame_dt_ms_i32: int | None
    creature_lifecycle: CaptureCreatureLifecycleDigest | None


class CaptureFile(msgspec.Struct, forbid_unknown_fields=True):
    script: Literal["gameplay_diff_capture"]
    session_id: str
    out_path: str
    capture_format_version: int
    config: CaptureConfig
    session_fingerprint: SessionFingerprint
    process: ProcessInfo
    exe: ModuleInfo
    grim: ModuleInfo | None
    pointers_resolved: dict[str, bool]
    ticks: list[CaptureTick]
