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


class CaptureCheckpointDebug(msgspec.Struct, forbid_unknown_fields=True):
    sampling_phase: str
    timing: dict[str, object]
    spawn: dict[str, object]
    rng: dict[str, object]
    perk_apply_outside_before: CapturePerkApplyOutsideBefore
    creature_lifecycle: dict[str, object] | None
    player_fire: dict[str, object] | None
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


class _CaptureEventHeadData(msgspec.Struct, forbid_unknown_fields=True):
    data: dict[str, object]


class CaptureEventHeadStateTransition(
    _CaptureEventHeadData,
    tag_field="kind",
    tag="state_transition",
):
    pass


class CaptureEventHeadModeTick(_CaptureEventHeadData, tag_field="kind", tag="mode_tick"):
    pass


class CaptureEventHeadInputPrimaryEdge(
    _CaptureEventHeadData,
    tag_field="kind",
    tag="input_primary_edge",
):
    pass


class CaptureEventHeadInputPrimaryDown(
    _CaptureEventHeadData,
    tag_field="kind",
    tag="input_primary_down",
):
    pass


class CaptureEventHeadInputAnyKey(
    _CaptureEventHeadData,
    tag_field="kind",
    tag="input_any_key",
):
    pass


class CaptureEventHeadPlayerFire(_CaptureEventHeadData, tag_field="kind", tag="player_fire"):
    pass


class CaptureEventHeadWeaponAssign(_CaptureEventHeadData, tag_field="kind", tag="weapon_assign"):
    pass


class CaptureEventHeadBonusApply(_CaptureEventHeadData, tag_field="kind", tag="bonus_apply"):
    pass


class CaptureEventHeadBonusSpawn(_CaptureEventHeadData, tag_field="kind", tag="bonus_spawn"):
    pass


class CaptureEventHeadSecondaryProjectileSpawn(
    _CaptureEventHeadData,
    tag_field="kind",
    tag="secondary_projectile_spawn",
):
    pass


class CaptureEventHeadProjectileSpawn(
    _CaptureEventHeadData,
    tag_field="kind",
    tag="projectile_spawn",
):
    pass


class CaptureEventHeadProjectileFindQuery(
    _CaptureEventHeadData,
    tag_field="kind",
    tag="projectile_find_query",
):
    pass


class CaptureEventHeadProjectileFindHit(
    _CaptureEventHeadData,
    tag_field="kind",
    tag="projectile_find_hit",
):
    pass


class CaptureEventHeadCreatureDamage(
    _CaptureEventHeadData,
    tag_field="kind",
    tag="creature_damage",
):
    pass


class CaptureEventHeadPlayerDamage(
    _CaptureEventHeadData,
    tag_field="kind",
    tag="player_damage",
):
    pass


class CaptureEventHeadCreatureDeath(
    _CaptureEventHeadData,
    tag_field="kind",
    tag="creature_death",
):
    pass


class CaptureEventHeadCreatureSpawn(
    _CaptureEventHeadData,
    tag_field="kind",
    tag="creature_spawn",
):
    pass


class CaptureEventHeadCreatureSpawnLow(
    _CaptureEventHeadData,
    tag_field="kind",
    tag="creature_spawn_low",
):
    pass


class CaptureEventHeadPerkDelta(_CaptureEventHeadData, tag_field="kind", tag="perk_delta"):
    pass


class CaptureEventHeadQuestTimelineDelta(
    _CaptureEventHeadData,
    tag_field="kind",
    tag="quest_timeline_delta",
):
    pass


class CaptureEventHeadSfx(_CaptureEventHeadData, tag_field="kind", tag="sfx"):
    pass


class CaptureEventHeadCreatureLifecycle(
    _CaptureEventHeadData,
    tag_field="kind",
    tag="creature_lifecycle",
):
    pass


class CaptureEventHeadCreatureUpdateMicro(
    _CaptureEventHeadData,
    tag_field="kind",
    tag="creature_update_micro",
):
    pass


class CaptureEventHeadPerkApply(
    msgspec.Struct,
    tag_field="kind",
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
    tag_field="kind",
    tag="state_enter",
    forbid_unknown_fields=True,
):
    state_id: int | None
    state_pending: int | None


class CapturePhaseMarkerStateLeave(
    _CapturePhaseMarkerData,
    tag_field="kind",
    tag="state_leave",
):
    pass


class CapturePhaseMarkerModeHint(_CapturePhaseMarkerData, tag_field="kind", tag="mode_hint"):
    pass


class CapturePhaseMarkerInputPrimaryEdge(
    _CapturePhaseMarkerData,
    tag_field="kind",
    tag="input_primary_edge",
):
    pass


class CapturePhaseMarkerRngActivity(
    _CapturePhaseMarkerData,
    tag_field="kind",
    tag="rng_activity",
):
    pass


class CapturePhaseMarkerStateSetCall(
    _CapturePhaseMarkerData,
    tag_field="kind",
    tag="state_set_call",
):
    pass


class CapturePhaseMarkerModeEnter(
    _CapturePhaseMarkerData,
    tag_field="kind",
    tag="mode_enter",
):
    pass


class CapturePhaseMarkerCreatureCountIncreaseWithoutSpawnHook(
    _CapturePhaseMarkerData,
    tag_field="kind",
    tag="creature_count_increase_without_spawn_hook",
):
    pass


class CapturePhaseMarkerCreatureCountDropWithoutDeathHook(
    _CapturePhaseMarkerData,
    tag_field="kind",
    tag="creature_count_drop_without_death_hook",
):
    pass


class CapturePhaseMarkerCreatureLifecycleDeltaMismatch(
    _CapturePhaseMarkerData,
    tag_field="kind",
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
    timing: dict[str, object]
    spawn: dict[str, object]
    rng: dict[str, object]
    perk_apply_outside_before: CapturePerkApplyOutsideBefore
    creature_lifecycle: dict[str, object] | None
    player_fire: dict[str, object] | None


class CaptureSnapshot(msgspec.Struct, forbid_unknown_fields=True):
    globals: dict[str, object]
    status: dict[str, object]
    player_count: int
    players: list[dict[str, object]]
    input: dict[str, object]
    input_bindings: dict[str, object]


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
    creature_lifecycle: dict[str, object] | None


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
