from __future__ import annotations

from typing import Literal, TypeAlias

import msgspec

CAPTURE_FORMAT_VERSION = 3


class CaptureConfig(msgspec.Struct):
    log_mode: str = "truncate"
    # Keep config forward-compatible with evolving capture-script env knobs.
    console_all_events: bool = False
    console_events: list[str] = msgspec.field(default_factory=list)
    include_caller: bool = True
    include_backtrace: bool = False
    include_tick_snapshots: bool = True
    emit_ticks_outside_tracked_states: bool = False
    tracked_states: list[int] = msgspec.field(default_factory=list)
    player_count_override: int = 0
    focus_tick: int = -1
    focus_radius: int = 0
    tick_details_every: int = 1
    heartbeat_ms: int = 1000
    max_head_per_kind: int = -1
    max_events_per_tick: int = -1
    max_rng_head_per_tick: int = -1
    max_rng_caller_kinds: int = -1
    enable_rng_state_mirror: bool = True
    max_creature_delta_ids: int = 32
    creature_sample_limit: int = -1
    projectile_sample_limit: int = -1
    secondary_projectile_sample_limit: int = -1
    bonus_sample_limit: int = -1
    enable_input_hooks: bool = True
    enable_rng_hooks: bool = True
    enable_sfx_hooks: bool = True
    enable_damage_hooks: bool = True
    enable_effect_hooks: bool = True
    creature_damage_projectile_only: bool = True
    enable_spawn_hooks: bool = True
    enable_creature_spawn_hook: bool = True
    enable_creature_death_hook: bool = True
    enable_bonus_spawn_hook: bool = True
    enable_creature_lifecycle_digest: bool = True


class SessionFingerprint(msgspec.Struct, forbid_unknown_fields=True):
    session_id: str
    module_hash: str | None = None
    ptrs_hash: str | None = None


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
    x: float = 0.0
    y: float = 0.0


class CapturePlayerCheckpoint(msgspec.Struct, forbid_unknown_fields=True):
    pos: CaptureVec2 = msgspec.field(default_factory=CaptureVec2)
    health: float = 0.0
    weapon_id: int = 0
    ammo: float = 0.0
    experience: int = 0
    level: int = 0
    bonus_timers: dict[str, int] = msgspec.field(default_factory=dict)


class CaptureDeath(msgspec.Struct, forbid_unknown_fields=True):
    creature_index: int = -1
    type_id: int = -1
    reward_value: float = 0.0
    xp_awarded: int = -1
    owner_id: int = -1


class CapturePerkSnapshot(msgspec.Struct, forbid_unknown_fields=True):
    pending_count: int = 0
    choices_dirty: bool = False
    choices: list[int] = msgspec.field(default_factory=list)
    player_nonzero_counts: list[list[list[int]]] = msgspec.field(default_factory=list)


class CaptureEventSummary(msgspec.Struct, forbid_unknown_fields=True):
    hit_count: int = -1
    pickup_count: int = -1
    sfx_count: int = -1
    sfx_head: list[str] = msgspec.field(default_factory=list)
    rng_call_count: int = 0
    input_true_count: int = 0


class CaptureStatusSnapshot(msgspec.Struct, forbid_unknown_fields=True):
    quest_unlock_index: int = -1
    quest_unlock_index_full: int = -1
    weapon_usage_counts: list[int] = msgspec.field(default_factory=list)


class CaptureRngHeadEntry(msgspec.Struct, forbid_unknown_fields=True):
    seq: int | None = None
    seed_epoch: int | None = None
    tick_index: int | None = None
    tick_call_index: int | None = None
    outside_tick: bool | None = None
    value: int | None = None
    value_u32: int | None = None
    value_15: int | None = None
    branch_id: str | None = None
    caller: str | None = None
    caller_static: str | None = None
    state_before_u32: int | None = None
    state_after_u32: int | None = None
    state_before_hex: str | None = None
    state_after_hex: str | None = None
    expected_value_15: int | None = None
    mirror_match: bool | None = None


class CaptureRngCallerCount(msgspec.Struct, forbid_unknown_fields=True):
    caller_static: str
    calls: int


class CaptureRngMarks(msgspec.Struct, forbid_unknown_fields=True):
    rand_calls: int = 0
    rand_hash: str = ""
    rand_last: int | None = None
    rand_head: list[CaptureRngHeadEntry] = msgspec.field(default_factory=list)
    rand_callers: list[CaptureRngCallerCount] = msgspec.field(default_factory=list)
    rand_caller_overflow: int = 0
    rand_seq_first: int | None = None
    rand_seq_last: int | None = None
    rand_seed_epoch_enter: int | None = None
    rand_seed_epoch_last: int | None = None
    rand_outside_before_calls: int = 0
    rand_outside_before_dropped: int = 0
    rand_outside_before_head: list[CaptureRngHeadEntry] = msgspec.field(default_factory=list)
    rand_mirror_mismatch_total: int = 0
    rand_mirror_unknown_total: int = 0


class CapturePerkApplyEntry(msgspec.Struct, forbid_unknown_fields=True):
    perk_id: int | None = None
    pending_before: int | None = None
    pending_after: int | None = None
    caller: str | None = None
    caller_static: str | None = None
    backtrace: list[str] | None = None


class CapturePerkApplyOutsideBefore(msgspec.Struct, forbid_unknown_fields=True):
    calls: int = 0
    dropped: int = 0
    head: list[CapturePerkApplyEntry] = msgspec.field(default_factory=list)


class CaptureCheckpointDebugStatus(msgspec.Struct, forbid_unknown_fields=True):
    quest_unlock_index: int = -1
    quest_unlock_index_full: int = -1


class CaptureCheckpointDebug(msgspec.Struct, forbid_unknown_fields=True):
    sampling_phase: str = ""
    timing: dict[str, object] = msgspec.field(default_factory=dict)
    spawn: dict[str, object] = msgspec.field(default_factory=dict)
    rng: dict[str, object] = msgspec.field(default_factory=dict)
    perk_apply_outside_before: CapturePerkApplyOutsideBefore = msgspec.field(
        default_factory=CapturePerkApplyOutsideBefore
    )
    creature_lifecycle: dict[str, object] | None = None
    before_players: list[CapturePlayerCheckpoint] = msgspec.field(default_factory=list)
    before_status: CaptureCheckpointDebugStatus = msgspec.field(default_factory=CaptureCheckpointDebugStatus)


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
    players: list[CapturePlayerCheckpoint] = msgspec.field(default_factory=list)
    status: CaptureStatusSnapshot = msgspec.field(default_factory=CaptureStatusSnapshot)
    bonus_timers: dict[str, int] = msgspec.field(default_factory=dict)
    rng_marks: CaptureRngMarks = msgspec.field(default_factory=CaptureRngMarks)
    deaths: list[CaptureDeath] = msgspec.field(default_factory=list)
    perk: CapturePerkSnapshot = msgspec.field(default_factory=CapturePerkSnapshot)
    events: CaptureEventSummary = msgspec.field(default_factory=CaptureEventSummary)
    debug: CaptureCheckpointDebug = msgspec.field(default_factory=CaptureCheckpointDebug)


class CaptureInputQueryCounter(msgspec.Struct, forbid_unknown_fields=True):
    calls: int = 0
    true_calls: int = 0


class CaptureInputQueryStats(msgspec.Struct, forbid_unknown_fields=True):
    primary_edge: CaptureInputQueryCounter = msgspec.field(default_factory=CaptureInputQueryCounter)
    primary_down: CaptureInputQueryCounter = msgspec.field(default_factory=CaptureInputQueryCounter)
    any_key: CaptureInputQueryCounter = msgspec.field(default_factory=CaptureInputQueryCounter)


class CaptureInputQueries(msgspec.Struct, forbid_unknown_fields=True):
    stats: CaptureInputQueryStats = msgspec.field(default_factory=CaptureInputQueryStats)
    query_hash: str = ""


class CaptureInputPlayerKeys(msgspec.Struct, forbid_unknown_fields=True):
    player_index: int
    move_forward_pressed: bool | None = None
    move_backward_pressed: bool | None = None
    turn_left_pressed: bool | None = None
    turn_right_pressed: bool | None = None
    fire_down: bool | None = None
    fire_pressed: bool | None = None
    reload_pressed: bool | None = None


class CaptureInputApprox(msgspec.Struct, forbid_unknown_fields=True):
    player_index: int
    move_dx: float = 0.0
    move_dy: float = 0.0
    aim_x: float = 0.0
    aim_y: float = 0.0
    aim_heading: float | None = None
    move_mode: int | None = None
    aim_scheme: int | None = None
    fired_events: int = 0
    moving: bool | None = None
    reload_active: bool | None = False
    weapon_id: int | None = None
    move_forward_pressed: bool | None = None
    move_backward_pressed: bool | None = None
    turn_left_pressed: bool | None = None
    turn_right_pressed: bool | None = None
    fire_down: bool | None = None
    fire_pressed: bool | None = None
    reload_pressed: bool | None = None


class _CaptureEventHeadData(msgspec.Struct, forbid_unknown_fields=True):
    data: dict[str, object] = msgspec.field(default_factory=dict)


class CaptureEventHeadStateTransition(
    _CaptureEventHeadData, tag_field="kind", tag="state_transition"
):
    pass


class CaptureEventHeadModeTick(_CaptureEventHeadData, tag_field="kind", tag="mode_tick"):
    pass


class CaptureEventHeadInputPrimaryEdge(
    _CaptureEventHeadData, tag_field="kind", tag="input_primary_edge"
):
    pass


class CaptureEventHeadInputPrimaryDown(
    _CaptureEventHeadData, tag_field="kind", tag="input_primary_down"
):
    pass


class CaptureEventHeadInputAnyKey(
    _CaptureEventHeadData, tag_field="kind", tag="input_any_key"
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
    _CaptureEventHeadData, tag_field="kind", tag="secondary_projectile_spawn"
):
    pass


class CaptureEventHeadProjectileSpawn(
    _CaptureEventHeadData, tag_field="kind", tag="projectile_spawn"
):
    pass


class CaptureEventHeadProjectileFindQuery(
    _CaptureEventHeadData, tag_field="kind", tag="projectile_find_query"
):
    pass


class CaptureEventHeadProjectileFindHit(
    _CaptureEventHeadData, tag_field="kind", tag="projectile_find_hit"
):
    pass


class CaptureEventHeadCreatureDamage(
    _CaptureEventHeadData, tag_field="kind", tag="creature_damage"
):
    pass


class CaptureEventHeadPlayerDamage(
    _CaptureEventHeadData, tag_field="kind", tag="player_damage"
):
    pass


class CaptureEventHeadCreatureDeath(
    _CaptureEventHeadData, tag_field="kind", tag="creature_death"
):
    pass


class CaptureEventHeadCreatureSpawn(
    _CaptureEventHeadData, tag_field="kind", tag="creature_spawn"
):
    pass


class CaptureEventHeadCreatureSpawnLow(
    _CaptureEventHeadData, tag_field="kind", tag="creature_spawn_low"
):
    pass


class CaptureEventHeadPerkDelta(_CaptureEventHeadData, tag_field="kind", tag="perk_delta"):
    pass


class CaptureEventHeadQuestTimelineDelta(
    _CaptureEventHeadData, tag_field="kind", tag="quest_timeline_delta"
):
    pass


class CaptureEventHeadSfx(_CaptureEventHeadData, tag_field="kind", tag="sfx"):
    pass


class CaptureEventHeadCreatureLifecycle(
    _CaptureEventHeadData, tag_field="kind", tag="creature_lifecycle"
):
    pass


class CaptureEventHeadPerkApply(
    msgspec.Struct, tag_field="kind", tag="perk_apply", forbid_unknown_fields=True
):
    perk_id: int | None = None
    pending_before: int | None = None
    pending_after: int | None = None
    caller: str | None = None
    caller_static: str | None = None
    backtrace: list[str] | None = None


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
    | CaptureEventHeadPerkApply
)


class _CapturePhaseMarkerData(msgspec.Struct, forbid_unknown_fields=True):
    data: dict[str, object] = msgspec.field(default_factory=dict)


class CapturePhaseMarkerStateEnter(
    msgspec.Struct, tag_field="kind", tag="state_enter", forbid_unknown_fields=True
):
    state_id: int | None = None
    state_pending: int | None = None


class CapturePhaseMarkerStateLeave(
    _CapturePhaseMarkerData, tag_field="kind", tag="state_leave"
):
    pass


class CapturePhaseMarkerModeHint(_CapturePhaseMarkerData, tag_field="kind", tag="mode_hint"):
    pass


class CapturePhaseMarkerInputPrimaryEdge(
    _CapturePhaseMarkerData, tag_field="kind", tag="input_primary_edge"
):
    pass


class CapturePhaseMarkerRngActivity(
    _CapturePhaseMarkerData, tag_field="kind", tag="rng_activity"
):
    pass


class CapturePhaseMarkerStateSetCall(
    _CapturePhaseMarkerData, tag_field="kind", tag="state_set_call"
):
    pass


class CapturePhaseMarkerModeEnter(
    _CapturePhaseMarkerData, tag_field="kind", tag="mode_enter"
):
    pass


class CapturePhaseMarkerCreatureCountIncreaseWithoutSpawnHook(
    _CapturePhaseMarkerData, tag_field="kind", tag="creature_count_increase_without_spawn_hook"
):
    pass


class CapturePhaseMarkerCreatureCountDropWithoutDeathHook(
    _CapturePhaseMarkerData, tag_field="kind", tag="creature_count_drop_without_death_hook"
):
    pass


class CapturePhaseMarkerCreatureLifecycleDeltaMismatch(
    _CapturePhaseMarkerData, tag_field="kind", tag="creature_lifecycle_delta_mismatch"
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
    calls: int = 0
    last_value: int | None = None
    hash: str = ""
    head: list[CaptureRngHeadEntry] = msgspec.field(default_factory=list)
    callers: list[CaptureRngCallerCount] = msgspec.field(default_factory=list)
    caller_overflow: int = 0
    seq_first: int | None = None
    seq_last: int | None = None
    seed_epoch_enter: int | None = None
    seed_epoch_last: int | None = None
    outside_before_calls: int = 0
    outside_before_dropped: int = 0
    outside_before_head: list[CaptureRngHeadEntry] = msgspec.field(default_factory=list)
    mirror_mismatch_total: int = 0
    mirror_unknown_total: int = 0


class CaptureDiagnostics(msgspec.Struct, forbid_unknown_fields=True):
    sampling_phase: str = ""
    timing: dict[str, object] = msgspec.field(default_factory=dict)
    spawn: dict[str, object] = msgspec.field(default_factory=dict)
    rng: dict[str, object] = msgspec.field(default_factory=dict)
    perk_apply_outside_before: CapturePerkApplyOutsideBefore = msgspec.field(
        default_factory=CapturePerkApplyOutsideBefore
    )
    creature_lifecycle: dict[str, object] | None = None


class CaptureSnapshot(msgspec.Struct, forbid_unknown_fields=True):
    globals: dict[str, object] = msgspec.field(default_factory=dict)
    status: dict[str, object] = msgspec.field(default_factory=dict)
    player_count: int = 1
    players: list[dict[str, object]] = msgspec.field(default_factory=list)
    input: dict[str, object] = msgspec.field(default_factory=dict)
    input_bindings: dict[str, object] = msgspec.field(default_factory=dict)


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
    creatures: list[CaptureCreatureSample] = msgspec.field(default_factory=list)
    projectiles: list[CaptureProjectileSample] = msgspec.field(default_factory=list)
    secondary_projectiles: list[CaptureSecondaryProjectileSample] = msgspec.field(default_factory=list)
    bonuses: list[CaptureBonusSample] = msgspec.field(default_factory=list)


class CaptureEventCounts(msgspec.Struct, forbid_unknown_fields=True):
    state_transition: int = 0
    player_fire: int = 0
    weapon_assign: int = 0
    bonus_apply: int = 0
    bonus_spawn: int = 0
    projectile_spawn: int = 0
    projectile_find_query: int = 0
    projectile_find_hit: int = 0
    secondary_projectile_spawn: int = 0
    player_damage: int = 0
    creature_damage: int = 0
    creature_spawn: int = 0
    creature_spawn_low: int = 0
    creature_death: int = 0
    creature_lifecycle: int = 0
    perk_apply: int = 0
    sfx: int = 0
    perk_delta: int = 0
    quest_timeline_delta: int = 0
    mode_tick: int = 0
    input_primary_edge: int = 0
    input_primary_down: int = 0
    input_any_key: int = 0


def _default_capture_checkpoint() -> CaptureCheckpoint:
    return CaptureCheckpoint(
        tick_index=0,
        state_hash="",
        command_hash="",
        rng_state=0,
        elapsed_ms=0,
        score_xp=0,
        kills=0,
        creature_count=0,
        perk_pending=0,
    )


def _default_session_fingerprint() -> SessionFingerprint:
    return SessionFingerprint(session_id="")


def _default_process_info() -> ProcessInfo:
    return ProcessInfo(pid=0, platform="", arch="", frida_version="", runtime="")


def _default_module_info() -> ModuleInfo:
    return ModuleInfo(base="", size=0, path="")


class CaptureTick(msgspec.Struct, forbid_unknown_fields=True):
    tick_index: int
    gameplay_frame: int
    focus_tick: bool = False
    state_id_enter: int | None = None
    state_id_leave: int | None = None
    state_pending_enter: int | None = None
    state_pending_leave: int | None = None
    mode_hint: str = ""
    game_mode_id: int = -1
    ts_enter_ms: int = 0
    ts_leave_ms: int = 0
    duration_ms: int = 0
    checkpoint: CaptureCheckpoint = msgspec.field(default_factory=_default_capture_checkpoint)
    event_counts: CaptureEventCounts = msgspec.field(default_factory=CaptureEventCounts)
    event_overflow: bool = False
    event_heads: list[CaptureEventHead] = msgspec.field(default_factory=list)
    phase_markers: list[CapturePhaseMarker] = msgspec.field(default_factory=list)
    input_queries: CaptureInputQueries = msgspec.field(default_factory=CaptureInputQueries)
    input_player_keys: list[CaptureInputPlayerKeys] = msgspec.field(default_factory=list)
    perk_apply_outside_before: CapturePerkApplyOutsideBefore = msgspec.field(
        default_factory=CapturePerkApplyOutsideBefore
    )
    perk_apply_in_tick: list[CapturePerkApplyEntry] = msgspec.field(default_factory=list)
    rng: CaptureRngSummary = msgspec.field(default_factory=CaptureRngSummary)
    diagnostics: CaptureDiagnostics = msgspec.field(default_factory=CaptureDiagnostics)
    input_approx: list[CaptureInputApprox] = msgspec.field(default_factory=list)
    frame_dt_ms: float | None = None
    frame_dt_ms_i32: int | None = None
    before: CaptureSnapshot | None = None
    after: CaptureSnapshot | None = None
    samples: CaptureSamples | None = None
    creature_lifecycle: dict[str, object] | None = None


class CaptureFile(msgspec.Struct, forbid_unknown_fields=True):
    script: Literal["gameplay_diff_capture"]
    session_id: str
    out_path: str
    capture_format_version: int = -1
    config: CaptureConfig = msgspec.field(default_factory=CaptureConfig)
    session_fingerprint: SessionFingerprint = msgspec.field(default_factory=_default_session_fingerprint)
    process: ProcessInfo = msgspec.field(default_factory=_default_process_info)
    exe: ModuleInfo = msgspec.field(default_factory=_default_module_info)
    grim: ModuleInfo | None = None
    pointers_resolved: dict[str, bool] = msgspec.field(default_factory=dict)
    ticks: list[CaptureTick] = msgspec.field(default_factory=list)
