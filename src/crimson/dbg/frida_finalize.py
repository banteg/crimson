from __future__ import annotations

import hashlib
import json
import math
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from tempfile import SpooledTemporaryFile, TemporaryDirectory
from typing import Any, BinaryIO, Protocol

import msgspec
import zstandard as zstd

from crimson.sim.run_spec import CreatureSlotResidue
from grim.geom import Vec2

from ..game_modes import GameMode
from ..persistence.save_status import (
    QUEST_PLAY_COUNT,
    RESERVED_SEED_WORDS_BYTE_SIZE,
    WEAPON_USAGE_COUNT,
    GameStatusData,
)
from ..quests.level import QuestLevel
from ..replay.checkpoints import ReplayCheckpoint
from ..replay.codec import dump_replay_file
from ..replay.types import Replay, ReplayHeader, ReplayTick, quantize_f32
from ..sim.input_providers import (
    GameFrameRngAdvanceOperation,
    PerkMenuOpenCommand,
    PerkPickCommand,
    ReplayPostludeOperation,
    ReplayPreludeOperation,
    ReplayTickCommand,
)
from .canonical_channels import (
    EntitySamplesSnapshot,
    ReplayStepSnapshot,
    RngStreamRow,
    SimStateSnapshot,
    SnapshotBonusTimers,
    SnapshotGameplay,
    SnapshotPlayer,
    SnapshotRgba,
    TimingSampleRow,
)
from .schema import (
    TRACE_FORMAT_VERSION,
    TRACE_SCHEMA_VERSION,
    ReplayTickChannels,
    TickRecord,
    TraceMeta,
    TraceProducer,
    TraceSource,
    TraceTickRange,
)
from .trace import TraceSummary, write_trace_iter

_FRAME_LEN_BYTES = 4
_EVIDENCE_FRAME_LEN_BYTES = 4
_TICK_ENCODER = msgspec.msgpack.Encoder()
_TICK_DECODER = msgspec.msgpack.Decoder(type=TickRecord)
_GAME_MODE_QUESTS = 3
FRIDA_CAPTURE_FORMAT_VERSION = 26
FRIDA_EVIDENCE_FORMAT_VERSION = 3
FRIDA_RUNTIME_VERSION = "17.15.4"
_EVIDENCE_ZSTD_LEVEL = 10
_EVIDENCE_DECODE_SPOOL_MAX_MEMORY = 8 * 1024 * 1024
_EVIDENCE_COMPRESSED_READ_BYTES = 1024 * 1024
_TRACE_CHUNK_TICKS = 256
_RUN_START_REASONS = frozenset(("run_start", "first_tick", "quest_attempt", "mode_or_stage_change"))
_RUN_END_REASONS = frozenset(("run_end", "quest_attempt", "mode_or_stage_change", "shutdown"))
# Replay RNG starts from the state latched before the first bootstrap draw.
_RUN_SETUP_SEED_SOURCE = "rng_state_before_bootstrap"
_FRAME_DISCARDED_RNG_CALLER_STATIC = "0x0040cac7"
_SUPPORTED_CAPTURE_MODES = frozenset((int(GameMode.SURVIVAL), int(GameMode.RUSH), int(GameMode.QUESTS)))


def _lcg_step_u32(state: int) -> int:
    return (state * 214013 + 2531011) & 0xFFFFFFFF


def _lcg_advance_u32(state: int, steps: int) -> int:
    """Advance the MSVC LCG exactly in logarithmic time."""
    remaining = int(steps)
    multiplier = 214013
    increment = 2531011
    accumulated_multiplier = 1
    accumulated_increment = 0
    while remaining > 0:
        if remaining & 1:
            accumulated_multiplier = (accumulated_multiplier * multiplier) & 0xFFFFFFFF
            accumulated_increment = (accumulated_increment * multiplier + increment) & 0xFFFFFFFF
        increment = (increment * (multiplier + 1)) & 0xFFFFFFFF
        multiplier = (multiplier * multiplier) & 0xFFFFFFFF
        remaining >>= 1
    return (accumulated_multiplier * int(state) + accumulated_increment) & 0xFFFFFFFF


_MODE_LABEL_BY_ID = {
    int(GameMode.DEMO): "demo",
    int(GameMode.SURVIVAL): "survival",
    int(GameMode.RUSH): "rush",
    int(GameMode.QUESTS): "quests",
    int(GameMode.TYPO): "typo",
    int(GameMode.TUTORIAL): "tutorial",
}


class FridaFinalizeError(ValueError):
    pass


class _BinaryReader(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...


class _CaptureRngStreamRow(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    tick_call_index: int
    value_15: int
    state_before_u32: int
    state_after_u32: int
    caller: int | None


class _CaptureSnapshotGameplay(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    mode_id: int
    quest_stage_major: int
    quest_stage_minor: int
    perk_pending_count: int
    perk_choices_dirty: bool
    bonus_timers: SnapshotBonusTimers


class _CaptureSimStateSnapshot(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    gameplay: _CaptureSnapshotGameplay
    players: list[SnapshotPlayer]


class _TickChannels(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    replay_step: ReplayStepSnapshot
    checkpoint: ReplayCheckpoint
    sim_state: _CaptureSimStateSnapshot
    entity_samples: EntitySamplesSnapshot
    rng_stream: list[_CaptureRngStreamRow]
    timing_samples: list[TimingSampleRow]


class _SessionFingerprintRow(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    session_id: str
    ptrs_hash: str
    module_hash: str | None


class _SessionConfigRow(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    out_path: str
    out_path_source: str
    capture_profile: str
    config_env_overrides: list[str]
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
    enable_rng_roll_log: bool
    max_rng_roll_log_events: int
    max_rng_outside_tick_head: int
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


class _SessionStartRow(
    msgspec.Struct,
    frozen=True,
    forbid_unknown_fields=True,
    tag_field="event",
    tag="session_start",
):
    capture_format_version: int
    session_id: str
    out_path: str
    platform: str
    arch: str
    frida_version: str
    script_version: str
    config: _SessionConfigRow
    session_fingerprint: _SessionFingerprintRow


class _OutsideRngHeadRow(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    state_before_u32: int
    state_after_u32: int
    value_15: int
    caller_static: str
    replay_operation_index: int


class _OutsideRngBag(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    calls: int
    dropped: int
    caller_counts: dict[str, int]
    head: list[_OutsideRngHeadRow]


class _CaptureVec2Row(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    x: float
    y: float


class _CapturePoolResidueRow(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    index: int
    active: int
    phase_seed: int
    state_flag: int
    collision_flag: int
    collision_timer: float
    lifecycle_stage: float
    pos: _CaptureVec2Row
    vel: _CaptureVec2Row
    hp: float
    max_hp: float
    heading: float
    target_heading: float
    size: float
    hit_flash_timer: float
    tint: SnapshotRgba
    force_target: int
    target: _CaptureVec2Row
    contact_damage: float
    move_speed: float
    attack_cooldown: float
    reward_value: float
    type_id: int
    target_player: int
    link_index: int
    target_offset: _CaptureVec2Row
    orbit_angle: float
    orbit_radius_u32: int
    flags: int
    ai_mode: int
    anim_phase: float


class _CaptureGameStatusRow(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    quest_unlock_index: int
    quest_unlock_index_full: int
    weapon_usage_counts: list[int]
    quest_play_counts: list[int]
    mode_play_survival: int
    mode_play_rush: int
    mode_play_typo: int
    mode_play_other: int
    play_time_ms: int
    reserved_seed_words: list[int]


class _RunSettingsRow(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    tick_rate: int
    quest_fail_retry_count: int
    hardcore: bool
    detail_preset: int
    violence_disabled: int
    world_size: float
    status: _CaptureGameStatusRow


class _RunStartRow(
    msgspec.Struct,
    frozen=True,
    forbid_unknown_fields=True,
    tag_field="event",
    tag="run_start",
):
    run_id: int
    mode_id: int
    player_count: int
    reason: str
    quest_stage_major: int
    quest_stage_minor: int
    global_tick_index: int
    rng_state_before_bootstrap: int
    rng_state_after_bootstrap: int
    rng_bootstrap_calls: int
    pool_residue: list[_CapturePoolResidueRow]
    settings: _RunSettingsRow


class _CaptureCheckpointEventEvidence(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    hit_count: int
    pickup_count: int
    sfx_count: int
    sfx_head: list[Any]
    hit_head: list[Any]


class _CaptureCheckpointEvidence(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    elapsed_ms: int
    deaths: list[Any]
    events: _CaptureCheckpointEventEvidence


class _CaptureClockEvidence(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    time_played_ms_raw: int
    quest_spawn_timeline_raw: int
    summed_replay_clock_ms: int
    canonical_elapsed_ms: int


class _CaptureTickEvidence(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    event_counts: dict[str, int]
    event_overflow: bool
    event_heads: dict[str, list[Any]]
    diagnostics: dict[str, Any]
    input_queries: dict[str, Any]
    input_player_keys: list[Any]
    input_approx: list[Any]
    before: dict[str, Any]
    after: dict[str, Any]
    samples: dict[str, Any]
    frame_dt_ms: int | float | None
    frame_dt_ms_i32: int | None
    checkpoint_private: _CaptureCheckpointEvidence
    clocks: _CaptureClockEvidence


class FridaEvidenceHeader(
    msgspec.Struct,
    frozen=True,
    forbid_unknown_fields=True,
    tag_field="kind",
    tag="header",
):
    evidence_format_version: int
    capture_format_version: int
    trace_format_version: int
    trace_schema_version: int
    frida_version: str
    session_id: str
    ptrs_hash: str
    module_hash: str | None
    run_id: int
    mode_id: int
    quest_stage_major: int
    quest_stage_minor: int
    tick_count: int
    raw_sha256: str
    trace_sha256: str
    replay_sha256: str


class FridaEvidenceTick(
    msgspec.Struct,
    frozen=True,
    forbid_unknown_fields=True,
    tag_field="kind",
    tag="tick",
):
    run_id: int
    tick_index: int
    global_tick_index: int
    evidence: _CaptureTickEvidence


class FridaEvidenceFooter(
    msgspec.Struct,
    frozen=True,
    forbid_unknown_fields=True,
    tag_field="kind",
    tag="footer",
):
    tick_count: int
    first_tick: int
    last_tick: int
    global_tick_first: int
    global_tick_last: int


type FridaEvidenceRow = FridaEvidenceHeader | FridaEvidenceTick | FridaEvidenceFooter


class FridaEvidenceBundle(msgspec.Struct, frozen=True):
    header: FridaEvidenceHeader
    ticks: list[FridaEvidenceTick]
    footer: FridaEvidenceFooter


_EVIDENCE_ENCODER = msgspec.msgpack.Encoder()
_EVIDENCE_DECODER = msgspec.msgpack.Decoder(type=FridaEvidenceRow)


class _TickRow(
    msgspec.Struct,
    frozen=True,
    forbid_unknown_fields=True,
    tag_field="event",
    tag="tick",
):
    run_id: int
    tick_index: int
    global_tick_index: int
    elapsed_ms: int
    dt_ms_i32: int
    mode_id: int
    channels: _TickChannels
    quest_stage_major: int
    quest_stage_minor: int
    rng_calls: int
    rng_outside_before: _OutsideRngBag
    rng_state_enter_u32: int
    rng_state_leave_u32: int
    evidence: _CaptureTickEvidence


class _RunEndRow(
    msgspec.Struct,
    frozen=True,
    forbid_unknown_fields=True,
    tag_field="event",
    tag="run_end",
):
    run_id: int
    mode_id: int
    quest_stage_major: int
    quest_stage_minor: int
    ticks_written: int
    reason: str
    global_tick_index: int
    trailing_prelude: list[ReplayPreludeOperation]
    rng_outside_tail: _OutsideRngBag


class _ErrorRow(
    msgspec.Struct,
    frozen=True,
    forbid_unknown_fields=True,
    tag_field="event",
    tag="error",
):
    error: str
    run_id: int | None = None
    global_tick_index: int | None = None


class _RunErrorRow(
    msgspec.Struct,
    frozen=True,
    forbid_unknown_fields=True,
    tag_field="event",
    tag="run_error",
):
    error: str
    run_id: int | None = None
    mode_id: int | None = None
    quest_stage_major: int | None = None
    quest_stage_minor: int | None = None
    global_tick_index: int | None = None


type _CaptureRow = _SessionStartRow | _RunStartRow | _TickRow | _RunEndRow | _ErrorRow | _RunErrorRow


_CAPTURE_ROW_DECODER = msgspec.json.Decoder(type=_CaptureRow)


class FinalizedTrace(msgspec.Struct, frozen=True):
    run_id: int
    out_path: Path
    replay_path: Path
    evidence_path: Path
    tick_count: int
    mode_id: int
    quest_stage_major: int
    quest_stage_minor: int
    summary: TraceSummary


class FinalizeResult(msgspec.Struct, frozen=True):
    raw_path: Path
    traces: list[FinalizedTrace]
    deleted_raw: bool


class _OpenRun(msgspec.Struct):
    run_id: int
    mode_id: int
    quest_stage_major: int
    quest_stage_minor: int
    replay_seed: int
    replay_player_count: int
    next_global_tick: int
    temp_path: Path
    stream: BinaryIO
    evidence_temp_path: Path
    evidence_stream: BinaryIO
    replay_seed_source: str
    status: GameStatusData
    tick_rate: int
    quest_fail_retry_count: int
    hardcore: bool
    detail_preset: int
    violence_disabled: int
    world_size: float
    pool_residue: tuple[CreatureSlotResidue, ...]
    tick_count: int = 0
    next_local_tick: int = 0
    replay_inputs: list[list[list[float | int]]] = msgspec.field(default_factory=list)
    replay_dt: list[float] = msgspec.field(default_factory=list)
    replay_prelude: list[list[ReplayPreludeOperation]] = msgspec.field(default_factory=list)
    replay_postlude: list[list[ReplayPostludeOperation]] = msgspec.field(default_factory=list)
    replay_commands: list[list[ReplayTickCommand]] = msgspec.field(default_factory=list)
    evidence_count: int = 0
    global_tick_first: int | None = None
    global_tick_last: int | None = None
    rng_outside_calls: int = 0
    rng_outside_dropped: int = 0
    rng_outside_caller_counts: dict[str, int] = msgspec.field(default_factory=dict)
    rng_state_after_bootstrap: int = 0
    rng_bootstrap_calls: int = 0
    rng_prev_leave_state: int | None = None


class _RawFingerprint(msgspec.Struct, frozen=True):
    path: str
    sha256: str
    size: int
    mtime_ns: int


def _fingerprint(path: Path) -> _RawFingerprint:
    stat = path.stat()
    raw = path.read_bytes()
    return _RawFingerprint(
        path=str(path),
        sha256=hashlib.sha256(raw).hexdigest(),
        size=int(stat.st_size),
        mtime_ns=int(stat.st_mtime_ns),
    )


def _residue_float(value: float | None, *, field: str) -> float:
    if value is None or not math.isfinite(float(value)):
        raise FridaFinalizeError(f"{field} must be a finite float in the pool residue snapshot")
    return float(value)


def _residue_int(value: int | None, *, field: str) -> int:
    if value is None:
        raise FridaFinalizeError(f"{field} must be present in the pool residue snapshot")
    return int(value)


def _residue_u8(value: int | None, *, field: str) -> int:
    integer = _residue_int(value, field=field)
    if not (0 <= integer <= 0xFF):
        raise FridaFinalizeError(f"{field} must be an unsigned byte in the pool residue snapshot")
    return integer


def _residue_vec2(row: _CaptureVec2Row, *, field: str) -> Vec2:
    return Vec2(
        x=_residue_float(row.x, field=f"{field}.x"),
        y=_residue_float(row.y, field=f"{field}.y"),
    )


def _pool_residue_from_run_start(run_start: _RunStartRow, *, field: str) -> tuple[CreatureSlotResidue, ...]:
    rows = run_start.pool_residue
    if not rows:
        raise FridaFinalizeError(f"{field}.pool_residue must be non-empty")
    out: list[CreatureSlotResidue] = []
    for i, row in enumerate(rows):
        slot_field = f"{field}.pool_residue[{i}]"
        if int(row.index) != i:
            raise FridaFinalizeError(f"{slot_field}.index={int(row.index)} does not match slot {i}")
        if _residue_int(row.active, field=f"{slot_field}.active") != 0:
            raise FridaFinalizeError(
                f"{slot_field} is active at run start; creature_reset_all must have run before the latch",
            )
        out.append(
            CreatureSlotResidue(
                index=i,
                phase_seed=_residue_int(row.phase_seed, field=f"{slot_field}.phase_seed"),
                state_flag=_residue_u8(row.state_flag, field=f"{slot_field}.state_flag"),
                collision_flag=_residue_u8(row.collision_flag, field=f"{slot_field}.collision_flag"),
                collision_timer=_residue_float(row.collision_timer, field=f"{slot_field}.collision_timer"),
                lifecycle_stage=_residue_float(row.lifecycle_stage, field=f"{slot_field}.lifecycle_stage"),
                pos=_residue_vec2(row.pos, field=f"{slot_field}.pos"),
                vel=_residue_vec2(row.vel, field=f"{slot_field}.vel"),
                hp=_residue_float(row.hp, field=f"{slot_field}.hp"),
                max_hp=_residue_float(row.max_hp, field=f"{slot_field}.max_hp"),
                heading=_residue_float(row.heading, field=f"{slot_field}.heading"),
                target_heading=_residue_float(row.target_heading, field=f"{slot_field}.target_heading"),
                size=_residue_float(row.size, field=f"{slot_field}.size"),
                hit_flash_timer=_residue_float(row.hit_flash_timer, field=f"{slot_field}.hit_flash_timer"),
                tint_r=_residue_float(row.tint.r, field=f"{slot_field}.tint.r"),
                tint_g=_residue_float(row.tint.g, field=f"{slot_field}.tint.g"),
                tint_b=_residue_float(row.tint.b, field=f"{slot_field}.tint.b"),
                tint_a=_residue_float(row.tint.a, field=f"{slot_field}.tint.a"),
                force_target=_residue_u8(row.force_target, field=f"{slot_field}.force_target"),
                target=_residue_vec2(row.target, field=f"{slot_field}.target"),
                contact_damage=_residue_float(row.contact_damage, field=f"{slot_field}.contact_damage"),
                move_speed=_residue_float(row.move_speed, field=f"{slot_field}.move_speed"),
                attack_cooldown=_residue_float(row.attack_cooldown, field=f"{slot_field}.attack_cooldown"),
                reward_value=_residue_float(row.reward_value, field=f"{slot_field}.reward_value"),
                type_id=_residue_int(row.type_id, field=f"{slot_field}.type_id"),
                target_player=_residue_int(row.target_player, field=f"{slot_field}.target_player"),
                link_index=_residue_int(row.link_index, field=f"{slot_field}.link_index"),
                target_offset=_residue_vec2(row.target_offset, field=f"{slot_field}.target_offset"),
                orbit_angle=_residue_float(row.orbit_angle, field=f"{slot_field}.orbit_angle"),
                orbit_radius_u32=_capture_u32(row.orbit_radius_u32, field=f"{slot_field}.orbit_radius_u32"),
                flags=_residue_int(row.flags, field=f"{slot_field}.flags"),
                ai_mode=_residue_int(row.ai_mode, field=f"{slot_field}.ai_mode"),
                anim_phase=_residue_float(row.anim_phase, field=f"{slot_field}.anim_phase"),
            ),
        )
    return tuple(out)


def _validate_capture_completeness(session_row: _SessionStartRow, *, field: str) -> None:
    """Reject captures recorded with trimming: parity traces must carry the
    full per-tick channels, never a sample of creatures/draws/events."""

    config = session_row.config
    untrimmed_required = {
        "creature_sample_limit": config.creature_sample_limit,
        "projectile_sample_limit": config.projectile_sample_limit,
        "secondary_projectile_sample_limit": config.secondary_projectile_sample_limit,
        "bonus_sample_limit": config.bonus_sample_limit,
        "max_rng_head_per_tick": config.max_rng_head_per_tick,
        "max_rng_caller_kinds": config.max_rng_caller_kinds,
        "max_events_per_tick": config.max_events_per_tick,
        "max_head_per_kind": config.max_head_per_kind,
    }
    untrimmed_required["max_rng_outside_tick_head"] = config.max_rng_outside_tick_head
    untrimmed_required["max_creature_delta_ids"] = config.max_creature_delta_ids
    trimmed = {name: int(value) for name, value in untrimmed_required.items() if int(value) >= 0}
    if trimmed:
        raise FridaFinalizeError(
            f"{field} capture was recorded with trimmed streams {trimmed}; "
            "parity captures require unlimited limits (-1)",
        )
    if int(config.focus_tick) >= 0:
        raise FridaFinalizeError(
            f"{field} capture used focus mode (focus_tick={int(config.focus_tick)}); "
            "parity captures must record every tick",
        )
    if int(config.player_count_override) > 0:
        raise FridaFinalizeError(
            f"{field} capture used player_count_override={int(config.player_count_override)}; "
            "parity captures must resolve the native player count",
        )
    disabled_required_hooks = [
        name
        for name, enabled in (
            ("enable_input_hooks", config.enable_input_hooks),
            ("enable_rng_hooks", config.enable_rng_hooks),
            ("enable_rng_state_mirror", config.enable_rng_state_mirror),
        )
        if not bool(enabled)
    ]
    if disabled_required_hooks:
        raise FridaFinalizeError(
            f"{field} capture disabled required replay hooks {disabled_required_hooks!r}",
        )


def _decode_capture_row(line: bytes, *, field: str) -> _CaptureRow:
    try:
        return _CAPTURE_ROW_DECODER.decode(line)
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise FridaFinalizeError(f"{field} invalid capture row: {exc}") from exc


def _canonical_channels_payload(
    *,
    channels: _TickChannels,
    evidence: _CaptureTickEvidence,
    field: str,
) -> ReplayTickChannels:
    rng_stream = [
        RngStreamRow(
            tick_call_index=int(row.tick_call_index),
            value_15=int(row.value_15),
            state_before_u32=int(row.state_before_u32),
            state_after_u32=int(row.state_after_u32),
            caller=None if row.caller is None else _capture_u32(row.caller, field=f"{field}.rng_stream[{idx}].caller"),
        )
        for idx, row in enumerate(channels.rng_stream)
    ]
    gameplay = channels.sim_state.gameplay
    checkpoint = channels.checkpoint
    required_event_counts = ("projectile_find_hit", "projectile_find_owner_collision", "bonus_apply")
    missing_event_counts = [name for name in required_event_counts if name not in evidence.event_counts]
    if missing_event_counts:
        raise FridaFinalizeError(f"{field} missing required event counts {missing_event_counts!r}")
    raw_hit_count = int(evidence.event_counts["projectile_find_hit"])
    owner_collision_count = int(evidence.event_counts["projectile_find_owner_collision"])
    pickup_count = int(evidence.event_counts["bonus_apply"])
    if raw_hit_count < 0 or owner_collision_count < 0 or pickup_count < 0:
        raise FridaFinalizeError(f"{field} event counts must be non-negative")
    if owner_collision_count > raw_hit_count:
        raise FridaFinalizeError(
            f"{field} projectile owner-collision count {owner_collision_count} exceeds raw hit count {raw_hit_count}",
        )
    expected_hit_count = raw_hit_count - owner_collision_count
    if checkpoint.deaths:
        raise FridaFinalizeError(f"{field}.checkpoint.deaths must be empty; raw deaths belong in evidence")
    if int(checkpoint.events.hit_count) != expected_hit_count:
        raise FridaFinalizeError(
            f"{field}.checkpoint.events.hit_count={int(checkpoint.events.hit_count)} "
            f"does not match canonical count {expected_hit_count}",
        )
    if int(checkpoint.events.pickup_count) != pickup_count:
        raise FridaFinalizeError(
            f"{field}.checkpoint.events.pickup_count={int(checkpoint.events.pickup_count)} "
            f"does not match canonical count {pickup_count}",
        )
    if int(checkpoint.events.sfx_count) != 0 or checkpoint.events.sfx_head or checkpoint.events.hit_head:
        raise FridaFinalizeError(
            f"{field}.checkpoint.events must not mix producer-specific SFX/hit details into canonical channels",
        )
    return ReplayTickChannels(
        replay_step=channels.replay_step,
        checkpoint=checkpoint,
        sim_state=SimStateSnapshot(
            gameplay=SnapshotGameplay(
                mode_id=int(gameplay.mode_id),
                quest_stage_major=int(gameplay.quest_stage_major),
                quest_stage_minor=int(gameplay.quest_stage_minor),
                perk_pending_count=int(gameplay.perk_pending_count),
                perk_choices_dirty=bool(gameplay.perk_choices_dirty),
                bonus_timers=gameplay.bonus_timers,
            ),
            players=list(channels.sim_state.players),
        ),
        entity_samples=channels.entity_samples,
        rng_stream=rng_stream,
        timing_samples=list(channels.timing_samples),
    )


def _capture_u32(value: int, *, field: str) -> int:
    out = int(value)
    if not (0 <= out <= 0xFFFFFFFF):
        raise FridaFinalizeError(f"{field} must be a uint32")
    return out


def _capture_static_caller(value: str, *, field: str) -> str:
    caller = str(value)
    try:
        parsed = int(caller, 16)
    except ValueError as exc:
        raise FridaFinalizeError(f"{field} must be a canonical static uint32 address") from exc
    if not (0 <= parsed <= 0xFFFFFFFF) or caller != f"0x{parsed:08x}":
        raise FridaFinalizeError(f"{field} must be a canonical static uint32 address")
    return caller


def _capture_status(row: _CaptureGameStatusRow, *, field: str) -> GameStatusData:
    if len(row.weapon_usage_counts) != int(WEAPON_USAGE_COUNT):
        raise FridaFinalizeError(
            f"{field}.weapon_usage_counts must contain exactly {int(WEAPON_USAGE_COUNT)} entries",
        )
    if len(row.quest_play_counts) != int(QUEST_PLAY_COUNT):
        raise FridaFinalizeError(
            f"{field}.quest_play_counts must contain exactly {int(QUEST_PLAY_COUNT)} entries",
        )
    if len(row.reserved_seed_words) != int(RESERVED_SEED_WORDS_BYTE_SIZE):
        raise FridaFinalizeError(
            f"{field}.reserved_seed_words must contain exactly {int(RESERVED_SEED_WORDS_BYTE_SIZE)} bytes",
        )
    weapon_usage_counts = tuple(
        _capture_u32(value, field=f"{field}.weapon_usage_counts[{index}]")
        for index, value in enumerate(row.weapon_usage_counts)
    )
    quest_play_counts = tuple(
        _capture_u32(value, field=f"{field}.quest_play_counts[{index}]")
        for index, value in enumerate(row.quest_play_counts)
    )
    reserved_seed_words_values = []
    for index, value in enumerate(row.reserved_seed_words):
        byte = int(value)
        if not (0 <= byte <= 0xFF):
            raise FridaFinalizeError(f"{field}.reserved_seed_words[{index}] must be a byte")
        reserved_seed_words_values.append(byte)
    mode_play_survival = _capture_u32(row.mode_play_survival, field=f"{field}.mode_play_survival")
    mode_play_rush = _capture_u32(row.mode_play_rush, field=f"{field}.mode_play_rush")
    mode_play_typo = _capture_u32(row.mode_play_typo, field=f"{field}.mode_play_typo")
    mode_play_other = _capture_u32(row.mode_play_other, field=f"{field}.mode_play_other")
    play_time_ms = _capture_u32(row.play_time_ms, field=f"{field}.play_time_ms")
    return GameStatusData(
        quest_unlock_index=int(row.quest_unlock_index),
        quest_unlock_index_full=int(row.quest_unlock_index_full),
        weapon_usage_counts=weapon_usage_counts,
        quest_play_counts=quest_play_counts,
        mode_play_survival=mode_play_survival,
        mode_play_rush=mode_play_rush,
        mode_play_typo=mode_play_typo,
        mode_play_other=mode_play_other,
        play_time_ms=play_time_ms,
        reserved_seed_words=bytes(reserved_seed_words_values),
    )


def _validate_run_settings(settings: _RunSettingsRow, *, field: str) -> GameStatusData:
    if int(settings.tick_rate) <= 0:
        raise FridaFinalizeError(f"{field}.tick_rate must be positive")
    if int(settings.quest_fail_retry_count) < 0:
        raise FridaFinalizeError(f"{field}.quest_fail_retry_count must be non-negative")
    if not (1 <= int(settings.detail_preset) <= 5):
        raise FridaFinalizeError(f"{field}.detail_preset must be in 1..5")
    if int(settings.violence_disabled) not in (0, 1):
        raise FridaFinalizeError(f"{field}.violence_disabled must be 0 or 1")
    if not math.isfinite(float(settings.world_size)) or float(settings.world_size) <= 0.0:
        raise FridaFinalizeError(f"{field}.world_size must be finite and positive")
    try:
        canonical_world_size = quantize_f32(float(settings.world_size))
    except OverflowError as exc:
        raise FridaFinalizeError(f"{field}.world_size must fit in f32") from exc
    if canonical_world_size != float(settings.world_size):
        raise FridaFinalizeError(f"{field}.world_size must be canonical f32")
    return _capture_status(settings.status, field=f"{field}.status")


def _replay_tick_inputs_from_step(
    replay_step: ReplayStepSnapshot,
    *,
    expected_players: int,
    field: str,
) -> list[list[float | int]]:
    if not math.isfinite(float(replay_step.dt)) or float(replay_step.dt) < 0.0:
        raise FridaFinalizeError(f"{field}.dt must be finite and >= 0")
    if float(replay_step.dt) != quantize_f32(float(replay_step.dt)):
        raise FridaFinalizeError(f"{field}.dt must already be canonical f32")
    if len(replay_step.inputs) != int(expected_players):
        raise FridaFinalizeError(
            f"{field}.inputs must contain {int(expected_players)} player rows, got {len(replay_step.inputs)}",
        )
    out: list[list[float | int]] = []
    for player_index, sample in enumerate(replay_step.inputs):
        player_field = f"{field}.inputs[{player_index}]"
        scalars = (
            ("move_x", sample.move_x),
            ("move_y", sample.move_y),
            ("aim_x", sample.aim_x),
            ("aim_y", sample.aim_y),
        )
        for scalar_name, scalar_value in scalars:
            if not math.isfinite(float(scalar_value)):
                raise FridaFinalizeError(f"{player_field}.{scalar_name} must be finite")
            if float(scalar_value) != quantize_f32(float(scalar_value)):
                raise FridaFinalizeError(f"{player_field}.{scalar_name} must already be canonical f32")
        flags = _capture_u32(sample.flags, field=f"{player_field}.flags")
        out.append([float(sample.move_x), float(sample.move_y), float(sample.aim_x), float(sample.aim_y), flags])
    return out


def _validate_replay_prelude(
    tick_row: _TickRow,
    *,
    expected_players: int,
    field: str,
) -> list[ReplayPreludeOperation]:
    prelude = list(tick_row.channels.replay_step.prelude)
    _validate_replay_prelude_operations(
        prelude,
        expected_players=expected_players,
        field=f"{field}.channels.replay_step.prelude",
    )
    return prelude


def _validate_replay_prelude_operations(
    prelude: list[ReplayPreludeOperation],
    *,
    expected_players: int,
    field: str,
) -> None:
    for operation_index, operation in enumerate(prelude):
        operation_field = f"{field}[{operation_index}]"
        if isinstance(operation, GameFrameRngAdvanceOperation):
            if int(operation.frames) <= 0:
                raise FridaFinalizeError(f"{operation_field}.frames must be positive")
            continue
        if not isinstance(operation, (PerkMenuOpenCommand, PerkPickCommand)):
            raise FridaFinalizeError(f"{operation_field} has unsupported replay operation")
        if not (0 <= int(operation.player_index) < int(expected_players)):
            raise FridaFinalizeError(
                f"{operation_field}.player_index={int(operation.player_index)} "
                f"is outside 0..{int(expected_players) - 1}",
            )
        if isinstance(operation, PerkPickCommand) and not (0 <= int(operation.choice_index) < 7):
            raise FridaFinalizeError(f"{operation_field}.choice_index must be in 0..6")


def _validate_rng_transition(
    *,
    state_before_u32: int,
    state_after_u32: int,
    value_15: int,
    field: str,
) -> None:
    before = _capture_u32(state_before_u32, field=f"{field}.state_before_u32")
    after = _capture_u32(state_after_u32, field=f"{field}.state_after_u32")
    expected_after = _lcg_step_u32(before)
    if after != expected_after:
        raise FridaFinalizeError(
            f"{field}.state_after_u32={after} does not match CRT transition {expected_after}",
        )
    value = int(value_15)
    expected_value = (after >> 16) & 0x7FFF
    if value != expected_value:
        raise FridaFinalizeError(f"{field}.value_15={value} does not match CRT output {expected_value}")


def _validate_outside_rng_bag(
    bag: _OutsideRngBag,
    *,
    prelude: list[ReplayPreludeOperation],
    field: str,
    expected_start: int | None = None,
    expected_end: int | None = None,
) -> None:
    calls = int(bag.calls)
    dropped = int(bag.dropped)
    rows = list(bag.head)
    if dropped != 0 or calls != len(rows):
        raise FridaFinalizeError(
            f"{field} must contain every outside RNG row (calls={calls} dropped={dropped} head={len(rows)})",
        )
    actual_counts: dict[str, int] = {}
    calls_by_operation: dict[int, int] = {}
    previous_operation_index: int | None = None
    previous_after = None if expected_start is None else _capture_u32(expected_start, field=f"{field}.start")
    for index, row in enumerate(rows):
        row_field = f"{field}.head[{index}]"
        caller = _capture_static_caller(row.caller_static, field=f"{row_field}.caller_static")
        operation_index = int(row.replay_operation_index)
        if not (0 <= operation_index < len(prelude)):
            raise FridaFinalizeError(
                f"{row_field}.replay_operation_index={operation_index} is outside 0..{len(prelude) - 1}",
            )
        if previous_operation_index is not None and operation_index < previous_operation_index:
            raise FridaFinalizeError(
                f"{row_field}.replay_operation_index={operation_index} precedes prior operation "
                f"{previous_operation_index}",
            )
        previous_operation_index = operation_index
        operation = prelude[operation_index]
        if isinstance(operation, GameFrameRngAdvanceOperation) and caller != _FRAME_DISCARDED_RNG_CALLER_STATIC:
            raise FridaFinalizeError(f"{row_field} frame operation has caller {caller!r}")
        actual_counts[caller] = actual_counts.get(caller, 0) + 1
        calls_by_operation[operation_index] = calls_by_operation.get(operation_index, 0) + 1
        if previous_after is not None and int(row.state_before_u32) != previous_after:
            raise FridaFinalizeError(
                f"{row_field}.state_before_u32={int(row.state_before_u32)} "
                f"does not continue prior RNG state {previous_after}",
            )
        _validate_rng_transition(
            state_before_u32=int(row.state_before_u32),
            state_after_u32=int(row.state_after_u32),
            value_15=int(row.value_15),
            field=row_field,
        )
        previous_after = int(row.state_after_u32)
    declared_counts = {str(key): int(value) for key, value in bag.caller_counts.items()}
    if declared_counts != actual_counts:
        raise FridaFinalizeError(
            f"{field}.caller_counts={declared_counts!r} does not match captured rows {actual_counts!r}",
        )
    for operation_index, operation in enumerate(prelude):
        if isinstance(operation, GameFrameRngAdvanceOperation):
            captured_calls = calls_by_operation.get(operation_index, 0)
            if captured_calls != int(operation.frames):
                raise FridaFinalizeError(
                    f"{field} frame operation {operation_index} records {int(operation.frames)} frame(s), "
                    f"but {captured_calls} RNG row(s) reference it",
                )
    if expected_end is not None:
        expected = _capture_u32(expected_end, field=f"{field}.end")
        actual = previous_after if previous_after is not None else expected_start
        if actual is not None and int(actual) != expected:
            raise FridaFinalizeError(f"{field} ends at RNG state {int(actual)}, expected {expected}")


def _validate_tick_channels(
    *,
    channels: _TickChannels,
    expected_players: int,
    tick_index: int,
    elapsed_ms: int,
    dt_ms_i32: int,
    mode_id: int,
    quest_stage_major: int,
    quest_stage_minor: int,
    field: str,
) -> None:
    checkpoint_players = list(channels.checkpoint.players)
    if len(checkpoint_players) <= 0:
        raise FridaFinalizeError(f"{field}.checkpoint.players must be non-empty")
    if len(checkpoint_players) != int(expected_players):
        raise FridaFinalizeError(
            f"{field}.checkpoint.players length {len(checkpoint_players)} "
            f"does not match run_start.player_count {int(expected_players)}",
        )
    if int(channels.checkpoint.tick_index) != int(tick_index):
        raise FridaFinalizeError(
            f"{field}.checkpoint.tick_index={int(channels.checkpoint.tick_index)} "
            f"does not match tick.tick_index {int(tick_index)}",
        )
    if int(channels.checkpoint.elapsed_ms) != int(elapsed_ms):
        raise FridaFinalizeError(
            f"{field}.checkpoint.elapsed_ms={int(channels.checkpoint.elapsed_ms)} "
            f"does not match tick.elapsed_ms {int(elapsed_ms)}",
        )
    rng_state = int(channels.checkpoint.rng_state)
    if rng_state < 0 or rng_state > 0xFFFFFFFF:
        raise FridaFinalizeError(f"{field}.checkpoint.rng_state must be a uint32")
    sim_players = list(channels.sim_state.players)
    if len(sim_players) != len(checkpoint_players):
        raise FridaFinalizeError(
            f"{field}.sim_state.players length {len(sim_players)} "
            f"does not match checkpoint.players length {len(checkpoint_players)}",
        )
    replay_step = channels.replay_step
    _replay_tick_inputs_from_step(
        replay_step,
        expected_players=int(expected_players),
        field=f"{field}.replay_step",
    )
    if replay_step.commands:
        raise FridaFinalizeError(f"{field}.replay_step.commands must be empty for supported classic modes")
    for player_index, player in enumerate(sim_players):
        if int(player.index) != int(player_index):
            raise FridaFinalizeError(
                f"{field}.sim_state.players[{player_index}].index={int(player.index)} does not match slot",
            )
        scalars = (
            ("pos.x", player.pos.x),
            ("pos.y", player.pos.y),
            ("heading", player.heading),
            ("move_speed", player.move_speed),
            ("move_phase", player.move_phase),
            ("aim.x", player.aim.x),
            ("aim.y", player.aim.y),
            ("aim_heading", player.aim_heading),
        )
        for scalar_name, scalar_value in scalars:
            if not math.isfinite(float(scalar_value)):
                raise FridaFinalizeError(
                    f"{field}.sim_state.players[{player_index}].{scalar_name} must be finite",
                )
    gameplay = channels.sim_state.gameplay
    if int(gameplay.mode_id) != int(mode_id):
        raise FridaFinalizeError(
            f"{field}.sim_state.gameplay.mode_id={int(gameplay.mode_id)} does not match tick.mode_id {int(mode_id)}",
        )
    expected_major = int(quest_stage_major) if mode_id == _GAME_MODE_QUESTS else 0
    expected_minor = int(quest_stage_minor) if mode_id == _GAME_MODE_QUESTS else 0
    if int(gameplay.quest_stage_major) != expected_major:
        raise FridaFinalizeError(
            f"{field}.sim_state.gameplay.quest_stage_major={int(gameplay.quest_stage_major)} "
            f"does not match canonical quest stage {expected_major}",
        )
    if int(gameplay.quest_stage_minor) != expected_minor:
        raise FridaFinalizeError(
            f"{field}.sim_state.gameplay.quest_stage_minor={int(gameplay.quest_stage_minor)} "
            f"does not match canonical quest stage {expected_minor}",
        )
    timing_samples = list(channels.timing_samples)
    if len(timing_samples) <= 0:
        raise FridaFinalizeError(f"{field}.timing_samples must be non-empty")
    for sample_index, sample in enumerate(timing_samples):
        if not str(sample.phase):
            raise FridaFinalizeError(f"{field}.timing_samples[{sample_index}].phase must be non-empty")
        if not str(sample.write_kind):
            raise FridaFinalizeError(f"{field}.timing_samples[{sample_index}].write_kind must be non-empty")
        if int(sample.tick_index) != int(tick_index):
            raise FridaFinalizeError(
                f"{field}.timing_samples[{sample_index}].tick_index={int(sample.tick_index)} "
                f"does not match tick.tick_index {int(tick_index)}",
            )
        if sample.gameplay_frame is not None and int(sample.gameplay_frame) != int(tick_index):
            raise FridaFinalizeError(
                f"{field}.timing_samples[{sample_index}].gameplay_frame={int(sample.gameplay_frame)} "
                f"does not match tick.tick_index {int(tick_index)}",
            )
    gpur_enter = next((sample for sample in timing_samples if str(sample.phase) == "gpur_enter"), None)
    if gpur_enter is None:
        raise FridaFinalizeError(f"{field}.timing_samples must include phase `gpur_enter`")
    if gpur_enter.frame_dt_f32 is None or not math.isfinite(float(gpur_enter.frame_dt_f32)):
        raise FridaFinalizeError(f"{field}.timing_samples.gpur_enter.frame_dt_f32 must be finite")
    if gpur_enter.frame_dt_ms_i32 is None:
        raise FridaFinalizeError(f"{field}.timing_samples.gpur_enter.frame_dt_ms_i32 must be present")
    if int(gpur_enter.frame_dt_ms_i32) < 0:
        raise FridaFinalizeError(f"{field}.timing_samples.gpur_enter.frame_dt_ms_i32 must be >= 0")
    if float(gpur_enter.frame_dt_f32) != float(replay_step.dt):
        raise FridaFinalizeError(
            f"{field}.timing_samples.gpur_enter.frame_dt_f32={float(gpur_enter.frame_dt_f32)} "
            f"does not match replay_step.dt {float(replay_step.dt)}",
        )
    if int(gpur_enter.frame_dt_ms_i32) != int(dt_ms_i32):
        raise FridaFinalizeError(
            f"{field}.timing_samples.gpur_enter.frame_dt_ms_i32={int(gpur_enter.frame_dt_ms_i32)} "
            f"does not match tick.dt_ms_i32 {int(dt_ms_i32)}",
        )
    if gpur_enter.mode_fn != "gameplay_update_and_render":
        raise FridaFinalizeError(
            f"{field}.timing_samples.gpur_enter.mode_fn must be 'gameplay_update_and_render'",
        )


def _tick_iter_from_spool(path: Path):
    with Path(path).open("rb") as handle:
        while True:
            len_raw = handle.read(_FRAME_LEN_BYTES)
            if not len_raw:
                break
            if len(len_raw) != _FRAME_LEN_BYTES:
                raise FridaFinalizeError(f"truncated tick spool frame length: {path}")
            frame_len = int.from_bytes(len_raw, "little", signed=False)
            if frame_len <= 0:
                raise FridaFinalizeError(f"invalid tick spool frame length: {frame_len}")
            payload = handle.read(frame_len)
            if len(payload) != frame_len:
                raise FridaFinalizeError(f"truncated tick spool payload: {path}")
            try:
                yield _TICK_DECODER.decode(payload)
            except (msgspec.DecodeError, msgspec.ValidationError) as exc:
                raise FridaFinalizeError(f"invalid tick spool payload in {path}") from exc


def _write_framed_payload(stream: BinaryIO, payload: bytes, *, field: str) -> None:
    frame_len = len(payload)
    if frame_len <= 0 or frame_len > 0xFFFFFFFF:
        raise FridaFinalizeError(f"{field} has invalid frame length {frame_len}")
    stream.write(frame_len.to_bytes(_EVIDENCE_FRAME_LEN_BYTES, "little", signed=False))
    stream.write(payload)


def _read_exact(stream: _BinaryReader, size: int, *, field: str) -> bytes:
    chunks: list[bytes] = []
    remaining = int(size)
    while remaining > 0:
        chunk = stream.read(remaining)
        if not chunk:
            raise FridaFinalizeError(f"truncated {field}")
        chunks.append(bytes(chunk))
        remaining -= len(chunk)
    return b"".join(chunks)


def _iter_framed_payloads(stream: _BinaryReader, *, field: str):
    while True:
        len_raw = stream.read(_EVIDENCE_FRAME_LEN_BYTES)
        if not len_raw:
            return
        if len(len_raw) != _EVIDENCE_FRAME_LEN_BYTES:
            raise FridaFinalizeError(f"truncated {field} frame length")
        frame_len = int.from_bytes(len_raw, "little", signed=False)
        if frame_len <= 0:
            raise FridaFinalizeError(f"invalid {field} frame length {frame_len}")
        yield _read_exact(stream, frame_len, field=f"{field} frame payload")


def _write_run_evidence(
    path: Path,
    *,
    raw_fingerprint: _RawFingerprint,
    session_start: _SessionStartRow,
    run: _OpenRun,
    trace_sha256: str,
    replay_sha256: str,
) -> None:
    if not run.evidence_stream.closed:
        run.evidence_stream.flush()
        run.evidence_stream.close()
    header = FridaEvidenceHeader(
        evidence_format_version=int(FRIDA_EVIDENCE_FORMAT_VERSION),
        capture_format_version=int(FRIDA_CAPTURE_FORMAT_VERSION),
        trace_format_version=int(TRACE_FORMAT_VERSION),
        trace_schema_version=int(TRACE_SCHEMA_VERSION),
        frida_version=str(session_start.frida_version),
        session_id=str(session_start.session_id),
        ptrs_hash=str(session_start.session_fingerprint.ptrs_hash),
        module_hash=session_start.session_fingerprint.module_hash,
        run_id=int(run.run_id),
        mode_id=int(run.mode_id),
        quest_stage_major=int(run.quest_stage_major),
        quest_stage_minor=int(run.quest_stage_minor),
        tick_count=int(run.tick_count),
        raw_sha256=raw_fingerprint.sha256,
        trace_sha256=str(trace_sha256),
        replay_sha256=str(replay_sha256),
    )
    if run.global_tick_first is None or run.global_tick_last is None:
        raise FridaFinalizeError(f"run {run.run_id}: evidence footer requires global tick bounds")
    footer = FridaEvidenceFooter(
        tick_count=int(run.tick_count),
        first_tick=0,
        last_tick=int(run.tick_count) - 1,
        global_tick_first=int(run.global_tick_first),
        global_tick_last=int(run.global_tick_last),
    )
    with Path(path).open("wb") as raw_handle, zstd.ZstdCompressor(level=_EVIDENCE_ZSTD_LEVEL).stream_writer(
        raw_handle,
        closefd=False,
    ) as compressed:
        _write_framed_payload(
            compressed,
            _EVIDENCE_ENCODER.encode(header),
            field="evidence header",
        )
        copied = 0
        with run.evidence_temp_path.open("rb") as spool:
            for payload in _iter_framed_payloads(spool, field="evidence spool"):
                try:
                    row = _EVIDENCE_DECODER.decode(payload)
                except (msgspec.DecodeError, msgspec.ValidationError) as exc:
                    raise FridaFinalizeError(
                        f"invalid evidence spool payload in {run.evidence_temp_path}",
                    ) from exc
                if not isinstance(row, FridaEvidenceTick):
                    raise FridaFinalizeError("evidence spool may contain only tick rows")
                _write_framed_payload(compressed, payload, field="evidence tick")
                copied += 1
        if copied != int(run.tick_count) or copied != int(run.evidence_count):
            raise FridaFinalizeError(
                f"run {run.run_id}: evidence count {copied} does not match tick_count {run.tick_count}",
            )
        _write_framed_payload(
            compressed,
            _EVIDENCE_ENCODER.encode(footer),
            field="evidence footer",
        )


def load_frida_evidence_file(path: Path) -> FridaEvidenceBundle:
    rows: list[FridaEvidenceRow] = []
    try:
        with (
            Path(path).open("rb") as compressed_handle,
            SpooledTemporaryFile(max_size=_EVIDENCE_DECODE_SPOOL_MAX_MEMORY, mode="w+b") as decompressed,
        ):
            decompressor = zstd.ZstdDecompressor().decompressobj()
            while chunk := compressed_handle.read(_EVIDENCE_COMPRESSED_READ_BYTES):
                decompressed.write(decompressor.decompress(chunk))
                if decompressor.unused_data or decompressor.unconsumed_tail:
                    raise FridaFinalizeError("Frida evidence sidecar has trailing bytes or extra zstd frames")
                if decompressor.eof:
                    if compressed_handle.read(1):
                        raise FridaFinalizeError("Frida evidence sidecar has trailing bytes or extra zstd frames")
                    break
            if not decompressor.eof:
                raise FridaFinalizeError("truncated Frida evidence zstd frame")
            decompressed.write(decompressor.flush())
            decompressed.seek(0)
            for payload in _iter_framed_payloads(decompressed, field="evidence"):
                rows.append(_EVIDENCE_DECODER.decode(payload))
    except (OSError, zstd.ZstdError, msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise FridaFinalizeError(f"invalid Frida evidence sidecar: {path}") from exc
    if len(rows) < 2 or not isinstance(rows[0], FridaEvidenceHeader) or not isinstance(rows[-1], FridaEvidenceFooter):
        raise FridaFinalizeError("Frida evidence sidecar must contain one header and footer")
    header = rows[0]
    footer = rows[-1]
    ticks = rows[1:-1]
    if not all(isinstance(row, FridaEvidenceTick) for row in ticks):
        raise FridaFinalizeError("Frida evidence sidecar contains an out-of-order row")
    typed_ticks = [row for row in ticks if isinstance(row, FridaEvidenceTick)]
    if int(header.evidence_format_version) != int(FRIDA_EVIDENCE_FORMAT_VERSION):
        raise FridaFinalizeError(
            f"unsupported Frida evidence version: {int(header.evidence_format_version)}",
        )
    if int(header.capture_format_version) != int(FRIDA_CAPTURE_FORMAT_VERSION):
        raise FridaFinalizeError(
            f"unsupported Frida capture version in evidence: {int(header.capture_format_version)}",
        )
    if int(header.trace_format_version) != int(TRACE_FORMAT_VERSION):
        raise FridaFinalizeError("Frida evidence trace format version does not match the current CDT format")
    if int(header.trace_schema_version) != int(TRACE_SCHEMA_VERSION):
        raise FridaFinalizeError("Frida evidence trace schema version does not match the current CDT schema")
    if int(header.tick_count) != len(typed_ticks) or int(footer.tick_count) != len(typed_ticks):
        raise FridaFinalizeError("Frida evidence tick count does not match header/footer")
    expected_ticks = list(range(len(typed_ticks)))
    actual_ticks = [int(row.tick_index) for row in typed_ticks]
    if actual_ticks != expected_ticks:
        raise FridaFinalizeError("Frida evidence tick indices must be contiguous from zero")
    if typed_ticks:
        if any(int(row.run_id) != int(header.run_id) for row in typed_ticks):
            raise FridaFinalizeError("Frida evidence tick run_id does not match header")
        if int(footer.first_tick) != actual_ticks[0] or int(footer.last_tick) != actual_ticks[-1]:
            raise FridaFinalizeError("Frida evidence footer tick bounds do not match rows")
        globals_actual = [int(row.global_tick_index) for row in typed_ticks]
        if globals_actual != list(range(globals_actual[0], globals_actual[0] + len(globals_actual))):
            raise FridaFinalizeError("Frida evidence global tick indices must be contiguous")
        if int(footer.global_tick_first) != globals_actual[0] or int(footer.global_tick_last) != globals_actual[-1]:
            raise FridaFinalizeError("Frida evidence footer global tick bounds do not match rows")
    return FridaEvidenceBundle(header=header, ticks=typed_ticks, footer=footer)


def _run_output_path(
    *,
    raw_path: Path,
    output_dir: Path,
    mode_id: int,
    quest_stage_major: int,
    quest_stage_minor: int,
    counters: dict[str, int],
) -> Path:
    base = Path(raw_path).stem
    is_quest_run = int(mode_id) == int(_GAME_MODE_QUESTS) and int(quest_stage_major) > 0 and int(quest_stage_minor) > 0
    if is_quest_run:
        key = f"quest_{int(quest_stage_major)}_{int(quest_stage_minor)}"
        idx = counters.get(key, 0) + 1
        counters[key] = idx
        name = f"{base}.quest_{int(quest_stage_major)}_{int(quest_stage_minor)}.run{idx}.cdt"
    else:
        mode_label = str(_MODE_LABEL_BY_ID.get(int(mode_id), f"mode_{int(mode_id)}"))
        key = mode_label
        idx = counters.get(key, 0) + 1
        counters[key] = idx
        name = f"{base}.{mode_label}.run{idx}.cdt"
    return Path(output_dir) / name


def _build_meta(
    *,
    raw_fingerprint: _RawFingerprint,
    session_start: _SessionStartRow,
    run: _OpenRun,
    tick_count: int,
    replay_sha256: str,
    replay_tick_rate: int,
) -> TraceMeta:
    producer_platform = str(session_start.platform)
    producer_arch = str(session_start.arch)
    producer_impl_version = str(session_start.script_version)
    tick_end = int(tick_count) - 1
    quest_level = (
        f"{int(run.quest_stage_major)}.{int(run.quest_stage_minor)}"
        if int(run.mode_id) == int(_GAME_MODE_QUESTS)
        else None
    )
    return TraceMeta(
        trace_format_version=int(TRACE_FORMAT_VERSION),
        trace_schema_version=int(TRACE_SCHEMA_VERSION),
        created_utc=datetime.now(tz=UTC).isoformat(),
        producer=TraceProducer(
            impl="frida_original",
            impl_version=producer_impl_version,
            platform=producer_platform,
            arch=producer_arch,
        ),
        source=TraceSource(
            path=raw_fingerprint.path,
            sha256=raw_fingerprint.sha256,
            size=raw_fingerprint.size,
            mtime_ns=raw_fingerprint.mtime_ns,
            kind="capture",
            replay_sha256=str(replay_sha256),
            tick_rate=int(replay_tick_rate),
            mode_id=int(run.mode_id),
            seed=int(run.replay_seed),
            player_count=int(run.replay_player_count),
            quest_level=quest_level,
            run_id=int(run.run_id),
            quest_stage_major=None if quest_level is None else int(run.quest_stage_major),
            quest_stage_minor=None if quest_level is None else int(run.quest_stage_minor),
            global_tick_first=None if run.global_tick_first is None else int(run.global_tick_first),
            global_tick_last=None if run.global_tick_last is None else int(run.global_tick_last),
            run_start_seed_source=str(run.replay_seed_source),
        ),
        tick_range=TraceTickRange(
            start_tick=0 if tick_count > 0 else -1,
            end_tick=tick_end if tick_count > 0 else -1,
            tick_count=int(tick_count),
        ),
        status=run.status,
    )


def _merge_outside_rng_bag(run: _OpenRun, bag: _OutsideRngBag) -> None:
    run.rng_outside_calls += int(bag.calls)
    run.rng_outside_dropped += int(bag.dropped)
    for key, count in bag.caller_counts.items():
        run.rng_outside_caller_counts[str(key)] = run.rng_outside_caller_counts.get(str(key), 0) + int(count)


def _account_tick_rng_evidence(
    run: _OpenRun,
    *,
    tick_row: _TickRow,
    rng_stream: list[RngStreamRow],
    field: str,
) -> None:
    """Require a complete, contiguous CRT stream for one captured tick."""
    bag = tick_row.rng_outside_before
    if int(tick_row.rng_calls) != len(rng_stream):
        raise FridaFinalizeError(
            f"{field}.rng_calls={int(tick_row.rng_calls)} does not match rng_stream length {len(rng_stream)}",
        )
    enter = _capture_u32(tick_row.rng_state_enter_u32, field=f"{field}.rng_state_enter_u32")
    leave = _capture_u32(tick_row.rng_state_leave_u32, field=f"{field}.rng_state_leave_u32")
    _validate_outside_rng_bag(
        bag,
        prelude=list(tick_row.channels.replay_step.prelude),
        field=f"{field}.rng_outside_before",
        expected_start=run.rng_prev_leave_state,
        expected_end=enter,
    )
    _merge_outside_rng_bag(run, bag)

    prev = enter
    for index, row in enumerate(rng_stream):
        row_field = f"{field}.rng_stream[{index}]"
        if int(row.tick_call_index) != index + 1:
            raise FridaFinalizeError(
                f"{row_field}.tick_call_index={int(row.tick_call_index)} does not match {index + 1}",
            )
        if row.caller is None:
            raise FridaFinalizeError(f"{row_field}.caller must be present")
        if int(row.state_before_u32) != prev:
            raise FridaFinalizeError(
                f"{row_field}.state_before_u32={int(row.state_before_u32)} does not continue prior RNG state {prev}",
            )
        _validate_rng_transition(
            state_before_u32=int(row.state_before_u32),
            state_after_u32=int(row.state_after_u32),
            value_15=int(row.value_15),
            field=row_field,
        )
        prev = int(row.state_after_u32)
    if prev != leave:
        raise FridaFinalizeError(f"{field}.rng_stream ends at RNG state {prev}, expected leave state {leave}")
    run.rng_prev_leave_state = leave


def _write_rng_evidence_report(out_path: Path, run: _OpenRun) -> None:
    report = {
        "run_id": int(run.run_id),
        "mode_id": int(run.mode_id),
        "replay_seed": int(run.replay_seed),
        "bootstrap_state_before": int(run.replay_seed),
        "bootstrap_state_after": int(run.rng_state_after_bootstrap),
        "bootstrap_calls": int(run.rng_bootstrap_calls),
        "outside_calls": int(run.rng_outside_calls),
        "outside_dropped": int(run.rng_outside_dropped),
        "outside_caller_counts": dict(
            sorted(run.rng_outside_caller_counts.items(), key=lambda kv: -kv[1]),
        ),
    }
    evidence_path = Path(out_path).with_suffix(".rng_evidence.json")
    evidence_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def _write_run_trace(
    *,
    raw_path: Path,
    output_dir: Path,
    raw_fingerprint: _RawFingerprint,
    session_start: _SessionStartRow,
    run: _OpenRun,
    counters: dict[str, int],
) -> FinalizedTrace:
    if not run.stream.closed:
        run.stream.flush()
        run.stream.close()
    if not run.evidence_stream.closed:
        run.evidence_stream.flush()
        run.evidence_stream.close()
    if int(run.replay_player_count) <= 0:
        raise FridaFinalizeError(f"run {run.run_id}: invalid replay player_count={run.replay_player_count}")
    if len(run.replay_inputs) != int(run.tick_count):
        raise FridaFinalizeError(
            f"run {run.run_id}: replay_inputs count {len(run.replay_inputs)} does not match tick_count {run.tick_count}",
        )
    if len(run.replay_dt) != int(run.tick_count):
        raise FridaFinalizeError(
            f"run {run.run_id}: replay_dt count {len(run.replay_dt)} does not match tick_count {run.tick_count}",
        )
    if len(run.replay_prelude) != int(run.tick_count):
        raise FridaFinalizeError(
            f"run {run.run_id}: replay_prelude count {len(run.replay_prelude)} "
            f"does not match tick_count {run.tick_count}",
        )
    if len(run.replay_postlude) != int(run.tick_count):
        raise FridaFinalizeError(
            f"run {run.run_id}: replay_postlude count {len(run.replay_postlude)} "
            f"does not match tick_count {run.tick_count}",
        )
    if len(run.replay_commands) != int(run.tick_count):
        raise FridaFinalizeError(
            f"run {run.run_id}: replay_commands count {len(run.replay_commands)} "
            f"does not match tick_count {run.tick_count}",
        )
    out_path = _run_output_path(
        raw_path=raw_path,
        output_dir=output_dir,
        mode_id=int(run.mode_id),
        quest_stage_major=int(run.quest_stage_major),
        quest_stage_minor=int(run.quest_stage_minor),
        counters=counters,
    )
    replay_path = Path(out_path).with_suffix(".crd")
    evidence_path = Path(out_path).with_suffix(".evidence.msgpack.zst")
    is_quest_run = (
        int(run.mode_id) == int(_GAME_MODE_QUESTS) and int(run.quest_stage_major) > 0 and int(run.quest_stage_minor) > 0
    )
    replay_header = ReplayHeader(
        game_mode_id=GameMode(int(run.mode_id)),
        player_count=int(run.replay_player_count),
        quest_level=(QuestLevel(int(run.quest_stage_major), int(run.quest_stage_minor)) if is_quest_run else None),
        preserve_bugs=True,
        tick_rate=int(run.tick_rate),
        seed=int(run.replay_seed),
        quest_fail_retry_count=int(run.quest_fail_retry_count),
        hardcore=bool(run.hardcore),
        detail_preset=int(run.detail_preset),
        violence_disabled=int(run.violence_disabled),
        world_size=float(run.world_size),
        status=run.status,
    )
    replay_header = msgspec.structs.replace(
        replay_header,
        initial_creature_pool=run.pool_residue,
    )
    replay_ticks = [
        ReplayTick(
            inputs=run.replay_inputs[i],
            dt=run.replay_dt[i],
            prelude=run.replay_prelude[i],
            postlude=run.replay_postlude[i],
            commands=run.replay_commands[i],
        )
        for i in range(run.tick_count)
    ]
    dump_replay_file(
        replay_path,
        Replay(header=replay_header, ticks=replay_ticks),
    )
    replay_sha256 = hashlib.sha256(replay_path.read_bytes()).hexdigest()
    meta = _build_meta(
        raw_fingerprint=raw_fingerprint,
        session_start=session_start,
        run=run,
        tick_count=int(run.tick_count),
        replay_sha256=replay_sha256,
        replay_tick_rate=int(replay_header.tick_rate),
    )
    summary = write_trace_iter(
        out_path,
        meta=meta,
        ticks=_tick_iter_from_spool(run.temp_path),
        chunk_ticks=_TRACE_CHUNK_TICKS,
    )
    _write_rng_evidence_report(out_path, run)
    trace_sha256 = hashlib.sha256(out_path.read_bytes()).hexdigest()
    _write_run_evidence(
        evidence_path,
        raw_fingerprint=raw_fingerprint,
        session_start=session_start,
        run=run,
        trace_sha256=trace_sha256,
        replay_sha256=replay_sha256,
    )
    return FinalizedTrace(
        run_id=int(run.run_id),
        out_path=Path(out_path),
        replay_path=Path(replay_path),
        evidence_path=Path(evidence_path),
        tick_count=int(run.tick_count),
        mode_id=int(run.mode_id),
        quest_stage_major=int(run.quest_stage_major),
        quest_stage_minor=int(run.quest_stage_minor),
        summary=summary,
    )


def _staged_artifact_pairs(
    staged_traces: list[FinalizedTrace],
    *,
    output_root: Path,
) -> list[tuple[Path, Path]]:
    pairs: list[tuple[Path, Path]] = []
    for trace in staged_traces:
        staged_rng_path = trace.out_path.with_suffix(".rng_evidence.json")
        for staged_path in (
            trace.out_path,
            trace.replay_path,
            staged_rng_path,
            trace.evidence_path,
        ):
            pairs.append((staged_path, Path(output_root) / staged_path.name))
    destinations = [destination for _, destination in pairs]
    if len(set(destinations)) != len(destinations):
        raise FridaFinalizeError("finalize staging produced duplicate artifact destinations")
    missing = [str(staged) for staged, _ in pairs if not staged.is_file()]
    if missing:
        raise FridaFinalizeError(f"finalize staging omitted artifacts: {missing!r}")
    invalid_destinations = [str(path) for path in destinations if path.exists() and not path.is_file()]
    if invalid_destinations:
        raise FridaFinalizeError(
            f"finalize destinations must be files when they already exist: {invalid_destinations!r}",
        )
    return pairs


def _publish_staged_traces(
    staged_traces: list[FinalizedTrace],
    *,
    output_root: Path,
    temp_root: Path,
) -> list[FinalizedTrace]:
    """Publish the complete artifact set, restoring prior files on failure."""

    pairs = _staged_artifact_pairs(staged_traces, output_root=output_root)
    backup_root = Path(temp_root) / "publish-backups"
    backup_root.mkdir()
    backups: list[tuple[Path, Path]] = []
    committed: list[Path] = []
    try:
        for index, (_, destination) in enumerate(pairs):
            if not destination.exists():
                continue
            backup = backup_root / f"{index:04d}-{destination.name}"
            destination.replace(backup)
            backups.append((backup, destination))
        for staged, destination in pairs:
            staged.replace(destination)
            committed.append(destination)
    except Exception as exc:
        rollback_errors: list[str] = []
        for destination in reversed(committed):
            try:
                destination.unlink(missing_ok=True)
            except OSError as rollback_exc:
                rollback_errors.append(f"remove {destination}: {rollback_exc}")
        for backup, destination in reversed(backups):
            try:
                backup.replace(destination)
            except OSError as rollback_exc:
                rollback_errors.append(f"restore {destination}: {rollback_exc}")
        detail = ""
        if rollback_errors:
            detail = f"; rollback errors: {rollback_errors!r}"
        raise FridaFinalizeError(f"failed to publish finalized artifact set{detail}") from exc

    return [
        msgspec.structs.replace(
            staged,
            out_path=Path(output_root) / staged.out_path.name,
            replay_path=Path(output_root) / staged.replay_path.name,
            evidence_path=Path(output_root) / staged.evidence_path.name,
        )
        for staged in staged_traces
    ]


def finalize_frida_jsonl_to_traces(
    raw_path: Path,
    *,
    output_dir: Path | None = None,
    delete_raw: bool = True,
) -> FinalizeResult:
    raw_path = Path(raw_path)
    if not raw_path.is_file():
        raise FridaFinalizeError(f"raw frida trace not found: {raw_path}")
    output_root = raw_path.parent if output_dir is None else Path(output_dir)
    output_root.mkdir(parents=True, exist_ok=True)
    raw_fingerprint = _fingerprint(raw_path)

    traces: list[FinalizedTrace] = []
    run_counters: dict[str, int] = {}
    session_start: _SessionStartRow | None = None
    active_run: _OpenRun | None = None
    closed_runs: list[_OpenRun] = []
    next_session_tick: int | None = None
    seen_run_ids: set[int] = set()

    temp_dir_obj = TemporaryDirectory(prefix=".crimson-frida-finalize-", dir=output_root)
    temp_root = Path(temp_dir_obj.name)
    try:
        with raw_path.open("rb") as handle:
            for line_no, raw_line in enumerate(handle, start=1):
                line = bytes(raw_line).strip()
                if not line:
                    continue
                row = _decode_capture_row(line, field=f"{raw_path}.lines[{line_no}]")
                match row:
                    case _SessionStartRow() as session_row:
                        if session_start is not None:
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}] duplicate session_start")
                        if int(session_row.capture_format_version) != int(FRIDA_CAPTURE_FORMAT_VERSION):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] unsupported capture_format_version="
                                f"{int(session_row.capture_format_version)}; "
                                f"expected {FRIDA_CAPTURE_FORMAT_VERSION}",
                            )
                        if not str(session_row.session_id):
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].session_id must be non-empty")
                        if not str(session_row.out_path):
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].out_path must be non-empty")
                        if not str(session_row.platform):
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].platform must be non-empty")
                        if not str(session_row.arch):
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].arch must be non-empty")
                        if str(session_row.frida_version) != FRIDA_RUNTIME_VERSION:
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].frida_version="
                                f"{str(session_row.frida_version)!r}; expected {FRIDA_RUNTIME_VERSION!r}",
                            )
                        if str(session_row.script_version) != str(FRIDA_CAPTURE_FORMAT_VERSION):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].script_version={session_row.script_version!r}; "
                                f"expected {str(FRIDA_CAPTURE_FORMAT_VERSION)!r}",
                            )
                        if str(session_row.config.out_path) != str(session_row.out_path):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].config.out_path must match out_path",
                            )
                        if str(session_row.config.out_path_source) not in {"host", "environment", "default"}:
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].config.out_path_source is invalid",
                            )
                        if str(session_row.session_fingerprint.session_id) != str(session_row.session_id):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].session_fingerprint.session_id must match session_id",
                            )
                        _validate_capture_completeness(session_row, field=f"{raw_path}.lines[{line_no}]")
                        session_start = session_row
                        continue
                    case _:
                        if session_start is None:
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}] must start with session_start")

                match row:
                    case _RunStartRow() as run_start:
                        if active_run is not None:
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}] run_start while run is active")
                        if next_session_tick is not None and int(run_start.global_tick_index) != next_session_tick:
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] run_start.global_tick_index={run_start.global_tick_index} "
                                f"does not match expected session tick {next_session_tick}",
                            )
                        if str(run_start.reason) not in _RUN_START_REASONS:
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].reason must be one of {sorted(_RUN_START_REASONS)!r}",
                            )
                        mode_id = int(run_start.mode_id)
                        if mode_id not in _SUPPORTED_CAPTURE_MODES:
                            supported = sorted(_SUPPORTED_CAPTURE_MODES)
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] unsupported mode_id={mode_id}; "
                                f"Frida replay capture supports only {supported!r}",
                            )
                        if int(run_start.run_id) in seen_run_ids:
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] duplicate run_id={int(run_start.run_id)}",
                            )
                        seen_run_ids.add(int(run_start.run_id))
                        if int(run_start.player_count) <= 0:
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].player_count must be positive")
                        if int(run_start.global_tick_index) < 0:
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].global_tick_index must be >= 0",
                            )
                        if not (0 <= int(run_start.rng_state_before_bootstrap) <= 0xFFFFFFFF):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].rng_state_before_bootstrap must be u32",
                            )
                        if not (0 <= int(run_start.rng_state_after_bootstrap) <= 0xFFFFFFFF):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].rng_state_after_bootstrap must be u32",
                            )
                        if int(run_start.rng_bootstrap_calls) < 0:
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].rng_bootstrap_calls must be >= 0",
                            )
                        expected_after_bootstrap = _lcg_advance_u32(
                            int(run_start.rng_state_before_bootstrap),
                            int(run_start.rng_bootstrap_calls),
                        )
                        if expected_after_bootstrap != int(run_start.rng_state_after_bootstrap):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] bootstrap RNG boundary does not match "
                                f"rng_bootstrap_calls={int(run_start.rng_bootstrap_calls)}: "
                                f"expected {expected_after_bootstrap}, got {int(run_start.rng_state_after_bootstrap)}",
                            )
                        pool_residue = _pool_residue_from_run_start(
                            run_start,
                            field=f"{raw_path}.lines[{line_no}]",
                        )
                        status = _validate_run_settings(
                            run_start.settings,
                            field=f"{raw_path}.lines[{line_no}].settings",
                        )
                        spool_path = temp_root / f"run_{int(run_start.run_id)}.ticks"
                        evidence_spool_path = temp_root / f"run_{int(run_start.run_id)}.evidence"
                        active_run = _OpenRun(
                            run_id=int(run_start.run_id),
                            mode_id=mode_id,
                            quest_stage_major=int(run_start.quest_stage_major),
                            quest_stage_minor=int(run_start.quest_stage_minor),
                            replay_seed=int(run_start.rng_state_before_bootstrap),
                            replay_player_count=int(run_start.player_count),
                            next_global_tick=int(run_start.global_tick_index),
                            temp_path=spool_path,
                            stream=spool_path.open("wb"),
                            evidence_temp_path=evidence_spool_path,
                            evidence_stream=evidence_spool_path.open("wb"),
                            replay_seed_source=_RUN_SETUP_SEED_SOURCE,
                            status=status,
                            tick_rate=int(run_start.settings.tick_rate),
                            quest_fail_retry_count=int(run_start.settings.quest_fail_retry_count),
                            hardcore=bool(run_start.settings.hardcore),
                            detail_preset=int(run_start.settings.detail_preset),
                            violence_disabled=int(run_start.settings.violence_disabled),
                            world_size=float(run_start.settings.world_size),
                            pool_residue=pool_residue,
                            rng_state_after_bootstrap=int(run_start.rng_state_after_bootstrap),
                            rng_bootstrap_calls=int(run_start.rng_bootstrap_calls),
                            rng_prev_leave_state=int(run_start.rng_state_after_bootstrap),
                        )
                        continue
                    case _TickRow() as tick_row:
                        if active_run is None:
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}] tick outside run")
                        if int(tick_row.run_id) != int(active_run.run_id):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] tick run_id={int(tick_row.run_id)} "
                                f"does not match active run {active_run.run_id}",
                            )
                        if int(tick_row.tick_index) != int(active_run.next_local_tick):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] tick_index={int(tick_row.tick_index)} "
                                f"does not match expected local tick {int(active_run.next_local_tick)}",
                            )
                        if int(tick_row.global_tick_index) != int(active_run.next_global_tick):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] global_tick_index={int(tick_row.global_tick_index)} "
                                f"does not match expected global tick {int(active_run.next_global_tick)}",
                            )
                        if int(tick_row.mode_id) != int(active_run.mode_id):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] tick mode_id={int(tick_row.mode_id)} "
                                f"does not match active run {active_run.mode_id}",
                            )
                        if int(tick_row.quest_stage_major) != int(active_run.quest_stage_major):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] tick quest_stage_major={int(tick_row.quest_stage_major)} "
                                f"does not match active run {active_run.quest_stage_major}",
                            )
                        if int(tick_row.quest_stage_minor) != int(active_run.quest_stage_minor):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] tick quest_stage_minor={int(tick_row.quest_stage_minor)} "
                                f"does not match active run {active_run.quest_stage_minor}",
                            )
                        if int(tick_row.elapsed_ms) < 0:
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].elapsed_ms must be >= 0",
                            )
                        if int(tick_row.dt_ms_i32) < 0:
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].dt_ms_i32 must be >= 0")
                        _validate_tick_channels(
                            channels=tick_row.channels,
                            expected_players=int(active_run.replay_player_count),
                            tick_index=int(tick_row.tick_index),
                            elapsed_ms=int(tick_row.elapsed_ms),
                            dt_ms_i32=int(tick_row.dt_ms_i32),
                            mode_id=int(tick_row.mode_id),
                            quest_stage_major=int(tick_row.quest_stage_major),
                            quest_stage_minor=int(tick_row.quest_stage_minor),
                            field=f"{raw_path}.lines[{line_no}].channels",
                        )
                        replay_inputs = _replay_tick_inputs_from_step(
                            tick_row.channels.replay_step,
                            expected_players=int(active_run.replay_player_count),
                            field=f"{raw_path}.lines[{line_no}].channels.replay_step",
                        )
                        replay_prelude = _validate_replay_prelude(
                            tick_row,
                            expected_players=int(active_run.replay_player_count),
                            field=f"{raw_path}.lines[{line_no}]",
                        )
                        channels = _canonical_channels_payload(
                            channels=tick_row.channels,
                            evidence=tick_row.evidence,
                            field=f"{raw_path}.lines[{line_no}].channels",
                        )
                        channels = msgspec.structs.replace(
                            channels,
                            replay_step=msgspec.structs.replace(channels.replay_step, prelude=replay_prelude),
                        )
                        _account_tick_rng_evidence(
                            active_run,
                            tick_row=tick_row,
                            rng_stream=channels.rng_stream,
                            field=f"{raw_path}.lines[{line_no}]",
                        )
                        active_run.replay_inputs.append(list(replay_inputs))
                        active_run.replay_dt.append(float(tick_row.channels.replay_step.dt))
                        active_run.replay_prelude.append(list(replay_prelude))
                        active_run.replay_postlude.append(list(tick_row.channels.replay_step.postlude))
                        active_run.replay_commands.append(list(tick_row.channels.replay_step.commands))
                        tick = TickRecord(
                            tick_index=int(tick_row.tick_index),
                            elapsed_ms=int(tick_row.elapsed_ms),
                            dt_ms_i32=int(tick_row.dt_ms_i32),
                            mode_id=int(tick_row.mode_id),
                            channels=channels,
                        )
                        payload = _TICK_ENCODER.encode(tick)
                        active_run.stream.write(len(payload).to_bytes(_FRAME_LEN_BYTES, "little", signed=False))
                        active_run.stream.write(payload)
                        evidence_row = FridaEvidenceTick(
                            run_id=int(tick_row.run_id),
                            tick_index=int(tick_row.tick_index),
                            global_tick_index=int(tick_row.global_tick_index),
                            evidence=tick_row.evidence,
                        )
                        _write_framed_payload(
                            active_run.evidence_stream,
                            _EVIDENCE_ENCODER.encode(evidence_row),
                            field=f"run {active_run.run_id} evidence tick {active_run.tick_count}",
                        )
                        active_run.evidence_count += 1
                        active_run.next_local_tick += 1
                        active_run.next_global_tick += 1
                        next_session_tick = active_run.next_global_tick
                        active_run.tick_count += 1
                        global_tick = int(tick_row.global_tick_index)
                        if active_run.global_tick_first is None:
                            active_run.global_tick_first = global_tick
                        active_run.global_tick_last = global_tick
                        continue
                    case _RunEndRow() as run_end:
                        if active_run is None:
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}] run_end without active run")
                        if int(run_end.run_id) != int(active_run.run_id):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] run_end run_id={int(run_end.run_id)} "
                                f"does not match active run {active_run.run_id}",
                            )
                        if str(run_end.reason) not in _RUN_END_REASONS:
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].reason must be one of {sorted(_RUN_END_REASONS)!r}",
                            )
                        if int(run_end.mode_id) != int(active_run.mode_id):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] run_end mode_id={int(run_end.mode_id)} "
                                f"does not match active run {active_run.mode_id}",
                            )
                        if int(run_end.quest_stage_major) != int(active_run.quest_stage_major):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] run_end quest_stage_major={int(run_end.quest_stage_major)} "
                                f"does not match active run {active_run.quest_stage_major}",
                            )
                        if int(run_end.quest_stage_minor) != int(active_run.quest_stage_minor):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] run_end quest_stage_minor={int(run_end.quest_stage_minor)} "
                                f"does not match active run {active_run.quest_stage_minor}",
                            )
                        if int(run_end.ticks_written) != int(active_run.tick_count):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] run_end.ticks_written={int(run_end.ticks_written)} "
                                f"does not match active run tick_count {int(active_run.tick_count)}",
                            )
                        if active_run.global_tick_last is None:
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] run_end cannot close an empty run",
                            )
                        if int(run_end.global_tick_index) != int(active_run.global_tick_last):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] run_end.global_tick_index="
                                f"{int(run_end.global_tick_index)} does not match last tick "
                                f"{int(active_run.global_tick_last)}",
                            )
                        trailing_prelude = list(run_end.trailing_prelude)
                        _validate_replay_prelude_operations(
                            trailing_prelude,
                            expected_players=int(active_run.replay_player_count),
                            field=f"{raw_path}.lines[{line_no}].trailing_prelude",
                        )
                        _validate_outside_rng_bag(
                            run_end.rng_outside_tail,
                            prelude=trailing_prelude,
                            field=f"{raw_path}.lines[{line_no}].rng_outside_tail",
                            expected_start=active_run.rng_prev_leave_state,
                        )
                        _merge_outside_rng_bag(active_run, run_end.rng_outside_tail)
                        active_run.stream.flush()
                        active_run.stream.close()
                        active_run.evidence_stream.flush()
                        active_run.evidence_stream.close()
                        closed_runs.append(active_run)
                        active_run = None
                        continue
                    case _ErrorRow() as error_row:
                        location = f"{raw_path}.lines[{line_no}]"
                        if error_row.global_tick_index is None:
                            raise FridaFinalizeError(f"{location} capture error={error_row.error!r}")
                        raise FridaFinalizeError(
                            f"{location} capture error={error_row.error!r} "
                            f"global_tick_index={int(error_row.global_tick_index)}",
                        )
                    case _RunErrorRow() as run_error:
                        location = f"{raw_path}.lines[{line_no}]"
                        suffix = (
                            ""
                            if run_error.global_tick_index is None
                            else f" global_tick_index={int(run_error.global_tick_index)}"
                        )
                        raise FridaFinalizeError(f"{location} run error={run_error.error!r}{suffix}")
                    case _:
                        raise FridaFinalizeError(f"{raw_path}.lines[{line_no}] unsupported capture row")

        if session_start is None:
            raise FridaFinalizeError(f"{raw_path} missing session_start")
        if active_run is not None:
            raise FridaFinalizeError(f"{raw_path} ended with active run {int(active_run.run_id)}")
        if not closed_runs:
            raise FridaFinalizeError(f"{raw_path} had no finalized runs")
        staged_output_root = temp_root / "output"
        staged_output_root.mkdir()
        staged_traces = [
            _write_run_trace(
                raw_path=raw_path,
                output_dir=staged_output_root,
                raw_fingerprint=raw_fingerprint,
                session_start=session_start,
                run=run,
                counters=run_counters,
            )
            for run in closed_runs
        ]
        traces.extend(
            _publish_staged_traces(
                staged_traces,
                output_root=output_root,
                temp_root=temp_root,
            ),
        )
    finally:
        if active_run is not None:
            with suppress(Exception):
                active_run.stream.close()
            with suppress(Exception):
                active_run.evidence_stream.close()
        with suppress(OSError):
            temp_dir_obj.cleanup()

    deleted = False
    if bool(delete_raw):
        raw_path.unlink(missing_ok=False)
        deleted = True

    return FinalizeResult(
        raw_path=raw_path,
        traces=list(traces),
        deleted_raw=bool(deleted),
    )
