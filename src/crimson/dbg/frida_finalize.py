from __future__ import annotations

import hashlib
import json
import math
import struct
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import BinaryIO

import msgspec

from ..game_modes import GameMode
from ..net.session_settings import session_settings_for_lockstep
from ..persistence.save_status import GameStatusData
from ..quests.level import QuestLevel
from ..replay.checkpoints import ReplayCheckpoint
from ..replay.codec import dump_replay_file
from ..replay.header_settings import replay_header_from_session_settings
from ..replay.types import Replay, ReplayCreatureSlotResidue, ReplayTick, ReplayVec2
from .canonical_channels import (
    EntitySamplesSnapshot,
    RngStreamRow,
    SimStateSnapshot,
    SnapshotBonusTimers,
    SnapshotGameplay,
    SnapshotPlayer,
    TimingSampleRow,
)
from .payloads import BuiltinObject
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
_TICK_ENCODER = msgspec.msgpack.Encoder()
_TICK_DECODER = msgspec.msgpack.Decoder(type=TickRecord)
_GAME_MODE_QUESTS = 3
# v13 samples clip_size as raw f32 bits; v14 emits the decoded value;
# v15 adds the creature pool residue snapshot on run_start rows.
_SUPPORTED_CAPTURE_FORMAT_VERSIONS = frozenset({13, 14, 15})
_POOL_RESIDUE_CAPTURE_VERSION = 15
_TRACE_CHUNK_TICKS = 256
_RUN_START_REASONS = frozenset(("run_start", "first_tick", "quest_attempt", "mode_or_stage_change"))
_RUN_END_REASONS = frozenset(("run_end", "quest_attempt", "mode_or_stage_change", "shutdown"))
_SEED_SOURCES = frozenset(("unknown", "crt_srand"))
# Replay seeds are derived from the rand state latched at run-setup entry
# (before the first terrain draw), not from the stale session-wide srand seed.
_RUN_SETUP_SEED_SOURCE = "run_setup_rng_state"
_LCG_GAP_SEARCH_LIMIT = 1 << 16


def _lcg_step_u32(state: int) -> int:
    return (state * 214013 + 2531011) & 0xFFFFFFFF


def _lcg_distance_u32(start: int, target: int, *, limit: int = _LCG_GAP_SEARCH_LIMIT) -> int | None:
    state = int(start) & 0xFFFFFFFF
    goal = int(target) & 0xFFFFFFFF
    for steps in range(limit):
        if state == goal:
            return steps
        state = _lcg_step_u32(state)
    return None
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


class _CaptureRngStreamRow(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    tick_call_index: int
    value_15: int
    state_before_u32: int
    state_after_u32: int
    caller_static: str | None = None


class _CaptureSnapshotGameplay(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    mode_id: int
    quest_stage_major: int
    quest_stage_minor: int
    perk_pending_count: int
    perk_choices_dirty: bool
    bonus_timers: SnapshotBonusTimers
    status: GameStatusData | None = None


class _CaptureSimStateSnapshot(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    gameplay: _CaptureSnapshotGameplay
    players: list[SnapshotPlayer]


class _TickChannels(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    checkpoint: ReplayCheckpoint
    sim_state: _CaptureSimStateSnapshot
    entity_samples: EntitySamplesSnapshot
    rng_stream: list[_CaptureRngStreamRow]
    timing_samples: list[TimingSampleRow]


class _SessionFingerprintRow(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    session_id: str
    ptrs_hash: str
    module_hash: str | None = None


class _SessionConfigRow(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    out_path: str
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
    flush_capture_writes: bool
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
    script_version: str
    config: _SessionConfigRow
    session_fingerprint: _SessionFingerprintRow


class _OutsideRngHeadRow(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    state_before_u32: int
    state_after_u32: int
    value_15: int | None = None
    caller_static: str | None = None


class _OutsideRngBag(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    calls: int = 0
    dropped: int = 0
    caller_counts: dict[str, int] = msgspec.field(default_factory=dict)
    head: list[_OutsideRngHeadRow] = msgspec.field(default_factory=list)


class _CaptureVec2Row(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    x: float | None = None
    y: float | None = None


class _CaptureTintRow(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    r: float | None = None
    g: float | None = None
    b: float | None = None
    a: float | None = None


class _CapturePoolResidueRow(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    index: int
    active: int | None = None
    phase_seed: float | None = None
    state_flag: int | None = None
    collision_flag: int | None = None
    collision_timer: float | None = None
    lifecycle_stage: float | None = None
    pos: _CaptureVec2Row = msgspec.field(default_factory=_CaptureVec2Row)
    vel: _CaptureVec2Row = msgspec.field(default_factory=_CaptureVec2Row)
    hp: float | None = None
    max_hp: float | None = None
    heading: float | None = None
    target_heading: float | None = None
    size: float | None = None
    hit_flash_timer: float | None = None
    tint: _CaptureTintRow = msgspec.field(default_factory=_CaptureTintRow)
    force_target: int | None = None
    target: _CaptureVec2Row = msgspec.field(default_factory=_CaptureVec2Row)
    contact_damage: float | None = None
    move_speed: float | None = None
    attack_cooldown: float | None = None
    reward_value: float | None = None
    type_id: int | None = None
    target_player: int | None = None
    link_index: int | None = None
    target_offset: _CaptureVec2Row = msgspec.field(default_factory=_CaptureVec2Row)
    orbit_angle: float | None = None
    orbit_radius_u32: int | None = None
    flags: int | None = None
    ai_mode: int | None = None
    anim_phase: float | None = None


class _RunStartRow(
    msgspec.Struct,
    frozen=True,
    forbid_unknown_fields=True,
    tag_field="event",
    tag="run_start",
):
    run_id: int
    mode_id: int
    seed: int
    player_count: int
    reason: str = "run_start"
    quest_stage_major: int = -1
    quest_stage_minor: int = -1
    seed_source: str = "unknown"
    tick_index_global: int | None = None
    rng_state_at_run_setup: int | None = None
    rng_setup_caller_static: str | None = None
    pool_residue: list[_CapturePoolResidueRow] | None = None


class _TickRow(
    msgspec.Struct,
    frozen=True,
    forbid_unknown_fields=True,
    tag_field="event",
    tag="tick",
):
    run_id: int
    elapsed_ms: int
    dt: float
    dt_ms_i32: int
    mode_id: int
    channels: _TickChannels
    tick_index_global: int | None = None
    quest_stage_major: int = -1
    quest_stage_minor: int = -1
    rng_calls: int | None = None
    rng_outside_before: _OutsideRngBag | None = None
    rng_state_enter_u32: int | None = None
    rng_state_leave_u32: int | None = None
    replay_inputs: list[tuple[float, float, float, float, int]] = msgspec.field(default_factory=list)


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
    reason: str = "run_end"
    tick_index_global: int | None = None
    rng_outside_tail: _OutsideRngBag | None = None


class _ErrorRow(
    msgspec.Struct,
    frozen=True,
    forbid_unknown_fields=True,
    tag_field="event",
    tag="error",
):
    error: str
    run_id: int | None = None
    tick_index_global: int | None = None


class _SessionEndRow(
    msgspec.Struct,
    frozen=True,
    forbid_unknown_fields=True,
    tag_field="event",
    tag="session_end",
):
    session_id: str
    ticks_written: int


type _CaptureRow = _SessionStartRow | _RunStartRow | _TickRow | _RunEndRow | _ErrorRow | _SessionEndRow


_CAPTURE_ROW_DECODER = msgspec.json.Decoder(type=_CaptureRow)


class FinalizedTrace(msgspec.Struct, frozen=True):
    run_id: int
    out_path: Path
    replay_path: Path
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
    temp_path: Path
    stream: BinaryIO
    replay_seed_source: str = "unknown"
    tick_count: int = 0
    next_local_tick: int = 0
    replay_inputs: list[list[list[float | int]]] = msgspec.field(default_factory=list)
    replay_dt: list[float] = msgspec.field(default_factory=list)
    status: GameStatusData = msgspec.field(default_factory=GameStatusData)
    global_tick_first: int | None = None
    global_tick_last: int | None = None
    rng_outside_calls: int = 0
    rng_outside_dropped: int = 0
    rng_outside_caller_counts: dict[str, int] = msgspec.field(default_factory=dict)
    rng_unhooked_in_tick: int = 0
    rng_unhooked_boundary: int = 0
    rng_unhooked_unresolved: int = 0
    rng_unhooked_gap_neighbors: dict[str, int] = msgspec.field(default_factory=dict)
    rng_setup_draw_distance: int | None = None
    rng_prev_leave_state: int | None = None
    pool_residue: tuple[ReplayCreatureSlotResidue, ...] | None = None


def _fingerprint(path: Path) -> BuiltinObject:
    stat = path.stat()
    raw = path.read_bytes()
    return {
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": int(stat.st_size),
        "mtime_ns": int(stat.st_mtime_ns),
    }


def _builtin_text(payload: BuiltinObject, key: str, default: str = "") -> str:
    value = payload.get(key)
    if value is None:
        return default
    if isinstance(value, str):
        return value
    if isinstance(value, (bool, int, float)):
        return str(value)
    return default


def _builtin_int(payload: BuiltinObject, key: str, default: int = 0) -> int:
    value = payload.get(key)
    if isinstance(value, (bool, int, float, str)):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _residue_float(value: float | None, *, field: str) -> float:
    if value is None:
        raise FridaFinalizeError(f"{field} must be a finite float in the pool residue snapshot")
    return float(value)


def _residue_int(value: int | None, *, field: str) -> int:
    if value is None:
        raise FridaFinalizeError(f"{field} must be present in the pool residue snapshot")
    return int(value)


def _residue_vec2(row: _CaptureVec2Row, *, field: str) -> ReplayVec2:
    return ReplayVec2(
        x=_residue_float(row.x, field=f"{field}.x"),
        y=_residue_float(row.y, field=f"{field}.y"),
    )


def _pool_residue_from_run_start(run_start: _RunStartRow, *, field: str) -> tuple[ReplayCreatureSlotResidue, ...]:
    rows = run_start.pool_residue
    if rows is None:
        raise FridaFinalizeError(f"{field}.pool_residue is required for capture v15 run_start rows")
    out: list[ReplayCreatureSlotResidue] = []
    for i, row in enumerate(rows):
        slot_field = f"{field}.pool_residue[{i}]"
        if int(row.index) != i:
            raise FridaFinalizeError(f"{slot_field}.index={int(row.index)} does not match slot {i}")
        if _residue_int(row.active, field=f"{slot_field}.active") != 0:
            raise FridaFinalizeError(
                f"{slot_field} is active at run start; creature_reset_all must have run before the latch",
            )
        out.append(
            ReplayCreatureSlotResidue(
                index=i,
                phase_seed=_residue_float(row.phase_seed, field=f"{slot_field}.phase_seed"),
                state_flag=_residue_int(row.state_flag, field=f"{slot_field}.state_flag"),
                collision_flag=_residue_int(row.collision_flag, field=f"{slot_field}.collision_flag"),
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
                force_target=_residue_int(row.force_target, field=f"{slot_field}.force_target"),
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
                orbit_radius_u32=_residue_int(row.orbit_radius_u32, field=f"{slot_field}.orbit_radius_u32"),
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
    # v13 sessions predate unlimited defaults for the diagnostic streams; from
    # v14 on they must be complete too (outside-tick rng head fed the per-frame
    # burn forensics, creature delta ids feed lifecycle digests).
    if int(session_row.capture_format_version) >= 14:
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


def _decode_clip_size_raw_bits(value: int, *, field: str) -> int:
    """Decode a v13 `clip_size` sample into the integral clip size.

    The native player struct stores clip_size as f32 and the v13 capture
    script samples it with a 32-bit integer read, so the wire value is the
    raw bit pattern (e.g. 1092616192 == 10.0f)."""

    bits = int(value) & 0xFFFFFFFF
    decoded = struct.unpack("<f", struct.pack("<I", bits))[0]
    if not math.isfinite(decoded) or not (0.0 <= decoded <= 10000.0):
        raise FridaFinalizeError(f"{field} is not a plausible f32 clip_size bit pattern: {int(value)}")
    rounded = round(decoded)
    if abs(decoded - rounded) > 1e-3:
        raise FridaFinalizeError(f"{field} decodes to a non-integral clip_size: {decoded!r}")
    return int(rounded)


def _normalized_capture_player(player: SnapshotPlayer, *, clip_size_raw_bits: bool, field: str) -> SnapshotPlayer:
    if not clip_size_raw_bits:
        return player
    weapon = msgspec.structs.replace(
        player.weapon,
        clip_size=_decode_clip_size_raw_bits(player.weapon.clip_size, field=f"{field}.weapon.clip_size"),
    )
    return msgspec.structs.replace(player, weapon=weapon)


def _decode_capture_row(line: bytes, *, field: str) -> _CaptureRow:
    try:
        return _CAPTURE_ROW_DECODER.decode(line)
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise FridaFinalizeError(f"{field} invalid capture row: {exc}") from exc


def _canonical_channels_payload(
    *,
    channels: _TickChannels,
    local_tick: int,
    clip_size_raw_bits: bool,
    field: str,
) -> tuple[ReplayCheckpoint, ReplayTickChannels]:
    checkpoint = msgspec.structs.replace(channels.checkpoint, tick_index=int(local_tick))
    rng_stream = [
        RngStreamRow(
            tick_call_index=int(row.tick_call_index),
            value_15=int(row.value_15),
            state_before_u32=int(row.state_before_u32),
            state_after_u32=int(row.state_after_u32),
            caller=(
                None
                if row.caller_static is None
                else _caller_from_capture(
                    row.caller_static,
                    field=f"{field}.rng_stream[{idx}].caller_static",
                )
            ),
        )
        for idx, row in enumerate(channels.rng_stream)
    ]
    # Capture timing rows carry session-global tick/frame counters and a null
    # mode_fn (the gpur_enter sample is built before any mode hook fires);
    # rebase them to the run-local domain the rewrite recorder emits so the
    # timing channel is comparable. `frame_dt_ms_f32` is recomputed from the
    # i32 sample: the native global is an i32 and the v13 capture script reads
    # it with a float read, leaving a denormal bit pattern on the wire.
    timing_samples = [
        msgspec.structs.replace(
            row,
            tick_index=int(local_tick),
            gameplay_frame=(None if row.gameplay_frame is None else int(local_tick)),
            mode_fn=(
                "gameplay_update_and_render"
                if row.mode_fn is None and row.phase == "gpur_enter"
                else row.mode_fn
            ),
            frame_dt_ms_f32=(
                row.frame_dt_ms_f32 if row.frame_dt_ms_i32 is None else float(int(row.frame_dt_ms_i32))
            ),
        )
        for row in channels.timing_samples
    ]
    normalized = _TickChannels(
        checkpoint=checkpoint,
        sim_state=channels.sim_state,
        entity_samples=channels.entity_samples,
        rng_stream=list(channels.rng_stream),
        timing_samples=timing_samples,
    )
    gameplay = normalized.sim_state.gameplay
    # Outside quest mode the native quest_stage globals are sticky menu
    # residue (whatever quest the menu last selected), not run state; the
    # canonical channel zeroes them like the rewrite does.
    in_quest = int(gameplay.mode_id) == _GAME_MODE_QUESTS
    return checkpoint, ReplayTickChannels(
        checkpoint=normalized.checkpoint,
        sim_state=SimStateSnapshot(
            gameplay=SnapshotGameplay(
                mode_id=int(gameplay.mode_id),
                quest_stage_major=(int(gameplay.quest_stage_major) if in_quest else 0),
                quest_stage_minor=(int(gameplay.quest_stage_minor) if in_quest else 0),
                perk_pending_count=int(gameplay.perk_pending_count),
                perk_choices_dirty=bool(gameplay.perk_choices_dirty),
                bonus_timers=gameplay.bonus_timers,
            ),
            players=[
                _normalized_capture_player(
                    player,
                    clip_size_raw_bits=clip_size_raw_bits,
                    field=f"{field}.sim_state.players[{idx}]",
                )
                for idx, player in enumerate(normalized.sim_state.players)
            ],
        ),
        entity_samples=normalized.entity_samples,
        rng_stream=rng_stream,
        timing_samples=list(normalized.timing_samples),
    )


def _caller_from_capture(value: str, *, field: str) -> int:
    text = value
    if not text.lower().startswith("0x"):
        raise FridaFinalizeError(f"{field} must be a 0x-prefixed hex string")
    try:
        caller = int(text, 16)
    except ValueError as exc:
        raise FridaFinalizeError(f"{field} invalid hex value: {text!r}") from exc
    if not (0 <= caller <= 0xFFFFFFFF):
        raise FridaFinalizeError(f"{field} must decode to a uint32")
    return caller


def _replay_tick_inputs_from_row(
    replay_inputs: list[tuple[float, float, float, float, int]],
    *,
    expected_players: int,
    field: str,
) -> list[list[float | int]]:
    if len(replay_inputs) != int(expected_players):
        raise FridaFinalizeError(
            f"{field} must contain {int(expected_players)} player rows, got {len(replay_inputs)}",
    )
    out: list[list[float | int]] = []
    for player_index, (move_x, move_y, aim_x, aim_y, flags) in enumerate(replay_inputs):
        player_field = f"{field}[{player_index}]"
        scalars = (
            ("move_x", move_x),
            ("move_y", move_y),
            ("aim_x", aim_x),
            ("aim_y", aim_y),
        )
        for scalar_name, scalar_value in scalars:
            if not math.isfinite(float(scalar_value)):
                raise FridaFinalizeError(f"{player_field}.{scalar_name} must be finite")
        out.append([float(move_x), float(move_y), float(aim_x), float(aim_y), int(flags)])
    return out


def _validate_tick_channels(
    *,
    channels: _TickChannels,
    expected_players: int,
    elapsed_ms: int,
    dt: float,
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
    gameplay = channels.sim_state.gameplay
    if int(gameplay.mode_id) != int(mode_id):
        raise FridaFinalizeError(
            f"{field}.sim_state.gameplay.mode_id={int(gameplay.mode_id)} "
            f"does not match tick.mode_id {int(mode_id)}",
        )
    if int(gameplay.quest_stage_major) != int(quest_stage_major):
        raise FridaFinalizeError(
            f"{field}.sim_state.gameplay.quest_stage_major={int(gameplay.quest_stage_major)} "
            f"does not match tick.quest_stage_major {int(quest_stage_major)}",
        )
    if int(gameplay.quest_stage_minor) != int(quest_stage_minor):
        raise FridaFinalizeError(
            f"{field}.sim_state.gameplay.quest_stage_minor={int(gameplay.quest_stage_minor)} "
            f"does not match tick.quest_stage_minor {int(quest_stage_minor)}",
        )
    timing_samples = list(channels.timing_samples)
    if len(timing_samples) <= 0:
        raise FridaFinalizeError(f"{field}.timing_samples must be non-empty")
    for sample_index, sample in enumerate(timing_samples):
        if not str(sample.phase):
            raise FridaFinalizeError(f"{field}.timing_samples[{sample_index}].phase must be non-empty")
        if not str(sample.write_kind):
            raise FridaFinalizeError(f"{field}.timing_samples[{sample_index}].write_kind must be non-empty")
    gpur_enter = next((sample for sample in timing_samples if str(sample.phase) == "gpur_enter"), None)
    if gpur_enter is None:
        raise FridaFinalizeError(f"{field}.timing_samples must include phase `gpur_enter`")
    if gpur_enter.frame_dt_f32 is None or not math.isfinite(float(gpur_enter.frame_dt_f32)):
        raise FridaFinalizeError(f"{field}.timing_samples.gpur_enter.frame_dt_f32 must be finite")
    if gpur_enter.frame_dt_ms_i32 is None:
        raise FridaFinalizeError(f"{field}.timing_samples.gpur_enter.frame_dt_ms_i32 must be present")
    if int(gpur_enter.frame_dt_ms_i32) < 0:
        raise FridaFinalizeError(f"{field}.timing_samples.gpur_enter.frame_dt_ms_i32 must be >= 0")
    if float(gpur_enter.frame_dt_f32) != float(dt):
        raise FridaFinalizeError(
            f"{field}.timing_samples.gpur_enter.frame_dt_f32={float(gpur_enter.frame_dt_f32)} "
            f"does not match tick.dt {float(dt)}",
        )
    if int(gpur_enter.frame_dt_ms_i32) != int(dt_ms_i32):
        raise FridaFinalizeError(
            f"{field}.timing_samples.gpur_enter.frame_dt_ms_i32={int(gpur_enter.frame_dt_ms_i32)} "
            f"does not match tick.dt_ms_i32 {int(dt_ms_i32)}",
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
    is_quest_run = (
        int(mode_id) == int(_GAME_MODE_QUESTS)
        and int(quest_stage_major) > 0
        and int(quest_stage_minor) > 0
    )
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
    raw_fingerprint: BuiltinObject,
    session_start: _SessionStartRow,
    run: _OpenRun,
    tick_count: int,
) -> TraceMeta:
    producer_platform = str(session_start.platform)
    producer_arch = str(session_start.arch)
    producer_impl_version = str(session_start.script_version)
    tick_end = int(tick_count) - 1
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
            path=_builtin_text(raw_fingerprint, "path"),
            sha256=_builtin_text(raw_fingerprint, "sha256"),
            size=_builtin_int(raw_fingerprint, "size"),
            mtime_ns=_builtin_int(raw_fingerprint, "mtime_ns"),
            mode_id=int(run.mode_id),
            seed=int(run.replay_seed),
            run_id=int(run.run_id),
            quest_stage_major=int(run.quest_stage_major),
            quest_stage_minor=int(run.quest_stage_minor),
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
    """Track rand draws the crt_rand hook never observed.

    Real memory states (gpur enter/leave plus per-call state_before) expose
    unhooked draws as LCG chain gaps; the per-caller counts say which hooked
    callers bracket each gap so the report points at what the port misses.
    """
    bag = tick_row.rng_outside_before
    if (
        tick_row.rng_calls is None
        or bag is None
        or tick_row.rng_state_enter_u32 is None
        or tick_row.rng_state_leave_u32 is None
    ):
        raise FridaFinalizeError(
            f"{field} must carry rng accounting "
            "(rng_calls, rng_outside_before, rng_state_enter_u32, rng_state_leave_u32)",
        )
    if int(tick_row.rng_calls) != len(rng_stream):
        raise FridaFinalizeError(
            f"{field}.rng_calls={int(tick_row.rng_calls)} does not match rng_stream length {len(rng_stream)}",
        )
    enter = int(tick_row.rng_state_enter_u32)
    leave = int(tick_row.rng_state_leave_u32)
    _merge_outside_rng_bag(run, bag)

    if run.rng_prev_leave_state is None:
        # First tick of the run: the distance from the replay seed (run-setup
        # rand state) to gpur enter is the run's setup draw count.
        run.rng_setup_draw_distance = _lcg_distance_u32(int(run.replay_seed), enter)
    else:
        # Between gpur windows: hooked outside draws are counted in the bag;
        # any excess chain distance is unhooked draws.
        total = _lcg_distance_u32(run.rng_prev_leave_state, enter)
        if total is None:
            run.rng_unhooked_unresolved += 1
        else:
            unhooked = total - int(bag.calls)
            if unhooked < 0:
                run.rng_unhooked_unresolved += 1
            else:
                run.rng_unhooked_boundary += unhooked

    prev = enter
    for row in rng_stream:
        gap = _lcg_distance_u32(prev, int(row.state_before_u32))
        if gap is None:
            run.rng_unhooked_unresolved += 1
        elif gap > 0:
            run.rng_unhooked_in_tick += gap
            neighbor = "unknown" if row.caller is None else f"0x{int(row.caller):08x}"
            run.rng_unhooked_gap_neighbors[neighbor] = run.rng_unhooked_gap_neighbors.get(neighbor, 0) + gap
        prev = int(row.state_after_u32)
    tail_gap = _lcg_distance_u32(prev, leave)
    if tail_gap is None:
        run.rng_unhooked_unresolved += 1
    elif tail_gap > 0:
        run.rng_unhooked_in_tick += tail_gap
        run.rng_unhooked_gap_neighbors["tick_tail"] = (
            run.rng_unhooked_gap_neighbors.get("tick_tail", 0) + tail_gap
        )
    run.rng_prev_leave_state = leave


def _write_rng_evidence_report(out_path: Path, run: _OpenRun) -> None:
    report = {
        "run_id": int(run.run_id),
        "mode_id": int(run.mode_id),
        "replay_seed": int(run.replay_seed),
        "setup_draw_distance": run.rng_setup_draw_distance,
        "outside_calls": int(run.rng_outside_calls),
        "outside_dropped": int(run.rng_outside_dropped),
        "outside_caller_counts": dict(
            sorted(run.rng_outside_caller_counts.items(), key=lambda kv: -kv[1]),
        ),
        "unhooked_in_tick": int(run.rng_unhooked_in_tick),
        "unhooked_boundary": int(run.rng_unhooked_boundary),
        "unhooked_unresolved": int(run.rng_unhooked_unresolved),
        "unhooked_gap_neighbors": dict(
            sorted(run.rng_unhooked_gap_neighbors.items(), key=lambda kv: -kv[1]),
        ),
    }
    evidence_path = Path(out_path).with_suffix(".rng_evidence.json")
    evidence_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def _write_run_trace(
    *,
    raw_path: Path,
    output_dir: Path,
    raw_fingerprint: BuiltinObject,
    session_start: _SessionStartRow,
    run: _OpenRun,
    counters: dict[str, int],
) -> FinalizedTrace:
    run.stream.flush()
    run.stream.close()
    if int(run.replay_player_count) <= 0:
        raise FridaFinalizeError(f"run {run.run_id}: invalid replay player_count={run.replay_player_count}")
    if len(run.replay_inputs) != int(run.tick_count):
        raise FridaFinalizeError(
            f"run {run.run_id}: replay_inputs count {len(run.replay_inputs)} does not match tick_count {run.tick_count}",
        )
    if len(run.replay_dt) != int(run.tick_count):
        raise FridaFinalizeError(
            f"run {run.run_id}: replay_dt count {len(run.replay_dt)} "
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
    meta = _build_meta(
        raw_fingerprint=raw_fingerprint,
        session_start=session_start,
        run=run,
        tick_count=int(run.tick_count),
    )
    summary = write_trace_iter(
        out_path,
        meta=meta,
        ticks=_tick_iter_from_spool(run.temp_path),
        chunk_ticks=_TRACE_CHUNK_TICKS,
    )
    replay_path = Path(out_path).with_suffix(".crd")
    is_quest_run = (
        int(run.mode_id) == int(_GAME_MODE_QUESTS)
        and int(run.quest_stage_major) > 0
        and int(run.quest_stage_minor) > 0
    )
    settings = session_settings_for_lockstep(
        mode_id=GameMode(int(run.mode_id)),
        player_count=int(run.replay_player_count),
        quest_level=(
            QuestLevel(int(run.quest_stage_major), int(run.quest_stage_minor))
            if is_quest_run
            else None
        ),
        preserve_bugs=False,
    )
    replay_header = replay_header_from_session_settings(
        settings,
        seed=int(run.replay_seed),
        status=run.status,
    )
    if run.pool_residue is not None:
        replay_header = msgspec.structs.replace(
            replay_header,
            initial_creature_pool=run.pool_residue,
        )
    replay_ticks = [
        ReplayTick(
            inputs=run.replay_inputs[i],
            dt=run.replay_dt[i],
        )
        for i in range(run.tick_count)
    ]
    dump_replay_file(
        replay_path,
        Replay(header=replay_header, ticks=replay_ticks),
    )
    _write_rng_evidence_report(out_path, run)
    return FinalizedTrace(
        run_id=int(run.run_id),
        out_path=Path(out_path),
        replay_path=Path(replay_path),
        tick_count=int(run.tick_count),
        mode_id=int(run.mode_id),
        quest_stage_major=int(run.quest_stage_major),
        quest_stage_minor=int(run.quest_stage_minor),
        summary=summary,
    )


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
    session_ended = False
    active_run: _OpenRun | None = None
    captured_tick_count = 0

    temp_dir_obj = TemporaryDirectory(prefix="crimson-frida-finalize-")
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
                        if int(session_row.capture_format_version) not in _SUPPORTED_CAPTURE_FORMAT_VERSIONS:
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}] unsupported capture_format_version="
                                f"{int(session_row.capture_format_version)}; "
                                f"expected one of {sorted(_SUPPORTED_CAPTURE_FORMAT_VERSIONS)}",
                            )
                        if not str(session_row.session_id):
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].session_id must be non-empty")
                        if not str(session_row.out_path):
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].out_path must be non-empty")
                        if not str(session_row.platform):
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].platform must be non-empty")
                        if not str(session_row.arch):
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].arch must be non-empty")
                        if not str(session_row.script_version):
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].script_version must be non-empty")
                        if str(session_row.config.out_path) != str(session_row.out_path):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].config.out_path must match out_path",
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
                        if str(run_start.reason) not in _RUN_START_REASONS:
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].reason must be one of {sorted(_RUN_START_REASONS)!r}",
                            )
                        if str(run_start.seed_source) not in _SEED_SOURCES:
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].seed_source must be one of {sorted(_SEED_SOURCES)!r}",
                            )
                        mode_id = int(run_start.mode_id)
                        if int(run_start.seed) < 0:
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].seed must be >= 0")
                        if int(run_start.player_count) <= 0:
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}].player_count must be positive")
                        # The session srand seed is stale by run start (menus and
                        # earlier runs already consumed draws); the rand state
                        # latched at run-setup entry is the replayable seed.
                        if run_start.rng_state_at_run_setup is None:
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].rng_state_at_run_setup is required for replay seeding",
                            )
                        if not (0 <= int(run_start.rng_state_at_run_setup) <= 0xFFFFFFFF):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].rng_state_at_run_setup must be u32",
                            )
                        pool_residue: tuple[ReplayCreatureSlotResidue, ...] | None = None
                        if int(session_start.capture_format_version) >= _POOL_RESIDUE_CAPTURE_VERSION:
                            pool_residue = _pool_residue_from_run_start(
                                run_start,
                                field=f"{raw_path}.lines[{line_no}]",
                            )
                        spool_path = temp_root / f"run_{int(run_start.run_id)}.ticks"
                        active_run = _OpenRun(
                            run_id=int(run_start.run_id),
                            mode_id=mode_id,
                            quest_stage_major=int(run_start.quest_stage_major),
                            quest_stage_minor=int(run_start.quest_stage_minor),
                            replay_seed=int(run_start.rng_state_at_run_setup),
                            replay_player_count=int(run_start.player_count),
                            temp_path=spool_path,
                            stream=spool_path.open("wb"),
                            replay_seed_source=_RUN_SETUP_SEED_SOURCE,
                            pool_residue=pool_residue,
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
                        if not math.isfinite(float(tick_row.dt)) or float(tick_row.dt) < 0.0:
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].dt must be finite and >= 0",
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
                            elapsed_ms=int(tick_row.elapsed_ms),
                            dt=float(tick_row.dt),
                            dt_ms_i32=int(tick_row.dt_ms_i32),
                            mode_id=int(tick_row.mode_id),
                            quest_stage_major=int(tick_row.quest_stage_major),
                            quest_stage_minor=int(tick_row.quest_stage_minor),
                            field=f"{raw_path}.lines[{line_no}].channels",
                        )
                        replay_inputs = _replay_tick_inputs_from_row(
                            tick_row.replay_inputs,
                            expected_players=int(active_run.replay_player_count),
                            field=f"{raw_path}.lines[{line_no}].replay_inputs",
                        )
                        _checkpoint, channels = _canonical_channels_payload(
                            channels=tick_row.channels,
                            local_tick=int(active_run.next_local_tick),
                            clip_size_raw_bits=(int(session_start.capture_format_version) == 13),
                            field=f"{raw_path}.lines[{line_no}].channels",
                        )
                        _account_tick_rng_evidence(
                            active_run,
                            tick_row=tick_row,
                            rng_stream=channels.rng_stream,
                            field=f"{raw_path}.lines[{line_no}]",
                        )
                        if int(active_run.tick_count) == 0 and tick_row.channels.sim_state.gameplay.status is not None:
                            active_run.status = tick_row.channels.sim_state.gameplay.status
                        active_run.replay_inputs.append(list(replay_inputs))
                        active_run.replay_dt.append(float(tick_row.dt))
                        tick = TickRecord(
                            tick_index=int(active_run.next_local_tick),
                            elapsed_ms=int(tick_row.elapsed_ms),
                            dt_ms_i32=int(tick_row.dt_ms_i32),
                            mode_id=int(tick_row.mode_id),
                            channels=channels,
                        )
                        payload = _TICK_ENCODER.encode(tick)
                        active_run.stream.write(len(payload).to_bytes(_FRAME_LEN_BYTES, "little", signed=False))
                        active_run.stream.write(payload)
                        active_run.next_local_tick += 1
                        active_run.tick_count += 1
                        captured_tick_count += 1
                        if tick_row.tick_index_global is not None:
                            global_tick = int(tick_row.tick_index_global)
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
                        if run_end.rng_outside_tail is None:
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].rng_outside_tail is required",
                            )
                        _merge_outside_rng_bag(active_run, run_end.rng_outside_tail)
                        traces.append(
                            _write_run_trace(
                                raw_path=raw_path,
                                output_dir=output_root,
                                raw_fingerprint=raw_fingerprint,
                                session_start=session_start,
                                run=active_run,
                                counters=run_counters,
                            ),
                        )
                        active_run = None
                        continue
                    case _ErrorRow() as error_row:
                        location = f"{raw_path}.lines[{line_no}]"
                        if error_row.tick_index_global is None:
                            raise FridaFinalizeError(f"{location} capture error={error_row.error!r}")
                        raise FridaFinalizeError(
                            f"{location} capture error={error_row.error!r} "
                            f"tick_index_global={int(error_row.tick_index_global)}",
                        )
                    case _SessionEndRow():
                        if active_run is not None:
                            raise FridaFinalizeError(f"{raw_path}.lines[{line_no}] session_end while run is active")
                        if str(row.session_id) != str(session_start.session_id):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].session_id must match session_start.session_id",
                            )
                        if int(row.ticks_written) != int(captured_tick_count):
                            raise FridaFinalizeError(
                                f"{raw_path}.lines[{line_no}].ticks_written={int(row.ticks_written)} "
                                f"does not match parsed tick_count {int(captured_tick_count)}",
                            )
                        session_ended = True
                        continue
                    case _:
                        raise FridaFinalizeError(f"{raw_path}.lines[{line_no}] unsupported capture row")

        if session_start is None:
            raise FridaFinalizeError(f"{raw_path} missing session_start")
        if active_run is not None:
            # Allow abrupt host/process shutdown to still produce a usable run.
            # We already validated all parsed rows and can finalize the in-flight spool.
            traces.append(
                _write_run_trace(
                    raw_path=raw_path,
                    output_dir=output_root,
                    raw_fingerprint=raw_fingerprint,
                    session_start=session_start,
                    run=active_run,
                    counters=run_counters,
                ),
            )
            active_run = None
        if not session_ended and not traces:
            raise FridaFinalizeError(f"{raw_path} missing session_end")
        if not traces:
            raise FridaFinalizeError(f"{raw_path} had no finalized runs")
    finally:
        if active_run is not None:
            with suppress(Exception):
                active_run.stream.close()
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
