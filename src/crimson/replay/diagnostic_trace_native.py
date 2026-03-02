from __future__ import annotations

import struct
from pathlib import Path

import msgspec

REPLAY_TICK_TRACE_SCHEMA_VERSION = 6
REPLAY_TICK_TRACE_MSGPACK_MAGIC = b"crimson_replay_tick_trace_msgpack_v3\n"

_ROW_LEN_STRUCT = struct.Struct("<I")


class ReplayTickTraceTiming(msgspec.Struct):
    elapsed_ms: int


class ReplayTickRng(msgspec.Struct):
    rng_state: int
    rng_after_perk_effects: int
    rng_after_creatures: int
    rng_after_projectiles: int
    rng_after_secondary_projectiles: int
    rng_after_particles: int
    rng_after_player_update: int
    rng_after_stage_spawns: int
    rng_after_wave_spawns: int
    rng_after_spawns: int
    rng_after_bonus_update: int


class ReplayTickTraceSummary(msgspec.Struct):
    score_xp: int
    kills: int
    shots_fired_p0: int
    creature_count: int
    perk_pending: int


class ReplayTickTraceVec2(msgspec.Struct):
    x: float
    y: float


class ReplayTickTraceWeaponState(msgspec.Struct):
    weapon_id: int | str
    ammo: float
    clip_size: int = 0
    reload_active: bool = False
    reload_timer: float = 0.0
    reload_timer_max: float = 0.0
    shot_cooldown: float = 0.0


class ReplayTickTracePlayerState(msgspec.Struct):
    index: int
    pos: ReplayTickTraceVec2
    health: float
    weapon: ReplayTickTraceWeaponState
    experience: int
    level: int


class ReplayTickTracePerkSelection(msgspec.Struct):
    pending_count: int = 0


class ReplayTickTraceBonusTimers(msgspec.Struct):
    weapon_power_up: float = 0.0
    reflex_boost: float = 0.0
    energizer: float = 0.0
    double_experience: float = 0.0
    freeze: float = 0.0


class ReplayTickTraceGameplayState(msgspec.Struct):
    bonuses: ReplayTickTraceBonusTimers
    perk_selection: ReplayTickTracePerkSelection
    pending_nuke_count: int = 0
    debug_nuke_kills_last: int = 0
    debug_nuke_tick_last: int = 0
    debug_nuke_kill_index_sum: int = 0
    debug_last_picked_bonus_id: int = 0
    debug_last_picked_bonus_amount: int = 0


class ReplayTickTraceCreatureSample(msgspec.Struct):
    index: int
    type_id: int
    hp: float
    pos: ReplayTickTraceVec2
    flags: int
    ai_mode: int
    link_index: int
    heading: float
    target_heading: float
    orbit_angle: float
    orbit_radius: float
    lifecycle_stage: float


class ReplayTickTraceProjectileSample(msgspec.Struct):
    index: int
    type_id: int
    angle: float
    pos: ReplayTickTraceVec2
    vel: ReplayTickTraceVec2
    life_timer: float
    speed_scale: float
    damage_pool: float
    hit_radius: float
    travel_budget: float
    owner_id: int


class ReplayTickTraceSecondaryProjectileSample(msgspec.Struct):
    index: int
    type_id: int
    angle: float
    pos: ReplayTickTraceVec2
    vel: ReplayTickTraceVec2
    speed: float
    trail_timer: float
    owner_id: int
    target_id: int


class ReplayTickTraceBonusSample(msgspec.Struct):
    index: int
    bonus_id: int
    picked: bool
    time_left: float
    time_max: float
    pos: ReplayTickTraceVec2
    amount: int


class ReplayTickTraceEntitySamples(msgspec.Struct):
    creatures: list[ReplayTickTraceCreatureSample] = msgspec.field(default_factory=list)
    projectiles: list[ReplayTickTraceProjectileSample] = msgspec.field(default_factory=list)
    secondary_projectiles: list[ReplayTickTraceSecondaryProjectileSample] = msgspec.field(default_factory=list)
    bonuses: list[ReplayTickTraceBonusSample] = msgspec.field(default_factory=list)


class ReplayTickTraceRow(msgspec.Struct):
    schema_version: int
    tick_index: int
    timing: ReplayTickTraceTiming
    rng: ReplayTickRng
    summary: ReplayTickTraceSummary
    gameplay_state: ReplayTickTraceGameplayState
    player_state: ReplayTickTracePlayerState
    entities: ReplayTickTraceEntitySamples = msgspec.field(default_factory=ReplayTickTraceEntitySamples)


_ROW_DECODER = msgspec.msgpack.Decoder(type=ReplayTickTraceRow)


def decode_replay_tick_trace_msgpack_row(payload: bytes, *, field: str) -> ReplayTickTraceRow:
    try:
        row = _ROW_DECODER.decode(payload)
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise ValueError(f"{field} must be a valid replay tick trace v6 msgpack row") from exc
    if int(row.schema_version) != int(REPLAY_TICK_TRACE_SCHEMA_VERSION):
        raise ValueError(
            f"{field}.schema_version must be {int(REPLAY_TICK_TRACE_SCHEMA_VERSION)}, got {int(row.schema_version)}",
        )
    return row


def decode_replay_tick_trace_msgpack_stream_bytes(data: bytes, *, field: str) -> list[ReplayTickTraceRow]:
    raw = bytes(data)
    if not raw.startswith(REPLAY_TICK_TRACE_MSGPACK_MAGIC):
        raise ValueError(f"{field} has invalid trace msgpack magic")
    offset = len(REPLAY_TICK_TRACE_MSGPACK_MAGIC)
    rows: list[ReplayTickTraceRow] = []
    row_index = 0
    while offset < len(raw):
        if (len(raw) - offset) < _ROW_LEN_STRUCT.size:
            raise ValueError(f"{field} has truncated row length prefix at offset {offset}")
        (row_len,) = _ROW_LEN_STRUCT.unpack_from(raw, offset)
        offset += _ROW_LEN_STRUCT.size
        if int(row_len) <= 0:
            raise ValueError(f"{field} has invalid row length {int(row_len)}")
        end = offset + int(row_len)
        if end > len(raw):
            raise ValueError(f"{field} has truncated row payload at index {row_index}")
        payload = raw[offset:end]
        offset = end
        rows.append(
            decode_replay_tick_trace_msgpack_row(
                payload,
                field=f"{field}.rows[{row_index}]",
            ),
        )
        row_index += 1
    return rows


def decode_replay_tick_trace_msgpack_stream(path: Path) -> list[ReplayTickTraceRow]:
    payload = Path(path).read_bytes()
    return decode_replay_tick_trace_msgpack_stream_bytes(payload, field=str(path))
