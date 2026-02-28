from __future__ import annotations

import struct
from pathlib import Path
from typing import TypeAlias

import msgspec

from ..bonuses.ids import BonusId
from ..perks.ids import PerkId

REPLAY_TICK_TRACE_SCHEMA_VERSION = 6
REPLAY_TICK_TRACE_MSGPACK_MAGIC = b"crimson_replay_tick_trace_msgpack_v3\n"
PERK_COUNT_SIZE = len(PerkId)
BONUS_ID_COUNT = len(BonusId)
ReplayTickTraceJsonRow: TypeAlias = dict[str, object]

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


class ReplayTickTraceRow(msgspec.Struct):
    schema_version: int
    tick_index: int
    timing: ReplayTickTraceTiming
    rng: ReplayTickRng
    summary: ReplayTickTraceSummary
    gameplay_state: ReplayTickTraceGameplayState
    player_state: ReplayTickTracePlayerState


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


def decode_replay_tick_trace_json_row(payload: object, *, field: str) -> ReplayTickTraceJsonRow:
    if not isinstance(payload, dict):
        raise TypeError(f"{field} must be a JSON object")
    out: dict[str, object] = {}
    for key, value in payload.items():
        if not isinstance(key, str):
            raise TypeError(f"{field} contains non-string key")
        out[key] = value
    return out


def decode_replay_tick_trace_jsonl(path: Path) -> list[ReplayTickTraceJsonRow]:
    rows: list[ReplayTickTraceJsonRow] = []
    raw_lines = Path(path).read_text(encoding="utf-8").splitlines()
    for idx, line in enumerate(raw_lines):
        line = str(line).strip()
        if not line:
            continue
        try:
            payload = msgspec.json.decode(line)
        except msgspec.DecodeError as exc:
            raise ValueError(f"{path}.lines[{idx}] must be valid json") from exc
        rows.append(
            decode_replay_tick_trace_json_row(
                payload,
                field=f"{path}.lines[{idx}]",
            ),
        )
    return rows
