from __future__ import annotations

import struct
from collections.abc import Sequence
from pathlib import Path

import msgspec

from ..bonuses.ids import BonusId
from ..perks.ids import PerkId

REPLAY_TICK_TRACE_SCHEMA_VERSION = 4
REPLAY_TICK_TRACE_MSGPACK_MAGIC = b"crimson_replay_tick_trace_msgpack_v2\n"
PERK_COUNT_SIZE = len(PerkId)
BONUS_ID_COUNT = len(BonusId)

_ROW_LEN_STRUCT = struct.Struct("<I")
_ROW_ENCODER = msgspec.msgpack.Encoder()


class ProjectileTraceEntry(msgspec.Struct, forbid_unknown_fields=True):
    index: int
    type_id: int
    pos_x: float
    pos_y: float
    origin_x: float
    origin_y: float
    life_timer: float
    damage_pool: float
    angle: float
    speed_scale: float
    owner_legacy: int
    hits_players: bool


class CreatureTraceEntry(msgspec.Struct, forbid_unknown_fields=True):
    index: int
    type_id: int
    flags: int
    ai_mode: int
    link_index: int
    pos_x: float
    pos_y: float
    target_x: float
    target_y: float
    heading: float
    target_heading: float
    hp: float
    lifecycle_stage: float
    size: float
    attack_cooldown: float


class BonusActiveEntry(msgspec.Struct, forbid_unknown_fields=True):
    bonus_id: int
    amount: int


class ProjectileTypeCountEntry(msgspec.Struct, forbid_unknown_fields=True):
    type_id: int
    count: int


class ReplayTickTiming(msgspec.Struct, forbid_unknown_fields=True):
    elapsed_ms: int


class ReplayTickRng(msgspec.Struct, forbid_unknown_fields=True):
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


class ReplayTickSummary(msgspec.Struct, forbid_unknown_fields=True):
    score_xp: int
    kills: int
    shots_fired_p0: int
    creature_count: int
    perk_pending: int


class ReplayTickPlayer(msgspec.Struct, forbid_unknown_fields=True):
    player_weapon_id: int
    player_ammo: float
    player_health: float
    player_pos_x: float
    player_pos_y: float
    player_aim_x: float
    player_aim_y: float
    player_heading: float
    player_aim_heading: float
    player_move_speed: float
    player_turn_speed: float
    player_level: int
    player_experience: int
    player_reload_active: bool
    player_reload_timer: float
    player_shot_cooldown: float
    player_shot_seq: int
    player_perk_counts: list[int]
    player_hot_tempered_timer: float
    player_shield_timer: float
    player_man_bomb_timer: float
    player_fire_cough_timer: float
    player_living_fortress_timer: float
    perk_interval_hot_tempered: float
    perk_interval_man_bomb: float
    perk_interval_fire_cough: float


class ReplayTickBonuses(msgspec.Struct, forbid_unknown_fields=True):
    bonus_timer_ms_by_id: list[int]
    bonus_active_count: int
    active_entries: list[BonusActiveEntry]


class ReplayTickProjectiles(msgspec.Struct, forbid_unknown_fields=True):
    projectile_count: int
    projectile_hit_count: int
    projectile_first_hit_creature_index: int
    projectile_first_hit_projectile_index: int
    projectile_first_hit_type_id: int
    projectile_first_hit_origin_x: float
    projectile_first_hit_origin_y: float
    projectile_first_hit_pos_x: float
    projectile_first_hit_pos_y: float
    projectile_first_hit_target_size: float
    projectile_first_hit_target_x: float
    projectile_first_hit_target_y: float
    projectile_type_counts: list[ProjectileTypeCountEntry]
    entries: list[ProjectileTraceEntry]


class ReplayTickCreatures(msgspec.Struct, forbid_unknown_fields=True):
    entries: list[CreatureTraceEntry]


class ReplayTickDebug(msgspec.Struct, forbid_unknown_fields=True):
    debug_pending_nuke: int
    debug_nuke_kills_last: int
    debug_nuke_tick_last: int
    debug_nuke_kill_index_sum: int
    debug_last_picked_bonus_id: int
    debug_last_picked_bonus_amount: int


class ReplayTickTraceRow(msgspec.Struct, forbid_unknown_fields=True):
    schema_version: int
    tick_index: int
    timing: ReplayTickTiming
    rng: ReplayTickRng
    summary: ReplayTickSummary
    player: ReplayTickPlayer
    bonuses: ReplayTickBonuses
    projectiles: ReplayTickProjectiles
    creatures: ReplayTickCreatures
    debug: ReplayTickDebug


_ROW_DECODER = msgspec.msgpack.Decoder(type=ReplayTickTraceRow)

def _validate_trace_row(row: ReplayTickTraceRow, *, field: str) -> None:
    if len(row.player.player_perk_counts) != int(PERK_COUNT_SIZE):
        raise ValueError(
            f"{field}.player.player_perk_counts must have {int(PERK_COUNT_SIZE)} entries, "
            f"got {len(row.player.player_perk_counts)}",
        )
    if len(row.bonuses.bonus_timer_ms_by_id) != int(BONUS_ID_COUNT):
        raise ValueError(
            f"{field}.bonuses.bonus_timer_ms_by_id must have {int(BONUS_ID_COUNT)} entries, "
            f"got {len(row.bonuses.bonus_timer_ms_by_id)}",
        )
    if int(row.bonuses.bonus_active_count) != len(row.bonuses.active_entries):
        raise ValueError(
            f"{field}.bonuses.bonus_active_count must equal len(active_entries), "
            f"got {int(row.bonuses.bonus_active_count)} and {len(row.bonuses.active_entries)}",
        )
    if int(row.projectiles.projectile_count) != len(row.projectiles.entries):
        raise ValueError(
            f"{field}.projectiles.projectile_count must equal len(entries), "
            f"got {int(row.projectiles.projectile_count)} and {len(row.projectiles.entries)}",
        )
    if int(row.summary.creature_count) != len(row.creatures.entries):
        raise ValueError(
            f"{field}.summary.creature_count must equal len(creatures.entries), "
            f"got {int(row.summary.creature_count)} and {len(row.creatures.entries)}",
        )

    last_type_id: int | None = None
    for idx, entry in enumerate(row.projectiles.projectile_type_counts):
        if int(entry.count) <= 0:
            raise ValueError(f"{field}.projectiles.projectile_type_counts[{idx}].count must be > 0")
        type_id = int(entry.type_id)
        if last_type_id is not None and type_id <= last_type_id:
            raise ValueError(
                f"{field}.projectiles.projectile_type_counts must be strictly sorted by type_id",
            )
        last_type_id = type_id


def decode_replay_tick_trace_msgpack_row(payload: bytes, *, field: str) -> ReplayTickTraceRow:
    try:
        row = _ROW_DECODER.decode(payload)
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise ValueError(f"{field} must be a valid replay tick trace v4 msgpack row") from exc
    if int(row.schema_version) != int(REPLAY_TICK_TRACE_SCHEMA_VERSION):
        raise ValueError(
            f"{field}.schema_version must be {int(REPLAY_TICK_TRACE_SCHEMA_VERSION)}, got {int(row.schema_version)}",
        )
    _validate_trace_row(row, field=field)
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


def encode_replay_tick_trace_msgpack_stream(rows: Sequence[ReplayTickTraceRow]) -> bytes:
    out = bytearray(REPLAY_TICK_TRACE_MSGPACK_MAGIC)
    for idx, row in enumerate(rows):
        _validate_trace_row(row, field=f"rows[{idx}]")
        payload = _ROW_ENCODER.encode(row)
        out.extend(_ROW_LEN_STRUCT.pack(len(payload)))
        out.extend(payload)
    return bytes(out)
