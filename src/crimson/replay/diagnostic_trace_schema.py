from __future__ import annotations

from pathlib import Path

import msgspec

from ..bonuses.ids import BonusId
from ..perks.ids import PerkId

REPLAY_TICK_TRACE_SCHEMA_VERSION = 3
PERK_COUNT_SIZE = len(PerkId)
BONUS_ID_COUNT = len(BonusId)


class ProjectileTraceEntry(msgspec.Struct, forbid_unknown_fields=True):
    index: int
    type_id: int
    pos_x_bits: int
    pos_y_bits: int
    origin_x_bits: int
    origin_y_bits: int
    life_timer_bits: int
    damage_pool_bits: int
    angle_bits: int
    speed_scale_bits: int
    owner_legacy: int
    hits_players: bool


class CreatureTraceEntry(msgspec.Struct, forbid_unknown_fields=True):
    index: int
    type_id: int
    flags: int
    ai_mode: int
    link_index: int
    pos_x_bits: int
    pos_y_bits: int
    target_x_bits: int
    target_y_bits: int
    heading_bits: int
    target_heading_bits: int
    hp_bits: int
    lifecycle_stage_bits: int
    size_bits: int
    attack_cooldown_bits: int


class BonusActiveEntry(msgspec.Struct, forbid_unknown_fields=True):
    bonus_id: int
    amount: int


class ProjectileTypeCountEntry(msgspec.Struct, forbid_unknown_fields=True):
    type_id: int
    count: int


class ReplayTickTimingJson(msgspec.Struct, forbid_unknown_fields=True):
    elapsed_ms: int


class ReplayTickRngJson(msgspec.Struct, forbid_unknown_fields=True):
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


class ReplayTickSummaryJson(msgspec.Struct, forbid_unknown_fields=True):
    score_xp: int
    kills: int
    shots_fired_p0: int
    creature_count: int
    perk_pending: int


class ReplayTickPlayerJson(msgspec.Struct, forbid_unknown_fields=True):
    player_weapon_id: int
    player_ammo_bits: int
    player_health_bits: int
    player_pos_x_bits: int
    player_pos_y_bits: int
    player_aim_x_bits: int
    player_aim_y_bits: int
    player_heading_bits: int
    player_aim_heading_bits: int
    player_move_speed_bits: int
    player_turn_speed_bits: int
    player_level: int
    player_experience: int
    player_reload_active: bool
    player_reload_timer_bits: int
    player_shot_cooldown_bits: int
    player_shot_seq: int
    player_perk_counts: list[int]
    player_hot_tempered_timer_bits: int
    player_shield_timer_bits: int
    player_man_bomb_timer_bits: int
    player_fire_cough_timer_bits: int
    player_living_fortress_timer_bits: int
    perk_interval_hot_tempered_bits: int
    perk_interval_man_bomb_bits: int
    perk_interval_fire_cough_bits: int


class ReplayTickBonusesJson(msgspec.Struct, forbid_unknown_fields=True):
    bonus_timer_ms_by_id: list[int]
    bonus_active_count: int
    active_entries: list[BonusActiveEntry]


class ReplayTickProjectilesJson(msgspec.Struct, forbid_unknown_fields=True):
    projectile_count: int
    projectile_hit_count: int
    projectile_first_hit_creature_index: int
    projectile_first_hit_projectile_index: int
    projectile_first_hit_type_id: int
    projectile_first_hit_origin_x_bits: int
    projectile_first_hit_origin_y_bits: int
    projectile_first_hit_pos_x_bits: int
    projectile_first_hit_pos_y_bits: int
    projectile_first_hit_target_size_bits: int
    projectile_first_hit_target_x_bits: int
    projectile_first_hit_target_y_bits: int
    projectile_type_counts: list[ProjectileTypeCountEntry]
    entries: list[ProjectileTraceEntry]


class ReplayTickCreaturesJson(msgspec.Struct, forbid_unknown_fields=True):
    entries: list[CreatureTraceEntry]


class ReplayTickDebugJson(msgspec.Struct, forbid_unknown_fields=True):
    debug_pending_nuke: int
    debug_nuke_kills_last: int
    debug_nuke_tick_last: int
    debug_nuke_kill_index_sum: int
    debug_last_picked_bonus_id: int
    debug_last_picked_bonus_amount: int


class ReplayTickTraceJsonRow(msgspec.Struct, forbid_unknown_fields=True):
    schema_version: int
    tick_index: int
    timing: ReplayTickTimingJson
    rng: ReplayTickRngJson
    summary: ReplayTickSummaryJson
    player: ReplayTickPlayerJson
    bonuses: ReplayTickBonusesJson
    projectiles: ReplayTickProjectilesJson
    creatures: ReplayTickCreaturesJson
    debug: ReplayTickDebugJson


_ROW_DECODER = msgspec.json.Decoder(type=ReplayTickTraceJsonRow)


def _validate_trace_row(row: ReplayTickTraceJsonRow, *, field: str) -> None:
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


def decode_replay_tick_trace_json_row(payload: bytes, *, field: str) -> ReplayTickTraceJsonRow:
    try:
        row = _ROW_DECODER.decode(payload)
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise ValueError(f"{field} must be a valid replay tick trace v3 json row") from exc
    if int(row.schema_version) != int(REPLAY_TICK_TRACE_SCHEMA_VERSION):
        raise ValueError(
            f"{field}.schema_version must be {int(REPLAY_TICK_TRACE_SCHEMA_VERSION)}, got {int(row.schema_version)}",
        )
    _validate_trace_row(row, field=field)
    return row


def decode_replay_tick_trace_jsonl(path: Path) -> list[ReplayTickTraceJsonRow]:
    rows: list[ReplayTickTraceJsonRow] = []
    for line_number, raw_line in enumerate(Path(path).read_bytes().splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        rows.append(decode_replay_tick_trace_json_row(line, field=f"trace row {line_number}"))
    return rows
