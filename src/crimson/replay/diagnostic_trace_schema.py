from __future__ import annotations

from pathlib import Path

import msgspec

REPLAY_TICK_TRACE_SCHEMA_VERSION = 2


class ProjectileTraceEntry(msgspec.Struct, forbid_unknown_fields=True):
    index: int
    type_id: int
    pos_x_q4: int
    pos_y_q4: int
    origin_x_q4: int
    origin_y_q4: int
    life_timer_q4: int
    damage_pool_q4: int
    angle_q6: int
    speed_scale_q4: int
    owner_legacy: int
    hits_players: bool


class CreatureTraceEntry(msgspec.Struct, forbid_unknown_fields=True):
    index: int
    type_id: int
    flags: int
    ai_mode: int
    link_index: int
    pos_x_q4: int
    pos_y_q4: int
    target_x_q4: int
    target_y_q4: int
    heading_q6: int
    target_heading_q6: int
    hp_q4: int
    lifecycle_stage_q4: int
    size_q4: int
    attack_cooldown_q6: int


class ReplayTickTimingJsonV2(msgspec.Struct, forbid_unknown_fields=True):
    elapsed_ms: int


class ReplayTickRngJsonV2(msgspec.Struct, forbid_unknown_fields=True):
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


class ReplayTickSummaryJsonV2(msgspec.Struct, forbid_unknown_fields=True):
    score_xp: int
    kills: int
    shots_fired_p0: int
    creature_count: int
    creature_active_index_sum: int
    creature_active_index_xor: int
    creature_state_hash: int
    perk_pending: int


class ReplayTickPlayerJsonV2(msgspec.Struct, forbid_unknown_fields=True):
    player_weapon_id: int
    player_ammo_q4: int
    player_health_q4: int
    player_pos_x_q4: int
    player_pos_y_q4: int
    player_aim_x_q4: int
    player_aim_y_q4: int
    player_heading_q6: int
    player_aim_heading_q6: int
    player_move_speed_q4: int
    player_turn_speed_q4: int
    player_level: int
    player_experience: int
    player_reload_active: bool
    player_reload_timer_q4: int
    player_shot_cooldown_q4: int
    player_shot_seq: int
    player_perk31_count: int
    player_perk53_count: int
    player_perk54_count: int
    player_perk55_count: int
    player_hot_tempered_timer_q6: int
    player_shield_timer_q4: int
    player_man_bomb_timer_q6: int
    player_fire_cough_timer_q6: int
    player_living_fortress_timer_q6: int
    perk_interval_hot_tempered_q6: int
    perk_interval_man_bomb_q6: int
    perk_interval_fire_cough_q6: int


class ReplayTickBonusesJsonV2(msgspec.Struct, forbid_unknown_fields=True):
    bonus_weapon_power_up_ms: int
    bonus_reflex_boost_ms: int
    bonus_energizer_ms: int
    bonus_double_experience_ms: int
    bonus_freeze_ms: int
    bonus_active_count: int
    bonus0_id: int
    bonus0_amount: int
    bonus1_id: int
    bonus1_amount: int


class ReplayTickProjectilesJsonV2(msgspec.Struct, forbid_unknown_fields=True):
    projectile_state_hash: int
    projectile_count: int
    projectile_active_index_sum: int
    projectile_active_index_xor: int
    projectile_type45_count: int
    projectile_hit_count: int
    projectile_type1_count: int
    projectile_type6_count: int
    projectile_type11_count: int
    projectile_type21_count: int
    projectile_first_hit_creature_index: int
    projectile_first_hit_projectile_index: int
    projectile_first_hit_type_id: int
    projectile_first_hit_origin_x_q4: int
    projectile_first_hit_origin_y_q4: int
    projectile_first_hit_pos_x_q4: int
    projectile_first_hit_pos_y_q4: int
    projectile_first_hit_target_size_q4: int
    projectile_first_hit_target_x_q4: int
    projectile_first_hit_target_y_q4: int
    entries: list[ProjectileTraceEntry]


class ReplayTickCreaturesJsonV2(msgspec.Struct, forbid_unknown_fields=True):
    entries: list[CreatureTraceEntry]


class ReplayTickDebugJsonV2(msgspec.Struct, forbid_unknown_fields=True):
    debug_pending_nuke: int
    debug_nuke_kills_last: int
    debug_nuke_tick_last: int
    debug_nuke_kill_index_sum: int
    debug_last_picked_bonus_id: int
    debug_last_picked_bonus_amount: int


class ReplayTickTraceJsonRowV2(msgspec.Struct, forbid_unknown_fields=True):
    schema_version: int
    tick_index: int
    timing: ReplayTickTimingJsonV2
    rng: ReplayTickRngJsonV2
    summary: ReplayTickSummaryJsonV2
    player: ReplayTickPlayerJsonV2
    bonuses: ReplayTickBonusesJsonV2
    projectiles: ReplayTickProjectilesJsonV2
    creatures: ReplayTickCreaturesJsonV2
    debug: ReplayTickDebugJsonV2


_ROW_DECODER = msgspec.json.Decoder(type=ReplayTickTraceJsonRowV2)


def decode_replay_tick_trace_json_row(payload: bytes, *, field: str) -> ReplayTickTraceJsonRowV2:
    try:
        row = _ROW_DECODER.decode(payload)
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise ValueError(f"{field} must be a valid replay tick trace v2 json row") from exc
    if int(row.schema_version) != int(REPLAY_TICK_TRACE_SCHEMA_VERSION):
        raise ValueError(
            f"{field}.schema_version must be {int(REPLAY_TICK_TRACE_SCHEMA_VERSION)}, got {int(row.schema_version)}",
        )
    return row


def decode_replay_tick_trace_jsonl(path: Path) -> list[ReplayTickTraceJsonRowV2]:
    rows: list[ReplayTickTraceJsonRowV2] = []
    for line_number, raw_line in enumerate(Path(path).read_bytes().splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        rows.append(decode_replay_tick_trace_json_row(line, field=f"trace row {line_number}"))
    return rows
