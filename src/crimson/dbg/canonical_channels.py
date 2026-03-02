from __future__ import annotations

from collections.abc import Mapping, Sequence

import msgspec


class SnapshotVec2(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    x: float
    y: float


class SnapshotWeapon(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    weapon_id: int
    ammo: float
    clip_size: int = 0
    reload_active: bool = False
    reload_timer: float = 0.0
    reload_timer_max: float = 0.0
    shot_cooldown: float = 0.0


class SnapshotPlayer(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    index: int
    pos: SnapshotVec2
    health: float
    weapon: SnapshotWeapon
    experience: int
    level: int


class SnapshotStatus(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    quest_unlock_index: int
    quest_unlock_index_full: int
    weapon_usage_counts: list[int] = msgspec.field(default_factory=list)


class SnapshotBonusTimers(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    weapon_power_up_ms: int = 0
    reflex_boost_ms: int = 0
    energizer_ms: int = 0
    double_experience_ms: int = 0
    freeze_ms: int = 0


class SnapshotGameplay(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    mode_id: int
    quest_stage_major: int
    quest_stage_minor: int
    perk_pending_count: int
    perk_choices_dirty: bool
    bonus_timers: SnapshotBonusTimers
    status: SnapshotStatus


class SimStateSnapshot(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    gameplay: SnapshotGameplay
    players: list[SnapshotPlayer] = msgspec.field(default_factory=list)


class RngStreamRow(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    tick_call_index: int
    value_15: int
    state_before_u32: int
    state_after_u32: int
    caller_static: str | None = None
    branch_id: str | None = None
    inferred: bool = False


class CreatureEntitySample(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    uid: int
    generation: int
    pool_kind: str
    index: int
    active: bool
    type_id: int
    hp: float
    pos: SnapshotVec2
    flags: int
    ai_mode: int
    link_index: int
    heading: float
    target_heading: float
    orbit_angle: float
    orbit_radius: float
    lifecycle_stage: float


class ProjectileEntitySample(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    uid: int
    generation: int
    pool_kind: str
    index: int
    active: bool
    type_id: int
    angle: float
    pos: SnapshotVec2
    vel: SnapshotVec2
    life_timer: float
    speed_scale: float
    damage_pool: float
    hit_radius: float
    travel_budget: float
    owner_id: int


class SecondaryProjectileEntitySample(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    uid: int
    generation: int
    pool_kind: str
    index: int
    active: bool
    type_id: int
    angle: float
    pos: SnapshotVec2
    vel: SnapshotVec2
    speed: float
    trail_timer: float
    owner_id: int
    target_id: int


class BonusEntitySample(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    uid: int
    generation: int
    pool_kind: str
    index: int
    active: bool
    bonus_id: int
    picked: bool
    time_left: float
    time_max: float
    pos: SnapshotVec2
    amount: int


class EntitySamplesSnapshot(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    creatures: list[CreatureEntitySample] = msgspec.field(default_factory=list)
    projectiles: list[ProjectileEntitySample] = msgspec.field(default_factory=list)
    secondary_projectiles: list[SecondaryProjectileEntitySample] = msgspec.field(default_factory=list)
    bonuses: list[BonusEntitySample] = msgspec.field(default_factory=list)


def bonus_timer_ms(value: float) -> int:
    ms = int(round(float(value) * 1000.0))
    if ms < 0:
        return 0
    return int(ms)


def _to_builtin(value: object) -> object:
    return msgspec.to_builtins(value)


def validate_sim_state(value: object, *, field: str) -> dict[str, object]:
    try:
        validated = msgspec.convert(value, type=SimStateSnapshot)
    except (msgspec.ValidationError, TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a valid SimStateSnapshot payload") from exc
    out = _to_builtin(validated)
    if not isinstance(out, dict):
        raise ValueError(f"{field} must decode to an object")
    return out


def validate_rng_stream(value: object, *, field: str) -> list[object]:
    try:
        validated = msgspec.convert(value, type=list[RngStreamRow])
    except (msgspec.ValidationError, TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a valid rng_stream payload") from exc
    out = _to_builtin(validated)
    if not isinstance(out, list):
        raise ValueError(f"{field} must decode to a list")
    return out


def validate_entity_samples(value: object, *, field: str) -> dict[str, object]:
    try:
        validated = msgspec.convert(value, type=EntitySamplesSnapshot)
    except (msgspec.ValidationError, TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a valid EntitySamplesSnapshot payload") from exc
    out = _to_builtin(validated)
    if not isinstance(out, dict):
        raise ValueError(f"{field} must decode to an object")
    return out


def status_payload_from_mapping(
    status: Mapping[str, object] | None,
    *,
    usage_count: int,
) -> SnapshotStatus:
    if status is None:
        return SnapshotStatus(
            quest_unlock_index=0,
            quest_unlock_index_full=0,
            weapon_usage_counts=[0] * max(0, int(usage_count)),
        )
    counts_raw = status.get("weapon_usage_counts")
    counts_list = list(counts_raw) if isinstance(counts_raw, Sequence) and not isinstance(counts_raw, (str, bytes, bytearray)) else []
    counts: list[int] = []
    for item in counts_list[: max(0, int(usage_count))]:
        if isinstance(item, bool):
            counts.append(int(item))
        elif isinstance(item, int):
            counts.append(int(item))
        elif isinstance(item, float):
            counts.append(int(item))
        else:
            counts.append(0)
    while len(counts) < int(max(0, usage_count)):
        counts.append(0)
    quest_unlock_index = status.get("quest_unlock_index")
    quest_unlock_index_full = status.get("quest_unlock_index_full")
    return SnapshotStatus(
        quest_unlock_index=int(quest_unlock_index) if isinstance(quest_unlock_index, (int, float)) and not isinstance(quest_unlock_index, bool) else 0,
        quest_unlock_index_full=int(quest_unlock_index_full)
        if isinstance(quest_unlock_index_full, (int, float)) and not isinstance(quest_unlock_index_full, bool)
        else 0,
        weapon_usage_counts=counts,
    )
