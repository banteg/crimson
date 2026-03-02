from __future__ import annotations

from collections.abc import Mapping
from typing import cast

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
    return cast("dict[str, object]", _to_builtin(validated))


def validate_rng_stream(value: object, *, field: str) -> list[object]:
    try:
        validated = msgspec.convert(value, type=list[RngStreamRow])
    except (msgspec.ValidationError, TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a valid rng_stream payload") from exc
    return cast("list[object]", _to_builtin(validated))


def validate_entity_samples(value: object, *, field: str) -> dict[str, object]:
    try:
        validated = msgspec.convert(value, type=EntitySamplesSnapshot)
    except (msgspec.ValidationError, TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a valid EntitySamplesSnapshot payload") from exc
    return cast("dict[str, object]", _to_builtin(validated))


def status_payload_from_mapping(
    status: Mapping[str, object] | None,
    *,
    usage_count: int,
) -> SnapshotStatus:
    expected_usage_count = max(0, int(usage_count))
    status_payload: dict[str, object] = {
        "quest_unlock_index": 0,
        "quest_unlock_index_full": 0,
        "weapon_usage_counts": [0] * expected_usage_count,
    }
    if status is not None:
        status_payload["quest_unlock_index"] = status.get("quest_unlock_index", 0)
        status_payload["quest_unlock_index_full"] = status.get("quest_unlock_index_full", 0)
        status_payload["weapon_usage_counts"] = status.get(
            "weapon_usage_counts",
            [0] * expected_usage_count,
        )
    try:
        validated = msgspec.convert(status_payload, type=SnapshotStatus)
    except (msgspec.ValidationError, TypeError, ValueError) as exc:
        raise ValueError("status payload must be a valid SnapshotStatus object") from exc
    counts = list(validated.weapon_usage_counts)
    if len(counts) < int(expected_usage_count):
        counts.extend([0] * (int(expected_usage_count) - len(counts)))
    elif len(counts) > int(expected_usage_count):
        counts = counts[: int(expected_usage_count)]
    return msgspec.structs.replace(validated, weapon_usage_counts=counts)
