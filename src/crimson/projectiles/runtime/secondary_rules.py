from __future__ import annotations

import msgspec

from ..types import SecondaryProjectileTypeId


class DetonationRule(msgspec.Struct, frozen=True, tag=True):
    pass


class RocketRule(msgspec.Struct, frozen=True, tag=True):
    base_speed: float = 90.0
    accel_factor_scale: float = 3.0
    speed_cap: float = 500.0
    ttl_decay_scale: float = 1.0
    detonation_scale: float = 1.0
    damage_speed_mul: float = 50.0
    damage_base: float = 500.0
    extra_decals: int = 0x14
    extra_radius: float = 90.0
    burst_scale: float | None = 0.4
    burst_min_detail: int = 3
    freeze_shard_target_pos: bool = False


class HomingRocketRule(msgspec.Struct, frozen=True, tag=True):
    base_speed: float = 190.0
    target_accel: float = 800.0
    max_velocity: float = 350.0
    ttl_decay_scale: float = 0.5
    detonation_scale: float = 0.35
    damage_speed_mul: float = 20.0
    damage_base: float = 80.0
    extra_decals: int = 10
    extra_radius: float = 64.0
    freeze_shard_target_pos: bool = False


class RocketMinigunRule(msgspec.Struct, frozen=True, tag=True):
    base_speed: float = 90.0
    accel_factor_scale: float = 4.0
    speed_cap: float = 600.0
    ttl_decay_scale: float = 1.0
    detonation_scale: float = 0.25
    damage_speed_mul: float = 20.0
    damage_base: float = 40.0
    extra_decals: int = 3
    extra_radius: float = 44.0
    freeze_shard_target_pos: bool = True


type SecondaryProjectileRule = DetonationRule | RocketRule | HomingRocketRule | RocketMinigunRule


SECONDARY_RULE_BY_TYPE_ID: dict[SecondaryProjectileTypeId, SecondaryProjectileRule] = {
    SecondaryProjectileTypeId.DETONATION: DetonationRule(),
    SecondaryProjectileTypeId.ROCKET: RocketRule(),
    SecondaryProjectileTypeId.HOMING_ROCKET: HomingRocketRule(),
    SecondaryProjectileTypeId.ROCKET_MINIGUN: RocketMinigunRule(),
}


_DEFAULT_ROCKET_RULE = RocketRule(
    detonation_scale=0.5,
    damage_speed_mul=0.0,
    damage_base=150.0,
    extra_decals=0,
    extra_radius=0.0,
    burst_scale=None,
)


def secondary_rule_for_type_id(type_id: SecondaryProjectileTypeId) -> SecondaryProjectileRule:
    return SECONDARY_RULE_BY_TYPE_ID.get(type_id, _DEFAULT_ROCKET_RULE)


__all__ = [
    "SECONDARY_RULE_BY_TYPE_ID",
    "SecondaryProjectileRule",
    "secondary_rule_for_type_id",
]
