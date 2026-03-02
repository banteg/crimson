from __future__ import annotations

import msgspec

from .ids import BonusId


class BonusDurationPayload(msgspec.Struct, frozen=True):
    seconds: int


class BonusWeaponPayload(msgspec.Struct, frozen=True):
    weapon_id: int


class BonusPointsPayload(msgspec.Struct, frozen=True):
    points: int


BonusPayload = BonusDurationPayload | BonusWeaponPayload | BonusPointsPayload


def bonus_duration_payload(seconds: int) -> BonusDurationPayload:
    return BonusDurationPayload(seconds=int(seconds))


def bonus_weapon_payload(weapon_id: int) -> BonusWeaponPayload:
    return BonusWeaponPayload(weapon_id=int(weapon_id))


def bonus_points_payload(points: int) -> BonusPointsPayload:
    return BonusPointsPayload(points=int(points))


def bonus_payload_from_bonus(*, bonus_id: BonusId, amount: int) -> BonusPayload:
    amount = int(amount)
    if bonus_id == BonusId.WEAPON:
        return bonus_weapon_payload(amount)
    if bonus_id == BonusId.POINTS:
        return bonus_points_payload(amount)
    return bonus_duration_payload(amount)


def bonus_payload_value(payload: BonusPayload) -> int:
    if isinstance(payload, BonusDurationPayload):
        return int(payload.seconds)
    if isinstance(payload, BonusWeaponPayload):
        return int(payload.weapon_id)
    return int(payload.points)


__all__ = [
    "BonusDurationPayload",
    "BonusPayload",
    "BonusPointsPayload",
    "BonusWeaponPayload",
    "bonus_duration_payload",
    "bonus_payload_from_bonus",
    "bonus_payload_value",
    "bonus_points_payload",
    "bonus_weapon_payload",
]
