from __future__ import annotations

import msgspec

from ..weapons import WeaponId
from .ids import BonusId


class BonusDurationPayload(msgspec.Struct, frozen=True):
    seconds: int


class BonusWeaponPayload(msgspec.Struct, frozen=True):
    weapon_id: WeaponId


class BonusPointsPayload(msgspec.Struct, frozen=True):
    points: int


BonusPayload = BonusDurationPayload | BonusWeaponPayload | BonusPointsPayload


def bonus_payload_from_bonus(*, bonus_id: BonusId, amount: int) -> BonusPayload:
    amount = int(amount)
    if bonus_id == BonusId.WEAPON:
        return BonusWeaponPayload(weapon_id=WeaponId(amount))
    if bonus_id == BonusId.POINTS:
        return BonusPointsPayload(points=amount)
    return BonusDurationPayload(seconds=amount)


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
    "bonus_payload_from_bonus",
    "bonus_payload_value",
]
