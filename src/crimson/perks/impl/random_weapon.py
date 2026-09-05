from __future__ import annotations

from ...weapon_runtime.assign import weapon_assign_player
from ...weapon_runtime.availability import weapon_pick_random_available
from ...weapons import WeaponId
from ..runtime.apply_context import PerkApplyCtx


def apply_random_weapon(ctx: PerkApplyCtx) -> None:
    current = ctx.owner.weapon.weapon_id
    weapon_id = current
    for _ in range(100):
        candidate = weapon_pick_random_available(ctx.state)
        weapon_id = candidate
        if candidate != WeaponId.PISTOL and candidate != current:
            break
    weapon_assign_player(ctx.owner, weapon_id, state=ctx.state)
