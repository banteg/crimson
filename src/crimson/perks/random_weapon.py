from __future__ import annotations

from ..weapons import WeaponId
from .apply_context import PerkApplyCtx


def apply_random_weapon(ctx: PerkApplyCtx) -> None:
    from ..gameplay import weapon_assign_player, weapon_pick_random_available

    current = int(ctx.owner.weapon_id)
    weapon_id = int(current)
    for _ in range(100):
        candidate = int(weapon_pick_random_available(ctx.state))
        weapon_id = candidate
        if candidate != int(WeaponId.PISTOL) and candidate != current:
            break
    weapon_assign_player(ctx.owner, weapon_id, state=ctx.state)
