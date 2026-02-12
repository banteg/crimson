from __future__ import annotations

from ...weapon_runtime.assign import weapon_assign_player
from ...weapon_runtime.availability import weapon_pick_random_available
from ...weapons import WeaponId
from ..runtime.apply_context import PerkApplyCtx
from ..runtime.hook_types import PerkHooks
from ..ids import PerkId


def apply_random_weapon(ctx: PerkApplyCtx) -> None:
    current = int(ctx.owner.weapon_id)
    weapon_id = int(current)
    for _ in range(100):
        candidate = int(weapon_pick_random_available(ctx.state))
        weapon_id = candidate
        if candidate != int(WeaponId.PISTOL) and candidate != current:
            break
    weapon_assign_player(ctx.owner, weapon_id, state=ctx.state)


HOOKS = PerkHooks(
    perk_id=PerkId.RANDOM_WEAPON,
    apply_handler=apply_random_weapon,
)
