from __future__ import annotations

from ..weapon_runtime.assign import weapon_assign_player
from ..weapons import WeaponId
from .apply_context import BonusApplyCtx


def apply_weapon(ctx: BonusApplyCtx) -> None:
    # Native weapon pickup is just weapon_assign_player: the old weapon is
    # never stashed anywhere (the alt slot is preloaded with a pistol at
    # player reset, so an empty alt slot cannot occur in native flow).
    weapon_assign_player(ctx.player, WeaponId(ctx.amount), state=ctx.state)
