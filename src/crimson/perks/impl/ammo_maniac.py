from __future__ import annotations

from ...weapon_runtime.assign import weapon_assign_player
from ..ids import PerkId
from ..runtime.apply_context import PerkApplyCtx
from ..runtime.hook_types import PerkHooks


def apply_ammo_maniac(ctx: PerkApplyCtx) -> None:
    if len(ctx.players) > 1:
        for player in ctx.players[1:]:
            player.perk_counts[:] = ctx.owner.perk_counts
    for player in ctx.players:
        weapon_assign_player(player, int(player.weapon.weapon_id), state=ctx.state)


HOOKS = PerkHooks(
    perk_id=PerkId.AMMO_MANIAC,
    apply_handler=apply_ammo_maniac,
)
