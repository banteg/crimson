from __future__ import annotations

from .apply_context import PerkApplyCtx
from .hook_types import PerkHooks
from .ids import PerkId


def apply_ammo_maniac(ctx: PerkApplyCtx) -> None:
    from ..gameplay import weapon_assign_player

    if len(ctx.players) > 1:
        for player in ctx.players[1:]:
            player.perk_counts[:] = ctx.owner.perk_counts
    for player in ctx.players:
        weapon_assign_player(player, int(player.weapon_id), state=ctx.state)


HOOKS = PerkHooks(
    perk_id=PerkId.AMMO_MANIAC,
    apply_handler=apply_ammo_maniac,
)
