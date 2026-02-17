from __future__ import annotations

from ..ids import PerkId
from ..runtime.apply_context import PerkApplyCtx
from ..runtime.hook_types import PerkHooks


def apply_my_favourite_weapon(ctx: PerkApplyCtx) -> None:
    for player in ctx.players:
        player.clip_size += 2


HOOKS = PerkHooks(
    perk_id=PerkId.MY_FAVOURITE_WEAPON,
    apply_handler=apply_my_favourite_weapon,
)
