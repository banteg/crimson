from __future__ import annotations

from ..runtime.apply_context import PerkApplyCtx


def apply_my_favourite_weapon(ctx: PerkApplyCtx) -> None:
    for player in ctx.players:
        player.weapon.clip_size += 2
