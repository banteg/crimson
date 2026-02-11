from __future__ import annotations

from .apply_context import PerkApplyCtx


def apply_my_favourite_weapon(ctx: PerkApplyCtx) -> None:
    for player in ctx.players:
        player.clip_size += 2
