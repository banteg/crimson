from __future__ import annotations

from .apply_context import PerkApplyCtx


def apply_thick_skinned(ctx: PerkApplyCtx) -> None:
    for player in ctx.players:
        if player.health > 0.0:
            player.health = max(1.0, player.health * (2.0 / 3.0))
