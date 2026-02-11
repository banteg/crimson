from __future__ import annotations

from .apply_context import PerkApplyCtx


def apply_plaguebearer(ctx: PerkApplyCtx) -> None:
    for player in ctx.players:
        player.plaguebearer_active = True
