from __future__ import annotations

from .apply_context import BonusApplyCtx


def apply_points(ctx: BonusApplyCtx) -> None:
    # Native adds Points directly to player0 XP (no Double XP multiplier).
    amount = int(ctx.amount)
    if amount <= 0:
        return
    target = ctx.player
    if ctx.players is not None and len(ctx.players) > 0:
        target = ctx.players[0]
    target.experience += int(amount)
