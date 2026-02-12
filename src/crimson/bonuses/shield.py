from __future__ import annotations

from .apply_context import BonusApplyCtx


def apply_shield(ctx: BonusApplyCtx) -> None:
    should_register = float(ctx.player.shield_timer) <= 0.0
    if ctx.players is not None and len(ctx.players) > 1:
        should_register = float(ctx.players[0].shield_timer) <= 0.0 and float(ctx.players[1].shield_timer) <= 0.0
    if should_register:
        ctx.register_player("shield_timer")
    ctx.player.shield_timer = float(ctx.player.shield_timer + float(ctx.amount) * ctx.economist_multiplier)
