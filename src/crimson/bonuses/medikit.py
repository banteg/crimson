from __future__ import annotations

from .apply_context import BonusApplyCtx


def apply_medikit(ctx: BonusApplyCtx) -> None:
    if float(ctx.player.health) >= 100.0:
        return
    ctx.player.health = min(100.0, float(ctx.player.health) + 10.0)
