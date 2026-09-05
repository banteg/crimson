from __future__ import annotations

from ..math_parity import f32
from .apply_context import BonusApplyCtx


def apply_shield(ctx: BonusApplyCtx) -> None:
    ctx.register_if_inactive()
    ctx.player.shield_timer = float(
        f32(float(ctx.player.shield_timer) + float(ctx.amount) * float(ctx.economist_multiplier)),
    )
