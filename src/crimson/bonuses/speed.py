from __future__ import annotations

from ..math_parity import f32
from .apply_context import BonusApplyCtx


def apply_speed(ctx: BonusApplyCtx) -> None:
    ctx.register_if_inactive()
    ctx.player.speed_bonus_timer = float(
        f32(float(ctx.player.speed_bonus_timer) + float(ctx.amount) * float(ctx.economist_multiplier)),
    )
