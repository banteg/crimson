from __future__ import annotations

from ..math_parity import f32
from .apply_context import BonusApplyCtx, bonus_apply_seconds


def apply_energizer(ctx: BonusApplyCtx) -> None:
    old = float(ctx.state.bonuses.energizer)
    ctx.register_if_inactive()

    ctx.state.bonuses.energizer = float(
        f32(float(old) + bonus_apply_seconds(ctx) * float(ctx.economist_multiplier)),
    )
