from __future__ import annotations

from .apply_context import BonusApplyCtx, bonus_apply_seconds


def apply_double_experience(ctx: BonusApplyCtx) -> None:
    old = float(ctx.state.bonuses.double_experience)
    if old <= 0.0:
        ctx.register_global("double_experience")
    ctx.state.bonuses.double_experience = float(old + bonus_apply_seconds(ctx) * ctx.economist_multiplier)
