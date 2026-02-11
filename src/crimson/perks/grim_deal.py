from __future__ import annotations

from .apply_context import PerkApplyCtx


def apply_grim_deal(ctx: PerkApplyCtx) -> None:
    ctx.owner.health = -1.0
    ctx.owner.experience += int(ctx.owner.experience * 0.18)
