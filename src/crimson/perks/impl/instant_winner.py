from __future__ import annotations

from ..runtime.apply_context import PerkApplyCtx


def apply_instant_winner(ctx: PerkApplyCtx) -> None:
    ctx.owner.experience += 2500
