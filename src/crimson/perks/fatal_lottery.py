from __future__ import annotations

from .apply_context import PerkApplyCtx


def apply_fatal_lottery(ctx: PerkApplyCtx) -> None:
    if ctx.state.rng.rand() & 1:
        ctx.owner.health = -1.0
    else:
        ctx.owner.experience += 10000
