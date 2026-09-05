from __future__ import annotations

from ...rng_caller_static import RngCallerStatic
from ..runtime.apply_context import PerkApplyCtx


def apply_fatal_lottery(ctx: PerkApplyCtx) -> None:
    if ctx.state.rng.rand_tagged(RngCallerStatic.PERK_APPLY_FATAL_LOTTERY) & 1:
        ctx.owner.health = -1.0
    else:
        ctx.owner.experience += 10000
