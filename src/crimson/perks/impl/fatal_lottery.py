from __future__ import annotations

from ..runtime.apply_context import PerkApplyCtx
from ..runtime.hook_types import PerkHooks
from ..ids import PerkId


def apply_fatal_lottery(ctx: PerkApplyCtx) -> None:
    if ctx.state.rng.rand() & 1:
        ctx.owner.health = -1.0
    else:
        ctx.owner.experience += 10000


HOOKS = PerkHooks(
    perk_id=PerkId.FATAL_LOTTERY,
    apply_handler=apply_fatal_lottery,
)
