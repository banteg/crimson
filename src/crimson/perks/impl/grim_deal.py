from __future__ import annotations

from ..runtime.apply_context import PerkApplyCtx
from ..runtime.hook_types import PerkHooks
from ..ids import PerkId


def apply_grim_deal(ctx: PerkApplyCtx) -> None:
    ctx.owner.health = -1.0
    ctx.owner.experience += int(ctx.owner.experience * 0.18)


HOOKS = PerkHooks(
    perk_id=PerkId.GRIM_DEAL,
    apply_handler=apply_grim_deal,
)
