from __future__ import annotations

from ...math_parity import f32, x87_pc24_mul
from ..runtime.apply_context import PerkApplyCtx

_GRIM_DEAL_XP_SCALE = f32(0.18)


def apply_grim_deal(ctx: PerkApplyCtx) -> None:
    experience = int(ctx.owner.experience)
    bonus = int(x87_pc24_mul(float(experience), _GRIM_DEAL_XP_SCALE))
    ctx.owner.health = -1.0
    ctx.owner.experience = experience + bonus
