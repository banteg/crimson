from __future__ import annotations

from grim.color import RGBA

from ..math_parity import f32
from .apply_context import BonusApplyCtx


def apply_reflex_boost(ctx: BonusApplyCtx) -> None:
    old = float(ctx.state.bonuses.reflex_boost)
    ctx.register_if_inactive()
    ctx.state.bonuses.reflex_boost = float(
        f32(float(old) + float(ctx.amount) * float(ctx.economist_multiplier)),
    )

    for target in ctx.players:
        target.weapon.ammo = float(target.weapon.clip_size)
        target.weapon.reload_timer = 0.0

    ctx.state.effects.spawn_ring(
        pos=ctx.origin_pos,
        detail_preset=ctx.detail_preset,
        color=RGBA(0.6, 0.6, 1.0, 1.0),
    )
