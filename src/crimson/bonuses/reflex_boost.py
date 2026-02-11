from __future__ import annotations

"""Reflex Boost pickup presentation behavior."""

from grim.color import RGBA

from ..sim.state_types import BonusPickupEvent, GameplayState
from .apply_context import BonusApplyCtx


def apply_reflex_boost(ctx: BonusApplyCtx) -> None:
    old = float(ctx.state.bonuses.reflex_boost)
    if old <= 0.0:
        ctx.register_global("reflex_boost")
    ctx.state.bonuses.reflex_boost = float(old + float(ctx.amount) * ctx.economist_multiplier)

    targets = ctx.players if ctx.players is not None else [ctx.player]
    for target in targets:
        target.ammo = float(target.clip_size)
        target.reload_active = False
        target.reload_timer = 0.0
        target.reload_timer_max = 0.0


def apply_reflex_boost_pickup_fx(*, state: GameplayState, pickup: BonusPickupEvent, detail_preset: int) -> None:
    """Spawn the blue ring used by Reflex Boost bonus pickups."""
    state.effects.spawn_ring(
        pos=pickup.pos,
        detail_preset=int(detail_preset),
        color=RGBA(0.6, 0.6, 1.0, 1.0),
    )
