from __future__ import annotations

from typing import TYPE_CHECKING

"""Reflex Boost pickup presentation behavior."""

from grim.color import RGBA

from ..math_parity import f32
from ..sim.state_types import BonusPickupEvent
from .apply_context import BonusApplyCtx

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState



def apply_reflex_boost(ctx: BonusApplyCtx) -> None:
    old = float(ctx.state.bonuses.reflex_boost)
    ctx.register_if_inactive()
    ctx.state.bonuses.reflex_boost = float(
        f32(float(old) + float(ctx.amount) * float(ctx.economist_multiplier)),
    )

    for target in ctx.players:
        target.weapon.ammo = float(target.weapon.clip_size)
        target.weapon.reload_timer = 0.0


def apply_reflex_boost_pickup_fx(*, state: GameplayState, pickup: BonusPickupEvent, detail_preset: int) -> None:
    """Spawn the blue ring used by Reflex Boost bonus pickups."""
    state.effects.spawn_ring(
        pos=pickup.pos,
        detail_preset=int(detail_preset),
        color=RGBA(0.6, 0.6, 1.0, 1.0),
    )
