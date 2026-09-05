from __future__ import annotations

from typing import TYPE_CHECKING

"""Freeze bonus behavior shared by sim, apply, and presentation steps."""


from grim.color import RGBA
from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest

from ..math_parity import f32
from ..rng_caller_static import RngCallerStatic
from ..sim.state_types import BonusPickupEvent
from .apply_context import BonusApplyCtx

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState


def apply_freeze(ctx: BonusApplyCtx) -> None:
    old = float(ctx.state.bonuses.freeze)
    if old <= 0.0:
        ctx.register_global("freeze")
    ctx.state.bonuses.freeze = f32(old + float(ctx.amount) * float(ctx.economist_multiplier))

    # Native bonus_apply visits every currently active corpse, including kills
    # earlier in this tick and entries below the normal despawn threshold.
    for creature in ctx.creatures or ():
        if not creature.active or creature.hp > 0.0:
            continue
        for _ in range(8):
            angle = float(ctx.state.rng.rand_tagged(RngCallerStatic.BONUS_APPLY_FREEZE_SHARD_ANGLE) % 612) * 0.01
            ctx.state.effects.spawn_freeze_shard(
                pos=creature.pos,
                angle=angle,
                rng=ctx.state.rng,
                detail_preset=ctx.detail_preset,
            )
        angle = float(ctx.state.rng.rand_tagged(RngCallerStatic.BONUS_APPLY_FREEZE_SHATTER_ANGLE) % 612) * 0.01
        ctx.state.effects.spawn_freeze_shatter(
            pos=creature.pos,
            angle=angle,
            rng=ctx.state.rng,
            detail_preset=ctx.detail_preset,
        )
        creature.active = False

    ctx.state.sfx_queue.append(SfxRequest(SfxId.SHOCKWAVE, ctx.origin_pos))


def freeze_bonus_active(*, state: GameplayState) -> bool:
    """Return whether Freeze timer is currently active."""
    return float(state.bonuses.freeze) > 0.0


def apply_freeze_pickup_fx(*, state: GameplayState, pickup: BonusPickupEvent, detail_preset: int) -> None:
    """Spawn the freeze-tinted ring used by Freeze bonus pickups."""
    state.effects.spawn_ring(
        pos=pickup.pos,
        detail_preset=int(detail_preset),
        color=RGBA(0.3, 0.5, 0.8, 1.0),
    )
