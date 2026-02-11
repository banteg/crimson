from __future__ import annotations

"""Freeze bonus behavior shared by sim, apply, and presentation steps."""

from dataclasses import dataclass

from grim.color import RGBA
from grim.geom import Vec2

from ..sim.state_types import BonusPickupEvent, GameplayState
from .apply_context import BonusApplyCtx


@dataclass(frozen=True, slots=True)
class DeferredFreezeCorpseFx:
    pos: Vec2
    detail_preset: int


def apply_freeze(ctx: BonusApplyCtx) -> None:
    old = float(ctx.state.bonuses.freeze)
    if old <= 0.0:
        ctx.register_global("freeze")
    ctx.state.bonuses.freeze = float(old + float(ctx.amount) * ctx.economist_multiplier)

    creatures = ctx.creatures
    if creatures:
        defer_corpse_fx = bool(ctx.defer_freeze_corpse_fx)
        rand = ctx.state.rng.rand
        for creature in creatures:
            if not creature.active:
                continue
            if creature.hp > 0.0:
                continue
            pos = creature.pos
            if defer_corpse_fx:
                ctx.state.deferred_freeze_corpse_fx.append(
                    DeferredFreezeCorpseFx(
                        pos=Vec2(float(pos.x), float(pos.y)),
                        detail_preset=int(ctx.detail_preset),
                    )
                )
            else:
                for _ in range(8):
                    angle = float(int(rand()) % 0x264) * 0.01
                    ctx.state.effects.spawn_freeze_shard(
                        pos=pos,
                        angle=angle,
                        rand=rand,
                        detail_preset=int(ctx.detail_preset),
                    )
                angle = float(int(rand()) % 0x264) * 0.01
                ctx.state.effects.spawn_freeze_shatter(
                    pos=pos,
                    angle=angle,
                    rand=rand,
                    detail_preset=int(ctx.detail_preset),
                )
            creature.active = False

    ctx.state.sfx_queue.append("sfx_shockwave")


def flush_deferred_freeze_corpse_fx(state: GameplayState) -> None:
    pending = state.deferred_freeze_corpse_fx
    if not pending:
        return

    rand = state.rng.rand
    for queued in pending:
        pos = queued.pos
        detail = int(queued.detail_preset)
        for _ in range(8):
            angle = float(int(rand()) % 0x264) * 0.01
            state.effects.spawn_freeze_shard(
                pos=pos,
                angle=angle,
                rand=rand,
                detail_preset=detail,
            )
        angle = float(int(rand()) % 0x264) * 0.01
        state.effects.spawn_freeze_shatter(
            pos=pos,
            angle=angle,
            rand=rand,
            detail_preset=detail,
        )
    pending.clear()


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
