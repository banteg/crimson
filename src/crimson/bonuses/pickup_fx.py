from __future__ import annotations

from typing import TYPE_CHECKING

"""Bonus pickup presentation hook registry."""

from collections.abc import Callable

from grim.color import RGBA

from ..rng_caller_static import RngCallerStatic
from ..sim.state_types import BonusPickupEvent
from .freeze import apply_freeze_pickup_fx
from .ids import BonusId
from .reflex_boost import apply_reflex_boost_pickup_fx

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState


type BonusPickupFxHook = Callable[[GameplayState, BonusPickupEvent, int], None]


def _apply_default_pickup_burst(*, state: GameplayState, pickup: BonusPickupEvent, detail_preset: int) -> None:
    if pickup.bonus_id == BonusId.NUKE:
        return
    state.effects.spawn_burst(
        pos=pickup.pos,
        count=12,
        rng=state.rng,
        detail_preset=int(detail_preset),
        lifetime=0.4,
        scale_step=0.1,
        color=RGBA(0.4, 0.5, 1.0, 0.5),
        rotation_caller=RngCallerStatic.BONUS_APPLY_PICKUP_BURST_ROTATION,
        vel_x_caller=RngCallerStatic.BONUS_APPLY_PICKUP_BURST_VEL_X,
        vel_y_caller=RngCallerStatic.BONUS_APPLY_PICKUP_BURST_VEL_Y,
    )


def _apply_reflex_boost_hook(state: GameplayState, pickup: BonusPickupEvent, detail_preset: int) -> None:
    apply_reflex_boost_pickup_fx(state=state, pickup=pickup, detail_preset=detail_preset)


def _apply_freeze_hook(state: GameplayState, pickup: BonusPickupEvent, detail_preset: int) -> None:
    apply_freeze_pickup_fx(state=state, pickup=pickup, detail_preset=detail_preset)


_BONUS_PICKUP_HOOKS: dict[BonusId, BonusPickupFxHook] = {
    BonusId.REFLEX_BOOST: _apply_reflex_boost_hook,
    BonusId.FREEZE: _apply_freeze_hook,
}


def emit_bonus_pickup_effects(*, state: GameplayState, pickups: list[BonusPickupEvent], detail_preset: int) -> None:
    """Emit deterministic pickup FX for the provided pickup list."""
    for pickup in pickups:
        _apply_default_pickup_burst(state=state, pickup=pickup, detail_preset=int(detail_preset))
        hook = _BONUS_PICKUP_HOOKS.get(pickup.bonus_id)
        if hook is not None:
            hook(state, pickup, int(detail_preset))
