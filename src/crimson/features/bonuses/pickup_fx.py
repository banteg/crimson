from __future__ import annotations

"""Bonus pickup presentation hook registry."""

from collections.abc import Callable

from grim.color import RGBA

from ...bonuses import BonusId
from ...gameplay import BonusPickupEvent, GameplayState
from .freeze import apply_freeze_pickup_fx
from .reflex_boost import apply_reflex_boost_pickup_fx

BonusPickupFxHook = Callable[[GameplayState, BonusPickupEvent, int], None]


def _apply_default_pickup_burst(*, state: GameplayState, pickup: BonusPickupEvent, detail_preset: int) -> None:
    if int(pickup.bonus_id) == int(BonusId.NUKE):
        return
    state.effects.spawn_burst(
        pos=pickup.pos,
        count=12,
        rand=state.rng.rand,
        detail_preset=int(detail_preset),
        lifetime=0.4,
        scale_step=0.1,
        color=RGBA(0.4, 0.5, 1.0, 0.5),
    )


def _apply_reflex_boost_hook(state: GameplayState, pickup: BonusPickupEvent, detail_preset: int) -> None:
    apply_reflex_boost_pickup_fx(state=state, pickup=pickup, detail_preset=detail_preset)


def _apply_freeze_hook(state: GameplayState, pickup: BonusPickupEvent, detail_preset: int) -> None:
    apply_freeze_pickup_fx(state=state, pickup=pickup, detail_preset=detail_preset)


_BONUS_PICKUP_HOOKS: dict[int, BonusPickupFxHook] = {
    int(BonusId.REFLEX_BOOST): _apply_reflex_boost_hook,
    int(BonusId.FREEZE): _apply_freeze_hook,
}


def emit_bonus_pickup_effects(*, state: GameplayState, pickups: list[BonusPickupEvent], detail_preset: int) -> None:
    """Emit deterministic pickup FX for the provided pickup list."""
    for pickup in pickups:
        _apply_default_pickup_burst(state=state, pickup=pickup, detail_preset=int(detail_preset))
        hook = _BONUS_PICKUP_HOOKS.get(int(pickup.bonus_id))
        if hook is not None:
            hook(state, pickup, int(detail_preset))

