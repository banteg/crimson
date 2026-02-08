from __future__ import annotations

"""Reflex Boost pickup presentation behavior."""

from grim.color import RGBA

from ...gameplay import BonusPickupEvent, GameplayState


def apply_reflex_boost_pickup_fx(*, state: GameplayState, pickup: BonusPickupEvent, detail_preset: int) -> None:
    """Spawn the blue ring used by Reflex Boost bonus pickups."""
    state.effects.spawn_ring(
        pos=pickup.pos,
        detail_preset=int(detail_preset),
        color=RGBA(0.6, 0.6, 1.0, 1.0),
    )

