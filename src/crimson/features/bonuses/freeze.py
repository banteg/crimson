from __future__ import annotations

"""Freeze bonus behavior shared by sim and presentation steps."""

from grim.color import RGBA

from ...gameplay import BonusPickupEvent, GameplayState


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

