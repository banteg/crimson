from __future__ import annotations

from ..sim.state_types import PlayerState
from .helpers import perk_active
from .ids import PerkId


def apply_reflex_boosted_dt(*, dt: float, players: list[PlayerState]) -> float:
    """Apply Reflex Boosted dt scaling from perk effects."""
    if float(dt) <= 0.0:
        return float(dt)
    if not players:
        return float(dt)
    if not perk_active(players[0], PerkId.REFLEX_BOOSTED):
        return float(dt)
    return float(dt) * 0.9
