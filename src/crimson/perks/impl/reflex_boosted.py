from __future__ import annotations

from ...math_parity import f32, x87_pc24_mul
from ...sim.state_types import PlayerState
from ..helpers import perk_active
from ..ids import PerkId


def apply_reflex_boosted_dt(*, dt: float, players: list[PlayerState]) -> float:
    """Apply Reflex Boosted dt scaling from perk effects."""
    if float(dt) <= 0.0:
        return float(dt)
    if not players:
        return float(dt)
    if not perk_active(players[0], PerkId.REFLEX_BOOSTED):
        return float(dt)
    return float(x87_pc24_mul(f32(float(dt)), f32(0.9)))
