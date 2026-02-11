from __future__ import annotations

from ...sim.state_types import PlayerState
from ..ids import PerkId


def adjust_perk_count(player: PlayerState, perk_id: PerkId, *, amount: int = 1) -> None:
    idx = int(perk_id)
    if 0 <= idx < len(player.perk_counts):
        player.perk_counts[idx] += int(amount)
