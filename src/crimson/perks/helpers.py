from __future__ import annotations

from ..sim.state_types import PlayerState
from .ids import PerkId


def perk_count_get(player: PlayerState, perk_id: PerkId) -> int:
    idx = int(perk_id)
    if idx < 0:
        return 0
    if idx >= len(player.perk_counts):
        return 0
    return int(player.perk_counts[idx])


def perk_active(player: PlayerState, perk_id: PerkId) -> bool:
    return perk_count_get(player, perk_id) > 0
