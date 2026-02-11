from __future__ import annotations

from typing import Sequence

from ..sim.state_types import GameplayState, PlayerState
from .apply_context import PerkApplyCtx
from .counts import adjust_perk_count
from .ids import PerkId
from .manifest import PERK_APPLY_HANDLERS
from .state import CreatureForPerks, PerkSelectionState


def perk_apply(
    state: GameplayState,
    players: list[PlayerState],
    perk_id: PerkId,
    *,
    perk_state: PerkSelectionState | None = None,
    dt: float | None = None,
    creatures: Sequence[CreatureForPerks] | None = None,
) -> None:
    """Apply immediate perk effects and increment the perk counter."""

    if not players:
        return
    owner = players[0]
    try:
        adjust_perk_count(owner, perk_id)
        handler = PERK_APPLY_HANDLERS.get(perk_id)
        if handler is not None:
            handler(
                PerkApplyCtx(
                    state=state,
                    players=players,
                    owner=owner,
                    perk_id=perk_id,
                    perk_state=perk_state,
                    dt=dt,
                    creatures=creatures,
                )
            )
    finally:
        if len(players) > 1:
            for player in players[1:]:
                player.perk_counts[:] = owner.perk_counts
