from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from ...sim.state_types import PlayerState
from ..ids import PerkId
from ..state import PerkSelectionState
from .apply_context import PerkApplyCtx
from .apply_handlers import PERK_APPLY_HANDLERS
from .counts import adjust_perk_count

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState

    from ...creatures.runtime import CreatureState


def perk_apply(
    state: GameplayState,
    players: list[PlayerState],
    perk_id: PerkId,
    *,
    perk_state: PerkSelectionState | None = None,
    dt: float | None = None,
    creatures: Sequence[CreatureState] | None = None,
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
                ),
            )
    finally:
        if len(players) > 1:
            for player in players[1:]:
                player.perk_counts[:] = owner.perk_counts
