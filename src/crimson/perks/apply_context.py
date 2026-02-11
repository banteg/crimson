from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Sequence

from ..sim.state_types import GameplayState, PlayerState
from .ids import PerkId
from .state import CreatureForPerks, PerkSelectionState


@dataclass(slots=True)
class PerkApplyCtx:
    state: GameplayState
    players: list[PlayerState]
    owner: PlayerState
    perk_id: PerkId
    perk_state: PerkSelectionState | None
    dt: float | None
    creatures: Sequence[CreatureForPerks] | None

    def frame_dt(self) -> float:
        return float(self.dt) if self.dt is not None else 0.0


PerkApplyHandler = Callable[[PerkApplyCtx], None]
