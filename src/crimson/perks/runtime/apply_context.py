from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING

import msgspec

from ...sim.state_types import PlayerState
from ..ids import PerkId
from ..state import PerkSelectionState

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState

    from ...creatures.runtime import CreatureState


class PerkApplyCtx(msgspec.Struct):
    state: GameplayState
    players: list[PlayerState]
    owner: PlayerState
    perk_id: PerkId
    perk_state: PerkSelectionState | None
    dt: float | None
    creatures: Sequence[CreatureState] | None

    def frame_dt(self) -> float:
        return float(self.dt) if self.dt is not None else 0.0


PerkApplyHandler = Callable[[PerkApplyCtx], None]
