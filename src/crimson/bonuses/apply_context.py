from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING

import msgspec

from grim.geom import Vec2

from ..creatures.damage_runtime import CreatureDamageRuntime
from ..sim.state_types import PlayerState
from .hud import bonus_timer_values
from .ids import BONUS_BY_ID, BonusId

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState

    from ..creatures.runtime import CreatureState


class BonusApplyCtx(msgspec.Struct):
    state: GameplayState
    player: PlayerState
    bonus_id: BonusId
    amount: int
    origin_pos: Vec2
    creatures: Sequence[CreatureState]
    players: list[PlayerState]
    detail_preset: int
    economist_multiplier: float
    label: str
    icon_id: int
    creature_damage_runtime: CreatureDamageRuntime

    def register_if_inactive(self) -> None:
        if any(timer > 0.0 for timer in bonus_timer_values(self.state, self.players, self.bonus_id)):
            return
        self.state.bonus_hud.register(self.bonus_id, label=self.label, icon_id=self.icon_id)

BonusApplyHandler = Callable[[BonusApplyCtx], None]


def bonus_apply_seconds(ctx: BonusApplyCtx) -> float:
    meta = BONUS_BY_ID.get(ctx.bonus_id)
    if meta is not None and meta.apply_seconds is not None:
        return float(meta.apply_seconds)
    return float(ctx.amount)
