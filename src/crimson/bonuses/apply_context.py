from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING

import msgspec

from grim.geom import Vec2

from ..creatures.damage_runtime import CreatureDamageRuntime
from ..sim.state_types import PlayerState
from .hud import _TimerRef
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

    def register_global(self, timer_key: str) -> None:
        self.state.bonus_hud.register(
            self.bonus_id,
            label=self.label,
            icon_id=self.icon_id,
            timer_ref=_TimerRef("global", str(timer_key)),
        )

    def register_player(self, timer_key: str) -> None:
        if len(self.players) > 1:
            self.state.bonus_hud.register(
                self.bonus_id,
                label=self.label,
                icon_id=self.icon_id,
                timer_ref=_TimerRef("player", str(timer_key), player_index=0),
                timer_ref_alt=_TimerRef("player", str(timer_key), player_index=1),
            )
        else:
            self.state.bonus_hud.register(
                self.bonus_id,
                label=self.label,
                icon_id=self.icon_id,
                timer_ref=_TimerRef("player", str(timer_key), player_index=int(self.player.index)),
            )

BonusApplyHandler = Callable[[BonusApplyCtx], None]


def bonus_apply_seconds(ctx: BonusApplyCtx) -> float:
    meta = BONUS_BY_ID.get(ctx.bonus_id)
    if meta is not None and meta.apply_seconds is not None:
        return float(meta.apply_seconds)
    return float(ctx.amount)
