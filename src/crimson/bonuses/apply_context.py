from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol, Sequence

from grim.geom import Vec2

from ..projectiles import CreatureDamageApplier, Damageable
from ..sim.state_types import GameplayState, PlayerState
from .hud import _TimerRef
from .ids import BONUS_BY_ID, BonusId


class HasPos(Protocol):
    pos: Vec2


@dataclass(slots=True)
class BonusApplyCtx:
    state: GameplayState
    player: PlayerState
    bonus_id: BonusId
    amount: int
    origin: HasPos | None
    creatures: Sequence[Damageable] | None
    players: list[PlayerState] | None
    apply_creature_damage: CreatureDamageApplier | None
    detail_preset: int
    economist_multiplier: float
    label: str
    icon_id: int
    defer_freeze_corpse_fx: bool = False

    def register_global(self, timer_key: str) -> None:
        self.state.bonus_hud.register(
            self.bonus_id,
            label=self.label,
            icon_id=self.icon_id,
            timer_ref=_TimerRef("global", str(timer_key)),
        )

    def register_player(self, timer_key: str) -> None:
        if self.players is not None and len(self.players) > 1:
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

    def origin_pos(self) -> HasPos:
        return self.origin or self.player


BonusApplyHandler = Callable[[BonusApplyCtx], None]


def bonus_apply_seconds(ctx: BonusApplyCtx) -> float:
    meta = BONUS_BY_ID.get(int(ctx.bonus_id))
    if meta is not None and meta.apply_seconds is not None:
        return float(meta.apply_seconds)
    return float(ctx.amount)
