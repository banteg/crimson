from __future__ import annotations

from typing import TYPE_CHECKING

import msgspec

from ..sim.state_types import PlayerState
from .ids import BonusId

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState



class BonusHudSlot(msgspec.Struct):
    active: bool = False
    bonus_id: BonusId = BonusId.UNUSED
    label: str = ""
    icon_id: int = -1
    slide_x: float = -184.0
    timer_values: tuple[float, ...] = (0.0,)


BONUS_HUD_SLOT_COUNT = 16


class BonusHudState(msgspec.Struct):
    slots: list[BonusHudSlot] = msgspec.field(default_factory=lambda: [BonusHudSlot() for _ in range(BONUS_HUD_SLOT_COUNT)])

    def register(
        self,
        bonus_id: BonusId,
        *,
        label: str,
        icon_id: int,
    ) -> None:
        existing = None
        free = None
        for slot in self.slots:
            if slot.active and slot.bonus_id == bonus_id:
                existing = slot
                break
            if (not slot.active) and free is None:
                free = slot
        slot = existing or free
        if slot is None:
            slot = self.slots[-1]
        slot.active = True
        slot.bonus_id = bonus_id
        slot.label = label
        slot.icon_id = int(icon_id)
        slot.slide_x = -184.0
        slot.timer_values = (0.0,)


def bonus_timer_values(state: GameplayState, players: list[PlayerState], bonus_id: BonusId) -> tuple[float, ...]:
    match bonus_id:
        case BonusId.WEAPON_POWER_UP:
            return (state.bonuses.weapon_power_up,)
        case BonusId.REFLEX_BOOST:
            return (state.bonuses.reflex_boost,)
        case BonusId.ENERGIZER:
            return (state.bonuses.energizer,)
        case BonusId.DOUBLE_EXPERIENCE:
            return (state.bonuses.double_experience,)
        case BonusId.FREEZE:
            return (state.bonuses.freeze,)
        case BonusId.FIRE_BULLETS:
            return tuple(player.fire_bullets_timer for player in players)
        case BonusId.SHIELD:
            return tuple(player.shield_timer for player in players)
        case BonusId.SPEED:
            return tuple(player.speed_bonus_timer for player in players)
        case _:
            raise ValueError(f"bonus has no HUD timer: {bonus_id}")


def bonus_hud_update(state: GameplayState, players: list[PlayerState], *, dt: float = 0.0) -> None:
    """Refresh HUD slots based on current timer values + advance slide animation."""

    dt = max(0.0, float(dt))

    for slot_index, slot in enumerate(state.bonus_hud.slots):
        if not slot.active:
            continue
        slot.timer_values = tuple(max(0.0, timer) for timer in bonus_timer_values(state, players, slot.bonus_id))

        if any(timer > 0.0 for timer in slot.timer_values):
            slot.slide_x += dt * 350.0
        else:
            slot.slide_x -= dt * 320.0

        if slot.slide_x > -2.0:
            slot.slide_x = -2.0

        if slot.slide_x < -184.0 and not any(other.active for other in state.bonus_hud.slots[slot_index + 1 :]):
            slot.active = False
            slot.bonus_id = BonusId.UNUSED
            slot.label = ""
            slot.icon_id = -1
            slot.slide_x = -184.0
            slot.timer_values = (0.0,)
