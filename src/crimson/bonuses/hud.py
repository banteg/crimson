from __future__ import annotations

from typing import TYPE_CHECKING

import msgspec

from ..math_parity import f32, x87_pc24_add, x87_pc24_mul, x87_pc24_sub
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
# Slots at or left of this offset are hidden and may be released.
BONUS_HUD_HIDDEN_X = -184.0


class BonusHudState(msgspec.Struct):
    slots: list[BonusHudSlot] = msgspec.field(default_factory=lambda: [BonusHudSlot() for _ in range(BONUS_HUD_SLOT_COUNT)])

    def register(
        self,
        bonus_id: BonusId,
        *,
        label: str,
        icon_id: int,
    ) -> None:
        """Mirror `bonus_hud_slot_activate`.

        Active slots always form a prefix, so the native timer-pointer dedupe keeps an
        existing slot and drops the new one. The kept slot reverses from its current
        `slide_x`; with preserved bugs that can be far below -184 (original bug #25).
        A full table drops the activation.
        """
        if any(slot.active and slot.bonus_id == bonus_id for slot in self.slots):
            return
        slot = next((slot for slot in self.slots if not slot.active), None)
        if slot is None:
            return
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
            slot.slide_x = x87_pc24_add(slot.slide_x, x87_pc24_mul(dt, f32(350.0)))
        else:
            slot.slide_x = x87_pc24_sub(slot.slide_x, x87_pc24_mul(dt, f32(320.0)))
            if not state.preserve_bugs:
                # Bug #25: park just past the hidden edge so a re-pick slides straight back.
                slot.slide_x = max(slot.slide_x, BONUS_HUD_HIDDEN_X - 1.0)

        if slot.slide_x > -2.0:
            slot.slide_x = -2.0

        if slot.slide_x < BONUS_HUD_HIDDEN_X and not any(other.active for other in state.bonus_hud.slots[slot_index + 1 :]):
            slot.active = False
            slot.bonus_id = BonusId.UNUSED
            slot.label = ""
            slot.icon_id = -1
            slot.slide_x = -184.0
            slot.timer_values = (0.0,)
