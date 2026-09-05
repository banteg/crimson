from __future__ import annotations

from typing import TYPE_CHECKING

import msgspec

from ..sim.state_types import PlayerState
from .ids import BonusId

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState



class _TimerRef(msgspec.Struct, frozen=True):
    kind: str  # "global" or "player"
    key: str
    player_index: int | None = None


class BonusHudSlot(msgspec.Struct):
    active: bool = False
    bonus_id: BonusId = BonusId.UNUSED
    label: str = ""
    icon_id: int = -1
    slide_x: float = -184.0
    timer_ref: _TimerRef | None = None
    timer_ref_alt: _TimerRef | None = None
    timer_value: float = 0.0
    timer_value_alt: float = 0.0


BONUS_HUD_SLOT_COUNT = 16


class BonusHudState(msgspec.Struct):
    slots: list[BonusHudSlot] = msgspec.field(default_factory=lambda: [BonusHudSlot() for _ in range(BONUS_HUD_SLOT_COUNT)])

    def register(
        self,
        bonus_id: BonusId,
        *,
        label: str,
        icon_id: int,
        timer_ref: _TimerRef,
        timer_ref_alt: _TimerRef | None = None,
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
        slot.timer_ref = timer_ref
        slot.timer_ref_alt = timer_ref_alt
        slot.timer_value = 0.0
        slot.timer_value_alt = 0.0


def bonus_hud_update(state: GameplayState, players: list[PlayerState], *, dt: float = 0.0) -> None:
    """Refresh HUD slots based on current timer values + advance slide animation."""

    global_timers = {
        "weapon_power_up": float(state.bonuses.weapon_power_up),
        "reflex_boost": float(state.bonuses.reflex_boost),
        "energizer": float(state.bonuses.energizer),
        "double_experience": float(state.bonuses.double_experience),
        "freeze": float(state.bonuses.freeze),
    }

    def _global_timer_value(key: str) -> float:
        try:
            return global_timers[key]
        except KeyError as exc:
            raise ValueError(f"Unexpected bonus HUD global timer key: {key}") from exc

    def _player_timer_value(player: PlayerState, key: str) -> float:
        player_timers = {
            "fire_bullets_timer": float(player.fire_bullets_timer),
            "shield_timer": float(player.shield_timer),
            "speed_bonus_timer": float(player.speed_bonus_timer),
        }
        try:
            return player_timers[key]
        except KeyError as exc:
            raise ValueError(f"Unexpected bonus HUD player timer key: {key}") from exc

    def _timer_value(ref: _TimerRef | None) -> float:
        if ref is None:
            return 0.0
        if ref.kind == "global":
            return max(0.0, _global_timer_value(ref.key))
        if ref.kind == "player":
            idx = ref.player_index
            if idx is None or not (0 <= idx < len(players)):
                return 0.0
            return max(0.0, _player_timer_value(players[idx], ref.key))
        return 0.0

    player_count = len(players)
    dt = max(0.0, float(dt))

    for slot_index, slot in enumerate(state.bonus_hud.slots):
        if not slot.active:
            continue
        timer = max(0.0, _timer_value(slot.timer_ref))
        timer_alt = (
            max(0.0, _timer_value(slot.timer_ref_alt)) if (slot.timer_ref_alt is not None and player_count > 1) else 0.0
        )
        slot.timer_value = float(timer)
        slot.timer_value_alt = float(timer_alt)

        if timer > 0.0 or timer_alt > 0.0:
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
            slot.timer_ref = None
            slot.timer_ref_alt = None
            slot.timer_value = 0.0
            slot.timer_value_alt = 0.0
