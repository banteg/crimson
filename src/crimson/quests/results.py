from __future__ import annotations

import math
from collections.abc import Sequence
from typing import TYPE_CHECKING

import msgspec

from ..math_parity import f32, x87_pc24_mul

if TYPE_CHECKING:
    from ..persistence.save_status import GameStatusData


def advance_quest_unlocks(status: GameStatusData, *, next_unlock: int, hardcore: bool) -> None:
    """Advance quest unlock progression on completion.

    Native `quest_mode_update` always raises `_quest_unlock_index`; hardcore
    completion additionally raises `_quest_unlock_index_full`.
    """
    if int(next_unlock) > int(status.quest_unlock_index):
        status.quest_unlock_index = int(next_unlock)
    if hardcore and int(next_unlock) > int(status.quest_unlock_index_full):
        status.quest_unlock_index_full = int(next_unlock)


class QuestFinalTime(msgspec.Struct, frozen=True):
    base_time_ms: int
    life_bonus_ms: int
    unpicked_perk_bonus_ms: int
    final_time_ms: int


class QuestResultsReveal(msgspec.Struct):
    """`quest_results_screen_update`'s breakdown reveal (`quest_results_reveal_*`, `quest_results_step`).

    Once the step timer runs out, one step per frame: base time +2000 every 40 ms, the life bonus +1000 every
    150 ms, one unpicked perk every 300 ms (each taking a flat 1000 ms off the running total), then a
    blink tick every 50 ms while the rows fade out.
    """

    step: int = 0
    step_timer_ms: int = 700
    base_time_ms: int = 0
    health_bonus_ms: int = 0
    perk_bonus_s: int = 0
    total_time_ms: int = 0

    def tick(self, frame_dt_ms: int, target: QuestFinalTime) -> str | None:
        """Advance one frame; returns "clink" for a reveal step, "blink" for a fade tick, else None."""
        self.step_timer_ms -= frame_dt_ms
        if self.step_timer_ms > 0:
            return None
        match self.step:
            case 0:
                self.step_timer_ms = 40
                self.base_time_ms += 2000
                if self.base_time_ms >= target.base_time_ms:
                    self.base_time_ms = target.base_time_ms
                    self.step += 1
                self.total_time_ms = self.base_time_ms
            case 1:
                self.health_bonus_ms += 1000
                self.step_timer_ms = 150
                self.total_time_ms -= 1000
                if self.health_bonus_ms >= target.life_bonus_ms:
                    self.health_bonus_ms = target.life_bonus_ms
                    self.step += 1
            case 2:
                self.step_timer_ms = 300
                self.perk_bonus_s += 1
                self.total_time_ms -= 1000
                pending_perks = target.unpicked_perk_bonus_ms // 1000
                if self.perk_bonus_s >= pending_perks:
                    self.perk_bonus_s = pending_perks
                    self.step_timer_ms = 1000
                    self.step += 1
                    self.total_time_ms = target.final_time_ms
            case _:
                self.step_timer_ms = 50
                return "blink"
        return "clink"


def compute_quest_final_time(
    *,
    base_time_ms: int,
    player_health_values: Sequence[float],
    pending_perk_count: int,
) -> QuestFinalTime:
    """Compute quest final time (ms) and breakdown.

    Modeled after `quest_results_screen_update`:
      final_time_ms = base_time_ms - life_bonus_ms - (pending_perk_count * 1000)

    Native truncates player 0's health before multiplying it by 50. Additional
    players use ``__ftol(health * 50.0f)``; applying that rule to every later
    slot preserves the original one/two-player results while extending it to
    the rewrite's three/four-player sessions.
    """

    base_ms = int(base_time_ms)
    player0_health = int(math.trunc(f32(player_health_values[0])))
    life_bonus_ms = int(math.trunc(x87_pc24_mul(float(player0_health), f32(50.0))))
    for health in player_health_values[1:]:
        life_bonus_ms += int(math.trunc(x87_pc24_mul(f32(health), f32(50.0))))

    unpicked_perk_bonus_ms = int(pending_perk_count) * 1000
    final_ms = base_ms - int(life_bonus_ms) - int(unpicked_perk_bonus_ms)
    # Native records negative final times; only an exactly-zero result is
    # remapped to 1 ms.
    if final_ms == 0:
        final_ms = 1

    return QuestFinalTime(
        base_time_ms=base_ms,
        life_bonus_ms=int(life_bonus_ms),
        unpicked_perk_bonus_ms=int(unpicked_perk_bonus_ms),
        final_time_ms=int(final_ms),
    )
