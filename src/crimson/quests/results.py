from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class QuestFinalTime:
    base_time_ms: int
    life_bonus_ms: int
    unpicked_perk_bonus_ms: int
    final_time_ms: int


def compute_quest_final_time(
    *,
    base_time_ms: int,
    player_health: float,
    pending_perk_count: int,
    player2_health: float | None = None,
) -> QuestFinalTime:
    """Compute quest final time (ms) and breakdown.

    Modeled after `quest_results_screen_update`:
      final_time_ms = base_time_ms - round(player_health) - (pending_perk_count * 1000)
      clamped to at least 1ms.
    """

    base_ms = int(base_time_ms)
    life_bonus_ms = int(round(float(player_health)))
    if player2_health is not None:
        life_bonus_ms += int(round(float(player2_health)))

    unpicked_perk_bonus_ms = max(0, int(pending_perk_count)) * 1000
    final_ms = base_ms - int(life_bonus_ms) - int(unpicked_perk_bonus_ms)
    if final_ms < 1:
        final_ms = 1

    return QuestFinalTime(
        base_time_ms=base_ms,
        life_bonus_ms=int(life_bonus_ms),
        unpicked_perk_bonus_ms=int(unpicked_perk_bonus_ms),
        final_time_ms=int(final_ms),
    )

