from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class QuestFinalTime:
    base_time_ms: int
    life_bonus_ms: int
    unpicked_perk_bonus_ms: int
    final_time_ms: int


@dataclass(slots=True)
class QuestResultsBreakdownAnim:
    """Phase-based breakdown animation modeled after `quest_results_screen_update`.

    The native flow animates the breakdown in four steps:
      0) base time counts up to `base_time_ms`
      1) life bonus counts up to `life_bonus_ms`
      2) perk bonus counts up (in 1s steps) to `unpicked_perk_bonus_ms`
      3) final-time highlight blink then completes
    """

    step: int = 0  # 0=base,1=life,2=perk,3=final blink,4=done
    step_timer_ms: int = 700

    base_time_ms: int = 0
    life_bonus_ms: int = 0
    unpicked_perk_bonus_s: int = 0
    final_time_ms: int = 0

    blink_ticks: int = 0
    done: bool = False

    @classmethod
    def start(cls) -> "QuestResultsBreakdownAnim":
        return cls()

    def set_final(self, target: QuestFinalTime) -> None:
        self.step = 4
        self.done = True
        self.step_timer_ms = 0
        self.base_time_ms = int(target.base_time_ms)
        self.life_bonus_ms = int(target.life_bonus_ms)
        self.unpicked_perk_bonus_s = max(0, int(target.unpicked_perk_bonus_ms) // 1000)
        self.final_time_ms = int(target.final_time_ms)
        self.blink_ticks = 0

    def highlight_alpha(self) -> float:
        if self.step != 3:
            return 1.0
        return max(0.0, min(1.0, 1.0 - float(self.blink_ticks) * 0.1))


def compute_quest_final_time(
    *,
    base_time_ms: int,
    player_health: float,
    pending_perk_count: int,
    player2_health: float | None = None,
    player_health_values: Sequence[float] | None = None,
) -> QuestFinalTime:
    """Compute quest final time (ms) and breakdown.

    Modeled after `quest_results_screen_update`:
      final_time_ms = base_time_ms - round(player_health) - (pending_perk_count * 1000)
      clamped to at least 1ms.
    """

    base_ms = int(base_time_ms)
    if player_health_values is not None and len(player_health_values) > 0:
        life_bonus_ms = 0
        for health in player_health_values:
            life_bonus_ms += int(round(float(health)))
    else:
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


def tick_quest_results_breakdown_anim(
    anim: QuestResultsBreakdownAnim,
    *,
    frame_dt_ms: int,
    target: QuestFinalTime,
) -> int:
    """Advance quest results breakdown animation.

    Returns the number of "clink" ticks to play this frame.
    """

    if anim.done:
        return 0

    clinks = 0
    remaining = max(0, int(frame_dt_ms))
    if remaining <= 0:
        return 0

    base_target_ms = max(0, int(target.base_time_ms))
    life_target_ms = max(0, int(target.life_bonus_ms))
    perk_target_s = max(0, int(target.unpicked_perk_bonus_ms) // 1000)

    while remaining > 0 and not anim.done:
        step_timer = int(anim.step_timer_ms)
        take = remaining if step_timer <= 0 else min(remaining, step_timer)
        anim.step_timer_ms = int(anim.step_timer_ms) - int(take)
        remaining -= int(take)

        while anim.step_timer_ms <= 0 and not anim.done:
            step = int(anim.step)
            if step == 0:
                anim.base_time_ms = min(base_target_ms, int(anim.base_time_ms) + 2000)
                anim.final_time_ms = int(anim.base_time_ms)
                anim.step_timer_ms += 40
                clinks += 1
                if int(anim.base_time_ms) >= base_target_ms:
                    anim.step = 1
                continue

            if step == 1:
                anim.life_bonus_ms = min(life_target_ms, int(anim.life_bonus_ms) + 1000)
                anim.final_time_ms = max(
                    1,
                    base_target_ms - int(anim.life_bonus_ms) - int(anim.unpicked_perk_bonus_s) * 1000,
                )
                anim.step_timer_ms += 150
                clinks += 1
                if int(anim.life_bonus_ms) >= life_target_ms:
                    anim.step = 2
                continue

            if step == 2:
                anim.unpicked_perk_bonus_s = min(perk_target_s, int(anim.unpicked_perk_bonus_s) + 1)
                anim.final_time_ms = max(
                    1,
                    base_target_ms - int(anim.life_bonus_ms) - int(anim.unpicked_perk_bonus_s) * 1000,
                )
                clinks += 1
                if int(anim.unpicked_perk_bonus_s) >= perk_target_s:
                    anim.final_time_ms = int(target.final_time_ms)
                    anim.step_timer_ms += 1000
                    anim.step = 3
                else:
                    anim.step_timer_ms += 300
                continue

            if step == 3:
                anim.blink_ticks += 1
                anim.step_timer_ms += 50
                if int(anim.blink_ticks) > 10:
                    anim.set_final(target)
                continue

            anim.set_final(target)

    return int(clinks)
