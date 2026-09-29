from __future__ import annotations

from crimson.quests.results import QuestResultsReveal, compute_quest_final_time

TARGET = compute_quest_final_time(base_time_ms=5000, player_health_values=(12.6,), pending_perk_count=2)


def _run(reveal: QuestResultsReveal, frames: int, dt_ms: int = 1000) -> list[str | None]:
    return [reveal.tick(dt_ms, TARGET) for _ in range(frames)]


def test_reveal_takes_one_step_per_frame() -> None:
    reveal = QuestResultsReveal()

    assert reveal.tick(10_000, TARGET) == "clink"
    assert (reveal.step, reveal.base_time_ms) == (0, 2000)


def test_reveal_counts_up_then_takes_flat_seconds_off_the_total() -> None:
    reveal = QuestResultsReveal()

    # Base 5000 in 2000 steps: 2000, 4000, 5000 (clamped).
    assert _run(reveal, 3) == ["clink"] * 3
    assert (reveal.step, reveal.base_time_ms, reveal.total_time_ms) == (1, 5000, 5000)
    # One life-bonus tick reaches 600 ms, but native takes a full second off the running total.
    assert _run(reveal, 1) == ["clink"]
    assert (reveal.step, reveal.health_bonus_ms, reveal.total_time_ms) == (2, 600, 4000)
    # Two unpicked perks, then the total snaps to the computed final time.
    assert _run(reveal, 2) == ["clink"] * 2
    assert (reveal.step, reveal.perk_bonus_s, reveal.total_time_ms) == (3, 2, TARGET.final_time_ms)
    assert _run(reveal, 2) == ["blink"] * 2


def test_reveal_waits_for_its_step_timer() -> None:
    reveal = QuestResultsReveal()

    assert reveal.tick(699, TARGET) is None
    assert reveal.tick(1, TARGET) == "clink"
    assert reveal.tick(39, TARGET) is None
