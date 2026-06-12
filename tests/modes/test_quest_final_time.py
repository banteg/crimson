from __future__ import annotations

from crimson.quests.results import compute_quest_final_time


def test_compute_quest_final_time_applies_bonuses_and_truncates() -> None:
    result = compute_quest_final_time(base_time_ms=10_000, player_health=10.4, pending_perk_count=2)
    assert result.base_time_ms == 10_000
    assert result.life_bonus_ms == 10  # __ftol truncation
    assert result.unpicked_perk_bonus_ms == 2000
    assert result.final_time_ms == 7990


def test_compute_quest_final_time_keeps_negative_and_remaps_exact_zero() -> None:
    # Native records negative final times; only an exactly-zero result is
    # remapped to 1 ms.
    negative = compute_quest_final_time(base_time_ms=10, player_health=1000.0, pending_perk_count=10)
    assert negative.final_time_ms == 10 - 1000 - 10_000

    zero = compute_quest_final_time(base_time_ms=11_000, player_health=1000.0, pending_perk_count=10)
    assert zero.final_time_ms == 1


def test_compute_quest_final_time_two_player_sums_life_bonus() -> None:
    result = compute_quest_final_time(base_time_ms=5000, player_health=5.2, player2_health=7.6, pending_perk_count=0)
    assert result.life_bonus_ms == 12  # trunc(5.2) + trunc(7.6)
    assert result.final_time_ms == 4988


def test_compute_quest_final_time_sums_all_player_health_values() -> None:
    result = compute_quest_final_time(
        base_time_ms=5000,
        player_health=5.2,
        player2_health=7.6,
        player_health_values=(5.2, 7.6, 3.3, 1.2),
        pending_perk_count=0,
    )
    assert result.life_bonus_ms == 16  # trunc of each health value
    assert result.final_time_ms == 4984
