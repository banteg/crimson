from __future__ import annotations

from crimson.quests.results import compute_quest_final_time


def test_compute_quest_final_time_applies_bonuses_and_clamps() -> None:
    result = compute_quest_final_time(base_time_ms=10_000, player_health=10.4, pending_perk_count=2)
    assert result.base_time_ms == 10_000
    assert result.life_bonus_ms == 10  # round(10.4)
    assert result.unpicked_perk_bonus_ms == 2000
    assert result.final_time_ms == 7990

    clamped = compute_quest_final_time(base_time_ms=10, player_health=1000.0, pending_perk_count=10)
    assert clamped.final_time_ms == 1


def test_compute_quest_final_time_two_player_sums_life_bonus() -> None:
    result = compute_quest_final_time(base_time_ms=5000, player_health=5.2, player2_health=7.6, pending_perk_count=0)
    assert result.life_bonus_ms == 13  # round(5.2) + round(7.6)
    assert result.final_time_ms == 4987

