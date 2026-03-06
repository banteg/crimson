from __future__ import annotations

from crimson.quests.results import (
    QuestResultsBreakdownAnim,
    compute_quest_final_time,
    tick_quest_results_breakdown_anim,
)


def test_breakdown_anim_reaches_final_values() -> None:
    target = compute_quest_final_time(
        base_time_ms=5000,
        player_health=100.0,
        pending_perk_count=3,
    )
    anim = QuestResultsBreakdownAnim.start()

    clinks = tick_quest_results_breakdown_anim(anim, frame_dt_ms=10_000, target=target)

    assert clinks > 0
    assert anim.done is True
    assert anim.base_time_ms == target.base_time_ms
    assert anim.life_bonus_ms == target.life_bonus_ms
    assert anim.unpicked_perk_bonus_s == target.unpicked_perk_bonus_ms // 1000
    assert anim.final_time_ms == target.final_time_ms


def test_breakdown_anim_can_skip_to_final() -> None:
    target = compute_quest_final_time(
        base_time_ms=12345,
        player_health=42.0,
        pending_perk_count=7,
    )
    anim = QuestResultsBreakdownAnim.start()
    anim.set_final(target)

    assert anim.done is True
    assert anim.base_time_ms == target.base_time_ms
    assert anim.life_bonus_ms == target.life_bonus_ms
    assert anim.unpicked_perk_bonus_s == target.unpicked_perk_bonus_ms // 1000
    assert anim.final_time_ms == target.final_time_ms


def test_breakdown_anim_highlight_alpha_decays_on_final_step() -> None:
    anim = QuestResultsBreakdownAnim.start()
    anim.step = 3
    anim.blink_ticks = 5
    assert anim.highlight_alpha() == 0.5
