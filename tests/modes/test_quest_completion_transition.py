from __future__ import annotations

from crimson.creatures.spawn import SpawnId
from crimson.quests.level import QuestLevel
from crimson.sim.mode_updates import QuestSpawnState, quest_mode_update
from crimson.ui.overlays.quest_run import quest_complete_banner_alpha
from grim.geom import Vec2
from tests.support.builders.session import make_world


def _idle_complete_frame(timer_ms: float, dt_ms: float) -> QuestSpawnState:
    # No creatures and an empty spawn table: the quest is idle-complete.
    quest = QuestSpawnState(completion_transition_ms=timer_ms)
    quest_mode_update(make_world(quest_level=QuestLevel(1, 1)), quest, dt_ms=dt_ms)
    return quest


def test_quest_completion_transition_holds_while_creatures_remain() -> None:
    world = make_world(quest_level=QuestLevel(1, 1))
    world.creatures.spawn_template(SpawnId.ALIEN_SMALL_GRAY_26, Vec2(), 0.0, state=world.state, detail_preset=5)
    world.state.bonuses.reflex_boost = 3.0
    quest = QuestSpawnState(completion_transition_ms=500.0)

    quest_mode_update(world, quest, dt_ms=16.0)

    # Native only returns early here; nothing resets the timer until the next run.
    assert quest.completion_transition_ms == 500.0
    assert (quest.completed, quest.play_hit_sfx, quest.play_completion_music) == (False, False, False)
    assert world.state.bonuses.reflex_boost == 3.0


def test_quest_completion_transition_clears_reflex_boost_and_completes_after_2500_ms() -> None:
    world = make_world(quest_level=QuestLevel(1, 1))
    world.state.bonuses.reflex_boost = 3.0
    quest = QuestSpawnState()
    completed_at = []
    for frame in range(28):
        quest_mode_update(world, quest, dt_ms=100.0)
        if quest.completed:
            completed_at.append(frame)

    assert world.state.bonuses.reflex_boost == 0.0
    # Completion checks the timer before this frame's increment.
    assert completed_at == [26, 27]
    assert quest.completion_transition_ms == 2800.0


def test_quest_completion_transition_triggers_hit_sfx_in_native_window() -> None:
    quest = _idle_complete_frame(801.0, 16.0)

    assert quest.completion_transition_ms == 851.0 + 16.0
    assert (quest.completed, quest.play_hit_sfx, quest.play_completion_music) == (False, True, False)


def test_quest_completion_transition_triggers_completion_music_in_native_window() -> None:
    quest = _idle_complete_frame(2001.0, 16.0)

    assert quest.completion_transition_ms == 2051.0 + 16.0
    assert (quest.completed, quest.play_hit_sfx, quest.play_completion_music) == (False, False, True)


def test_quest_complete_banner_alpha_matches_native_envelope() -> None:
    assert quest_complete_banner_alpha(0.0) == 0.0
    assert quest_complete_banner_alpha(250.0) == 0.5
    assert quest_complete_banner_alpha(500.0) == 1.0
    assert quest_complete_banner_alpha(1500.0) == 1.0
    assert quest_complete_banner_alpha(1750.0) == 0.5
    assert quest_complete_banner_alpha(2000.0) == 0.0
