from __future__ import annotations

from crimson.game_modes import GameMode
from crimson.modes.components.highscore_record_builder import build_highscore_record
from crimson.quests.level import QuestLevel
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.run_result import run_shot_counts
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2


def test_run_shot_counts_clamp_piercing_hits_to_shots() -> None:
    state = GameplayState()
    state.shots_fired = 5
    state.shots_hit = 10
    assert run_shot_counts(state) == (5, 5)


def test_build_highscore_record_keeps_typo_counts_unclamped() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    state.game_mode = GameMode.TYPO
    state.typo.typing.submit_count = 3
    state.typo.typing.match_count = 5

    record = build_highscore_record(
        state=state,
        player=player,
        run_elapsed_ms=0,
        creature_kill_count=0,
    )

    assert record.shots_fired == 3
    assert record.shots_hit == 5


def test_build_highscore_record_for_a_hardcore_quest_uses_the_start_tag() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    state.game_mode = GameMode.QUESTS
    state.quest_level = QuestLevel(5, 10)
    state.hardcore = True
    rng_state = state.rng.state

    record = build_highscore_record(
        state=state,
        player=player,
        run_elapsed_ms=0,
        creature_kill_count=0,
        rand_value=0x0AAC0004,
    )

    assert record.game_mode_id == GameMode.QUESTS
    assert record.quest_level == QuestLevel(5, 10)
    assert record.hardcore_marker == 0x75
    assert record.uni_num == 0x0AAC0004
    assert state.rng.state == rng_state
