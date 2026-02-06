from __future__ import annotations

from grim.geom import Vec2

from crimson.bonuses import BonusId
from crimson.game_modes import GameMode
from crimson.gameplay import GameplayState, PlayerState, bonus_pick_random_type


class _SeqRng:
    def __init__(self, values: list[int]) -> None:
        self._values = [int(v) for v in values] or [0]
        self._idx = 0

    def rand(self) -> int:
        if self._idx >= len(self._values):
            return int(self._values[-1])
        value = int(self._values[self._idx])
        self._idx += 1
        return value


def test_bonus_pick_random_type_quest_2_10_suppresses_nuke() -> None:
    # roll=35 => Nuke; roll=95 => Freeze
    state = GameplayState(rng=_SeqRng([34, 94]))  # type: ignore[arg-type]
    state.game_mode = int(GameMode.QUESTS)
    state.quest_stage_major = 2
    state.quest_stage_minor = 10
    players = [PlayerState(index=0, pos=Vec2(0.0, 0.0))]

    bonus_id = bonus_pick_random_type(state.bonus_pool, state, players)
    assert bonus_id == int(BonusId.FREEZE)


def test_bonus_pick_random_type_hardcore_quest_2_10_suppresses_nuke_and_freeze() -> None:
    state = GameplayState(rng=_SeqRng([34, 94, 0]))  # type: ignore[arg-type]
    state.game_mode = int(GameMode.QUESTS)
    state.hardcore = True
    state.quest_stage_major = 2
    state.quest_stage_minor = 10
    players = [PlayerState(index=0, pos=Vec2(0.0, 0.0))]

    bonus_id = bonus_pick_random_type(state.bonus_pool, state, players)
    assert bonus_id == int(BonusId.POINTS)


def test_bonus_pick_random_type_quest_4_10_suppresses_nuke_and_freeze() -> None:
    state = GameplayState(rng=_SeqRng([34, 94, 0]))  # type: ignore[arg-type]
    state.game_mode = int(GameMode.QUESTS)
    state.quest_stage_major = 4
    state.quest_stage_minor = 10
    players = [PlayerState(index=0, pos=Vec2(0.0, 0.0))]

    bonus_id = bonus_pick_random_type(state.bonus_pool, state, players)
    assert bonus_id == int(BonusId.POINTS)


def test_bonus_pick_random_type_quest_5_10_suppresses_nuke() -> None:
    state = GameplayState(rng=_SeqRng([34, 94]))  # type: ignore[arg-type]
    state.game_mode = int(GameMode.QUESTS)
    state.quest_stage_major = 5
    state.quest_stage_minor = 10
    players = [PlayerState(index=0, pos=Vec2(0.0, 0.0))]

    bonus_id = bonus_pick_random_type(state.bonus_pool, state, players)
    assert bonus_id == int(BonusId.FREEZE)


def test_bonus_pick_random_type_hardcore_quest_3_10_suppresses_nuke() -> None:
    state = GameplayState(rng=_SeqRng([34, 94]))  # type: ignore[arg-type]
    state.game_mode = int(GameMode.QUESTS)
    state.hardcore = True
    state.quest_stage_major = 3
    state.quest_stage_minor = 10
    players = [PlayerState(index=0, pos=Vec2(0.0, 0.0))]

    bonus_id = bonus_pick_random_type(state.bonus_pool, state, players)
    assert bonus_id == int(BonusId.FREEZE)
