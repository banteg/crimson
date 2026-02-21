from __future__ import annotations

import pytest

from crimson.bonuses import BonusId
from crimson.bonuses.selection import bonus_pick_random_type
from crimson.game_modes import GameMode
from crimson.gameplay import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2


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


@pytest.mark.parametrize(
    ("rng_values", "hardcore", "quest_stage_major", "quest_stage_minor", "expected_bonus_id"),
    [
        ([34, 94], False, 2, 10, BonusId.FREEZE),
        ([34, 94, 0], True, 2, 10, BonusId.POINTS),
        ([34, 94, 0], False, 4, 10, BonusId.POINTS),
        ([34, 94], False, 5, 10, BonusId.FREEZE),
        ([34, 94], True, 3, 10, BonusId.FREEZE),
    ],
    ids=[
        "quest-2-10-suppresses-nuke",
        "hardcore-quest-2-10-suppresses-nuke-and-freeze",
        "quest-4-10-suppresses-nuke-and-freeze",
        "quest-5-10-suppresses-nuke",
        "hardcore-quest-3-10-suppresses-nuke",
    ],
)
def test_bonus_pick_random_type_quest_suppression(
    rng_values: list[int],
    hardcore: bool,
    quest_stage_major: int,
    quest_stage_minor: int,
    expected_bonus_id: BonusId,
) -> None:
    state = GameplayState(rng=_SeqRng(rng_values))  # type: ignore[arg-type]
    state.game_mode = int(GameMode.QUESTS)
    state.hardcore = hardcore
    state.quest_stage_major = quest_stage_major
    state.quest_stage_minor = quest_stage_minor
    players = [PlayerState(index=0, pos=Vec2())]

    bonus_id = bonus_pick_random_type(state.bonus_pool, state, players)
    assert bonus_id == int(expected_bonus_id)
