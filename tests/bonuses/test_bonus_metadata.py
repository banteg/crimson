from __future__ import annotations

import pytest

from crimson.bonuses import BonusId
from crimson.bonuses.pool import BonusPool
from crimson.gameplay import GameplayState
from grim.geom import Vec2


@pytest.mark.parametrize(
    "bonus_id",
    [
        BonusId.NUKE,
        BonusId.DOUBLE_EXPERIENCE,
        BonusId.SHOCK_CHAIN,
        BonusId.FIREBLAST,
    ],
)
def test_bonus_spawn_uses_native_constructor_default_amount(bonus_id: BonusId) -> None:
    pool = BonusPool(size=1)

    entry = pool.spawn_at(
        Vec2(100.0, 100.0),
        bonus_id,
        state=GameplayState(),
        emit_burst=False,
    )

    assert entry is not None
    assert entry.amount == 1
