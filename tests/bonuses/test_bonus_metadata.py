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


def test_bonus_spawn_spacing_uses_native_pc24_hypotenuse_boundary() -> None:
    pool = BonusPool(size=2)
    active = pool.entries[0]
    active.bonus_id = BonusId.POINTS
    active.pos = Vec2(100.0, 100.0)

    spawned = pool.spawn_at_pos(
        Vec2(123.16073417663574, 122.08122253417969),
        state=GameplayState(),
        players=[],
    )

    # Double-precision dx²+dy² is just below 32², but native PC=24 math
    # rounds the hypotenuse to exactly 32 and therefore permits the spawn.
    assert not pool._is_sentinel_entry(spawned)
