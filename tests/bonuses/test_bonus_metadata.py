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


def test_tutorial_bonus_seed_overwrites_fixed_slot_with_native_timer() -> None:
    pool = BonusPool(size=3)
    pool.entries[1].bonus_id = BonusId.NUKE
    pool.entries[1].time_left = 7.0

    entry = pool.seed_tutorial_entry(
        1,
        pos=Vec2(600.0, 400.0),
        bonus_id=BonusId.POINTS,
        amount=1000,
    )

    assert entry is pool.entries[1]
    assert pool.entries[0].bonus_id == BonusId.UNUSED
    assert entry.bonus_id == BonusId.POINTS
    assert entry.time_left == 100.0
    assert entry.time_max == 100.0
    assert entry.picked is False
    assert entry.amount == 1000
    assert entry.pos == Vec2(600.0, 400.0)


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
