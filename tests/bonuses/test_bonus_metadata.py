from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.bonuses.pool import BonusPool
from grim.geom import Vec2


def test_tutorial_bonus_seed_overwrites_fixed_slot_with_native_timer() -> None:
    pool = BonusPool()
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
