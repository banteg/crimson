from __future__ import annotations

import math

from crimson.typo.spawns import tick_typo_spawns
from crimson.creatures.spawn import CreatureTypeId


def test_tick_typo_spawns_basic_pair() -> None:
    cooldown, spawns = tick_typo_spawns(
        elapsed_ms=0,
        spawn_cooldown_ms=0,
        frame_dt_ms=1,
        player_count=1,
        world_width=1024.0,
        world_height=1024.0,
    )

    assert cooldown == 3499
    assert [(s.type_id, s.pos.x) for s in spawns] == [
        (CreatureTypeId.SPIDER_SP2, 1088.0),
        (CreatureTypeId.ALIEN, -64.0),
    ]
    assert spawns[0].pos.y == spawns[1].pos.y
    assert spawns[0].pos.y == 256.0 + 1024.0 * 0.5


def test_tick_typo_spawns_multiple_steps() -> None:
    cooldown, spawns = tick_typo_spawns(
        elapsed_ms=8000,
        spawn_cooldown_ms=0,
        frame_dt_ms=10_000,
        player_count=1,
        world_width=900.0,
        world_height=1000.0,
    )

    assert cooldown >= 100
    assert len(spawns) % 2 == 0
    assert len(spawns) >= 2
    assert {s.type_id for s in spawns} == {CreatureTypeId.SPIDER_SP2, CreatureTypeId.ALIEN}

    y_expected = math.cos(8000 * 0.001) * 256.0 + 1000.0 * 0.5
    assert spawns[0].pos.y == y_expected

