from __future__ import annotations

import pytest

from crimson.crand import Crand
from crimson.creatures.spawn import CreatureTypeId, tick_survival_wave_spawns


def test_tick_survival_wave_spawns_no_trigger() -> None:
    rng = Crand(123)
    cooldown, spawns = tick_survival_wave_spawns(
        100.0,
        16.0,
        rng,
        player_count=2,
        survival_elapsed_ms=0.0,
        player_experience=0,
        terrain_width=1024,
        terrain_height=1024,
    )

    assert cooldown == pytest.approx(68.0, abs=1e-9)
    assert spawns == ()
    assert rng.state == 123


def test_tick_survival_wave_spawns_triggers_single_spawn() -> None:
    rng = Crand(1)
    cooldown, spawns = tick_survival_wave_spawns(
        -1.0,
        0.0,
        rng,
        player_count=1,
        survival_elapsed_ms=0.0,
        player_experience=0,
        terrain_width=1024,
        terrain_height=1024,
    )

    assert cooldown == pytest.approx(499.0, abs=1e-9)
    assert len(spawns) == 1
    c = spawns[0]

    assert c.pos_x == pytest.approx(35.0, abs=1e-9)
    assert c.pos_y == pytest.approx(1064.0, abs=1e-9)
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.health == pytest.approx(85.0, abs=1e-9)
    assert c.reward_value == pytest.approx(336.0, abs=1e-9)
    assert rng.state == 0xA6E9C9A6


def test_tick_survival_wave_spawns_extra_spawns_when_interval_is_negative() -> None:
    rng = Crand(1)
    cooldown, spawns = tick_survival_wave_spawns(
        -1.0,
        0.0,
        rng,
        player_count=1,
        survival_elapsed_ms=905400.0,  # 500 - (elapsed/0x708) == -3
        player_experience=0,
        terrain_width=1024,
        terrain_height=1024,
    )

    assert cooldown == pytest.approx(0.0, abs=1e-9)
    assert len(spawns) == 3
    assert [(c.pos_x, c.pos_y) for c in spawns] == [
        (pytest.approx(35.0, abs=1e-9), pytest.approx(1064.0, abs=1e-9)),
        (pytest.approx(1064.0, abs=1e-9), pytest.approx(947.0, abs=1e-9)),
        (pytest.approx(-40.0, abs=1e-9), pytest.approx(435.0, abs=1e-9)),
    ]
    assert [c.type_id for c in spawns] == [
        CreatureTypeId.ALIEN,
        CreatureTypeId.ALIEN,
        CreatureTypeId.SPIDER_SP1,
    ]
    assert rng.state == 0xBB25E9C6

