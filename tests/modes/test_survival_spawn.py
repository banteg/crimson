from __future__ import annotations

from crimson.creatures.runtime import CreaturePool, CreatureState
from crimson.creatures.spawn import CreatureFlags, CreatureTypeId, survival_spawn_creature
from crimson.math_parity import f32
from grim.geom import Vec2
from grim.rand import Crand, CrandLike
from tests.support.helpers import assert_float_close


def _spawn_survival(pos: Vec2, rng: CrandLike, *, player_experience: int) -> CreatureState:
    pool = CreaturePool()
    return pool.entries[survival_spawn_creature(pool, pos, rng, player_experience=player_experience)]


def test_survival_spawn_creature_xp_threshold_25000_consumes_extra_rand() -> None:
    rng_24999 = Crand(1)
    c_24999 = _spawn_survival(Vec2(1.0, 2.0), rng_24999, player_experience=24_999)

    assert c_24999.type_id == CreatureTypeId.SPIDER_SP1
    assert (c_24999.flags & CreatureFlags.STOP_AND_GO) != 0
    assert rng_24999.state == 0xC1BBB05F

    rng_25000 = Crand(1)
    c_25000 = _spawn_survival(Vec2(1.0, 2.0), rng_25000, player_experience=25_000)

    assert c_25000.type_id == CreatureTypeId.SPIDER_SP1
    assert (c_25000.flags & CreatureFlags.STOP_AND_GO) != 0
    assert rng_25000.state == 0xA6E9C9A6


def test_survival_spawn_creature_applies_zombie_speed_floor_and_health_scale() -> None:
    rng = Crand(1)
    c = _spawn_survival(Vec2(1.0, 2.0), rng, player_experience=90_000)

    assert c.type_id == CreatureTypeId.ZOMBIE
    assert c.flags == CreatureFlags(0)
    assert_float_close(c.move_speed, float(f32(1.3)))
    assert_float_close(c.hp, 264.75)
    assert_float_close(c.max_hp, 264.75)
    assert rng.state == 0xC1BBB05F
