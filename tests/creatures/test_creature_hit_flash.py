"""Hit-flash lifetime observed from native update and damage executions."""

import json
import struct
from pathlib import Path

from crimson.creatures.damage import creature_apply_damage
from crimson.creatures.spawn import CreatureAiMode, CreatureFlags
from crimson.sim.state_types import PerkCounts, PlayerState
from grim.geom import Vec2
from grim.rand import Crand
from tests.support.builders.session import make_world
from tests.support.factories import make_creature_state, step_creatures

FIXTURES = Path(__file__).resolve().parents[2] / "tests/fixtures/native/creature-hit-flash.json"
from tests.support.factories import make_step_runtime, world_with_creature


def bits(value: float) -> int:
    return struct.unpack("<I", struct.pack("<f", value))[0]


def test_hit_flash_countdown_matches_native_witnesses() -> None:
    witnesses = json.loads(FIXTURES.read_text())["countdown"]
    assert len(witnesses) == 8
    for witness in witnesses:
        case = witness["input"]
        world = make_world()
        pool = world.creatures
        world.state.bonuses.freeze = case["freeze"]
        world.players[0].pos = Vec2(300, 400)
        for row in case["creatures"]:
            creature = make_creature_state(
                pos=Vec2(120, 230),
                hp=row["health"],
                active=bool(row["active"]),
                death_timer=row["death_timer"],
                size=40,
            )
            creature.hit_flash_timer = row["hit_flash_timer"]
            creature.ai_mode = CreatureAiMode(row["ai_mode"])
            pool.entries[row["index"]] = creature
        step_creatures(world, case["dt"])
        for expected in witness["expected"]:
            assert bits(pool.entries[expected["index"]].hit_flash_timer) == expected["timer_bits"], case["name"]


def test_damage_hit_flash_matches_native_witnesses() -> None:
    witnesses = json.loads(FIXTURES.read_text())["damage"]
    assert len(witnesses) == 480
    for witness in witnesses:
        case = witness["input"]
        row = case["creatures"][0]
        creature = make_creature_state(
            pos=Vec2(),
            active=bool(row["active"]),
            hp=row["health"],
            size=row["size"],
            flags=CreatureFlags(row["flags"]),
            death_timer=row["lifecycle"],
        )
        creature.hit_flash_timer = row["hit_flash"]
        world = world_with_creature(creature, rng=Crand(case["rng_seed"]), perks=PerkCounts(), players=[PlayerState(index=0, pos=Vec2(), health=100)] if case["players"] else [])
        creature_apply_damage(make_step_runtime(world, dt=case["dt"]), 0, case["damage"], case["damage_type"], Vec2())
        assert bits(creature.hit_flash_timer) == witness["timer_bits"], case["name"]
