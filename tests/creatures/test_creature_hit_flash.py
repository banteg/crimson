"""Hit-flash lifetime observed from native update and damage executions."""

import json
import struct
from pathlib import Path

from crimson.creatures.damage import creature_apply_damage
from crimson.creatures.runtime import CreaturePool
from crimson.creatures.spawn import CreatureAiMode, CreatureFlags
from crimson.owner_ref import OwnerRef
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from grim.rand import Crand
from tests.support.factories import make_creature_state, make_creature_update_options

FIXTURES = Path(__file__).resolve().parents[2] / "crimson-zig/src/runtime/testdata/creature-hit-flash.json"


def bits(value: float) -> int:
    return struct.unpack("<I", struct.pack("<f", value))[0]


def test_hit_flash_countdown_matches_native_witnesses() -> None:
    witnesses = json.loads(FIXTURES.read_text())["countdown"]
    assert len(witnesses) == 8
    for witness in witnesses:
        case = witness["input"]
        pool = CreaturePool()
        state = GameplayState()
        state.bonuses.freeze = case["freeze"]
        players = [PlayerState(index=0, pos=Vec2(300, 400), health=100)]
        for row in case["creatures"]:
            creature = make_creature_state(
                pos=Vec2(120, 230),
                hp=row["health"],
                active=bool(row["active"]),
                lifecycle_stage=row["lifecycle_stage"],
                size=40,
            )
            creature.hit_flash_timer = row["hit_flash_timer"]
            creature.ai_mode = CreatureAiMode(row["ai_mode"])
            pool.entries[row["index"]] = creature
        pool.update(case["dt"], options=make_creature_update_options(state=state, players=players))
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
            lifecycle_stage=row["lifecycle"],
        )
        creature.hit_flash_timer = row["hit_flash"]
        creature_apply_damage(
            creature,
            damage_amount=case["damage"],
            damage_type=case["damage_type"],
            impulse=Vec2(),
            owner=OwnerRef.from_player(0),
            dt=case["dt"],
            players=[PlayerState(index=0, pos=Vec2(), health=100)] if case["players"] else [],
            rng=Crand(case["rng_seed"]),
        )
        assert bits(creature.hit_flash_timer) == witness["timer_bits"], case["name"]
