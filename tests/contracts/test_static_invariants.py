from __future__ import annotations

from crimson.creatures.runtime import CreaturePool
from crimson.creatures.spawn_ids import SpawnId
from crimson.creatures.spawn_templates import SPAWN_TEMPLATES
from crimson.sim.gameplay_state import GameplayState
from grim.geom import Vec2
from grim.rand import Crand


def test_spawn_templates_register_the_native_children() -> None:
    template_ids = {entry.spawn_id for entry in SPAWN_TEMPLATES}
    children_by_parent: dict[SpawnId, list[SpawnId]] = {}
    for template_id in template_ids:
        pool = CreaturePool()
        pool.spawn_template(template_id, Vec2(512.0, 512.0), 0.0, state=GameplayState(rng=Crand(0xBEEF)), detail_preset=5)
        children = [slot.child_template_id for slot in pool.spawn_slots if slot.owner_creature >= 0]
        if children:
            children_by_parent[template_id] = children

    # Occupied slots in creature_spawn_slot_table after each 1.9.93 creature_spawn_template call.
    assert children_by_parent == {
        SpawnId.ZOMBIE_BOSS_SPAWNER_00: [SpawnId.ZOMBIE_RANDOM_41],
        SpawnId.DEN_ALIEN_BASIC_07: [SpawnId.ALIEN_RANDOM_1D],
        SpawnId.DEN_ALIEN_BASIC_SLOWER_08: [SpawnId.ALIEN_RANDOM_1D],
        SpawnId.DEN_ALIEN_WEAK_SMALL_09: [SpawnId.ALIEN_RANDOM_1D],
        SpawnId.DEN_SPIDER_BASIC_0A: [SpawnId.SPIDER_SP1_RANDOM_32],
        SpawnId.DEN_SPIDER_PLASMA_SHOOTERS_0B: [SpawnId.SPIDER_PLASMA_SHOOTER_3C],
        SpawnId.DEN_LIZARD_WEAK_0C: [SpawnId.LIZARD_RANDOM_31],
        SpawnId.DEN_LIZARD_WEAK_SLOWER_0D: [SpawnId.LIZARD_RANDOM_31],
        SpawnId.ALIEN_SPAWNER_RING_24_0E: [SpawnId.AI1_LIZARD_BLUE_TINT_1C],
        SpawnId.DEN_SPIDER_WEAK_10: [SpawnId.SPIDER_SP1_RANDOM_32],
    }
    assert {child for children in children_by_parent.values() for child in children} <= template_ids
