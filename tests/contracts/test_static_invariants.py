from __future__ import annotations

from crimson.creatures.runtime import CreaturePool
from crimson.creatures.spawn_ids import SpawnId
from crimson.creatures.spawn_templates import SPAWN_TEMPLATES
from crimson.sim.gameplay_state import GameplayState
from grim.geom import Vec2
from grim.rand import Crand


def test_spawn_template_child_references_exist() -> None:
    template_ids = {entry.spawn_id for entry in SPAWN_TEMPLATES}

    child_template_ids: set[SpawnId] = set()
    for template_id in template_ids:
        pool = CreaturePool()
        pool.spawn_template(template_id, Vec2(512.0, 512.0), 0.0, state=GameplayState(rng=Crand(0xBEEF)), detail_preset=5)
        child_template_ids.update(slot.child_template_id for slot in pool.spawn_slots if slot.owner_creature >= 0)

    assert child_template_ids <= template_ids
