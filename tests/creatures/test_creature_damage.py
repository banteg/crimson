from __future__ import annotations

from crimson.creatures.damage import (
    creature_apply_damage,
)
from crimson.creatures.damage_types import CreatureDamageType
from crimson.creatures.runtime import CreatureState
from grim.geom import Vec2
from tests.support.factories import make_step_runtime, world_with_creature
from tests.support.helpers import ScriptedCrand


def test_lethal_branch_gates_on_entry_health_not_lifecycle() -> None:
    # Native creature_apply_damage runs the lethal branch whenever entry hp > 0,
    # even for a creature whose death already started (Shrinkifier corpse with
    # hp still positive).
    creature = CreatureState(active=True, hp=5.0, max_hp=400.0, death_timer=15.0, size=40.0)
    world = world_with_creature(creature, rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    world.state.scripted_burst_active = True
    step_runtime = make_step_runtime(world, dt=0.016)

    killed = creature_apply_damage(
        step_runtime, 0, 10.0, CreatureDamageType.EXPLOSION, Vec2(),
    )

    assert killed is True
    assert len(step_runtime.deaths) == 1
