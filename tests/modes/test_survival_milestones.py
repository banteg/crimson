from __future__ import annotations

import pytest

from crimson.sim.mode_updates import SurvivalSpawnState, survival_update
from crimson.sim.world_state import WorldState
from tests.support.builders.session import make_world


def _run_milestones(stage: int, level: int) -> tuple[int, WorldState]:
    world = make_world()
    world.players[0].level = level
    # A cooldown the frame cannot run down keeps the wave spawner out of it.
    spawn = SurvivalSpawnState(stage=stage, spawn_cooldown_ms=1000.0)
    survival_update(world, spawn, elapsed_ms=0.0, dt_ms=0.0)
    return spawn.stage, world


def _positions(world: WorldState) -> list[tuple[float, float]]:
    return [(creature.pos.x, creature.pos.y) for creature in world.creatures.entries if creature.active]


@pytest.mark.parametrize(
    ("stage", "level", "expected_stage", "spawns"),
    [
        (0, 4, 0, False),
        (0, 5, 1, True),
        (0, 20, 7, True),  # cascades through stages when level is already high
        (1, 8, 1, False),
        (1, 9, 2, True),
        (2, 10, 2, False),
        (2, 11, 3, True),
        (3, 13, 4, True),
        (4, 15, 5, True),
        (5, 17, 6, True),
        (6, 19, 7, True),
        (7, 21, 8, True),
        (8, 26, 9, True),
        (9, 31, 9, False),
        (9, 32, 10, True),
    ],
)
def test_survival_milestones_advance_on_player_level(stage: int, level: int, expected_stage: int, spawns: bool) -> None:
    new_stage, world = _run_milestones(stage, level)

    assert new_stage == expected_stage
    assert bool(_positions(world)) == spawns


def test_survival_stage9_final_wave_surrounds_the_arena() -> None:
    stage, world = _run_milestones(9, 32)

    assert stage == 10
    assert _positions(world) == [
        (1088.0, 512.0),
        (-64.0, 512.0),
        *((x, -64.0) for x in (384.0, 448.0, 512.0, 576.0)),
        *((x, 1088.0) for x in (384.0, 448.0, 512.0, 576.0)),
    ]
