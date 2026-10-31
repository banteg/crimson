"""1.9.8 `projectile_spawn` spawns a Fire Bullets shot ahead of each player shot instead of converting it."""

from __future__ import annotations

import pytest

from crimson.cl_build import ClBuild
from crimson.game_modes import GameMode
from crimson.owner_id import player_owner_id
from crimson.projectiles.runtime import projectile_spawn
from crimson.projectiles.types import ProjectileTemplateId
from crimson.sim.run_init import initialize_run
from crimson.sim.run_spec import RunSpec
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from tests.support.factories import fire_player_weapon, player_input


def _world(*, player_count: int = 1, preserve_bugs: bool = False) -> WorldState:
    spec = RunSpec(
        game_mode_id=GameMode.SURVIVAL,
        seed=7,
        player_count=player_count,
        preserve_bugs=preserve_bugs,
        cl_build=ClBuild.V1_9_8,
    )
    return initialize_run(spec).session.world


def _spawn_pistol(world: WorldState, player_index: int, owner_id: int) -> int:
    return projectile_spawn(
        world.state,
        players=world.players,
        pos=Vec2(100.0, 100.0),
        angle=0.0,
        type_id=ProjectileTemplateId.PISTOL,
        owner_id=owner_id,
        owner_player_index=player_index,
    )


def test_full_pool_original_overwrites_its_fire_bullets_shot() -> None:
    world = _world()
    entries = world.state.projectiles.entries
    for entry in entries:
        entry.active = True
    world.players[0].fire_bullets_timer = 10.0
    generation = entries[-1].generation

    index = _spawn_pistol(world, 0, player_owner_id(0))

    # Both spawns fall back to the last of 1.9.8's 64 slots, so only the original survives.
    assert index == len(entries) - 1 == 63
    assert entries[index].type_id == ProjectileTemplateId.PISTOL
    assert entries[index].generation == generation + 2
    assert world.state.shots_fired == 2


def test_last_free_slot_takes_the_fire_bullets_shot() -> None:
    world = _world()
    entries = world.state.projectiles.entries
    for entry in entries:
        entry.active = True
    entries[5].active = False
    world.players[0].fire_bullets_timer = 10.0

    index = _spawn_pistol(world, 0, player_owner_id(0))

    assert index == 63
    assert entries[5].type_id == ProjectileTemplateId.FIRE_BULLETS
    assert entries[63].type_id == ProjectileTemplateId.PISTOL


@pytest.mark.parametrize(
    ("preserve_bugs", "type_ids", "shots_fired"),
    [
        (False, [ProjectileTemplateId.PISTOL], 1),
        # Native reads both players' timers whoever fired (original bug 13).
        (True, [ProjectileTemplateId.FIRE_BULLETS, ProjectileTemplateId.PISTOL], 2),
    ],
)
def test_partner_fire_bullets_timer_adds_a_shot_only_with_preserve_bugs(
    preserve_bugs: bool, type_ids: list[ProjectileTemplateId], shots_fired: int,
) -> None:
    world = _world(player_count=2, preserve_bugs=preserve_bugs)
    player0 = world.players[0]
    # Past the run start's shot delay.
    player0.weapon.shot_cooldown = 0.0
    world.players[1].fire_bullets_timer = 10.0

    fire_player_weapon(world, player0, player_input(fire_down=True, aim=player0.pos + Vec2(200.0, 0.0)), 1 / 60)

    assert [entry.type_id for entry in world.state.projectiles.entries if entry.active] == type_ids
    assert world.state.shots_fired == shots_fired


@pytest.mark.parametrize(("scripted_burst", "owner_id"), [(True, player_owner_id(0)), (False, 5)])
def test_scripted_bursts_and_creature_shots_gain_no_fire_bullets(scripted_burst: bool, owner_id: int) -> None:
    world = _world()
    world.players[0].fire_bullets_timer = 10.0
    world.state.scripted_burst_active = scripted_burst

    _spawn_pistol(world, 0, owner_id)

    assert [entry.type_id for entry in world.state.projectiles.entries if entry.active] == [ProjectileTemplateId.PISTOL]
    assert world.state.shots_fired == 0


@pytest.mark.parametrize(
    ("preserve_bugs", "type_ids", "shots_fired"),
    [
        (False, [ProjectileTemplateId.FIRE_BULLETS, ProjectileTemplateId.PISTOL], 2),
        # Native's owner list stops at -3, so a fourth player's own-id shots neither count nor gain one.
        (True, [ProjectileTemplateId.PISTOL], 0),
    ],
)
def test_fourth_player_shot_gains_fire_bullets_by_default(
    preserve_bugs: bool, type_ids: list[ProjectileTemplateId], shots_fired: int,
) -> None:
    world = _world(player_count=4, preserve_bugs=preserve_bugs)
    world.players[3].fire_bullets_timer = 10.0

    _spawn_pistol(world, 3, player_owner_id(3))

    assert [entry.type_id for entry in world.state.projectiles.entries if entry.active] == type_ids
    assert world.state.shots_fired == shots_fired
