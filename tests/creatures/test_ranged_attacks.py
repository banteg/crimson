from __future__ import annotations

import math

from crimson.creatures.spawn import CreatureAiMode, CreatureFlags, SpawnId
from crimson.math_parity import f32, f32_from_bits
from crimson.projectiles.runtime import projectile_spawn
from crimson.projectiles.types import ProjectileTemplateId
from crimson.rng_caller_static import RngCallerStatic
from grim.geom import Vec2
from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest
from tests.support.audio import sfx_ids
from tests.support.builders.session import make_world
from tests.support.factories import (
    make_creature_state,
    make_step_runtime,
    place_creatures,
    step_creatures,
)
from tests.support.helpers import ScriptedCrand, assert_float_close


def _wrap_angle(angle: float) -> float:
    return (angle + math.pi) % math.tau - math.pi


def test_ranged_creature_fires_along_heading_not_direct_aim() -> None:
    world = make_world()
    state = world.state
    player = world.players[0]
    player.pos = Vec2(0.0, 200.0)

    creature = world.creatures.entries[0]
    creature.active = True
    creature.hp = 10.0
    creature.pos = Vec2()
    creature.heading = 0.0
    creature.flags = CreatureFlags.RANGED_ATTACK_SHOCK
    creature.ai_mode = CreatureAiMode.CHASE_PLAYER
    creature.contact_damage = 0.0

    step_runtime = step_creatures(world, 0.001)

    spawned = [proj for proj in state.projectiles.entries if proj.active]
    assert len(spawned) == 1
    proj = spawned[0]
    # A creature owns it, so it can hit players.
    assert proj.owner_id >= 0
    assert int(proj.type_id) == 9
    assert_float_close(proj.angle, creature.heading)

    direct_aim = math.atan2(player.pos.y - creature.pos.y, player.pos.x - creature.pos.x) + math.pi / 2.0
    assert abs(_wrap_angle(proj.angle - direct_aim)) > 0.1
    assert step_runtime.sfx == [SfxRequest(SfxId.SHOCK_FIRE, creature.pos)]


def test_ranged_creature_does_not_fire_when_too_close() -> None:
    world = make_world()
    state = world.state
    player = world.players[0]
    player.pos = Vec2(0.0, 64.0)

    creature = world.creatures.entries[0]
    creature.active = True
    creature.hp = 10.0
    creature.pos = Vec2()
    creature.flags = CreatureFlags.RANGED_ATTACK_SHOCK
    creature.ai_mode = CreatureAiMode.CHASE_PLAYER
    creature.move_speed = 0.0
    creature.contact_damage = 0.0

    step_runtime = step_creatures(world, 0.001)

    spawned = [proj for proj in state.projectiles.entries if proj.active]
    assert not spawned
    assert sfx_ids(step_runtime.sfx) == []


def test_ranged_variant_uses_orbit_radius_as_projectile_type() -> None:
    world = make_world()
    state = world.state
    player = world.players[0]
    player.pos = Vec2(0.0, 200.0)
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    state.rng = rng

    pool = world.creatures
    creature = pool.entries[0]
    creature.active = True
    creature.hp = 10.0
    creature.pos = Vec2()
    creature.heading = 0.0
    creature.flags = CreatureFlags.RANGED_ATTACK_VARIANT
    creature.ai_mode = CreatureAiMode.CHASE_PLAYER
    creature.ranged_projectile_type = 26
    creature.orbit_angle = 0.4
    creature.contact_damage = 0.0

    step_runtime = step_creatures(world, 0.001)

    spawned = [proj for proj in state.projectiles.entries if proj.active]
    assert len(spawned) == 1
    proj = spawned[0]
    # A creature owns it, so it can hit players.
    assert proj.owner_id >= 0
    assert int(proj.type_id) == 26
    assert creature.attack_cooldown == f32(0.4)
    assert step_runtime.sfx == [SfxRequest(SfxId.PLASMAMINIGUN_FIRE, creature.pos, gain=0.8)]
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.CREATURE_UPDATE_ALL_PLASMAMINIGUN_COOLDOWN,
    ]


def test_plasma_shooter_packs_its_projectile_type_into_orbit_radius() -> None:
    world = make_world()
    idx = world.creatures.spawn_template(
        SpawnId.SPIDER_PLASMA_SHOOTER_3C, Vec2(), 0.0, state=world.state, detail_preset=5,
    )
    # Native writes the int arm of the orbit_radius union: the radius reads as 26's bits.
    assert world.creatures.entries[idx].ranged_projectile_type == 26
    assert world.creatures.entries[idx].orbit_radius == f32_from_bits(26)


def test_ranged_projectile_can_damage_player() -> None:
    world = make_world()
    player = world.players[0]
    player.pos = Vec2(4.0, 0.0)

    projectile_spawn(
        world.state,
        players=world.players,
        pos=Vec2(),
        angle=math.pi / 2.0,
        type_id=ProjectileTemplateId.PLASMA_RIFLE,
        owner_id=0,
        owner_player_index=0,
    )

    world.state.projectiles.step(
        make_step_runtime(world, dt=0.001),
    )

    # Creature projectiles subtract a flat 10 from an unshielded player.
    assert player.health == 90.0


def test_ranged_projectile_can_damage_creature_before_player() -> None:
    world = make_world()
    player = world.players[0]
    player.pos = Vec2(4.0, 0.0)
    target = place_creatures(
        world,
        [
            make_creature_state(pos=Vec2(-200.0, -200.0), hp=10.0),
            make_creature_state(pos=Vec2(4.0, 0.0), hp=100.0),
        ],
    )[1]
    step_runtime = make_step_runtime(world, dt=0.1)

    projectile_spawn(
        world.state,
        players=world.players,
        pos=Vec2(),
        angle=math.pi / 2.0,
        type_id=ProjectileTemplateId.PLASMA_RIFLE,
        owner_id=0,
        owner_player_index=0,
    )

    world.state.projectiles.step(
        step_runtime,
    )

    assert target.hp <= 0.0
    assert [death.index for death in step_runtime.deaths] == [1]
    assert player.health == 100.0
