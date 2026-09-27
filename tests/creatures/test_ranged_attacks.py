from __future__ import annotations

import math

from crimson.creatures.runtime import CreaturePool
from crimson.creatures.spawn import CreatureAiMode, CreatureFlags, CreatureInit
from crimson.math_parity import f32, f32_from_bits
from crimson.owner_ref import OwnerRef
from crimson.projectiles.runtime import PrimaryStepCtx
from crimson.projectiles.types import ProjectileTemplateId
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest
from tests.support.audio import sfx_ids
from tests.support.builders.session import make_world
from tests.support.factories import (
    make_creature_state,
    make_creature_update_options,
    make_projectile_update_options,
    make_step_runtime,
    place_creatures,
)
from tests.support.helpers import ScriptedCrand, assert_float_close


def _wrap_angle(angle: float) -> float:
    return (angle + math.pi) % math.tau - math.pi


def test_ranged_creature_fires_along_heading_not_direct_aim() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(0.0, 200.0))

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.hp = 10.0
    creature.pos = Vec2()
    creature.heading = 0.0
    creature.flags = CreatureFlags.RANGED_ATTACK_SHOCK
    creature.ai_mode = CreatureAiMode.CHASE_PLAYER
    creature.contact_damage = 0.0

    result = pool.update(0.001, options=make_creature_update_options(state=state, players=[player]))

    spawned = [proj for proj in state.projectiles.entries if proj.active]
    assert len(spawned) == 1
    proj = spawned[0]
    assert proj.hits_players is True
    assert int(proj.type_id) == 9
    assert_float_close(proj.angle, creature.heading)

    direct_aim = math.atan2(player.pos.y - creature.pos.y, player.pos.x - creature.pos.x) + math.pi / 2.0
    assert abs(_wrap_angle(proj.angle - direct_aim)) > 0.1
    assert result.sfx == (SfxRequest(SfxId.SHOCK_FIRE, creature.pos),)


def test_ranged_creature_does_not_fire_when_too_close() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(0.0, 64.0))

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.hp = 10.0
    creature.pos = Vec2()
    creature.flags = CreatureFlags.RANGED_ATTACK_SHOCK
    creature.ai_mode = CreatureAiMode.CHASE_PLAYER
    creature.move_speed = 0.0
    creature.contact_damage = 0.0

    result = pool.update(0.001, options=make_creature_update_options(state=state, players=[player]))

    spawned = [proj for proj in state.projectiles.entries if proj.active]
    assert not spawned
    assert sfx_ids(result.sfx) == []


def test_ranged_variant_uses_orbit_radius_as_projectile_type() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(0.0, 200.0))
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    pool = CreaturePool()
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

    result = pool.update(
        0.001,
        options=make_creature_update_options(
            state=state,
            players=[player],
            rng=rng,
        ),
    )

    spawned = [proj for proj in state.projectiles.entries if proj.active]
    assert len(spawned) == 1
    proj = spawned[0]
    assert proj.hits_players is True
    assert int(proj.type_id) == 26
    assert creature.attack_cooldown == f32(0.4)
    assert result.sfx == (SfxRequest(SfxId.PLASMAMINIGUN_FIRE, creature.pos, gain=0.8),)
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.CREATURE_UPDATE_ALL_PLASMAMINIGUN_COOLDOWN,
    ]


def test_spawn_init_packs_ranged_projectile_type_into_orbit_radius() -> None:
    pool = CreaturePool()
    init = CreatureInit(
        origin_template_id=0,
        pos=Vec2(),
        heading=0.0,
        phase_seed=0,
        flags=CreatureFlags.RANGED_ATTACK_VARIANT,
        ai_mode=2,
        ranged_projectile_type=26,
    )
    idx = pool.spawn_init(init)
    assert idx is not None
    # Native writes the int arm of the orbit_radius union: the radius reads as 26's bits.
    assert pool.entries[idx].ranged_projectile_type == 26
    assert pool.entries[idx].orbit_radius == f32_from_bits(26)


def test_ranged_projectile_can_damage_player() -> None:
    world = make_world()
    player = world.players[0]
    player.pos = Vec2(4.0, 0.0)

    world.state.projectiles.spawn(
        pos=Vec2(),
        angle=math.pi / 2.0,
        type_id=ProjectileTemplateId.PLASMA_RIFLE,
        owner=OwnerRef.from_creature(0),
        hits_players=True,
    )

    world.state.projectiles.step(
        PrimaryStepCtx(
            dt=0.001,
            creatures=world.creatures.entries,
            options=make_projectile_update_options(world),
        ),
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

    world.state.projectiles.spawn(
        pos=Vec2(),
        angle=math.pi / 2.0,
        type_id=ProjectileTemplateId.PLASMA_RIFLE,
        owner=OwnerRef.from_creature(0),
        hits_players=True,
    )

    world.state.projectiles.step(
        PrimaryStepCtx(
            dt=0.1,
            creatures=world.creatures.entries,
            options=make_projectile_update_options(world, step_runtime=step_runtime),
        ),
    )

    assert target.hp <= 0.0
    assert [death.index for death in step_runtime.deaths] == [1]
    assert player.health == 100.0
