from __future__ import annotations

from grim.geom import Vec2

import math

from crimson.creatures.runtime import CreaturePool
from crimson.creatures.spawn import CreatureFlags, CreatureInit
from crimson.gameplay import GameplayState, PlayerState


def _wrap_angle(angle: float) -> float:
    return (angle + math.pi) % math.tau - math.pi


def test_ranged_creature_fires_along_heading_not_direct_aim() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(0.0, 200.0))

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.hp = 10.0
    creature.pos.x = 0.0
    creature.pos.y = 0.0
    creature.heading = 0.0
    creature.flags = CreatureFlags.RANGED_ATTACK_SHOCK
    creature.ai_mode = 2
    creature.contact_damage = 0.0

    result = pool.update(0.001, state=state, players=[player])

    spawned = [proj for proj in state.projectiles.entries if proj.active]
    assert len(spawned) == 1
    proj = spawned[0]
    assert proj.hits_players is True
    assert int(proj.type_id) == 9
    assert math.isclose(proj.angle, creature.heading, abs_tol=1e-9)

    direct_aim = math.atan2(player.pos.y - creature.pos.y, player.pos.x - creature.pos.x) + math.pi / 2.0
    assert abs(_wrap_angle(proj.angle - direct_aim)) > 0.1
    assert result.sfx == ("sfx_shock_fire",)


def test_ranged_creature_does_not_fire_when_too_close() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(0.0, 64.0))

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.hp = 10.0
    creature.pos.x = 0.0
    creature.pos.y = 0.0
    creature.flags = CreatureFlags.RANGED_ATTACK_SHOCK
    creature.ai_mode = 2
    creature.move_speed = 0.0
    creature.contact_damage = 0.0

    result = pool.update(0.001, state=state, players=[player])

    spawned = [proj for proj in state.projectiles.entries if proj.active]
    assert not spawned
    assert result.sfx == ()


def test_ranged_variant_uses_orbit_radius_as_projectile_type() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(0.0, 200.0))

    pool = CreaturePool()
    creature = pool.entries[0]
    creature.active = True
    creature.hp = 10.0
    creature.pos.x = 0.0
    creature.pos.y = 0.0
    creature.heading = 0.0
    creature.flags = CreatureFlags.RANGED_ATTACK_VARIANT
    creature.ai_mode = 2
    creature.orbit_radius = 26.0
    creature.orbit_angle = 0.4
    creature.contact_damage = 0.0

    result = pool.update(0.001, state=state, players=[player], rand=lambda: 0)

    spawned = [proj for proj in state.projectiles.entries if proj.active]
    assert len(spawned) == 1
    proj = spawned[0]
    assert proj.hits_players is True
    assert int(proj.type_id) == 26
    assert math.isclose(creature.attack_cooldown, 0.4, abs_tol=1e-9)
    assert result.sfx == ("sfx_plasmaminigun_fire",)


def test_spawn_init_packs_ranged_projectile_type_into_orbit_radius() -> None:
    pool = CreaturePool()
    init = CreatureInit(
        origin_template_id=0,
        pos=Vec2(0.0, 0.0),
        heading=0.0,
        phase_seed=0.0,
        flags=CreatureFlags.RANGED_ATTACK_VARIANT,
        ai_mode=2,
        ranged_projectile_type=26,
    )
    idx = pool.spawn_init(init)
    assert pool.entries[idx].orbit_radius == 26.0


def test_ranged_projectile_can_damage_player() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(4.0, 0.0))

    state.projectiles.spawn(
        pos=Vec2(0.0, 0.0),
        angle=math.pi / 2.0,
        type_id=9,
        owner_id=0,
        base_damage=45.0,
        hits_players=True,
    )

    def _apply_player_damage(player_index: int, damage: float) -> None:
        assert player_index == 0
        player.health -= float(damage)

    state.projectiles.update(
        0.001,
        [],
        world_size=1024.0,
        rng=state.rng.rand,
        runtime_state=state,
        players=[player],
        apply_player_damage=_apply_player_damage,
    )

    assert player.health < 100.0


def test_ranged_projectile_can_damage_creature_before_player() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(4.0, 0.0))

    pool = CreaturePool()
    shooter = pool.entries[0]
    shooter.active = True
    shooter.hp = 10.0
    shooter.pos.x = 0.0
    shooter.pos.y = 0.0

    target = pool.entries[1]
    target.active = True
    target.hp = 100.0
    target.pos.x = 4.0
    target.pos.y = 0.0

    state.projectiles.spawn(
        pos=Vec2(0.0, 0.0),
        angle=math.pi / 2.0,
        type_id=9,
        owner_id=0,
        base_damage=45.0,
        hits_players=True,
    )

    player_damage_called = False

    def _apply_player_damage(player_index: int, damage: float) -> None:
        nonlocal player_damage_called

        player_damage_called = True
        player.health -= float(damage)

    state.projectiles.update(
        0.1,
        pool.entries[:2],
        world_size=1024.0,
        rng=state.rng.rand,
        runtime_state=state,
        players=[player],
        apply_player_damage=_apply_player_damage,
    )

    assert target.hp < 100.0
    assert player_damage_called is False
    assert player.health == 100.0
