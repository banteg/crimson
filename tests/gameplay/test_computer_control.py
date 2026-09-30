from __future__ import annotations

from crimson.aim_schemes import AimScheme
from crimson.movement_controls import MovementControlType
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import make_creature_state, place_creatures, player_input, step_player


def _computer_world(pos: Vec2, creatures: list[tuple[Vec2, float]], *, auto_target: int = 0):
    world = make_world()
    player = PlayerState(index=0, pos=pos, aim=pos, auto_target=auto_target)
    world.players[:] = [player]
    place_creatures(world, [make_creature_state(pos=creature_pos, hp=hp) for creature_pos, hp in creatures])
    return world, player


def test_retarget_takes_the_first_creature_64_units_closer_in_pool_order() -> None:
    # Target 0 sits 200 away; creature 1 (130) beats it by 64 first, so creature 2 (100)
    # would have to beat 130 by 64 too.
    world, player = _computer_world(
        Vec2(500.0, 500.0),
        [(Vec2(700.0, 500.0), 10.0), (Vec2(630.0, 500.0), 10.0), (Vec2(600.0, 500.0), 10.0)],
    )

    step_player(world, player, player_input(aim_scheme=AimScheme.COMPUTER), 0.016)

    assert player.auto_target == 1


def test_retarget_starts_from_scratch_when_the_target_is_dead() -> None:
    world, player = _computer_world(
        Vec2(500.0, 500.0),
        [(Vec2(510.0, 500.0), 0.0), (Vec2(900.0, 500.0), 10.0), (Vec2(800.0, 500.0), 10.0)],
    )

    step_player(world, player, player_input(aim_scheme=AimScheme.COMPUTER), 0.016)

    assert player.auto_target == 2


def test_computer_aim_eases_toward_the_target_and_auto_fires_in_reach() -> None:
    world, player = _computer_world(Vec2(500.0, 500.0), [(Vec2(600.0, 500.0), 10.0)])

    step_player(world, player, player_input(aim_scheme=AimScheme.COMPUTER), 0.1)

    # `aim += normalize(target - aim) * |target - aim| * 6 * dt`: 60% of the way.
    assert player.aim == Vec2(560.0, 500.0)
    assert any(projectile.active for projectile in world.state.projectiles.entries)


def test_computer_aim_holds_fire_out_of_reach() -> None:
    world, player = _computer_world(Vec2(500.0, 500.0), [(Vec2(900.0, 500.0), 10.0)])

    step_player(world, player, player_input(aim_scheme=AimScheme.COMPUTER), 0.1)

    assert not any(projectile.active for projectile in world.state.projectiles.entries)


def test_computer_movement_ignores_the_input_move() -> None:
    worlds = []
    for move in (Vec2(), Vec2(1.0, 0.0)):
        world, player = _computer_world(Vec2(500.0, 500.0), [(Vec2(560.0, 520.0), 10.0)])
        player.move_speed = 2.0
        step_player(world, player, player_input(move=move, move_mode=MovementControlType.COMPUTER), 0.016)
        worlds.append(player)
    assert worlds[0].pos == worlds[1].pos
    assert worlds[0].pos != Vec2(500.0, 500.0)


def test_computer_movement_circles_the_centre_without_a_live_target() -> None:
    world, player = _computer_world(Vec2(612.0, 512.0), [(Vec2(700.0, 700.0), 0.0)])
    # Heading east of the centre: the orbit heading is atan2(0, 100) + pi = pi (south).
    player.heading = 3.1415927
    player.move_speed = 2.0

    step_player(world, player, player_input(move_mode=MovementControlType.COMPUTER), 0.016)

    assert player.pos.y > 512.0
    assert abs(player.pos.x - 612.0) < 0.01
