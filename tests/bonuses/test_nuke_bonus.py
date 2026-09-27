from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.bonuses.apply import bonus_apply
from crimson.projectiles.types import ProjectileTemplateId
from crimson.rng_caller_static import RngCallerStatic
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import make_creature_state as _creature
from tests.support.factories import make_step_runtime, place_creatures
from tests.support.helpers import ScriptedCrand, assert_float_close


def test_nuke_damage_is_limited_to_radius() -> None:
    world = make_world()
    player = world.players[0]
    near, far = place_creatures(
        world,
        [
            _creature(pos=player.pos + Vec2(100.0, 0.0), hp=10.0),
            _creature(pos=player.pos + Vec2(300.0, 0.0), hp=10.0),
        ],
    )[:2]
    step_runtime = make_step_runtime(world)

    bonus_apply(
        world.state,
        player,
        BonusId.NUKE,
        amount=1,
        step_runtime=step_runtime,
        origin=player.pos,
        creatures=world.creatures.entries,
        players=world.players,
        detail_preset=5,
    )

    assert near.hp <= 0.0
    assert far.hp == 10.0
    assert [death.index for death in step_runtime.deaths] == [0]
    # The spawn guard holds through the blast, so nuke kills never drop bonuses.
    assert world.state.bonus_pool.iter_active() == []
    assert not world.state.bonus_spawn_guard


def test_nuke_damage_rounds_each_native_radial_distance_operation() -> None:
    world = make_world()
    player = world.players[0]
    # Each hp keeps the explosion-type subtraction exact, so `hp_before - hp` is the dealt damage.
    hp_before = [1000.0, 256.0]
    creatures = place_creatures(
        world,
        [
            _creature(pos=player.pos + Vec2(x_offset, 100.0), hp=hp)
            for x_offset, hp in zip((10.0, 200.0), hp_before, strict=True)
        ],
    )
    bonus_apply(
        world.state,
        player,
        BonusId.NUKE,
        amount=1,
        step_runtime=make_step_runtime(world),
        origin=player.pos,
        creatures=creatures,
        players=world.players,
        detail_preset=5,
    )

    assert [hp - creature.hp for hp, creature in zip(hp_before, creatures[:2], strict=True)] == [
        777.5062255859375,
        161.9660186767578,
    ]


def test_nuke_projectile_parameters_round_each_x87_operation() -> None:
    rng = ScriptedCrand(
        [0, 320, 30, 0, 0, 0, 0, 0, 0, 391, 413],
        fallback=ScriptedCrand.Fallback.ZERO,
    )
    world = make_world()
    world.state.rng = rng
    player = world.players[0]

    bonus_apply(
        world.state,
        player,
        BonusId.NUKE,
        amount=1,
        step_runtime=make_step_runtime(world),
        origin=player.pos,
        creatures=world.creatures.entries,
        players=world.players,
        detail_preset=5,
    )

    active = [entry for entry in world.state.projectiles.entries if entry.active]
    assert active[0].angle == 3.1999998092651367
    assert active[0].speed_scale == 0.7999999523162842
    assert active[-2].angle == 3.9099998474121094
    assert active[-1].angle == 4.130000114440918


def test_nuke_spawns_projectiles_with_weapon_meta_speed() -> None:
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    world = make_world()
    world.state.rng = rng
    player = world.players[0]

    bonus_apply(
        world.state,
        player,
        BonusId.NUKE,
        amount=1,
        step_runtime=make_step_runtime(world),
        origin=player.pos,
        creatures=world.creatures.entries,
        players=world.players,
        detail_preset=5,
    )

    active = [entry for entry in world.state.projectiles.entries if entry.active]

    pistol = [entry for entry in active if entry.type_id == int(ProjectileTemplateId.PISTOL)]
    assert len(pistol) == 4
    for entry in pistol:
        assert_float_close(entry.travel_budget, 55.0)
        assert_float_close(entry.speed_scale, 0.5)

    gauss = [entry for entry in active if entry.type_id == int(ProjectileTemplateId.GAUSS_GUN)]
    assert len(gauss) == 2
    for entry in gauss:
        assert_float_close(entry.travel_budget, 215.0)
        assert_float_close(entry.speed_scale, 1.0)

    assert [record.caller for record in rng.records_since()[:11]] == [
        RngCallerStatic.BONUS_APPLY_NUKE_BULLET_COUNT,
        *([RngCallerStatic.BONUS_APPLY_NUKE_PISTOL_ANGLE, RngCallerStatic.BONUS_APPLY_NUKE_PISTOL_SPEED_SCALE] * 4),
        RngCallerStatic.BONUS_APPLY_NUKE_GAUSS_ANGLE_1,
        RngCallerStatic.BONUS_APPLY_NUKE_GAUSS_ANGLE_2,
    ]
