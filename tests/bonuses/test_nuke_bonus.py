from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.bonuses.apply import bonus_apply
from crimson.creatures.runtime import CreaturePool
from crimson.gameplay import GameplayState
from crimson.projectiles.types import ProjectileTemplateId
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand, assert_float_close


def test_nuke_damage_is_limited_to_radius() -> None:
    state = GameplayState()
    state.bonus_spawn_guard = True
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0))

    pool = CreaturePool()
    near = pool.entries[0]
    near.active = True
    near.pos = player.pos + Vec2(100.0, 0.0)
    near.hp = 10.0
    near.max_hp = 10.0

    far = pool.entries[1]
    far.active = True
    far.pos = player.pos + Vec2(300.0, 0.0)
    far.hp = 10.0
    far.max_hp = 10.0

    bonus_apply(
        state,
        player,
        BonusId.NUKE,
        origin=player.pos,
        creatures=pool.entries,
        players=[player],
        detail_preset=5,
    )

    assert near.hp <= 0.0
    assert far.hp == 10.0
    assert not state.bonus_spawn_guard


def test_nuke_damage_rounds_each_native_radial_distance_operation() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0))
    pool = CreaturePool()
    for index, x_offset in enumerate((10.0, 200.0)):
        creature = pool.entries[index]
        creature.active = True
        creature.pos = player.pos + Vec2(x_offset, 100.0)
        creature.hp = 1000.0

    bonus_apply(
        state,
        player,
        BonusId.NUKE,
        origin=player.pos,
        creatures=pool.entries,
        players=[player],
        detail_preset=5,
    )

    assert pool.entries[0].hp == 222.4937744140625
    assert pool.entries[1].hp == 838.0339965820312


def test_nuke_projectile_parameters_round_each_x87_operation() -> None:
    rng = ScriptedCrand(
        [0, 320, 30, 0, 0, 0, 0, 0, 0, 391, 413],
        fallback=ScriptedCrand.Fallback.ZERO,
    )
    state = GameplayState(rng=rng)
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0))

    bonus_apply(
        state,
        player,
        BonusId.NUKE,
        origin=player.pos,
        creatures=[],
        players=[player],
        detail_preset=5,
    )

    active = [entry for entry in state.projectiles.entries if entry.active]
    assert active[0].angle == 3.1999998092651367
    assert active[0].speed_scale == 0.7999999523162842
    assert active[-2].angle == 3.9099998474121094
    assert active[-1].angle == 4.130000114440918


def test_nuke_spawns_projectiles_with_weapon_meta_speed() -> None:
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    state = GameplayState(rng=rng)
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0))

    bonus_apply(state, player, BonusId.NUKE, origin=player.pos, creatures=[], players=[player], detail_preset=5)

    active = [entry for entry in state.projectiles.entries if entry.active]

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
