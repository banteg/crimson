from __future__ import annotations

import math
import struct

import pytest

from crimson.aim_schemes import AimScheme
from crimson.bonuses import BonusId
from crimson.bonuses.apply import bonus_apply
from crimson.bonuses.hud import bonus_hud_update
from crimson.gameplay import (
    _RELATIVE_MOVE_HEADING_LEFT,
    GameplayState,
    _direction_from_heading_native,
    _player_heading_approach_target_with_delta,
    _player_turn_aligned_velocity_native,
    player_update,
)
from crimson.math_parity import (
    NATIVE_HALF_PI,
    NATIVE_PI,
    NATIVE_TAU,
    f32,
    x87_fpatan,
    x87_pc24_add,
    x87_pc24_mul,
    x87_pc24_mul_chain,
    x87_pc24_sub,
)
from crimson.movement_controls import MovementControlType
from crimson.owner_ref import OwnerRef
from crimson.perks import PerkId
from crimson.perks.runtime.effects import perks_update_effects
from crimson.projectiles.runtime import PrimaryStepCtx, ProjectilePool
from crimson.projectiles.types import ProjectileTemplateId
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapon_runtime import (
    WeaponFireCtx,
    fire_weapon,
    weapon_assign_player,
)
from crimson.weapon_runtime.fire import _native_muzzle_pos
from crimson.weapons import WeaponId
from grim.geom import Vec2
from grim.rand import Crand, RecordingCrand
from grim.sfx_map import SfxId
from tests.support.factories import make_creature_state as _creature
from tests.support.factories import make_projectile_update_options
from tests.support.helpers import ScriptedCrand, assert_float_close


def _active_type_ids(pool: ProjectilePool) -> list[int]:
    return [entry.type_id for entry in pool.entries if entry.active]


def test_player_update_weapon_power_up_scales_shot_cooldown_decay() -> None:
    state = GameplayState()
    state.bonuses.weapon_power_up = 1.0

    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        weapon=WeaponSlot(weapon_id=WeaponId.PISTOL, shot_cooldown=1.0),
    )
    player_update(player, PlayerInput(aim=Vec2(101.0, 100.0)), 0.5, state)

    assert_float_close(player.weapon.shot_cooldown, 0.25)


def test_player_update_shot_cooldown_decay_keeps_tiny_positive_residual() -> None:
    state = GameplayState()
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        weapon=WeaponSlot(weapon_id=WeaponId.PISTOL, shot_cooldown=0.034000005573034286),
    )

    player_update(player, PlayerInput(aim=Vec2(101.0, 100.0)), 0.034, state)

    assert player.weapon.shot_cooldown == 3.725290298461914e-09


def test_player_update_spread_floor_is_native_f32() -> None:
    state = GameplayState()
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        spread_heat=f32(0.01),
    )

    player_update(player, PlayerInput(aim=Vec2(101.0, 100.0)), f32(0.1), state)

    assert player.spread_heat == f32(0.01)
    assert player.spread_heat != 0.01


def test_player_update_low_health_timer_spawns_bleed_fx_and_resets_timer(mocker) -> None:
    rng = ScriptedCrand(0)
    state = GameplayState(rng=rng)
    aim_heading_before = 1.25
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 200.0),
        health=19.0,
        low_health_timer=0.0,
        aim_heading=aim_heading_before,
    )
    spawn_blood_splatter = mocker.Mock()
    state.effects.spawn_blood_splatter = spawn_blood_splatter

    player_update(player, PlayerInput(aim=Vec2(101.0, 200.0)), 0.016, state)

    expected_angle = float(aim_heading_before)
    expected_bleed_dir_angle = float(aim_heading_before) + (1.5707964 - 0.5)
    expected_x = f32(math.cos(expected_bleed_dir_angle) * -6.0 + 100.0)
    expected_y = f32(math.sin(expected_bleed_dir_angle) * -6.0 + 200.0)

    assert spawn_blood_splatter.call_count == 3
    for call in spawn_blood_splatter.call_args_list:
        pos = call.kwargs["pos"]
        assert isinstance(pos, Vec2)
        assert_float_close(pos.x, expected_x)
        assert_float_close(pos.y, expected_y)
        assert call.kwargs["angle"] == expected_angle
        assert call.kwargs["age"] == 0.0
        assert call.kwargs["detail_preset"] == 5
        assert call.kwargs["violence_disabled"] == 0

    assert player.low_health_timer == 1.0
    assert len(state.sfx_queue) == 1
    assert state.sfx_queue[0] in {SfxId.BLOODSPILL_01, SfxId.BLOODSPILL_02}
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PLAYER_UPDATE_LOW_HEALTH_BLOODSPILL,
    ]


def test_player_update_low_health_timer_100_sentinel_skips_bleed_fx(mocker) -> None:
    state = GameplayState()
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 200.0),
        health=19.0,
        low_health_timer=100.0,
    )
    spawn_blood_splatter = mocker.Mock()
    state.effects.spawn_blood_splatter = spawn_blood_splatter

    player_update(player, PlayerInput(aim=Vec2(101.0, 200.0)), 0.016, state)

    spawn_blood_splatter.assert_not_called()
    assert player.low_health_timer == 100.0
    assert state.sfx_queue == []


def test_player_update_spread_damping_scalar_recovers_toward_one_when_gate_non_positive() -> None:
    state = GameplayState(player_spread_damping_scalar=0.5, player_spread_damping_gate=0.0)
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))

    player_update(player, PlayerInput(aim=Vec2(101.0, 100.0)), 0.5, state)

    assert_float_close(state.player_spread_damping_scalar, f32(0.9))


def test_player_update_spread_damping_scalar_decays_to_floor_when_gate_positive() -> None:
    state = GameplayState(player_spread_damping_scalar=0.35, player_spread_damping_gate=1.0)
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))

    player_update(player, PlayerInput(aim=Vec2(101.0, 100.0)), 0.1, state)

    assert_float_close(state.player_spread_damping_scalar, 0.3)


def test_player_update_stationary_reloader_tripples_reload_decay() -> None:
    state = GameplayState()
    player = PlayerState(
        index=0,
        pos=Vec2(50.0, 50.0),
        weapon=WeaponSlot(
            weapon_id=WeaponId.PISTOL,
            clip_size=10,
            ammo=0,
            reload_active=True,
            reload_timer=1.0,
            reload_timer_max=1.0,
        ),
    )
    player.perk_counts[int(PerkId.STATIONARY_RELOADER)] = 1

    player_update(player, PlayerInput(aim=Vec2(51.0, 50.0)), 0.1, state)

    assert_float_close(player.weapon.reload_timer, f32(0.7))


def test_player_update_preloads_ammo_only_before_reload_underflow() -> None:
    state = GameplayState()
    player = PlayerState(
        index=0,
        pos=Vec2(50.0, 50.0),
        weapon=WeaponSlot(
            weapon_id=WeaponId.ION_CANNON,
            clip_size=6,
            ammo=-1.0,
            reload_active=True,
            reload_timer=0.01,
            reload_timer_max=3.0,
            shot_cooldown=0.5,
        ),
    )

    player_update(player, PlayerInput(aim=Vec2(51.0, 50.0)), 0.016, state)

    assert_float_close(player.weapon.ammo, 6.0)


def test_player_update_does_not_preload_ammo_when_reload_timer_is_zero() -> None:
    state = GameplayState()
    player = PlayerState(
        index=0,
        pos=Vec2(50.0, 50.0),
        weapon=WeaponSlot(
            weapon_id=WeaponId.ION_CANNON,
            clip_size=6,
            ammo=-1.0,
            reload_active=True,
            reload_timer=0.0,
            reload_timer_max=3.0,
            shot_cooldown=0.5,
        ),
    )

    player_update(player, PlayerInput(aim=Vec2(51.0, 50.0)), 0.016, state)

    assert_float_close(player.weapon.ammo, -1.0)


def test_player_update_preloads_ammo_on_tiny_negative_reload_crossing() -> None:
    state = GameplayState()
    player = PlayerState(
        index=0,
        pos=Vec2(50.0, 50.0),
        weapon=WeaponSlot(
            weapon_id=WeaponId.ION_CANNON,
            clip_size=6,
            ammo=-1.0,
            reload_active=True,
            reload_timer=0.03199996426701546,
            reload_timer_max=3.0,
            shot_cooldown=0.5,
        ),
    )

    player_update(player, PlayerInput(aim=Vec2(51.0, 50.0)), 0.03200000151991844, state)

    assert_float_close(player.weapon.ammo, 6.0)


def test_player_update_does_not_preload_ammo_on_tiny_positive_reload_residual() -> None:
    state = GameplayState()
    player = PlayerState(
        index=0,
        pos=Vec2(50.0, 50.0),
        weapon=WeaponSlot(
            weapon_id=WeaponId.ION_CANNON,
            clip_size=6,
            ammo=-1.0,
            reload_active=True,
            reload_timer=0.10000000894069672,
            reload_timer_max=3.0,
            shot_cooldown=0.5,
        ),
    )

    player_update(player, PlayerInput(aim=Vec2(51.0, 50.0), fire_down=True), 0.10000000149011612, state)

    assert_float_close(player.weapon.ammo, -1.0)
    assert player.weapon.reload_timer == 7.450580596923828e-09


def test_player_update_empty_reload_fire_tick_keeps_underflow_and_restarts_reload() -> None:
    state = GameplayState()
    player = PlayerState(
        index=0,
        pos=Vec2(50.0, 50.0),
        weapon=WeaponSlot(
            weapon_id=WeaponId.ION_CANNON,
            clip_size=6,
            ammo=0.0,
            reload_active=True,
            reload_timer=0.0,
            reload_timer_max=3.0,
            shot_cooldown=0.0,
        ),
    )

    player_update(
        player,
        PlayerInput(aim=Vec2(51.0, 50.0), fire_down=True),
        0.03100000135600567,
        state,
    )

    assert_float_close(player.weapon.ammo, -1.0)
    assert player.weapon.reload_active is True
    assert player.weapon.reload_timer > 0.0
    assert_float_close(player.weapon.reload_timer, player.weapon.reload_timer_max)


def test_player_update_fire_held_at_reload_boundary_preloads_clip_before_shot() -> None:
    state = GameplayState()
    player = PlayerState(
        index=0,
        pos=Vec2(50.0, 50.0),
        weapon=WeaponSlot(
            weapon_id=WeaponId.SUBMACHINE_GUN,
            clip_size=30,
            ammo=0.0,
            reload_active=True,
            reload_timer=0.09999996426701546,
            reload_timer_max=1.2,
            shot_cooldown=0.0,
        ),
    )

    player_update(
        player,
        PlayerInput(aim=Vec2(51.0, 50.0), fire_down=True),
        0.10000000149011612,
        state,
    )

    assert_float_close(player.weapon.reload_timer, 0.0)
    assert player.weapon.reload_active is False
    assert_float_close(player.weapon.ammo, 29.0)


def test_player_update_tops_up_when_stationary_reload_finishes_same_tick() -> None:
    state = GameplayState()
    player = PlayerState(
        index=0,
        pos=Vec2(50.0, 50.0),
        weapon=WeaponSlot(
            weapon_id=WeaponId.ION_CANNON,
            clip_size=6,
            ammo=0.0,
            reload_active=True,
            reload_timer=0.06,
            reload_timer_max=3.0,
            shot_cooldown=0.5,
        ),
    )
    player.perk_counts[int(PerkId.STATIONARY_RELOADER)] = 1

    player_update(
        player,
        PlayerInput(aim=Vec2(51.0, 50.0), fire_down=True),
        0.03100000135600567,
        state,
    )

    assert_float_close(player.weapon.reload_timer, 0.0)
    assert_float_close(player.weapon.ammo, 6.0)
    assert player.weapon.reload_active is True


def test_player_update_preserve_bugs_keeps_empty_reload_loop() -> None:
    state = GameplayState(preserve_bugs=True)
    player = PlayerState(
        index=0,
        pos=Vec2(50.0, 50.0),
        weapon=WeaponSlot(
            weapon_id=WeaponId.ION_CANNON,
            clip_size=6,
            ammo=0.0,
            reload_active=True,
            reload_timer=0.06,
            reload_timer_max=3.0,
            shot_cooldown=0.5,
        ),
    )
    player.perk_counts[int(PerkId.STATIONARY_RELOADER)] = 1

    player_update(
        player,
        PlayerInput(aim=Vec2(51.0, 50.0), fire_down=True),
        0.03100000135600567,
        state,
    )

    assert_float_close(player.weapon.reload_timer, 0.0)
    assert_float_close(player.weapon.ammo, 0.0)
    assert player.weapon.reload_active is True


def test_player_update_move_to_cursor_reload_key_does_not_start_reload() -> None:
    state = GameplayState()
    player = PlayerState(
        index=0,
        pos=Vec2(50.0, 50.0),
        weapon=WeaponSlot(weapon_id=WeaponId.PISTOL, clip_size=10, ammo=10),
    )

    player_update(
        player,
        PlayerInput(
            aim=Vec2(51.0, 50.0),
            reload_pressed=True,
            move_to_cursor_pressed=True,
        ),
        0.1,
        state,
    )

    assert player.weapon.reload_active is False
    assert player.weapon.reload_timer == 0.0


def test_player_update_mode4_reload_gate_blocks_manual_reload_without_cursor_key_state() -> None:
    state = GameplayState()
    player = PlayerState(
        index=0,
        pos=Vec2(50.0, 50.0),
        weapon=WeaponSlot(weapon_id=WeaponId.PISTOL, clip_size=10, ammo=0.0),
    )

    player_update(
        player,
        PlayerInput(
            aim=Vec2(51.0, 50.0),
            reload_pressed=True,
            move_mode=MovementControlType.MOUSE_POINT_CLICK,
            move_to_cursor_pressed=False,
        ),
        0.1,
        state,
    )

    assert player.weapon.reload_active is False
    assert player.weapon.reload_timer == 0.0


def test_player_update_manual_reload_requires_single_player() -> None:
    state = GameplayState()
    player0 = PlayerState(
        index=0,
        pos=Vec2(50.0, 50.0),
        weapon=WeaponSlot(weapon_id=WeaponId.PISTOL, clip_size=10, ammo=0.0),
    )
    player1 = PlayerState(
        index=1,
        pos=Vec2(60.0, 50.0),
        weapon=WeaponSlot(weapon_id=WeaponId.PISTOL, clip_size=10, ammo=10.0),
    )

    player_update(
        player0,
        PlayerInput(aim=Vec2(51.0, 50.0), reload_pressed=True),
        0.1,
        state,
        players=[player0, player1],
    )

    assert player0.weapon.reload_active is False
    assert player0.weapon.reload_timer == 0.0


def test_player_update_speed_bonus_expires_before_player_update_step() -> None:
    state = GameplayState()
    no_bonus = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    no_bonus.move_speed = 2.0
    no_bonus.heading = 0.0

    with_bonus = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    with_bonus.speed_bonus_timer = 0.018
    with_bonus.move_speed = 2.0
    with_bonus.heading = 0.0

    input_state = PlayerInput(move=Vec2(1.0, 0.0), aim=Vec2(200.0, 100.0))
    perks_update_effects(state, [no_bonus, with_bonus], 0.018)
    player_update(no_bonus, input_state, 0.018, state)
    player_update(with_bonus, input_state, 0.018, state)

    no_bonus_delta = (no_bonus.pos - Vec2(100.0, 100.0)).length()
    with_bonus_delta = (with_bonus.pos - Vec2(100.0, 100.0)).length()

    assert_float_close(with_bonus_delta, no_bonus_delta)
    assert_float_close(with_bonus.speed_bonus_timer, 0.0)


def test_player_update_angry_reloader_spawns_ring_at_half() -> None:
    pool = ProjectilePool(size=64)
    state = GameplayState(projectiles=pool)
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        weapon=WeaponSlot(
            weapon_id=WeaponId.PISTOL,
            clip_size=10,
            ammo=0,
            reload_active=True,
            reload_timer=1.1,
            reload_timer_max=2.0,
        ),
    )
    player.perk_counts[int(PerkId.ANGRY_RELOADER)] = 1

    player_update(player, PlayerInput(aim=Vec2(101.0, 100.0)), 0.2, state)

    owners = {entry.owner for entry in pool.entries if entry.active}
    assert owners == {OwnerRef.from_local_player(0)}
    type_ids = _active_type_ids(pool)
    assert type_ids.count(int(ProjectileTemplateId.PLASMA_MINIGUN)) == 15


def test_player_update_man_bomb_spawns_8_projectiles_when_charged() -> None:
    pool = ProjectilePool(size=32)
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    state = GameplayState(projectiles=pool, rng=rng)
    state.bonus_spawn_guard = True
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), man_bomb_timer=3.9)
    player.perk_counts[int(PerkId.MAN_BOMB)] = 1

    player_update(player, PlayerInput(aim=Vec2(101.0, 100.0)), 0.2, state)

    assert state.bonus_spawn_guard
    owners = {entry.owner for entry in pool.entries if entry.active}
    assert owners == {OwnerRef.from_local_player(0)}
    type_ids = _active_type_ids(pool)
    assert len(type_ids) == 8
    assert type_ids.count(int(ProjectileTemplateId.ION_MINIGUN)) == 4
    assert type_ids.count(int(ProjectileTemplateId.ION_RIFLE)) == 4
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PLAYER_UPDATE_MAN_BOMB_ION_MINIGUN_ANGLE,
        RngCallerStatic.PLAYER_UPDATE_MAN_BOMB_ION_RIFLE_ANGLE,
        RngCallerStatic.PLAYER_UPDATE_MAN_BOMB_ION_MINIGUN_ANGLE,
        RngCallerStatic.PLAYER_UPDATE_MAN_BOMB_ION_RIFLE_ANGLE,
        RngCallerStatic.PLAYER_UPDATE_MAN_BOMB_ION_MINIGUN_ANGLE,
        RngCallerStatic.PLAYER_UPDATE_MAN_BOMB_ION_RIFLE_ANGLE,
        RngCallerStatic.PLAYER_UPDATE_MAN_BOMB_ION_MINIGUN_ANGLE,
        RngCallerStatic.PLAYER_UPDATE_MAN_BOMB_ION_RIFLE_ANGLE,
    ]


def test_player_update_man_bomb_can_fire_on_large_moving_frame_then_resets() -> None:
    pool = ProjectilePool(size=32)
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    state = GameplayState(projectiles=pool, rng=rng)
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), man_bomb_timer=0.0)
    player.perk_counts[int(PerkId.MAN_BOMB)] = 1

    player_update(player, PlayerInput(move=Vec2(1.0, 0.0), aim=Vec2(101.0, 100.0)), 4.2, state)

    type_ids = _active_type_ids(pool)
    assert len(type_ids) == 8
    assert type_ids.count(int(ProjectileTemplateId.ION_MINIGUN)) == 4
    assert type_ids.count(int(ProjectileTemplateId.ION_RIFLE)) == 4
    assert player.man_bomb_timer == 0.0
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PLAYER_UPDATE_MAN_BOMB_ION_MINIGUN_ANGLE,
        RngCallerStatic.PLAYER_UPDATE_MAN_BOMB_ION_RIFLE_ANGLE,
        RngCallerStatic.PLAYER_UPDATE_MAN_BOMB_ION_MINIGUN_ANGLE,
        RngCallerStatic.PLAYER_UPDATE_MAN_BOMB_ION_RIFLE_ANGLE,
        RngCallerStatic.PLAYER_UPDATE_MAN_BOMB_ION_MINIGUN_ANGLE,
        RngCallerStatic.PLAYER_UPDATE_MAN_BOMB_ION_RIFLE_ANGLE,
        RngCallerStatic.PLAYER_UPDATE_MAN_BOMB_ION_MINIGUN_ANGLE,
        RngCallerStatic.PLAYER_UPDATE_MAN_BOMB_ION_RIFLE_ANGLE,
    ]


def test_player_update_fire_cough_spawns_fire_bullet_projectile() -> None:
    pool = ProjectilePool(size=8)
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    state = GameplayState(projectiles=pool, rng=rng)
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), fire_cough_timer=1.95)
    player.perk_counts[int(PerkId.FIRE_CAUGH)] = 1

    player_update(player, PlayerInput(aim=Vec2(101.0, 100.0)), 0.1, state)

    owners = {entry.owner for entry in pool.entries if entry.active}
    assert owners == {OwnerRef.from_local_player(0)}
    type_ids = _active_type_ids(pool)
    assert type_ids == [int(ProjectileTemplateId.FIRE_BULLETS)]
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PLAYER_UPDATE_FIRE_COUGH_SPREAD_DIR,
        RngCallerStatic.PLAYER_UPDATE_FIRE_COUGH_SPREAD_MAG,
        RngCallerStatic.FX_SPAWN_SPRITE_ROTATION,
        RngCallerStatic.PLAYER_UPDATE_FIRE_COUGH_INTERVAL_RESET,
    ]


def test_player_update_fire_cough_uses_pre_move_position_for_spawn() -> None:
    pool = ProjectilePool(size=8)
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    state = GameplayState(projectiles=pool, rng=rng)
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        aim=Vec2(200.0, 100.0),
        aim_heading=0.0,
        fire_cough_timer=1.95,
    )
    player.perk_counts[int(PerkId.FIRE_CAUGH)] = 1

    before_pos = Vec2(float(player.pos.x), float(player.pos.y))
    player_update(
        player,
        PlayerInput(move=Vec2(1.0, 0.0), aim=Vec2(200.0, 100.0)),
        0.1,
        state,
    )

    assert float(player.pos.x) > float(before_pos.x)
    entry = next(e for e in pool.entries if e.active)
    assert int(entry.type_id) == int(ProjectileTemplateId.FIRE_BULLETS)

    expected = before_pos + Vec2.from_heading(0.0).rotated(-0.150915) * 16.0
    assert_float_close(float(entry.pos.x), float(f32(float(expected.x))))
    assert_float_close(float(entry.pos.y), float(f32(float(expected.y))))
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PLAYER_UPDATE_FIRE_COUGH_SPREAD_DIR,
        RngCallerStatic.PLAYER_UPDATE_FIRE_COUGH_SPREAD_MAG,
        RngCallerStatic.FX_SPAWN_SPRITE_ROTATION,
        RngCallerStatic.PLAYER_UPDATE_FIRE_COUGH_INTERVAL_RESET,
    ]


def test_player_fire_weapon_fire_bullets_spawns_weapon_pellet_count() -> None:
    pool = ProjectilePool(size=64)
    state = GameplayState(projectiles=pool)
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        weapon=WeaponSlot(weapon_id=WeaponId.SHOTGUN, clip_size=10, ammo=10),
        fire_bullets_timer=1.0,
    )
    player.aim_dir = Vec2(1.0, 0.0)

    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(fire_down=True, aim=Vec2(101.0, 100.0)),
            dt=0.0,
            state=state,
        ),
    )

    type_ids = _active_type_ids(pool)
    assert len(type_ids) == 12
    assert set(type_ids) == {int(ProjectileTemplateId.FIRE_BULLETS)}


def test_player_fire_weapon_fire_bullets_overrides_rocket_weapons() -> None:
    from crimson.weapons import WEAPON_BY_ID

    rocket_weapon_ids = (
        WeaponId.ROCKET_LAUNCHER,
        WeaponId.SEEKER_ROCKETS,
        WeaponId.MINI_ROCKET_SWARMERS,
        WeaponId.ROCKET_MINIGUN,
    )

    for weapon_id in rocket_weapon_ids:
        pool = ProjectilePool(size=64)
        state = GameplayState(projectiles=pool)
        player = PlayerState(index=0, pos=Vec2())
        player.aim_dir = Vec2(1.0, 0.0)
        player.spread_heat = 0.0
        weapon_assign_player(player, weapon_id, state=state)

        player.fire_bullets_timer = 1.0

        fire_weapon(
            WeaponFireCtx(
                player=player,
                input_state=PlayerInput(fire_down=True, aim=Vec2(200.0, 0.0)),
                dt=0.016,
                state=state,
            ),
        )

        weapon = WEAPON_BY_ID[weapon_id]

        type_ids = _active_type_ids(pool)
        assert len(type_ids) == int(weapon.pellet_count)
        assert set(type_ids) == {int(ProjectileTemplateId.FIRE_BULLETS)}
        assert not any(entry.active for entry in state.secondary_projectiles.entries)


def test_player_fire_weapon_fire_bullets_does_not_consume_ammo() -> None:
    pool = ProjectilePool(size=64)
    state = GameplayState(projectiles=pool)
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        weapon=WeaponSlot(weapon_id=WeaponId.SHOTGUN, clip_size=10, ammo=10),
        fire_bullets_timer=1.0,
    )
    player.aim_dir = Vec2(1.0, 0.0)

    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(fire_down=True, aim=Vec2(101.0, 100.0)),
            dt=0.0,
            state=state,
        ),
    )

    assert_float_close(player.weapon.ammo, 10.0)


def test_player_fire_weapon_fire_bullets_can_fire_at_zero_ammo_and_then_reload() -> None:
    pool = ProjectilePool(size=64)
    state = GameplayState(projectiles=pool)
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        weapon=WeaponSlot(weapon_id=WeaponId.SHOTGUN, clip_size=10, ammo=0),
        fire_bullets_timer=1.0,
    )
    player.aim_dir = Vec2(1.0, 0.0)

    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(fire_down=True, aim=Vec2(101.0, 100.0)),
            dt=0.0,
            state=state,
        ),
    )

    type_ids = _active_type_ids(pool)
    assert len(type_ids) == 12
    assert set(type_ids) == {int(ProjectileTemplateId.FIRE_BULLETS)}
    assert player.weapon.reload_active
    assert player.weapon.reload_timer > 0.0


def test_player_fire_weapon_can_fire_with_negative_ammo_then_reloads() -> None:
    pool = ProjectilePool(size=8)
    state = GameplayState(projectiles=pool)
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        weapon=WeaponSlot(weapon_id=WeaponId.ION_CANNON, clip_size=6, ammo=-1.0, reload_active=False, reload_timer=0.0),
    )
    player.aim_dir = Vec2(1.0, 0.0)

    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(fire_down=True, aim=Vec2(200.0, 100.0)),
            dt=0.016,
            state=state,
        ),
    )

    type_ids = _active_type_ids(pool)
    assert type_ids == [int(ProjectileTemplateId.ION_CANNON)]
    assert_float_close(player.weapon.ammo, -2.0)
    assert player.weapon.reload_active
    assert_float_close(player.weapon.reload_timer, 3.0)


def test_player_fire_weapon_spread_cap_is_native_f32() -> None:
    pool = ProjectilePool(size=8)
    state = GameplayState(projectiles=pool)
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        weapon=WeaponSlot(weapon_id=WeaponId.PISTOL, clip_size=10, ammo=10),
        spread_heat=f32(0.47),
    )

    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(fire_down=True, aim=Vec2(200.0, 100.0)),
            dt=0.0,
            state=state,
        ),
    )

    assert player.spread_heat == f32(0.48)
    assert player.spread_heat != 0.48


def test_player_fire_weapon_fire_bullets_uses_fire_bullets_spread_heat_inc_for_pellet_weapons() -> None:
    from crimson.weapons import weapon_entry_for_projectile_type_id

    pool = ProjectilePool(size=64)
    state = GameplayState(projectiles=pool)
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        weapon=WeaponSlot(weapon_id=WeaponId.SHOTGUN, clip_size=10, ammo=10),
        fire_bullets_timer=1.0,
    )
    player.aim_dir = Vec2(1.0, 0.0)

    fire_bullets_weapon = weapon_entry_for_projectile_type_id(ProjectileTemplateId.FIRE_BULLETS)

    start_heat = player.spread_heat
    expected = x87_pc24_add(
        start_heat,
        x87_pc24_mul(fire_bullets_weapon.spread_heat_inc, f32(1.3)),
    )

    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(fire_down=True, aim=Vec2(101.0, 100.0)),
            dt=0.0,
            state=state,
        ),
    )

    assert player.spread_heat == expected


def test_player_fire_weapon_fire_bullets_uses_fire_bullets_spread_heat_inc_for_single_pellet_weapons() -> None:
    from crimson.projectiles.types import ProjectileTemplateId
    from crimson.weapons import weapon_entry_for_projectile_type_id

    pool = ProjectilePool(size=64)
    state = GameplayState(projectiles=pool)
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE, clip_size=25, ammo=25),
        fire_bullets_timer=1.0,
    )
    player.aim_dir = Vec2(1.0, 0.0)

    fire_bullets_weapon = weapon_entry_for_projectile_type_id(ProjectileTemplateId.FIRE_BULLETS)

    start_heat = player.spread_heat
    expected = x87_pc24_add(
        start_heat,
        x87_pc24_mul(fire_bullets_weapon.spread_heat_inc, f32(1.3)),
    )

    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(fire_down=True, aim=Vec2(101.0, 100.0)),
            dt=0.0,
            state=state,
        ),
    )

    assert player.spread_heat == expected


def test_player_fire_weapon_shotgun_spawns_pellets() -> None:
    pool = ProjectilePool(size=64)
    state = GameplayState(projectiles=pool)
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        weapon=WeaponSlot(weapon_id=WeaponId.SHOTGUN, clip_size=10, ammo=10),
    )
    player.aim_dir = Vec2(1.0, 0.0)

    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(fire_down=True, aim=Vec2(101.0, 100.0)),
            dt=0.0,
            state=state,
        ),
    )

    type_ids = _active_type_ids(pool)
    assert len(type_ids) == 12
    assert set(type_ids) == {int(ProjectileTemplateId.SHOTGUN)}


def test_player_update_tracks_aim_point() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(10.0, 20.0))
    input_state = PlayerInput(aim=Vec2(123.0, 456.0))

    player_update(player, input_state, 0.1, state)

    assert player.aim == Vec2(123.0, 456.0)


def test_player_update_sets_survival_fire_seen_when_fire_input_is_down() -> None:
    state = GameplayState()
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        weapon=WeaponSlot(weapon_id=WeaponId.PISTOL, shot_cooldown=1.0),
    )

    player_update(player, PlayerInput(aim=Vec2(101.0, 100.0), fire_down=True), 0.016, state)

    assert state.survival_reward_fire_seen is True


def test_player_update_turns_toward_move_heading_with_turn_slowdown() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), move_speed=2.0, heading=0.0)
    input_state = PlayerInput(move=Vec2(1.0, 0.0), aim=Vec2(101.0, 100.0))

    player_update(player, input_state, 0.1, state)

    # Native turn target here is diagonal right; heading settles at f32(pi/4).
    expected_heading = f32(math.pi / 4.0)
    radians = float(expected_heading) - 1.5707964
    move_x = math.cos(radians)
    move_y = math.sin(radians)
    move_dx = f32(move_x * 2.0 * 25.0)
    move_dy = f32(move_y * 2.0 * 25.0)
    expected_x = f32(100.0 + float(f32(0.1 * float(move_dx))))
    expected_y = f32(100.0 + float(f32(0.1 * float(move_dy))))

    assert_float_close(player.pos.x, expected_x)
    assert_float_close(player.pos.y, expected_y)
    assert_float_close(player.heading, expected_heading)


def test_player_update_w_then_up_left_converges_to_diagonal_heading() -> None:
    def _angular_distance(a: float, b: float) -> float:
        diff = abs((a - b) % math.tau)
        return min(diff, math.tau - diff)

    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), move_speed=2.0, heading=0.0)
    dt = 1.0 / 60.0
    aim = Vec2(200.0, 100.0)

    for _ in range(30):
        player_update(player, PlayerInput(move=Vec2(0.0, -1.0), aim=aim), dt, state)

    target_heading = Vec2(-1.0, -1.0).to_heading() % math.tau
    start_diff = _angular_distance(player.heading % math.tau, target_heading)

    for _ in range(20):
        player_update(player, PlayerInput(move=Vec2(-1.0, -1.0), aim=aim), dt, state)

    end_diff = _angular_distance(player.heading % math.tau, target_heading)
    assert end_diff < start_diff - 0.25
    assert end_diff < 0.4


def test_player_update_relative_mode_dispatch_updates_turn_speed() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), heading=0.0, aim_heading=0.0, move_speed=0.5, turn_speed=1.0)
    input_state = PlayerInput(
        aim=Vec2(200.0, 100.0),
        move_mode=MovementControlType.RELATIVE,
        move_forward_pressed=False,
        move_backward_pressed=False,
        turn_left_pressed=False,
        turn_right_pressed=True,
    )

    player_update(player, input_state, 0.1, state)

    assert player.turn_speed > 1.0
    assert player.heading > 0.0


def test_player_update_digital_turn_only_rotates_and_accelerates() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), heading=0.0, aim_heading=0.0, move_speed=0.0, turn_speed=1.0)
    input_state = PlayerInput(
        move=Vec2(1.0, 0.0),
        aim=Vec2(200.0, 100.0),
        move_forward_pressed=False,
        move_backward_pressed=False,
        turn_left_pressed=False,
        turn_right_pressed=True,
    )

    player_update(player, input_state, 0.1, state)

    assert player.heading > 0.0
    assert (float(player.aim_heading) % math.tau) > 0.0
    assert_float_close(player.turn_speed, 1.0)
    assert player.move_speed > 0.0
    assert player.pos.x > 100.0
    assert player.pos.y < 100.0


def test_player_update_digital_forward_turn_moves_in_heading_direction() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), heading=0.0, aim_heading=0.0, move_speed=0.0, turn_speed=1.0)
    input_state = PlayerInput(
        move=Vec2(-1.0, -1.0),
        aim=Vec2(200.0, 100.0),
        move_forward_pressed=True,
        move_backward_pressed=False,
        turn_left_pressed=True,
        turn_right_pressed=False,
    )

    player_update(player, input_state, 0.1, state)

    assert player.heading < 0.0
    assert_float_close(
        float(f32(float(player.aim_heading) % math.tau)),
        float(f32((player.aim - player.pos).to_heading() % math.tau)),
    )
    assert_float_close(player.turn_speed, 1.0)
    assert player.move_speed > 0.0
    assert player.pos.x < 100.0
    assert player.pos.y < 100.0


def test_player_update_digital_turn_conflict_prefers_right() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), heading=0.0, aim_heading=0.0, move_speed=0.0, turn_speed=1.0)
    input_state = PlayerInput(
        move=Vec2(0.0, 0.0),
        aim=Vec2(200.0, 100.0),
        move_forward_pressed=False,
        move_backward_pressed=False,
        turn_left_pressed=True,
        turn_right_pressed=True,
    )

    player_update(player, input_state, 0.1, state)

    assert player.heading > 0.0
    assert (float(player.aim_heading) % math.tau) > math.pi / 2.0
    assert_float_close(player.turn_speed, 1.0)
    assert player.pos.x > 100.0
    assert player.pos.y < 100.0


def test_player_update_digital_move_conflict_prefers_backward() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), heading=0.0, aim_heading=0.0, move_speed=0.0, turn_speed=1.0)
    input_state = PlayerInput(
        move=Vec2(0.0, 0.0),
        aim=Vec2(200.0, 100.0),
        move_forward_pressed=True,
        move_backward_pressed=True,
        turn_left_pressed=False,
        turn_right_pressed=False,
    )

    player_update(player, input_state, 0.1, state)

    assert player.move_speed > 0.0
    assert_float_close(player.pos.x, 100.0)
    assert_float_close(player.pos.y, 100.0)
    assert player.heading > 0.0


def test_player_update_move_phase_uses_native_intermediate_f32_store() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0))

    player_update(
        player,
        PlayerInput(move=Vec2(0.0, 1.0), aim=Vec2(512.0, 512.0)),
        0.03200000151991844,
        state,
    )

    assert player.move_speed == f32(0.1600000113248825)
    assert player.move_phase == f32(f32(0.03200000151991844 * player.move_speed) * 19.0)


def test_player_update_minigun_speed_cap_is_f32_before_move_phase() -> None:
    state = GameplayState()
    player = PlayerState(
        index=0,
        pos=Vec2(439.3449401855469, 646.193603515625),
        move_speed=f32(0.8),
        move_phase=1.4318476915359497,
        weapon=WeaponSlot(weapon_id=WeaponId.MEAN_MINIGUN, clip_size=120, ammo=19),
    )

    player_update(
        player,
        PlayerInput(
            aim=Vec2(560.0, 496.0),
            move_forward_pressed=True,
            move_backward_pressed=False,
            turn_left_pressed=False,
            turn_right_pressed=True,
        ),
        0.08900000154972076,
        state,
    )

    assert player.move_speed == f32(0.8)
    assert player.move_phase == 2.7846479415893555


def test_player_update_move_speed_uses_native_acceleration_f32_store() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), move_speed=0.4750000238418579)

    player_update(
        player,
        PlayerInput(move=Vec2(0.0, 1.0), aim=Vec2(512.0, 512.0)),
        0.032999999821186066,
        state,
    )

    assert player.move_speed == 0.6399999856948853


def test_player_direction_heading_subtraction_uses_native_f32_store() -> None:
    heading = 3.93251371383667

    direction = _direction_from_heading_native(heading)
    radians = f32(heading - NATIVE_HALF_PI)

    assert direction.x == math.cos(radians)
    assert direction.y == math.sin(radians)


def test_player_turn_aligned_velocity_uses_native_intermediate_f32_stores() -> None:
    # Retaining the full product until the final velocity store moves this
    # backward-diagonal step one ULP too far left.
    direction = _direction_from_heading_native(3.9270143508911133)

    velocity = _player_turn_aligned_velocity_native(
        direction=direction,
        move_speed=2.0,
        angle_diff=3.0040740966796875e-05,
        speed_multiplier=2.0,
    )

    assert velocity == Vec2(-70.7116470336914, 70.7083511352539)
    assert f32(302.53350830078125 + f32(0.04400000348687172 * velocity.x)) == 299.4222106933594


def test_player_update_keyboard_aim_scheme_uses_heading_dispatch() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), heading=0.0, aim_heading=0.0)
    input_state = PlayerInput(
        move=Vec2(),
        aim=Vec2(500.0, 500.0),
        move_mode=MovementControlType.STATIC,
        aim_scheme=AimScheme.KEYBOARD,
        turn_left_pressed=False,
        turn_right_pressed=True,
        move_forward_pressed=False,
        move_backward_pressed=False,
    )

    player_update(player, input_state, 0.1, state)

    assert player.aim != Vec2(500.0, 500.0)
    assert_float_close(
        float(f32((player.aim - player.pos).to_heading() % math.tau)),
        float(f32(float(player.aim_heading) % math.tau)),
    )


def test_player_update_wraps_negative_target_heading_before_turning() -> None:
    state = GameplayState()
    player = PlayerState(
        index=0,
        pos=Vec2(796.2267, 538.7482),
        move_speed=2.0,
        heading=-0.011166,
    )
    input_state = PlayerInput(move=Vec2(-1.0, -1.0), aim=Vec2(972.364, 723.654))

    player_update(player, input_state, 0.011, state)

    # Native normalizes movement target headings into [0, 2pi] before
    # `player_heading_approach_target`; x movement should continue left here.
    assert player.pos.x < 796.2267
    assert player.heading < math.tau


def test_player_heading_approach_target_spills_scaled_product_to_float32() -> None:
    def _f32_from_bits(bits: int) -> float:
        return struct.unpack("<f", struct.pack("<I", int(bits) & 0xFFFFFFFF))[0]

    def _bits_f32(value: float) -> int:
        return struct.unpack("<I", struct.pack("<f", float(value)))[0]

    # Without a float32 spill of `frame_dt * diff`, this opposite-heading
    # boundary turns one ULP too far.
    heading_before = _f32_from_bits(0x40966A37)
    dt = _f32_from_bits(0x3D75C290)

    player = PlayerState(index=0, pos=Vec2(), heading=heading_before)
    diff, turn_delta = _player_heading_approach_target_with_delta(player, float(_RELATIVE_MOVE_HEADING_LEFT), dt)

    assert _bits_f32(diff) == 0x3C435A00
    assert _bits_f32(turn_delta) == 0x3B6A6C00
    assert _bits_f32(player.heading) == 0x40968784


def test_player_fire_weapon_uses_disc_spread_jitter() -> None:
    pool = ProjectilePool(size=8)
    seed = 0xBEEF
    rng = RecordingCrand(Crand(seed))
    state = GameplayState(projectiles=pool, rng=rng)

    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        weapon=WeaponSlot(weapon_id=WeaponId.PISTOL, clip_size=10, ammo=10),
        spread_heat=0.2,
    )

    aim_x = 200.0
    aim_y = 100.0

    expected_rng = Crand(seed)
    # Native gameplay fire uses four exact `player_update` casing draws before
    # the later shot-angle jitter work.
    for _ in range(4):
        expected_rng.rand()
    rand_dir = expected_rng.rand()
    rand_mag = expected_rng.rand()

    dx = x87_pc24_sub(aim_x, player.pos.x)
    dy = x87_pc24_sub(aim_y, player.pos.y)
    dist_sq = x87_pc24_add(x87_pc24_mul(dx, dx), x87_pc24_mul(dy, dy))
    half_len = x87_pc24_mul(math.sqrt(dist_sq), 0.5)
    offset_term = x87_pc24_mul_chain(
        half_len,
        player.spread_heat,
        float(rand_mag & 0x1FF),
        0.001953125,
    )
    dir_angle = x87_pc24_mul(float(rand_dir & 0x1FF), f32(float(NATIVE_TAU) / 512.0))
    jitter_x = x87_pc24_add(x87_pc24_mul(math.cos(dir_angle), offset_term), aim_x)
    jitter_y = x87_pc24_add(x87_pc24_mul(math.sin(dir_angle), offset_term), aim_y)
    expected_angle = x87_pc24_sub(
        x87_fpatan(
            x87_pc24_sub(player.pos.y, jitter_y),
            x87_pc24_sub(player.pos.x, jitter_x),
        ),
        NATIVE_HALF_PI,
    )

    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(fire_down=True, aim=Vec2(aim_x, aim_y)),
            dt=0.0,
            state=state,
        ),
    )

    projectiles = pool.iter_active()
    assert len(projectiles) == 1
    assert_float_close(projectiles[0].angle, expected_angle)
    assert len(state.effects.iter_active()) == 1
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PLAYER_UPDATE_CASING_ANGLE,
        RngCallerStatic.PLAYER_UPDATE_CASING_SPEED,
        RngCallerStatic.PLAYER_UPDATE_CASING_ROTATION,
        RngCallerStatic.PLAYER_UPDATE_CASING_ROTATION_STEP,
        RngCallerStatic.PLAYER_UPDATE_SHOT_JITTER_DIR,
        RngCallerStatic.PLAYER_UPDATE_SHOT_JITTER_MAG,
        RngCallerStatic.PLAYER_UPDATE_SHOT_SFX,
        RngCallerStatic.FX_SPAWN_SPRITE_ROTATION,
        RngCallerStatic.FX_SPAWN_SPRITE_ROTATION,
    ]


def test_player_fire_weapon_disc_spread_rounds_each_x87_operation() -> None:
    pool = ProjectilePool(size=8)
    state = GameplayState(
        projectiles=pool,
        rng=ScriptedCrand(
            [3210, 6757, 16721, 32587, 146, 4299, 4835],
            fallback=ScriptedCrand.Fallback.REPEAT_LAST,
        ),
    )
    player = PlayerState(
        index=0,
        pos=Vec2(284.0749816894531, 934.1846923828125),
        weapon=WeaponSlot(weapon_id=WeaponId.MEAN_MINIGUN, clip_size=120, ammo=110),
        spread_heat=0.24259991943836212,
    )

    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(fire_down=True, aim=Vec2(272.0, 787.0)),
            dt=0.07300000637769699,
            state=state,
        ),
    )

    projectiles = pool.iter_active()
    assert len(projectiles) == 1
    assert projectiles[0].angle == -0.09688407182693481
    assert player.spread_heat == 0.32319992780685425


def test_player_fire_weapon_uses_native_muzzle_arithmetic() -> None:
    muzzle = _native_muzzle_pos(
        Vec2(137.84991455078125, 935.0262451171875),
        -4.14423131942749,
    )

    assert muzzle == Vec2(152.47727966308594, 941.5100708007812)


def test_player_fire_weapon_secondary_owner_uses_native_friendly_fire_encoding() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    weapon_assign_player(player, WeaponId.SEEKER_ROCKETS, state=state)

    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(fire_down=True, aim=Vec2(200.0, 100.0)),
            dt=0.0,
            state=state,
            creatures=[],
        ),
    )

    projectile = state.secondary_projectiles.iter_active()[0]
    assert projectile.owner.to_legacy() == -100


@pytest.mark.parametrize(
    ("weapon_id", "pellet_count", "jitter_caller", "speed_caller"),
    [
        (
            WeaponId.SHOTGUN,
            12,
            RngCallerStatic.PLAYER_UPDATE_SHOTGUN_PELLET_JITTER,
            RngCallerStatic.PLAYER_UPDATE_SHOTGUN_PELLET_SPEED_SCALE,
        ),
        (
            WeaponId.SAWED_OFF_SHOTGUN,
            12,
            RngCallerStatic.PLAYER_UPDATE_SAWED_OFF_SHOTGUN_PELLET_JITTER,
            RngCallerStatic.PLAYER_UPDATE_SAWED_OFF_SHOTGUN_PELLET_SPEED_SCALE,
        ),
        (
            WeaponId.JACKHAMMER,
            4,
            RngCallerStatic.PLAYER_UPDATE_JACKHAMMER_PELLET_JITTER,
            RngCallerStatic.PLAYER_UPDATE_JACKHAMMER_PELLET_SPEED_SCALE,
        ),
        (
            WeaponId.GAUSS_SHOTGUN,
            6,
            RngCallerStatic.PLAYER_UPDATE_GAUSS_SHOTGUN_PELLET_JITTER,
            RngCallerStatic.PLAYER_UPDATE_GAUSS_SHOTGUN_PELLET_SPEED_SCALE,
        ),
        (
            WeaponId.ION_SHOTGUN,
            8,
            RngCallerStatic.PLAYER_UPDATE_ION_SHOTGUN_PELLET_JITTER,
            RngCallerStatic.PLAYER_UPDATE_ION_SHOTGUN_PELLET_SPEED_SCALE,
        ),
        (
            WeaponId.PLASMA_SHOTGUN,
            14,
            RngCallerStatic.PLAYER_UPDATE_PLASMA_SHOTGUN_PELLET_JITTER,
            RngCallerStatic.PLAYER_UPDATE_PLASMA_SHOTGUN_PELLET_SPEED_SCALE,
        ),
    ],
)
def test_player_fire_weapon_tags_exact_pellet_loop_callers(
    weapon_id: WeaponId,
    pellet_count: int,
    jitter_caller: RngCallerStatic,
    speed_caller: RngCallerStatic,
) -> None:
    pool = ProjectilePool(size=64)
    rng = RecordingCrand(Crand(0xBEEF))
    state = GameplayState(projectiles=pool, rng=rng)
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        weapon=WeaponSlot(weapon_id=weapon_id, clip_size=99, ammo=99),
    )

    fire_weapon(
        WeaponFireCtx(
            player=player,
            input_state=PlayerInput(fire_down=True, aim=Vec2(200.0, 100.0)),
            dt=0.0,
            state=state,
        ),
    )

    assert len(pool.iter_active()) == pellet_count
    assert [record.caller for record in rng.records_since()[-(pellet_count * 2) :]] == [
        caller for _ in range(pellet_count) for caller in (jitter_caller, speed_caller)
    ]


def test_player_update_hot_tempered_spawns_ring() -> None:
    pool = ProjectilePool(size=16)
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    state = GameplayState(projectiles=pool, rng=rng)
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), hot_tempered_timer=1.95)
    player.perk_counts[int(PerkId.HOT_TEMPERED)] = 1

    player_update(player, PlayerInput(aim=Vec2(101.0, 100.0)), 0.1, state)

    owners = {entry.owner for entry in pool.entries if entry.active}
    assert owners == {OwnerRef.from_local_player(0)}
    type_ids = _active_type_ids(pool)
    assert len(type_ids) == 8
    assert type_ids.count(int(ProjectileTemplateId.PLASMA_MINIGUN)) == 4
    assert type_ids.count(int(ProjectileTemplateId.PLASMA_RIFLE)) == 4
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PLAYER_UPDATE_HOT_TEMPERED_INTERVAL_RESET,
    ]


def test_player_update_hot_tempered_spawns_from_pre_move_position() -> None:
    pool = ProjectilePool(size=16)
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    state = GameplayState(projectiles=pool, rng=rng)
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), hot_tempered_timer=1.95)
    player.perk_counts[int(PerkId.HOT_TEMPERED)] = 1

    player_update(
        player,
        PlayerInput(
            aim=Vec2(101.0, 100.0),
            move_forward_pressed=True,
            move_backward_pressed=False,
            turn_left_pressed=False,
            turn_right_pressed=False,
        ),
        0.1,
        state,
    )

    assert abs(player.pos.y - 100.0) > 1e-6
    origins = {(entry.origin.x, entry.origin.y) for entry in pool.entries if entry.active}
    assert origins == {(100.0, 100.0)}
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PLAYER_UPDATE_HOT_TEMPERED_INTERVAL_RESET,
    ]


def test_player_update_hot_tempered_converts_to_fire_bullets_when_active() -> None:
    pool = ProjectilePool(size=16)
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    state = GameplayState(projectiles=pool, rng=rng)
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), hot_tempered_timer=1.95, fire_bullets_timer=1.0)
    player.perk_counts[int(PerkId.HOT_TEMPERED)] = 1

    player_update(player, PlayerInput(aim=Vec2(101.0, 100.0)), 0.1, state, players=[player])

    owners = {entry.owner for entry in pool.entries if entry.active}
    assert owners == {OwnerRef.from_local_player(0)}
    type_ids = _active_type_ids(pool)
    assert len(type_ids) == 8
    assert set(type_ids) == {int(ProjectileTemplateId.FIRE_BULLETS)}
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PLAYER_UPDATE_HOT_TEMPERED_INTERVAL_RESET,
    ]


def test_bonus_apply_registers_hud_slot_and_expires() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))

    bonus_apply(state, player, BonusId.WEAPON_POWER_UP, amount=3, origin=player.pos, creatures=[], players=[player])
    for _ in range(40):
        bonus_hud_update(state, [player], dt=1.0 / 60.0)

    assert any(slot.active and slot.bonus_id == BonusId.WEAPON_POWER_UP for slot in state.bonus_hud.slots)

    state.bonuses.weapon_power_up = 0.0
    for _ in range(60):
        bonus_hud_update(state, [player], dt=1.0 / 60.0)
    assert not any(slot.active and slot.bonus_id == BonusId.WEAPON_POWER_UP for slot in state.bonus_hud.slots)


@pytest.mark.parametrize(
    "bonus_id",
    [BonusId.WEAPON_POWER_UP, BonusId.REFLEX_BOOST, BonusId.FIRE_BULLETS],
)
def test_ammo_refill_bonuses_preserve_native_reload_metadata(bonus_id: BonusId) -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    player.weapon.clip_size = 8
    player.weapon.ammo = 3.0
    player.weapon.reload_active = True
    player.weapon.reload_timer = 0.5
    player.weapon.reload_timer_max = f32(1.2)

    bonus_apply(
        state,
        player,
        bonus_id,
        origin=player.pos,
        creatures=[],
        players=[player],
    )

    assert player.weapon.ammo == 8.0
    assert player.weapon.reload_timer == 0.0
    assert player.weapon.reload_active is True
    assert player.weapon.reload_timer_max == f32(1.2)


def test_bonus_apply_shock_chain_spawns_projectile_and_chains() -> None:
    pool = ProjectilePool(size=8)
    state = GameplayState(projectiles=pool)
    player = PlayerState(index=0, pos=Vec2())
    far_y = math.sqrt(100.0 * 100.0 - 50.0 * 50.0)
    creatures = [
        _creature(pos=Vec2(50.0, 0.0), hp=100.0),
        _creature(pos=Vec2(80.0, 0.0), hp=100.0),
        _creature(pos=Vec2(100.0, far_y), hp=100.0),
    ]

    bonus_apply(state, player, BonusId.SHOCK_CHAIN, origin=player.pos, creatures=creatures, players=[player])
    assert state.shock_chain_links_left == 0x20
    first_proj = state.shock_chain_projectile_id
    assert first_proj >= 0

    pool.step(
        PrimaryStepCtx(
            dt=0.1,
            creatures=creatures,
            options=make_projectile_update_options(
                world_size=1024.0,
                rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
                runtime_state=state,
            ),
        ),
    )

    assert state.shock_chain_links_left == 0x20
    assert state.shock_chain_projectile_id == first_proj
    assert sum(1 for entry in pool.entries if entry.active) == 1

    pool.step(
        PrimaryStepCtx(
            dt=0.1,
            creatures=creatures,
            options=make_projectile_update_options(
                world_size=1024.0,
                rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
                runtime_state=state,
            ),
        ),
    )

    assert state.shock_chain_links_left == 0x1F
    assert state.shock_chain_projectile_id != first_proj
    assert sum(1 for entry in pool.entries if entry.active) >= 2
    chained = pool.entries[int(state.shock_chain_projectile_id)]
    # Native stores (float)(atan2(dy, dx) - 1.5707964 - 3.1415927).
    expected_angle = float(f32(math.atan2(far_y, 50.0) - NATIVE_HALF_PI - NATIVE_PI))
    assert_float_close(chained.angle, expected_angle)


def test_player_update_held_reload_key_starts_reload_without_edge() -> None:
    # Native gates manual reload on grim_is_key_active (key held), so a held
    # reload key chains reloads back-to-back as each one completes.
    state = GameplayState()
    player = PlayerState(
        index=0,
        pos=Vec2(50.0, 50.0),
        weapon=WeaponSlot(weapon_id=WeaponId.PISTOL, clip_size=10, ammo=10),
    )

    player_update(
        player,
        PlayerInput(aim=Vec2(51.0, 50.0), reload_down=True),
        0.1,
        state,
    )

    assert player.weapon.reload_active is True
    assert player.weapon.reload_timer > 0.0
