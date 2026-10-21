from __future__ import annotations

import pytest

from crimson.bonuses import BonusId
from crimson.bonuses.apply import bonus_apply
from crimson.bonuses.hud import bonus_hud_update
from crimson.math_parity import (
    f32,
    x87_pc24_mul,
    x87_pc24_sub,
)
from crimson.movement_controls import MovementControlType
from crimson.owner_id import OWNER_LOCAL_PLAYER
from crimson.perks import PerkId
from crimson.projectiles.runtime import ProjectilePool
from crimson.projectiles.types import ProjectileTemplateId
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapon_runtime import weapon_assign_player
from crimson.weapon_runtime.assign import player_start_reload
from crimson.weapons import WeaponId
from grim.geom import Vec2
from grim.rand import Crand, RecordingCrand
from tests.support.builders.session import make_world
from tests.support.factories import (
    make_step_runtime,
    player_input,
    step_player,
)
from tests.support.helpers import assert_float_close


def _active_type_ids(pool: ProjectilePool) -> list[int]:
    return [entry.type_id for entry in pool.entries if entry.active]


def test_dead_player_update_only_advances_native_death_timer() -> None:
    world = make_world()
    state = world.state
    state.player_spread_damping_scalar = 0.5
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        health=0.0,
        death_timer=16.0,
        bleed_drip_timer=0.25,
        muzzle_flash_alpha=0.75,
        weapon=WeaponSlot(weapon_id=WeaponId.PISTOL, shot_cooldown=0.5),
    )
    world.players[:] = [player]

    step_player(world, player, player_input(), f32(0.1))

    assert player.death_timer == x87_pc24_sub(16.0, x87_pc24_mul(f32(0.1), f32(20.0)))
    assert player.bleed_drip_timer == 0.25
    assert player.muzzle_flash_alpha == 0.75
    assert player.weapon.shot_cooldown == 0.5
    assert state.player_spread_damping_scalar == 0.5


def test_player_update_tops_up_when_stationary_reload_finishes_same_tick() -> None:
    world = make_world()
    state = world.state
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
    world.players[:] = [player]
    state.perks[int(PerkId.STATIONARY_RELOADER)] = 1

    step_player(
        world,
        player,
        player_input(aim=Vec2(51.0, 50.0), fire_down=True),
        0.03100000135600567,
    )

    assert_float_close(player.weapon.reload_timer, 0.0)
    assert_float_close(player.weapon.ammo, 6.0)
    assert player.weapon.reload_active is True


@pytest.mark.parametrize("rules,preserve_bugs", [(1, False), (1, True), (2, False), (2, True)])
def test_pulse_gun_full_reload_at_50fps_refills_on_exact_zero(rules: int, preserve_bugs: bool) -> None:
    world = make_world(preserve_bugs=preserve_bugs)
    world.state.rules = rules
    player = world.players[0]
    weapon_assign_player(player, WeaponId.PULSE_GUN, state=world.state)
    player.weapon.ammo = 0.0
    player_start_reload(player, world.state)
    for _ in range(5):
        step_player(world, player, player_input(), 0.02)
    assert player.weapon.reload_timer == 0.0
    assert player.weapon.ammo == (0.0 if preserve_bugs or rules == 1 else player.weapon.clip_size)
    # A completed reload must not become an unconditional refill each frame.
    player.weapon.ammo = 2.0
    step_player(world, player, player_input(), 0.02)
    assert player.weapon.ammo == 2.0


@pytest.mark.parametrize("preserve_bugs", [False, True])
def test_stationary_reload_exact_scaled_boundary(preserve_bugs: bool) -> None:
    world = make_world(preserve_bugs=preserve_bugs)
    world.state.perks[PerkId.STATIONARY_RELOADER] = 1
    player = world.players[0]
    player.weapon.ammo = 0.0
    player.weapon.reload_timer = 0.09375
    player.weapon.reload_active = True
    step_player(world, player, player_input(), 0.03125)
    assert player.weapon.reload_timer == 0.0
    assert player.weapon.ammo == (0.0 if preserve_bugs else player.weapon.clip_size)


def test_player_update_hot_tempered_spawns_ring() -> None:
    rng = RecordingCrand(Crand(0x1234))
    world = make_world()
    state = world.state
    pool = state.projectiles
    state.rng = rng
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), hot_tempered_timer=1.35)
    world.players[:] = [player]
    state.perks[int(PerkId.HOT_TEMPERED)] = 1

    step_player(world, player, player_input(aim=Vec2(101.0, 100.0)), 0.08400000631809235)

    owners = {entry.owner_id for entry in pool.entries if entry.active}
    assert owners == {OWNER_LOCAL_PLAYER}
    type_ids = _active_type_ids(pool)
    assert len(type_ids) == 8
    assert type_ids.count(int(ProjectileTemplateId.PLASMA_MINIGUN)) == 4
    assert type_ids.count(int(ProjectileTemplateId.PLASMA_RIFLE)) == 4
    assert [entry.angle for entry in pool.entries if entry.active] == [
        0.0,
        0.7853981852531433,
        1.5707963705062866,
        2.356194496154785,
        3.1415927410125732,
        3.9269909858703613,
        4.71238899230957,
        5.4977874755859375,
    ]
    assert player.hot_tempered_timer == 0.03400003910064697
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PLAYER_UPDATE_HOT_TEMPERED_INTERVAL_RESET,
    ]


def test_player_update_hot_tempered_spawns_from_pre_move_position() -> None:
    rng = RecordingCrand(Crand(0x1234))
    world = make_world()
    state = world.state
    pool = state.projectiles
    state.rng = rng
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), hot_tempered_timer=1.95)
    world.players[:] = [player]
    state.perks[int(PerkId.HOT_TEMPERED)] = 1

    step_player(
        world,
        player,
        player_input(
            move_mode=MovementControlType.STATIC,
            aim=Vec2(101.0, 100.0),
            move_forward_down=True,
            move_backward_down=False,
            turn_left_down=False,
            turn_right_down=False,
        ),
        0.1,
    )

    assert abs(player.pos.y - 100.0) > 1e-6
    origins = {(entry.origin.x, entry.origin.y) for entry in pool.entries if entry.active}
    assert origins == {(100.0, 100.0)}
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PLAYER_UPDATE_HOT_TEMPERED_INTERVAL_RESET,
    ]


def test_player_update_hot_tempered_converts_to_fire_bullets_when_active() -> None:
    rng = RecordingCrand(Crand(0x1234))
    world = make_world()
    state = world.state
    pool = state.projectiles
    state.rng = rng
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), hot_tempered_timer=1.95, fire_bullets_timer=1.0)
    world.players[:] = [player]
    state.perks[int(PerkId.HOT_TEMPERED)] = 1

    step_player(world, player, player_input(aim=Vec2(101.0, 100.0)), 0.1)

    owners = {entry.owner_id for entry in pool.entries if entry.active}
    assert owners == {OWNER_LOCAL_PLAYER}
    type_ids = _active_type_ids(pool)
    assert len(type_ids) == 8
    assert set(type_ids) == {int(ProjectileTemplateId.FIRE_BULLETS)}
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PLAYER_UPDATE_HOT_TEMPERED_INTERVAL_RESET,
    ]


def test_bonus_apply_registers_hud_slot_and_expires() -> None:
    world = make_world()
    state = world.state
    player = world.players[0]

    bonus_apply(
        state,
        player,
        BonusId.WEAPON_POWER_UP,
        step_runtime=make_step_runtime(world),
        amount=3,
        origin=player.pos,
        creatures=world.creatures.entries,
        players=world.players,
    )
    for _ in range(40):
        bonus_hud_update(state, world.players, dt=1.0 / 60.0)

    assert any(slot.active and slot.bonus_id == BonusId.WEAPON_POWER_UP for slot in state.bonus_hud.slots)

    state.bonuses.weapon_power_up = 0.0
    for _ in range(60):
        bonus_hud_update(state, world.players, dt=1.0 / 60.0)
    assert not any(slot.active and slot.bonus_id == BonusId.WEAPON_POWER_UP for slot in state.bonus_hud.slots)
