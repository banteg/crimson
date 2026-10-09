"""Whole-frame `player_update` (0x004136b0) under every movement and aim scheme vs the port's input pipeline.

Each case seeds one player slot of a 1-4 player game (position, heading, aim, speed,
weapon, perks, Reflex Boost), a few creatures, the held keys, stick axes, POV hat and
mouse, then runs one native `player_update`. The port turns the same device state into
a `PlayerInput` with `LocalInputInterpreter`, packs it into a replay tick and back
(live play feeds the sim exactly that), and runs `player_update` on it. The player
fields, the projectiles it fires and the `crt_rand` state are compared bit for bit.

Native reads devices through a fake Grim interface: `grim_is_key_down` (+0x44),
`grim_is_key_active` (+0x80) and `grim_get_config_float` (+0x84) answer from the case,
as do the `input_primary_just_pressed` and `input_aim_pov_*_active` helpers. The port
runs with `preserve_bugs`, as native behaves (the Stationary Reloader preload, POV 0).
"""

from __future__ import annotations

import functools
import random
import struct
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from pytest_mock import MockerFixture

from crimson import local_input
from crimson.aim_schemes import AimScheme
from crimson.local_input import LocalInputInterpreter
from crimson.math_parity import f32
from crimson.movement_controls import MovementControlType
from crimson.perks import PerkId
from crimson.projectiles.types import Projectile
from crimson.render.world.viewport import screen_to_world_with
from crimson.replay.input_codec import pack_tick, unpack_tick_inputs
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.sim.timing import ftol_ms_i32, reflex_boost_time_scale_factor
from crimson.weapon_runtime import weapon_assign_player
from crimson.weapons import WeaponId
from grim.config import default_crimson_cfg
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import step_player

from ._support import (
    CREATURE_STRIDE,
    PLAYER_STRIDE,
    PROJECTILE_LAYOUT,
    PROJECTILE_STRIDE,
    Mismatch,
    compare_fields,
    compare_pool,
    mismatch_report,
    prepare_gameplay,
)

# `player_state_t` (third_party/headers/crimsonland_types.h).
_PLAYER_LAYOUT: dict[str, tuple[int, str]] = {
    "pos_x": (0x14, "f"),
    "pos_y": (0x18, "f"),
    "health": (0x24, "f"),
    "heading": (0x2C, "f"),
    "size": (0x34, "f"),
    "aim_x": (0x50, "f"),
    "aim_y": (0x54, "f"),
    "speed_multiplier": (0x5C, "f"),
    "move_speed": (0x68, "f"),
    "move_phase": (0x94, "f"),
    "spread_heat": (0x2B8, "f"),
    "weapon_id": (0x2C0, "i"),
    "clip_size": (0x2C4, "f"),
    "reload_active": (0x2C8, "B"),
    "ammo": (0x2CC, "f"),
    "reload_timer": (0x2D0, "f"),
    "shot_cooldown": (0x2D4, "f"),
    "reload_timer_max": (0x2D8, "f"),
    "muzzle_flash_alpha": (0x2FC, "f"),
    "aim_heading": (0x300, "f"),
    "turn_speed": (0x304, "f"),
    "bleed_drip_timer": (0x310, "f"),
    "auto_target": (0x320, "i"),
    "move_target_x": (0x324, "f"),
    "move_target_y": (0x328, "f"),
}
_PERK_COUNTS = 0xB8
# `player_input_t` at 0x32c: move/turn keys, fire, two reserved, aim keys, then X/Y axes.
_INPUT = 0x32C
_INPUT_MOVE_KEYS = _INPUT + 0x00
_INPUT_FIRE_KEY = _INPUT + 0x10
_INPUT_AIM_KEYS = _INPUT + 0x1C
_INPUT_AXES = _INPUT + 0x24
_CVAR_VALUE = 0x0C

_GRIM_IS_KEY_DOWN_SLOT = 0x44 // 4
_GRIM_IS_KEY_ACTIVE_SLOT = 0x80 // 4
_GRIM_GET_CONFIG_FLOAT_SLOT = 0x84 // 4

_ALT_MOVE_KEYS = (0xC8, 0xD0, 0xCB, 0xCD)
_RELOAD_KEY = 0x13  # DIK_R, the default reload binding
_POV_LEFT = 0x133
_POV_RIGHT = 0x134
_PAD_AIM_DIST_MUL = 96.0

_WEAPONS = (WeaponId.PISTOL, WeaponId.ASSAULT_RIFLE, WeaponId.SHOTGUN, WeaponId.MEAN_MINIGUN, WeaponId.PLASMA_RIFLE)
_PERKS = (
    PerkId.LONG_DISTANCE_RUNNER,
    PerkId.SHARPSHOOTER,
    PerkId.FASTSHOT,
    PerkId.STATIONARY_RELOADER,
    PerkId.ANXIOUS_LOADER,
)
_PERK_ID_GLOBALS = {
    "perk_id_long_distance_runner": PerkId.LONG_DISTANCE_RUNNER,
    "perk_id_sharpshooter": PerkId.SHARPSHOOTER,
    "perk_id_fastshot": PerkId.FASTSHOT,
    "perk_id_fastloader": PerkId.FASTLOADER,
    "perk_id_stationary_reloader": PerkId.STATIONARY_RELOADER,
    "perk_id_anxious_loader": PerkId.ANXIOUS_LOADER,
    "perk_id_angry_reloader": PerkId.ANGRY_RELOADER,
    "perk_id_alternate_weapon": PerkId.ALTERNATE_WEAPON,
    "perk_id_regression_bullets": PerkId.REGRESSION_BULLETS,
    "perk_id_ammunition_within": PerkId.AMMUNITION_WITHIN,
    "perk_id_man_bomb": PerkId.MAN_BOMB,
    "perk_id_living_fortress": PerkId.LIVING_FORTRESS,
    "perk_id_fire_caugh": PerkId.FIRE_CAUGH,
    "perk_id_hot_tempered": PerkId.HOT_TEMPERED,
}
_CASES_PER_COMBO = 150


def _rf(rng: random.Random, lo: float, hi: float) -> float:
    return f32(rng.uniform(lo, hi))


@dataclass
class _Devices:
    held: set[int] = field(default_factory=set)
    axes: dict[int, float] = field(default_factory=dict)
    fire_pressed: bool = False
    mouse: Vec2 = Vec2()

    def key(self, call) -> int:
        return int(call.arg_u32(0) in self.held)

    def axis(self, call) -> float:
        return self.axes.get(call.arg_i32(0), 0.0)


@dataclass(frozen=True)
class _Case:
    player_count: int
    player_index: int
    move_mode: MovementControlType
    aim_scheme: AimScheme
    seed: int
    dt: float
    pos: Vec2
    heading: float
    aim: Vec2
    aim_heading: float
    move_speed: float
    move_phase: float
    turn_speed: float
    spread_heat: float
    weapon_id: WeaponId
    ammo: float
    reload_timer: float
    shot_cooldown: float
    speed_bonus: bool
    auto_target: int
    move_target: Vec2
    camera: Vec2
    perks: tuple[PerkId, ...]
    reflex_timer: float
    creatures: tuple[tuple[Vec2, float, bool], ...]

    def label(self) -> str:
        return (
            f"{self.move_mode.name}/{self.aim_scheme.name} p{self.player_index}/{self.player_count} "
            f"seed=0x{self.seed:08x}"
        )


def _random_case(rng: random.Random, move_mode: MovementControlType, aim_scheme: AimScheme) -> _Case:
    player_count = rng.randint(1, 4)
    pos = Vec2(_rf(rng, 60.0, 964.0), _rf(rng, 60.0, 964.0))
    creatures = []
    for _ in range(rng.randrange(0, 5)):
        offset = Vec2(_rf(rng, -400.0, 400.0), _rf(rng, -400.0, 400.0))
        health = rng.choice((0.0, -5.0, _rf(rng, 1.0, 200.0), _rf(rng, 1.0, 200.0)))
        creatures.append((Vec2(f32(pos.x + offset.x), f32(pos.y + offset.y)), health, rng.random() < 0.85))
    aim_offset = Vec2(_rf(rng, -300.0, 300.0), _rf(rng, -300.0, 300.0))
    ammo_roll = rng.random()
    return _Case(
        player_count=player_count,
        player_index=rng.randrange(player_count),
        move_mode=move_mode,
        aim_scheme=aim_scheme,
        seed=rng.getrandbits(32),
        dt=_rf(rng, 0.004, 0.04),
        pos=pos,
        heading=_rf(rng, 0.0, 6.2831855),
        aim=Vec2(f32(pos.x + aim_offset.x), f32(pos.y + aim_offset.y)),
        aim_heading=_rf(rng, -3.0, 9.0),
        move_speed=_rf(rng, 0.0, 2.8),
        move_phase=_rf(rng, 0.0, 14.0),
        turn_speed=_rf(rng, 0.5, 7.5),
        spread_heat=_rf(rng, 0.01, 0.48),
        weapon_id=rng.choice(_WEAPONS),
        ammo=0.0 if ammo_roll < 0.1 else (1.0 if ammo_roll < 0.3 else 5.0),
        reload_timer=rng.choice((0.0, 0.0, _rf(rng, 0.0, 0.05), _rf(rng, 0.0, 1.0))),
        shot_cooldown=rng.choice((0.0, 0.0, _rf(rng, 0.0, 0.05), _rf(rng, 0.0, 0.5))),
        speed_bonus=rng.random() < 0.2,
        auto_target=rng.choice((-1, 0, 0, 1, 2, 3)),
        move_target=rng.choice((Vec2(-1.0, -1.0), Vec2(_rf(rng, 0.0, 1024.0), _rf(rng, 0.0, 1024.0)))),
        camera=Vec2(_rf(rng, -384.0, 0.0), _rf(rng, -544.0, 0.0)),
        perks=tuple(perk for perk in _PERKS if rng.random() < 0.2),
        reflex_timer=rng.choice((0.0, 0.0, 0.0, _rf(rng, 0.1, 5.0))),
        creatures=tuple(creatures),
    )


def _roll_devices(rng: random.Random, config, case: _Case, devices: _Devices) -> None:
    binds = config.controls.player(case.player_index)
    codes = [*binds.move_codes, *_ALT_MOVE_KEYS, binds.fire_code, *binds.keyboard_aim_codes, _RELOAD_KEY, _POV_LEFT, _POV_RIGHT]
    devices.held = {int(code) for code in codes if rng.random() < 0.3}
    devices.axes = {
        int(code): rng.choice((0.0, _rf(rng, -1.0, 1.0), _rf(rng, -1.0, 1.0), _rf(rng, -0.25, 0.25)))
        for code in (*binds.aim_axis_codes, *binds.move_axis_codes)
    }
    devices.fire_pressed = binds.fire_code in devices.held and rng.random() < 0.5
    devices.mouse = Vec2(float(rng.randrange(0, 640)), float(rng.randrange(0, 480)))
    if rng.random() < 0.5:
        devices.mouse = Vec2(_rf(rng, 0.0, 639.0), _rf(rng, 0.0, 479.0))


def _fake_grim_interface(oracle, devices: _Devices) -> int:
    ret_one_arg = oracle.load_code(b"\x31\xc0\xc2\x04\x00")  # xor eax, eax; ret 4
    slots = [ret_one_arg] * 256
    for slot, fn, returns in (
        (_GRIM_IS_KEY_DOWN_SLOT, devices.key, "eax"),
        (_GRIM_IS_KEY_ACTIVE_SLOT, devices.key, "eax"),
        (_GRIM_GET_CONFIG_FLOAT_SLOT, devices.axis, "st0"),
    ):
        slots[slot] = oracle.load_code(b"\xcc" * 16)
        oracle.stub(slots[slot], fn, pop=4, returns=returns)
    vtable = oracle.alloc(0x400, data=struct.pack("<256I", *slots))
    return oracle.alloc(0x10, data=struct.pack("<I", vtable))


class _Native:
    def __init__(self, oracle) -> None:
        self.oracle = oracle
        self.devices = _Devices()
        prepare_gameplay(oracle)
        oracle.write_u32("grim_interface_ptr", _fake_grim_interface(oracle, self.devices))
        oracle.stub("input_primary_just_pressed", lambda _call: int(self.devices.fire_pressed))
        oracle.stub("input_aim_pov_left_active", lambda _call: int(_POV_LEFT in self.devices.held))
        oracle.stub("input_aim_pov_right_active", lambda _call: int(_POV_RIGHT in self.devices.held))
        for name, perk in _PERK_ID_GLOBALS.items():
            oracle.write_u32(name, int(perk))
        cvar = oracle.alloc(0x40)
        oracle.write_f32(cvar + _CVAR_VALUE, _PAD_AIM_DIST_MUL)
        oracle.write_u32("cv_padAimDistMul", cvar)
        oracle.write_u32("config_key_reload", _RELOAD_KEY)
        for name, code in zip(
            ("player2_move_key_forward", "player2_move_key_backward", "player2_turn_key_left", "player2_turn_key_right"),
            _ALT_MOVE_KEYS,
            strict=True,
        ):
            oracle.write_u32(name, code)
        self.pristine = oracle.snapshot()
        self.table = oracle.resolve("player_state_table")

    def player(self, index: int) -> int:
        return self.table + index * PLAYER_STRIDE

    def run(self, case: _Case, config, weapon_slot: WeaponSlot) -> dict[str, float | int]:
        oracle = self.oracle
        devices = self.devices
        oracle.restore(self.pristine)
        oracle.rand_state = case.seed
        oracle.write_u32("config_player_count", case.player_count)
        oracle.write_u32("current_player_index", case.player_index)
        for index in range(case.player_count):
            binds = config.controls.player(index)
            address = self.player(index)
            oracle.write_u32(oracle.resolve("config_movement_schemes") + 4 * index, int(binds.movement))
            oracle.write_u32(oracle.resolve("config_aim_schemes") + 4 * index, int(binds.aim_scheme) & 0xFFFF_FFFF)
            oracle.write(address + _INPUT_MOVE_KEYS, struct.pack("<4i", *binds.move_codes))
            oracle.write_u32(address + _INPUT_FIRE_KEY, binds.fire_code)
            oracle.write(address + _INPUT_AIM_KEYS, struct.pack("<2i", *binds.keyboard_aim_codes))
            # The config stores the axes Y/X; the runtime input is X/Y.
            aim_y, aim_x = binds.aim_axis_codes
            move_y, move_x = binds.move_axis_codes
            oracle.write(address + _INPUT_AXES, struct.pack("<4i", aim_x, aim_y, move_x, move_y))
        oracle.write_f32("ui_mouse_x", devices.mouse.x)
        oracle.write_f32("ui_mouse_y", devices.mouse.y)
        oracle.write_f32("camera_offset", case.camera.x)
        oracle.write_f32(oracle.resolve("camera_offset") + 4, case.camera.y)
        oracle.write_f32("frame_dt", case.dt)
        oracle.write_u32("frame_dt_ms", ftol_ms_i32(case.dt))
        oracle.write_f32("player_spread_damping_scalar", 1.0)
        oracle.write_f32("player_spread_damping_gate", 0.0)
        if case.reflex_timer > 0.0:
            oracle.write_u8("time_scale_active", 1)
            oracle.write_f32("bonus_reflex_boost_timer", case.reflex_timer)
            oracle.write_f32(
                "time_scale_factor",
                reflex_boost_time_scale_factor(reflex_boost_timer=case.reflex_timer, time_scale_active=True),
            )
        for perk in case.perks:
            oracle.write_u32(self.player(0) + _PERK_COUNTS + 4 * int(perk), 1)

        creature_pool = oracle.resolve("creature_pool")
        for index, (pos, health, active) in enumerate(case.creatures):
            address = creature_pool + index * CREATURE_STRIDE
            oracle.write_u8(address, int(active))
            oracle.write_f32(address + 0x14, pos.x)
            oracle.write_f32(address + 0x18, pos.y)
            oracle.write_f32(address + 0x24, health)
            oracle.write_f32(address + 0x34, 50.0)

        player = self.player(case.player_index)
        fields = {
            "pos_x": case.pos.x,
            "pos_y": case.pos.y,
            "health": 100.0,
            "heading": case.heading,
            "size": 48.0,
            "aim_x": case.aim.x,
            "aim_y": case.aim.y,
            "speed_multiplier": 2.0,
            "move_speed": case.move_speed,
            "move_phase": case.move_phase,
            "spread_heat": case.spread_heat,
            "weapon_id": int(case.weapon_id),
            "clip_size": float(weapon_slot.clip_size),
            "reload_active": int(weapon_slot.reload_active),
            "ammo": case.ammo,
            "reload_timer": case.reload_timer,
            "shot_cooldown": case.shot_cooldown,
            "reload_timer_max": weapon_slot.reload_timer_max,
            "muzzle_flash_alpha": 0.0,
            "aim_heading": case.aim_heading,
            "turn_speed": case.turn_speed,
            "bleed_drip_timer": 100.0,
            "auto_target": case.auto_target,
            "move_target_x": case.move_target.x,
            "move_target_y": case.move_target.y,
        }
        for name, value in fields.items():
            offset, kind = _PLAYER_LAYOUT[name]
            if kind == "f":
                oracle.write_f32(player + offset, float(value))
            elif kind == "B":
                oracle.write_u8(player + offset, int(value))
            else:
                oracle.write_u32(player + offset, int(value) & 0xFFFF_FFFF)
        if case.speed_bonus:
            oracle.write_f32(player + 0x314, 5.0)

        oracle.call("player_update")
        return oracle.read_fields(player, _PLAYER_LAYOUT)


@functools.cache
def _weapon_slot(weapon_id: WeaponId) -> WeaponSlot:
    world = make_world()
    player = world.players[0]
    weapon_assign_player(player, weapon_id, state=world.state)
    return player.weapon


def _patch_devices(mocker: MockerFixture, devices: _Devices) -> None:
    mocker.patch.object(local_input, "input_code_is_down", side_effect=lambda code, **_kw: int(code) in devices.held)
    mocker.patch.object(
        local_input,
        "input_code_is_pressed",
        side_effect=lambda code, **_kw: devices.fire_pressed and int(code) in devices.held,
    )
    mocker.patch.object(local_input, "input_axis_value", side_effect=lambda code, **_kw: devices.axes.get(int(code), 0.0))


def _python_frame(case: _Case, devices: _Devices, config):
    world = make_world(player_count=case.player_count, preserve_bugs=True)
    state = world.state
    state.rng.srand(case.seed)
    for perk in case.perks:
        state.perks[perk] = 1
    if case.reflex_timer > 0.0:
        state.time_scale_active = True
        state.bonuses.reflex_boost = case.reflex_timer
    for index, (pos, health, active) in enumerate(case.creatures):
        creature = world.creatures.entries[index]
        creature.active = active
        creature.pos = pos
        creature.hp = health
        creature.size = 50.0

    player = world.players[case.player_index]
    weapon_assign_player(player, case.weapon_id, state=state)
    player.pos = case.pos
    player.heading = case.heading
    player.aim = case.aim
    player.aim_heading = case.aim_heading
    player.move_speed = case.move_speed
    player.move_phase = case.move_phase
    player.turn_speed = case.turn_speed
    player.spread_heat = case.spread_heat
    player.auto_target = case.auto_target
    player.speed_bonus_timer = 5.0 if case.speed_bonus else 0.0
    player.weapon.ammo = case.ammo
    player.weapon.reload_timer = case.reload_timer
    player.weapon.shot_cooldown = case.shot_cooldown

    interpreter = LocalInputInterpreter(preserve_bugs=True)
    interpreter.reset(players=world.players)
    slot = interpreter._states[case.player_index]
    slot.move_target = case.move_target
    mouse_world = screen_to_world_with(devices.mouse, camera=case.camera, view_scale=Vec2(1.0, 1.0))
    live = interpreter.build_player_input(
        player_index=case.player_index,
        player=player,
        config=config,
        mouse_screen=devices.mouse,
        mouse_world=mouse_world,
        pad_aim_dist_mul=_PAD_AIM_DIST_MUL,
    )
    (input_state,) = unpack_tick_inputs(pack_tick([live]).inputs)
    step_player(world, player, input_state, case.dt)
    return world, player, slot


def _python_fields(player: PlayerState, slot) -> dict[str, float | int]:
    return {
        "pos_x": player.pos.x,
        "pos_y": player.pos.y,
        "heading": player.heading,
        "aim_x": player.aim.x,
        "aim_y": player.aim.y,
        "move_speed": player.move_speed,
        "move_phase": player.move_phase,
        "spread_heat": player.spread_heat,
        "weapon_id": int(player.weapon.weapon_id),
        "reload_active": int(player.weapon.reload_active),
        "ammo": player.weapon.ammo,
        "reload_timer": player.weapon.reload_timer,
        "shot_cooldown": player.weapon.shot_cooldown,
        "reload_timer_max": player.weapon.reload_timer_max,
        "muzzle_flash_alpha": player.muzzle_flash_alpha,
        "aim_heading": player.aim_heading,
        "turn_speed": player.turn_speed,
        "auto_target": player.auto_target,
        "move_target_x": slot.move_target.x,
        "move_target_y": slot.move_target.y,
    }


def _python_projectile(projectile: Projectile) -> dict[str, float | int]:
    return {
        "active": int(projectile.active),
        "angle": projectile.angle,
        "pos_x": projectile.pos.x,
        "pos_y": projectile.pos.y,
        "type_id": int(projectile.type_id),
        "speed_scale": projectile.speed_scale,
        "owner_id": projectile.owner_id,
    }


_MOVE_MODES = (
    MovementControlType.UNKNOWN,
    MovementControlType.RELATIVE,
    MovementControlType.STATIC,
    MovementControlType.DUAL_ACTION_PAD,
    MovementControlType.MOUSE_POINT_CLICK,
    MovementControlType.COMPUTER,
)
_AIM_SCHEMES = (
    AimScheme.UNKNOWN,
    AimScheme.MOUSE,
    AimScheme.KEYBOARD,
    AimScheme.JOYSTICK,
    AimScheme.MOUSE_RELATIVE,
    AimScheme.DUAL_ACTION_PAD,
    AimScheme.COMPUTER,
)


# Native `player_update` (and the port) couples the two schemes in two places only: computer movement
# or computer aim runs the auto-target scan, and keyboard aim turns only under relative or static
# movement. Those pairs run in full; every other move and aim block is independent of the other
# scheme, so each remaining scheme runs once.
_SCHEME_PAIRS = (
    *((move_mode, AimScheme.COMPUTER) for move_mode in _MOVE_MODES),
    *((MovementControlType.COMPUTER, aim_scheme) for aim_scheme in _AIM_SCHEMES if aim_scheme is not AimScheme.COMPUTER),
    *((move_mode, AimScheme.KEYBOARD) for move_mode in _MOVE_MODES if move_mode is not MovementControlType.COMPUTER),
    (MovementControlType.UNKNOWN, AimScheme.UNKNOWN),
    (MovementControlType.RELATIVE, AimScheme.MOUSE_RELATIVE),
    (MovementControlType.STATIC, AimScheme.JOYSTICK),
    (MovementControlType.DUAL_ACTION_PAD, AimScheme.DUAL_ACTION_PAD),
    (MovementControlType.MOUSE_POINT_CLICK, AimScheme.MOUSE),
)


@pytest.mark.parametrize(
    ("move_mode", "aim_scheme"),
    [
        pytest.param(move_mode, aim_scheme, id=f"{move_mode.name.lower()}-{aim_scheme.name.lower()}")
        for move_mode, aim_scheme in _SCHEME_PAIRS
    ],
)
def test_player_update_controls_match_native(
    oracle,
    mocker: MockerFixture,
    move_mode: MovementControlType,
    aim_scheme: AimScheme,
) -> None:
    native = _Native(oracle)
    _patch_devices(mocker, native.devices)
    projectile_pool = oracle.resolve("projectile_pool")
    rng = random.Random(f"{move_mode.name}/{aim_scheme.name}")
    mismatches: list[Mismatch] = []
    for _ in range(_CASES_PER_COMBO):
        case = _random_case(rng, move_mode, aim_scheme)
        config = default_crimson_cfg(Path("<memory>"))
        config.gameplay.player_count = case.player_count
        config.controls.reload_code = _RELOAD_KEY
        for index in range(4):
            config.controls.player(index).movement = move_mode
            config.controls.player(index).aim_scheme = aim_scheme
        _roll_devices(rng, config, case, native.devices)

        native_fields = native.run(case, config, _weapon_slot(case.weapon_id))
        world, player, slot = _python_frame(case, native.devices, config)
        label = case.label()
        address = native.player(case.player_index)
        mismatches += compare_fields(label, native_fields, _python_fields(player, slot), address=address)
        mismatches += compare_pool(
            oracle, projectile_pool, PROJECTILE_STRIDE, PROJECTILE_LAYOUT, world.state.projectiles.entries,
            _python_projectile, f"{label} projectile",
        )
        if oracle.rand_state != world.state.rng.state:
            mismatches.append(Mismatch(label, "rand_state", oracle.rand_state, world.state.rng.state, 0))
    assert not mismatches, mismatch_report(mismatches, total_cases=_CASES_PER_COMBO)
