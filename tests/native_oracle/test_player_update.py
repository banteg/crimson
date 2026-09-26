"""`player_update` (0x004136b0) movement, reload and aim fragments vs `crimson.gameplay`.

Each test seeds the slot-0 `player_state_t` and the frame the fragment reads,
runs the original code, and compares the stored floats bit for bit with the
Python helper that ports the same block.
"""

from __future__ import annotations

import random
import struct
from collections.abc import Callable

from pytest_mock import MockerFixture

from crimson.creatures.runtime import CreatureState
from crimson.creatures.spawn import SpawnId, SpawnSlotInit
from crimson.gameplay import (
    _aim_heading_from_aim_point_native,
    _native_move_target_heading,
    _player_accelerate_move_speed,
    _player_apply_move_speed_caps,
    _player_apply_move_with_spawn_avoidance,
    _player_decelerate_move_speed,
    _player_heading_approach_target_with_delta,
    _player_heading_velocity,
    _player_move,
    _player_move_delta_from_velocity,
    _player_move_toward_heading,
    player_update,
    survival_level_threshold,
)
from crimson.math_parity import f32, x87_pc24_hypot, x87_pc24_sub
from crimson.movement_controls import MovementControlType
from crimson.perks import PerkId
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.sim.timing import reflex_boost_time_scale_factor
from crimson.weapons import WeaponId
from grim.geom import Vec2

from ._support import CREATURE_STRIDE, Mismatch, compare_fields, mismatch_report

_PLAYER_LAYOUT: dict[str, tuple[int, str]] = {
    "pos_x": (0x14, "f"),
    "pos_y": (0x18, "f"),
    "move_dx": (0x1C, "f"),
    "move_dy": (0x20, "f"),
    "heading": (0x2C, "f"),
    "size": (0x34, "f"),
    "aim_x": (0x50, "f"),
    "aim_y": (0x54, "f"),
    "move_speed": (0x68, "f"),
    "spread_heat": (0x2B8, "f"),
    "weapon_id": (0x2C0, "i"),
    "reload_timer": (0x2D0, "f"),
    "reload_timer_max": (0x2D8, "f"),
    "aim_heading": (0x300, "f"),
    "turn_speed": (0x304, "f"),
    "auto_target": (0x320, "i"),
    "move_target_x": (0x324, "f"),
    "move_target_y": (0x328, "f"),
}
_PERK_COUNTS = 0x490968 - 0x4908B0  # player_state_t.perk_counts
_SPAWN_SLOT_STRIDE = 0x18
# `mov ebp, 0x40000000` (0x00413e1e): movement blocks cap move_speed with ebp = 2.0f.
_MOVEMENT_REGS_EBP = 0x40000000
_SAMPLES = 1500


def _rf(rng: random.Random, lo: float, hi: float) -> float:
    return f32(rng.uniform(lo, hi))


class _Frame:
    """The fragment's stack frame: float/int slots at `esp`-relative offsets."""

    def __init__(self, size: int = 0x80) -> None:
        self.data = bytearray(size)

    def f32(self, offset: int, value: float) -> _Frame:
        struct.pack_into("<f", self.data, offset, value)
        return self

    def i32(self, offset: int, value: int) -> _Frame:
        struct.pack_into("<i", self.data, offset, value)
        return self


class _Harness:
    def __init__(self, oracle) -> None:
        self.oracle = oracle
        self.player = oracle.resolve("player_state_table")
        self.pristine = oracle.snapshot()

    def reset(self, **fields: float) -> None:
        self.oracle.restore(self.pristine)
        for name, value in fields.items():
            offset, kind = _PLAYER_LAYOUT[name]
            if kind == "f":
                self.oracle.write_f32(self.player + offset, float(value))
            else:
                self.oracle.write_u32(self.player + offset, int(value) & 0xFFFFFFFF)

    def run(self, start: int, stop: int, frame: _Frame) -> dict[str, float | int]:
        self.oracle.run(
            start,
            stop,
            regs={"edi": self.player, "esi": self.player + 0x14, "ebp": _MOVEMENT_REGS_EBP},
            frame=bytes(frame.data),
        )
        return self.oracle.read_fields(self.player, _PLAYER_LAYOUT)

    def frame_f32(self, offset: int) -> float:
        return self.oracle.read_f32(self.oracle.frame_pointer() + offset)


def _python_player(**fields) -> PlayerState:
    weapon = WeaponSlot(weapon_id=fields.pop("weapon_id", WeaponId.PISTOL))
    fields.setdefault("pos", Vec2())
    return PlayerState(index=0, weapon=weapon, **fields)


def _check(cases: int, mismatches: list[Mismatch]) -> None:
    assert not mismatches, mismatch_report(mismatches, total_cases=cases)


def test_heading_approach_target_matches_native(oracle) -> None:
    """`player_heading_approach_target` (0x00413540), including unwrapped computer targets."""

    harness = _Harness(oracle)
    rng = random.Random(0x413540)
    mismatches: list[Mismatch] = []
    for index in range(_SAMPLES):
        heading = _rf(rng, -7.0, 13.0)
        target = _rf(rng, -4.8, 6.3) if index % 2 else _rf(rng, 0.0, 6.2831855)
        dt = _rf(rng, 0.0005, 0.2)
        harness.reset(heading=heading)
        oracle.write_f32("frame_dt", dt)
        result = oracle.call("player_heading_approach_target", float(target))

        player = _python_player(heading=heading)
        diff, turn_delta = _player_heading_approach_target_with_delta(player, target, dt)
        case = f"heading={heading!r} target={target!r} dt={dt!r}"
        native = {
            "heading": oracle.read_f32(harness.player + 0x2C),
            "turn_delta": oracle.read_f32("player_heading_turn_delta"),
            "diff": result.st0,
        }
        python = {"heading": player.heading, "turn_delta": turn_delta, "diff": diff}
        mismatches += compare_fields(case, native, python, address=0x00413540)
    _check(_SAMPLES, mismatches)


def _movement_case(rng: random.Random) -> dict[str, float | int]:
    return {
        "heading": _rf(rng, 0.0, 6.2831855),
        "move_speed": _rf(rng, 0.0, 2.8),
        "weapon_id": rng.choice((int(WeaponId.PISTOL), int(WeaponId.MEAN_MINIGUN))),
    }


def _run_velocity_fragment(
    oracle,
    *,
    start: int,
    stop: int,
    seed: int,
    python_step: Callable[[PlayerState, float, float], Vec2],
) -> None:
    harness = _Harness(oracle)
    rng = random.Random(seed)
    mismatches: list[Mismatch] = []
    for _ in range(_SAMPLES):
        fields = _movement_case(rng)
        scalar = rng.choice((2.0, 3.0, _rf(rng, 1.0, 3.0)))
        dt = _rf(rng, 0.0005, 0.1)
        harness.reset(**fields)
        oracle.write_f32("frame_dt", dt)
        native = harness.run(start, stop, _Frame().f32(0x1C, scalar))
        native["delta_x"] = harness.frame_f32(0x48)
        native["delta_y"] = harness.frame_f32(0x4C)

        player = _python_player(
            heading=fields["heading"],
            move_speed=fields["move_speed"],
            weapon_id=WeaponId(fields["weapon_id"]),
        )
        delta = python_step(player, dt, scalar)
        python = {
            "heading": player.heading,
            "move_speed": player.move_speed,
            "move_dx": player.aim.x,  # python_step parks the stored velocity here
            "move_dy": player.aim.y,
            "delta_x": delta.x,
            "delta_y": delta.y,
        }
        mismatches += compare_fields(f"{fields} scalar={scalar!r} dt={dt!r}", native, python, address=start)
    _check(_SAMPLES, mismatches)


def _park_velocity(player: PlayerState, velocity: Vec2, dt: float) -> Vec2:
    player.aim = velocity
    return _player_move_delta_from_velocity(dt, velocity)


def test_relative_forward_velocity_matches_native(oracle) -> None:
    """Relative-scheme forward block (0x00414750..0x00414838): accelerate, cap, `* 25.0f` chain."""

    def step(player: PlayerState, dt: float, scalar: float) -> Vec2:
        _player_accelerate_move_speed(player, player, dt)
        _player_apply_move_speed_caps(player)
        velocity = _player_heading_velocity(player, speed_multiplier=scalar, speed_scale=25.0)
        return _park_velocity(player, velocity, dt)

    _run_velocity_fragment(oracle, start=0x00414750, stop=0x00414838, seed=0x414750, python_step=step)


def test_relative_backward_velocity_matches_native(oracle) -> None:
    """Relative-scheme backward block (0x0041467b..0x0041474b): `* -25.0f`, no speed cap."""

    def step(player: PlayerState, dt: float, scalar: float) -> Vec2:
        _player_accelerate_move_speed(player, player, dt)
        velocity = _player_heading_velocity(player, speed_multiplier=scalar, speed_scale=-25.0)
        return _park_velocity(player, velocity, dt)

    _run_velocity_fragment(oracle, start=0x0041467B, stop=0x0041474B, seed=0x41467B, python_step=step)


def test_decelerate_velocity_matches_native(oracle) -> None:
    """Point-click idle block (0x0041412c..0x004141ad), shared by every scheme's decel path."""

    def step(player: PlayerState, dt: float, scalar: float) -> Vec2:
        _player_decelerate_move_speed(player, dt)
        velocity = _player_heading_velocity(player, speed_multiplier=scalar, speed_scale=25.0)
        return _park_velocity(player, velocity, dt)

    _run_velocity_fragment(oracle, start=0x0041412C, stop=0x004141AD, seed=0x41412C, python_step=step)


def test_turn_aligned_velocity_matches_native(oracle) -> None:
    """Point-click steering block (0x00414018..0x00414123): approach, accelerate, `(pi - diff) * 7.957747f` chain."""

    harness = _Harness(oracle)
    rng = random.Random(0x414018)
    mismatches: list[Mismatch] = []
    for _ in range(_SAMPLES):
        fields = _movement_case(rng)
        target = _rf(rng, 0.0, 6.2831855)
        scalar = rng.choice((2.0, 3.0, _rf(rng, 1.0, 3.0)))
        dt = _rf(rng, 0.0005, 0.1)
        harness.reset(**fields)
        oracle.write_f32("frame_dt", dt)
        native = harness.run(0x00414018, 0x00414123, _Frame().f32(0x1C, scalar).f32(0x20, target))
        native["delta_x"] = harness.frame_f32(0x48)
        native["delta_y"] = harness.frame_f32(0x4C)

        player = _python_player(
            heading=fields["heading"],
            move_speed=fields["move_speed"],
            weapon_id=WeaponId(fields["weapon_id"]),
        )
        delta = _player_move_toward_heading(
            player,
            player,
            target_heading=target,
            movement_dt=dt,
            speed_multiplier=scalar,
        )
        python = {
            "heading": player.heading,
            "move_speed": player.move_speed,
            "delta_x": delta.x,
            "delta_y": delta.y,
        }
        case = f"{fields} target={target!r} scalar={scalar!r} dt={dt!r}"
        mismatches += compare_fields(case, native, python, address=0x00414018)
    _check(_SAMPLES, mismatches)


def test_point_click_target_heading_matches_native(oracle) -> None:
    """Point-click target heading (0x00413fa9..0x00414018): `atan2f(pos - target) - 1.5707964f`, `+= 6.2831855f`.

    `local_input` passes the raw f32 `move_target - pos` delta; the sim negates it.
    """

    harness = _Harness(oracle)
    rng = random.Random(0x413FA9)
    mismatches: list[Mismatch] = []
    cases = 0
    while cases < _SAMPLES:
        pos = Vec2(_rf(rng, 0.0, 1024.0), _rf(rng, 0.0, 1024.0))
        target = Vec2(_rf(rng, 0.0, 1024.0), _rf(rng, 0.0, 1024.0))
        if rng.random() < 0.2:
            target = Vec2(pos.x, target.y)  # +0 x component
        move = Vec2(x87_pc24_sub(target.x, pos.x), x87_pc24_sub(target.y, pos.y))
        if (move.x * move.x + move.y * move.y) < 21.0 * 21.0:
            continue
        cases += 1
        harness.reset(pos_x=pos.x, pos_y=pos.y, move_target_x=target.x, move_target_y=target.y)
        harness.run(0x00413FA9, 0x00414018, _Frame())
        native = {"target_heading": harness.frame_f32(0x20)}
        python = {"target_heading": _native_move_target_heading(move, normalize=False, wrap=True)}
        mismatches += compare_fields(f"pos={pos} target={target}", native, python, address=0x00413FA9)
    _check(cases, mismatches)


def test_pad_target_heading_matches_native(oracle) -> None:
    """Dual-pad target heading (0x0041421e..0x00414276): normalize, `atan2f - 1.5707964f`, `+= 6.2831855f`.

    `D3DXVec2Normalize` picks a CPU-specific path at runtime, so the stub answers
    with the port's x87 model; the check covers the heading math around it.
    """

    harness = _Harness(oracle)

    def normalize(call) -> int:
        dst, src = call.arg_u32(0), call.arg_u32(1)
        normalized = Vec2(oracle.read_f32(src), oracle.read_f32(src + 4)).normalized()
        oracle.write_f32(dst, normalized.x)
        oracle.write_f32(dst + 4, normalized.y)
        return dst

    oracle.stub("D3DXVec2Normalize", normalize, pop=8)
    harness.pristine = oracle.snapshot()
    rng = random.Random(0x41421E)
    mismatches: list[Mismatch] = []
    for index in range(_SAMPLES):
        stick = Vec2(_rf(rng, -1.0, 1.0), _rf(rng, -1.0, 1.0))
        if index % 5 == 0:
            stick = Vec2(0.0, stick.y)
        harness.reset()
        # Native steers along `-movement_input`; the port's move vector is that direction.
        harness.run(0x0041421E, 0x00414276, _Frame().f32(0x38, x87_pc24_sub(0.0, stick.x)).f32(0x3C, x87_pc24_sub(0.0, stick.y)))
        native = {"target_heading": harness.frame_f32(0x20)}
        python = {"target_heading": _native_move_target_heading(stick, normalize=True, wrap=True)}
        mismatches += compare_fields(f"stick={stick}", native, python, address=0x0041421E)
    _check(_SAMPLES, mismatches)


def test_computer_target_heading_matches_native(oracle) -> None:
    """Computer steering heading (0x00414c7f..0x00414d82): unwrapped `atan2f(pos - goal) - 1.5707964f`.

    The goal is the arena centre beyond 300 units, else the auto-target creature.
    """

    harness = _Harness(oracle)
    creature = oracle.resolve("creature_pool")
    rng = random.Random(0x414C7F)
    mismatches: list[Mismatch] = []
    for _ in range(_SAMPLES):
        pos = Vec2(_rf(rng, 0.0, 1024.0), _rf(rng, 0.0, 1024.0))
        prey = Vec2(_rf(rng, 0.0, 1024.0), _rf(rng, 0.0, 1024.0))
        harness.reset(pos_x=pos.x, pos_y=pos.y, auto_target=0)
        oracle.write_u8(creature, 1)
        oracle.write_f32(creature + 0x14, prey.x)
        oracle.write_f32(creature + 0x18, prey.y)
        oracle.write_f32(creature + 0x24, 10.0)
        harness.run(0x00414C7F, 0x00414D82, _Frame())

        center = Vec2(512.0, 512.0)
        center_delta = Vec2(x87_pc24_sub(center.x, pos.x), x87_pc24_sub(center.y, pos.y))
        goal = center if x87_pc24_hypot(center_delta.x, center_delta.y) > 300.0 else prey
        move = Vec2(x87_pc24_sub(goal.x, pos.x), x87_pc24_sub(goal.y, pos.y))
        native = {"target_heading": harness.frame_f32(0x20)}
        python = {"target_heading": _native_move_target_heading(move, normalize=False, wrap=False)}
        mismatches += compare_fields(f"pos={pos} prey={prey}", native, python, address=0x00414C7F)
    _check(_SAMPLES, mismatches)


def test_relative_turn_matches_native(oracle) -> None:
    """Relative-scheme turning (0x004144dc right, 0x00414520 left): `turn_speed += frame_dt * 10.0f` at PC24."""

    harness = _Harness(oracle)
    rng = random.Random(0x4144DC)
    mismatches: list[Mismatch] = []
    for index in range(_SAMPLES):
        left = bool(index % 2)
        fields = {
            "heading": _rf(rng, -6.0, 12.0),
            "aim_heading": _rf(rng, -6.0, 12.0),
            "turn_speed": _rf(rng, 1.0, 7.0),
        }
        dt = _rf(rng, 0.0005, 0.1)
        harness.reset(**fields)
        oracle.write_f32("frame_dt", dt)
        native = harness.run(0x00414520 if left else 0x004144DC, 0x00414568, _Frame())

        player = _python_player(**fields)
        state = GameplayState()
        _player_move(
            player,
            player,
            PlayerInput(
                move_mode=MovementControlType.RELATIVE,
                turn_left_pressed=left,
                turn_right_pressed=not left,
                move_forward_pressed=False,
                move_backward_pressed=False,
            ),
            state,
            dt,
            MovementControlType.RELATIVE,
            2.0,
            None,
            None,
        )
        python = {"heading": player.heading, "aim_heading": player.aim_heading, "turn_speed": player.turn_speed}
        mismatches += compare_fields(f"{fields} dt={dt!r} left={left}", native, python, address=0x004144DC)
    _check(_SAMPLES, mismatches)


def _spawn_avoidance_case(
    oracle,
    harness: _Harness,
    *,
    pos: Vec2,
    delta: Vec2,
    size: float,
    alt_weapon: bool,
    owners: list[tuple[Vec2, float]],
) -> list[Mismatch]:
    creature_pool = oracle.resolve("creature_pool")
    slot_table = oracle.resolve("creature_spawn_slot_table")
    harness.reset(pos_x=pos.x, pos_y=pos.y, size=size)
    if alt_weapon:
        oracle.write_u32("perk_id_alternate_weapon", int(PerkId.ALTERNATE_WEAPON))
        oracle.write_u32(harness.player + _PERK_COUNTS + 4 * int(PerkId.ALTERNATE_WEAPON), 1)
    for index, (owner_pos, owner_size) in enumerate(owners):
        address = creature_pool + index * CREATURE_STRIDE
        oracle.write_f32(address + 0x14, owner_pos.x)
        oracle.write_f32(address + 0x18, owner_pos.y)
        oracle.write_f32(address + 0x34, owner_size)
        oracle.write_u32(slot_table + index * _SPAWN_SLOT_STRIDE, address)
    delta_address = oracle.alloc_f32s(delta.x, delta.y)
    oracle.call("player_apply_move_with_spawn_avoidance", 0, harness.player + 0x14, delta_address)
    native = oracle.read_fields(harness.player, _PLAYER_LAYOUT)

    player = _python_player(pos=pos, size=size)
    if alt_weapon:
        player.perk_counts[int(PerkId.ALTERNATE_WEAPON)] = 1
    creatures = [CreatureState(pos=owner_pos, size=owner_size) for owner_pos, owner_size in owners]
    slots = [
        SpawnSlotInit(owner_creature=index, timer=0.0, count=0, limit=0, interval=0.0, child_template_id=SpawnId(0))
        for index in range(len(owners))
    ]
    _player_apply_move_with_spawn_avoidance(
        player,
        perk_player=player,
        delta=delta,
        spawn_slots=slots,
        creatures=creatures,
    )
    python = {"pos_x": player.pos.x, "pos_y": player.pos.y}
    case = f"pos={pos} delta={delta} size={size!r} alt={alt_weapon} owners={owners}"
    return compare_fields(case, native, python, address=0x0041E290)


def test_spawn_avoidance_matches_native(oracle) -> None:
    """`player_apply_move_with_spawn_avoidance` (0x0041e290) with Alternate Weapon and spawner owners."""

    harness = _Harness(oracle)
    rng = random.Random(0x41E290)
    mismatches: list[Mismatch] = []
    for index in range(_SAMPLES):
        # From the origin the stored position is the (scaled) delta itself.
        pos = Vec2() if index % 4 == 0 else Vec2(_rf(rng, 100.0, 900.0), _rf(rng, 100.0, 900.0))
        owners = []
        for _slot in range(rng.randrange(1, 4)):
            offset = Vec2(_rf(rng, -40.0, 40.0), _rf(rng, -40.0, 40.0))
            owners.append((Vec2(f32(pos.x + offset.x), f32(pos.y + offset.y)), _rf(rng, 20.0, 80.0)))
        mismatches += _spawn_avoidance_case(
            oracle,
            harness,
            pos=pos,
            delta=Vec2(_rf(rng, -6.0, 6.0), _rf(rng, -6.0, 6.0)),
            size=_rf(rng, 30.0, 60.0),
            alt_weapon=rng.random() < 0.5,
            owners=owners,
        )

    # Radius boundary: from the origin, step (1, 0) toward an owner exactly one
    # candidate radius beyond the step, where `r(r(a + b) * 0.33333334f)` and a
    # single wide rounding disagree.  Only the native radius decides the collision.
    boundary_cases = 0
    while boundary_cases < 200:
        owner_size = _rf(rng, 20.0, 45.0)
        size = _rf(rng, 20.0, 45.0)
        native_radius = f32(f32(owner_size + size) * f32(0.33333334))
        wide_radius = f32((owner_size + size) * 0.33333334)
        if native_radius == wide_radius:
            continue
        boundary_cases += 1
        reach = rng.choice((native_radius, wide_radius))
        mismatches += _spawn_avoidance_case(
            oracle,
            harness,
            pos=Vec2(),
            delta=Vec2(1.0, 0.0),
            size=size,
            alt_weapon=False,
            owners=[(Vec2(f32(1.0 + reach), 0.0), owner_size)],
        )
    _check(_SAMPLES + boundary_cases, mismatches)


def test_angry_reloader_ring_matches_native(oracle, mocker: MockerFixture) -> None:
    """Angry Reloader ring (0x00415162..0x004151c1): `step = 6.2831855f / count`, `i * step + 0.1f`."""

    import crimson.weapon_runtime.spawn as spawn_module

    harness = _Harness(oracle)
    native_angles: list[float] = []
    oracle.stub("projectile_spawn", lambda call: native_angles.append(call.arg_f32(1)))
    harness.pristine = oracle.snapshot()
    python_spawn = mocker.patch.object(spawn_module, "projectile_spawn")

    rng = random.Random(0x415162)
    mismatches: list[Mismatch] = []
    cases = 200
    for _ in range(cases):
        reload_timer_max = _rf(rng, 0.55, 6.0)
        native_angles.clear()
        python_spawn.reset_mock()
        harness.reset(reload_timer_max=reload_timer_max)
        harness.run(0x00415162, 0x004151C1, _Frame().i32(0x20, -100))

        player = _python_player()
        player.perk_counts[int(PerkId.ANGRY_RELOADER)] = 1
        player.weapon.reload_timer_max = reload_timer_max
        player.weapon.reload_timer = f32(reload_timer_max * 0.5 + 0.001)
        player_update(player, PlayerInput(aim=Vec2(1.0, 0.0)), 0.05, GameplayState())
        python_angles = [call.kwargs["angle"] for call in python_spawn.call_args_list]

        case = f"reload_timer_max={reload_timer_max!r}"
        if len(native_angles) != len(python_angles):
            mismatches.append(Mismatch(case, "count", len(native_angles), len(python_angles), 0x00415162))
            continue
        native = {f"angle[{i}]": angle for i, angle in enumerate(native_angles)}
        python = {f"angle[{i}]": angle for i, angle in enumerate(python_angles)}
        mismatches += compare_fields(case, native, python, address=0x00415188)
    _check(cases, mismatches)


def test_reflex_restored_frame_dt_drives_spread_and_reload(oracle) -> None:
    """Reflex Boost restore + spread/reload (0x00414f44..0x00415219) vs `player_update` end to end.

    Native restores `frame_dt` right after movement; spread cooling, the reload
    preload check and the reload countdown all read the restored value.
    """

    harness = _Harness(oracle)
    rng = random.Random(0x414F44)
    mismatches: list[Mismatch] = []
    for _ in range(_SAMPLES):
        pos = Vec2(_rf(rng, 100.0, 900.0), _rf(rng, 100.0, 900.0))
        dt = _rf(rng, 0.001, 0.05)
        reflex_timer = rng.choice((_rf(rng, 0.0, 1.0), _rf(rng, 1.0, 5.0)))
        spread_heat = _rf(rng, 0.01, 0.5)
        reload_timer_max = _rf(rng, 0.5, 4.0)
        reload_timer = rng.choice((0.0, _rf(rng, 0.0, 0.1), _rf(rng, 0.0, reload_timer_max)))
        time_scale_factor = reflex_boost_time_scale_factor(reflex_boost_timer=reflex_timer, time_scale_active=True)

        state = GameplayState()
        state.time_scale_active = True
        state.bonuses.reflex_boost = reflex_timer
        player = _python_player(pos=pos, spread_heat=spread_heat)
        player.weapon.reload_timer = reload_timer
        player.weapon.reload_timer_max = reload_timer_max
        frame_dt = player_update(
            player,
            PlayerInput(
                aim=Vec2(pos.x + 60.0, pos.y),
                move_mode=MovementControlType.STATIC,
                move_forward_pressed=False,
                move_backward_pressed=False,
                turn_left_pressed=False,
                turn_right_pressed=False,
            ),
            dt,
            state,
        )

        harness.reset(pos_x=pos.x, pos_y=pos.y, spread_heat=spread_heat, reload_timer=reload_timer)
        oracle.write_f32(harness.player + 0x2D8, reload_timer_max)
        oracle.write_u8("time_scale_active", 1)
        oracle.write_f32("time_scale_factor", time_scale_factor)
        movement_dt = f32(f32(f32(0.6) / time_scale_factor) * dt)
        oracle.write_f32("frame_dt", movement_dt)
        native = harness.run(0x00414F44, 0x00415219, _Frame().f32(0x30, pos.x).f32(0x34, pos.y))
        native["frame_dt"] = oracle.read_f32("frame_dt")

        python = {
            "frame_dt": frame_dt,
            "spread_heat": player.spread_heat,
            "reload_timer": player.weapon.reload_timer,
        }
        case = f"dt={dt!r} reflex={reflex_timer!r} spread={spread_heat!r} reload={reload_timer!r}/{reload_timer_max!r}"
        mismatches += compare_fields(case, native, python, address=0x00414F44)
    _check(_SAMPLES, mismatches)


def test_aim_heading_is_recomputed_on_the_player(oracle) -> None:
    """Final aim heading (0x0041572e..0x00415753), including an aim point on the player."""

    harness = _Harness(oracle)
    rng = random.Random(0x41572E)
    mismatches: list[Mismatch] = []
    for index in range(_SAMPLES):
        pos = Vec2(_rf(rng, 0.0, 1024.0), _rf(rng, 0.0, 1024.0))
        aim = pos if index % 4 == 0 else Vec2(_rf(rng, 0.0, 1024.0), _rf(rng, 0.0, 1024.0))
        harness.reset(pos_x=pos.x, pos_y=pos.y, aim_x=aim.x, aim_y=aim.y, aim_heading=1.0)
        native = harness.run(0x0041572E, 0x00415753, _Frame())

        player = _python_player(pos=pos, aim_heading=1.0)
        player_update(player, PlayerInput(aim=aim), 0.016, GameplayState())
        python = {
            "aim_heading": player.aim_heading,
            "helper": _aim_heading_from_aim_point_native(pos, aim),
        }
        native["helper"] = native["aim_heading"]
        mismatches += compare_fields(f"pos={pos} aim={aim}", native, python, address=0x0041572E)
    _check(_SAMPLES, mismatches)


def test_survival_level_threshold_matches_native(oracle) -> None:
    """Level-up threshold in `gameplay_update_and_render` (0x0040afae): CRT `__CIpow` at PC24."""

    mismatches: list[Mismatch] = []
    levels = range(1, 2001)
    for level in levels:
        oracle.write_u32("player_level", level)
        oracle.run(0x0040AFAE, 0x0040AFCE, regs={"esi": 1000})
        threshold = struct.unpack("<i", struct.pack("<I", oracle.reg("ecx")))[0]
        if threshold != survival_level_threshold(level):
            mismatches.append(Mismatch(f"level={level}", "threshold", threshold, survival_level_threshold(level), 0x0040AFAE))
    _check(len(levels), mismatches)
