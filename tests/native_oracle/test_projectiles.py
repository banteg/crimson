"""`projectile_spawn` (0x00420440) and the player fire paths (shotgun pellets, particle weapons) vs the Python port."""

from __future__ import annotations

import random
import struct

import pytest

from crimson.math_parity import f32
from crimson.owner_ref import OwnerRef
from crimson.projectiles.runtime.projectile_pool import ProjectilePool
from crimson.projectiles.types import Projectile, ProjectileTemplateId
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from crimson.weapon_runtime import WeaponFireCtx, fire_weapon, weapon_assign_player
from crimson.weapons import WeaponId
from grim.geom import Vec2
from grim.rand import CRT_RAND_INC, CRT_RAND_MULT, CrtRand

from ._support import (
    PARTICLE_LAYOUT,
    PARTICLE_STRIDE,
    PLAYER_OFFSETS,
    PROJECTILE_LAYOUT,
    PROJECTILE_STRIDE,
    Mismatch,
    compare_fields,
    mismatch_report,
    prepare_gameplay,
)

_LOCAL_PLAYER_OWNER_ID = -100


def _python_projectile(projectile: Projectile) -> dict[str, float | int | None]:
    return {
        "active": int(projectile.active),
        "angle": projectile.angle,
        "pos_x": projectile.pos.x,
        "pos_y": projectile.pos.y,
        "origin_x": projectile.origin.x,
        "origin_y": projectile.origin.y,
        "vel_x": projectile.vel.x,
        "vel_y": projectile.vel.y,
        "type_id": int(projectile.type_id),
        "life_timer": projectile.life_timer,
        "reserved": projectile.reserved,
        "speed_scale": projectile.speed_scale,
        "damage_pool": projectile.damage_pool,
        "hit_radius": projectile.hit_radius,
        "travel_budget": projectile.travel_budget,
    }


def test_projectile_spawn_fields_match_native(oracle) -> None:
    oracle.call("weapon_table_init")
    pristine = oracle.snapshot()
    pool_base = oracle.resolve("projectile_pool")
    pos_arg = oracle.alloc(8)
    rng = random.Random(0x420440)
    mismatches: list[Mismatch] = []
    cases = 0
    for type_id in ProjectileTemplateId:
        for _ in range(40):
            cases += 1
            pos = Vec2(f32(rng.uniform(-100.0, 1100.0)), f32(rng.uniform(-100.0, 1100.0)))
            angle = f32(rng.uniform(-7.0, 7.0))
            oracle.restore(pristine)
            oracle.write_f32(pos_arg, pos.x)
            oracle.write_f32(pos_arg + 4, pos.y)
            index = oracle.call("projectile_spawn", pos_arg, angle, int(type_id), _LOCAL_PLAYER_OWNER_ID).eax

            pool = ProjectilePool()
            python_index = pool.spawn(pos=pos, angle=angle, type_id=type_id, owner=OwnerRef.from_local_player(0))
            address = pool_base + index * PROJECTILE_STRIDE
            case = f"type 0x{int(type_id):02x} pos=({pos.x!r}, {pos.y!r}) angle={angle!r}"
            if python_index != index:
                mismatches.append(Mismatch(case, "index", index, python_index, address))
            native = oracle.read_fields(address, PROJECTILE_LAYOUT)
            mismatches += compare_fields(case, native, _python_projectile(pool.entries[python_index]), address=address)
    assert not mismatches, mismatch_report(mismatches, total_cases=cases)


# Return address of the pellet-jitter `crt_rand` call in `player_fire_weapon` (0x00444d65).
_NATIVE_PELLET_JITTER_RETURN = 0x00444D6A


def _python_shotgun_volley(seed: int, pos: Vec2, aim: Vec2, aim_heading: float) -> tuple[GameplayState, int]:
    """Fire the port's shotgun; return the state and the RNG seed at the first pellet draw."""

    from crimson.weapon_runtime.fire import _PELLET_JITTER_CALLER_BY_WEAPON

    rng = CrtRand(seed)
    first_pellet_state: list[int] = []
    pellet_caller = int(_PELLET_JITTER_CALLER_BY_WEAPON[WeaponId.SHOTGUN])

    def sink(state_before: int, _state_after: int, _value: int, caller: int | None) -> None:
        if caller == pellet_caller and not first_pellet_state:
            first_pellet_state.append(state_before)

    rng.set_trace_sink(sink)
    state = GameplayState(rng=rng)
    player = PlayerState(index=0, pos=pos)
    weapon_assign_player(player, WeaponId.SHOTGUN, state=state)
    player.spread_heat = 0.0
    # `player_update` stores aim_heading before firing; the muzzle reads it.
    player.aim_heading = aim_heading
    fire_weapon(WeaponFireCtx(player=player, input_state=PlayerInput(fire_down=True, aim=aim), dt=0.016, state=state))
    assert first_pellet_state, "port did not draw shotgun pellet jitter"
    return state, first_pellet_state[0]


def _aligning_rand(oracle, pellet_seed: int):
    """Exact Python `crt_rand` that jumps to `pellet_seed` at the first pellet-jitter draw."""

    aligned = False

    def rand(call) -> int:
        nonlocal aligned
        if call.return_address == _NATIVE_PELLET_JITTER_RETURN and not aligned:
            aligned = True
            oracle.rand_state = pellet_seed
        oracle.rand_state = (oracle.rand_state * CRT_RAND_MULT + CRT_RAND_INC) & 0xFFFF_FFFF
        return (oracle.rand_state >> 16) & 0x7FFF

    return rand


def _native_fire(oracle, pristine, *, pos: Vec2, aim: Vec2, aim_arg: int, rand_state: int) -> None:
    player = oracle.resolve("player_state_table")
    oracle.restore(pristine)
    oracle.write_f32(player + PLAYER_OFFSETS["pos_x"], pos.x)
    oracle.write_f32(player + PLAYER_OFFSETS["pos_y"], pos.y)
    oracle.write_f32(player + PLAYER_OFFSETS["health"], 100.0)
    oracle.write_f32(player + PLAYER_OFFSETS["size"], 48.0)
    oracle.write_u32(player + PLAYER_OFFSETS["weapon_id"], int(WeaponId.SHOTGUN))
    oracle.write_f32(player + PLAYER_OFFSETS["clip_size"], 12.0)
    oracle.write_f32(aim_arg, aim.x)
    oracle.write_f32(aim_arg + 4, aim.y)
    oracle.rand_state = rand_state
    oracle.call("player_fire_weapon", aim_arg, 1, 0)


def test_typo_shotgun_pellets_match_native(oracle) -> None:
    """Native `player_fire_weapon` (0x00444980, Typ-o's fire path) vs the port's `fire_weapon`.

    Both sides fire a SHOTGUN with zero spread heat from the same position and aim.
    The port gets the native aim heading (its `player_update` stores it before
    firing); `crt_rand` runs as an exact Python LCG stub (see test_harness) so
    the native seed can be aligned to the port's at the first pellet draw.
    """

    oracle.call("weapon_table_init")
    oracle.stub("sfx_play_panned", 0)
    oracle.write_u32("terrain_texture_width", 1024)
    oracle.write_u32("terrain_texture_height", 1024)
    pristine = oracle.snapshot()
    pool_base = oracle.resolve("projectile_pool")
    aim_heading_address = oracle.resolve("player_state_table") + PLAYER_OFFSETS["aim_heading"]
    aim_arg = oracle.alloc(8)

    rng = random.Random(0x444980)
    mismatches: list[Mismatch] = []
    cases = 0
    for _ in range(150):
        cases += 1
        pos = Vec2(f32(rng.uniform(100.0, 900.0)), f32(rng.uniform(100.0, 900.0)))
        aim = Vec2(f32(pos.x + rng.uniform(-300.0, 300.0)), f32(pos.y + rng.uniform(-300.0, 300.0)))
        seed = rng.getrandbits(32)

        # The aim heading does not depend on RNG: take it from a first native run.
        _native_fire(oracle, pristine, pos=pos, aim=aim, aim_arg=aim_arg, rand_state=seed)
        native_aim_heading = oracle.read_f32(aim_heading_address)
        state, pellet_seed = _python_shotgun_volley(seed, pos, aim, native_aim_heading)

        # Pre-pellet native draws (muzzle sprites) vary with the RNG, so align the
        # seed at the first pellet-jitter call instead of counting draws.
        oracle.stub("crt_rand", _aligning_rand(oracle, pellet_seed))
        _native_fire(oracle, pristine, pos=pos, aim=aim, aim_arg=aim_arg, rand_state=seed)
        oracle.unstub("crt_rand")

        case = f"shotgun seed=0x{seed:08x} pos=({pos.x!r}, {pos.y!r}) aim=({aim.x!r}, {aim.y!r})"
        python_projectiles = [entry for entry in state.projectiles.entries if entry.active]
        for index, projectile in enumerate(python_projectiles):
            address = pool_base + index * PROJECTILE_STRIDE
            native = oracle.read_fields(address, PROJECTILE_LAYOUT)
            mismatches += compare_fields(f"{case} pellet[{index}]", native, _python_projectile(projectile), address=address)
    assert not mismatches, mismatch_report(mismatches, total_cases=cases)


# `player_update` fire block from the muzzle math (0x00415a1f) to just past the
# ammo subtraction (0x004174c4). Its stack frame holds the aim heading at +0x1c
# and a pointer to the player's spread heat at +0x24.
_PLAYER_FIRE_BLOCK_START = 0x00415A1F
_PLAYER_FIRE_BLOCK_STOP = 0x004174C4


def _fake_grim_interface(oracle) -> int:
    """A `grim_interface_ptr` whose every vtable slot is a `thiscall` key query returning 0."""

    key_inactive = oracle.load_code(b"\x31\xc0\xc2\x04\x00")  # xor eax, eax; ret 4
    vtable = oracle.alloc(0x400, data=struct.pack("<256I", *([key_inactive] * 256)))
    return oracle.alloc(0x10, data=struct.pack("<I", vtable))


@pytest.mark.parametrize(
    "weapon_id",
    [WeaponId.FLAMETHROWER, WeaponId.BLOW_TORCH, WeaponId.HR_FLAMER, WeaponId.BUBBLEGUN],
    ids=lambda weapon_id: weapon_id.name.lower(),
)
def test_particle_weapons_match_native(oracle, weapon_id: WeaponId) -> None:
    """Flamer and Bubblegun shots: unwrapped `heading - 1.5707964f` particle angles and float32 ammo costs.

    Fires a full clip through the native `player_update` fire block and the port's
    `fire_weapon`, comparing ammo after every shot and the first shot's particle.
    """

    prepare_gameplay(oracle)
    oracle.write_u32("grim_interface_ptr", _fake_grim_interface(oracle))
    pristine = oracle.snapshot()
    player = oracle.resolve("player_state_table")
    particle_pool = oracle.resolve("particle_pool")
    ammo_address = player + PLAYER_OFFSETS["ammo"]

    rng = random.Random(0x415A1F + int(weapon_id))
    mismatches: list[Mismatch] = []
    cases = 0
    for _ in range(20):
        cases += 1
        seed = rng.getrandbits(32)
        pos = Vec2(f32(rng.uniform(100.0, 900.0)), f32(rng.uniform(100.0, 900.0)))
        aim = Vec2(f32(pos.x + rng.uniform(-300.0, 300.0)), f32(pos.y + rng.uniform(-300.0, 300.0)))
        # Headings outside (-pi/2, 3pi/2] expose angle wrapping.
        aim_heading = f32(rng.uniform(-1.0, 7.3))

        state = GameplayState()
        state.rng.srand(seed)
        python_player = PlayerState(index=0, pos=pos)
        weapon_assign_player(python_player, weapon_id, state=state)
        python_player.aim_heading = aim_heading

        oracle.restore(pristine)
        oracle.rand_state = seed
        for field, value in (("pos_x", pos.x), ("pos_y", pos.y), ("aim_x", aim.x), ("aim_y", aim.y)):
            oracle.write_f32(player + PLAYER_OFFSETS[field], value)
        oracle.write_f32(player + PLAYER_OFFSETS["health"], 100.0)
        oracle.write_f32(player + PLAYER_OFFSETS["size"], 48.0)
        oracle.write_u32(player + PLAYER_OFFSETS["weapon_id"], int(weapon_id))
        oracle.write_f32(player + PLAYER_OFFSETS["clip_size"], python_player.weapon.clip_size)
        oracle.write_f32(ammo_address, python_player.weapon.ammo)

        case = f"{weapon_id.name} seed=0x{seed:08x} heading={aim_heading!r}"
        shot = 0
        while python_player.weapon.ammo > 0.0:
            shot += 1
            frame = bytearray(0x400)
            struct.pack_into("<f", frame, 0x1C, aim_heading)
            struct.pack_into("<I", frame, 0x24, player + PLAYER_OFFSETS["spread_heat"])
            oracle.write_f32(player + PLAYER_OFFSETS["spread_heat"], 0.0)
            oracle.run(
                _PLAYER_FIRE_BLOCK_START,
                _PLAYER_FIRE_BLOCK_STOP,
                regs={"edi": player, "esi": player + PLAYER_OFFSETS["pos_x"]},
                frame=bytes(frame),
            )
            # Keep the port's cooldown and spread gates in step with the fragment.
            python_player.weapon.shot_cooldown = 0.0
            python_player.spread_heat = 0.0
            fire_weapon(
                WeaponFireCtx(
                    player=python_player, input_state=PlayerInput(fire_down=True, aim=aim), dt=0.016, state=state,
                ),
            )
            if shot == 1:
                particle = next(entry for entry in reversed(state.particles.entries) if entry.active)
                slot = state.particles.entries.index(particle)
                address = particle_pool + slot * PARTICLE_STRIDE
                python_particle = {
                    "active": int(particle.active),
                    "pos_x": particle.pos.x,
                    "pos_y": particle.pos.y,
                    "vel_x": particle.vel.x,
                    "vel_y": particle.vel.y,
                    "intensity": particle.intensity,
                    "angle": particle.angle,
                    "style_id": int(particle.style_id),
                }
                native_particle = oracle.read_fields(address, PARTICLE_LAYOUT)
                mismatches += compare_fields(
                    f"{case} particle[{slot}]", native_particle, python_particle, address=address,
                )
            native_ammo = oracle.read_f32(ammo_address)
            ammo = compare_fields(
                f"{case} shot {shot}", {"ammo": native_ammo}, {"ammo": python_player.weapon.ammo}, address=ammo_address,
            )
            if ammo:
                mismatches += ammo
                break
        if not mismatches and oracle.read_f32(ammo_address) > 0.0:
            mismatches.append(Mismatch(case, "clip shots", shot + 1, shot, ammo_address))
        if oracle.rand_state != state.rng.state:
            mismatches.append(Mismatch(case, "rand_state", oracle.rand_state, state.rng.state, 0))
    assert not mismatches, mismatch_report(mismatches, total_cases=cases)
