"""`projectile_spawn` (0x00420440) and the player fire paths (Typ-o's `player_fire_weapon`, particle weapons) vs the Python port."""

from __future__ import annotations

import random
import struct

import pytest

from crimson.math_parity import f32
from crimson.owner_id import OWNER_LOCAL_PLAYER
from crimson.perks import PerkId
from crimson.projectiles.runtime import projectile_spawn
from crimson.projectiles.types import Projectile, ProjectileTemplateId
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.typo.player import player_fire_weapon
from crimson.weapon_runtime import weapon_assign_player, weapon_entry
from crimson.weapons import WEAPON_TABLE, WeaponId
from grim.geom import Vec2
from grim.rand import CrtRand
from tests.support.builders.session import make_world
from tests.support.factories import fire_player_weapon, player_input

from ._support import (
    PARTICLE_LAYOUT,
    PARTICLE_STRIDE,
    PLAYER_OFFSETS,
    PROJECTILE_LAYOUT,
    PROJECTILE_STRIDE,
    SPRITE_LAYOUT,
    SPRITE_STRIDE,
    Mismatch,
    compare_fields,
    mismatch_report,
    prepare_gameplay,
    python_sprite,
)

_OWNER_LOCAL_PLAYER = -100


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
            index = oracle.call("projectile_spawn", pos_arg, angle, int(type_id), _OWNER_LOCAL_PLAYER).eax

            world = make_world()
            python_index = projectile_spawn(
                world.state,
                players=world.players,
                pos=pos,
                angle=angle,
                type_id=type_id,
                owner_id=OWNER_LOCAL_PLAYER,
                owner_player_index=0,
            )
            pool = world.state.projectiles
            address = pool_base + index * PROJECTILE_STRIDE
            case = f"type 0x{int(type_id):02x} pos=({pos.x!r}, {pos.y!r}) angle={angle!r}"
            if python_index != index:
                mismatches.append(Mismatch(case, "index", index, python_index, address))
            native = oracle.read_fields(address, PROJECTILE_LAYOUT)
            mismatches += compare_fields(case, native, _python_projectile(pool.entries[python_index]), address=address)
            shots_fired = oracle.read_u32("highscore_record_shots_fired")
            if shots_fired != world.state.shots_fired:
                mismatches.append(Mismatch(case, "shots_fired", shots_fired, world.state.shots_fired, 0))
    assert not mismatches, mismatch_report(mismatches, total_cases=cases)


# `player_state_t` fields `player_fire_weapon` reads or writes.
_TYPO_PLAYER_LAYOUT: dict[str, tuple[int, str]] = {
    "death_timer": (0x10, "f"),
    "pos_x": (0x14, "f"),
    "pos_y": (0x18, "f"),
    "health": (0x24, "f"),
    "size": (0x34, "f"),
    "aim_x": (0x50, "f"),
    "aim_y": (0x54, "f"),
    "move_phase": (0x94, "f"),
    "experience": (0xAC, "i"),
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
}
_PLAYER_PERK_COUNTS = 0xB8
# `weapon_t` (0x7c bytes) `shot_sfx_base_id` and `reload_sfx_id`. Native sfx ids come from the
# audio load, so each weapon's pair is tagged to read the calls back.
_WEAPON_STRIDE = 0x7C
_WEAPON_SHOT_SFX = 0x58
_WEAPON_RELOAD_SFX = 0x60
_SHOT_SFX_TAG = 0x1000
_RELOAD_SFX_TAG = 0x2000
_TYPO_FIRE_PERKS = {
    "perk_id_sharpshooter": PerkId.SHARPSHOOTER,
    "perk_id_fastshot": PerkId.FASTSHOT,
    "perk_id_fastloader": PerkId.FASTLOADER,
    "perk_id_regression_bullets": PerkId.REGRESSION_BULLETS,
    "perk_id_ammunition_within": PerkId.AMMUNITION_WITHIN,
}


def _python_typo_player(player: PlayerState) -> dict[str, float | int]:
    return {
        "death_timer": player.death_timer,
        "pos_x": player.pos.x,
        "pos_y": player.pos.y,
        "aim_x": player.aim.x,
        "aim_y": player.aim.y,
        "move_phase": player.move_phase,
        "spread_heat": player.spread_heat,
        "reload_active": int(player.weapon.reload_active),
        "ammo": player.weapon.ammo,
        "reload_timer": player.weapon.reload_timer,
        "shot_cooldown": player.weapon.shot_cooldown,
        "reload_timer_max": player.weapon.reload_timer_max,
        "muzzle_flash_alpha": player.muzzle_flash_alpha,
        "aim_heading": player.aim_heading,
    }


def _random_typo_player(rng: random.Random, weapon_id: WeaponId) -> PlayerState:
    return PlayerState(
        index=0,
        # Some start outside the terrain, for the clamp.
        pos=Vec2(f32(rng.uniform(-40.0, 1064.0)), f32(rng.uniform(-40.0, 1064.0))),
        health=f32(rng.uniform(1.0, 100.0)) if rng.random() < 0.85 else f32(rng.uniform(-10.0, 0.0)),
        size=f32(rng.uniform(20.0, 80.0)),
        death_timer=f32(rng.uniform(-1.0, 16.0)),
        move_phase=f32(rng.uniform(0.0, 60.0)),
        muzzle_flash_alpha=f32(rng.uniform(0.0, 1.6)),
        spread_heat=f32(rng.uniform(0.0, 0.5)),
        experience=rng.choice((0, rng.randrange(1, 5000))),
        weapon=WeaponSlot(
            weapon_id=weapon_id,
            clip_size=rng.choice((0, rng.randrange(1, 40))),
            ammo=f32(rng.uniform(-2.0, 30.0)),
            reload_active=rng.random() < 0.5,
            reload_timer=f32(rng.uniform(0.0, 3.0)) if rng.random() < 0.5 else 0.0,
            reload_timer_max=f32(rng.uniform(0.0, 3.0)),
            shot_cooldown=f32(rng.uniform(0.0, 1.0)),
        ),
    )


def test_typo_player_fire_weapon_matches_native(oracle) -> None:
    """Typ-o's `player_fire_weapon` (0x00444980) vs `crimson.typo.player.player_fire_weapon`.

    Living and dead players with any weapon, perks, reload and clip state, and
    random frame dt, spread damping, fire/reload requests and RNG seed; compares
    the player, every sprite and projectile, the sfx calls and the RNG state.
    """

    prepare_gameplay(oracle)
    weapon_table = oracle.resolve("weapon_table")
    for weapon in WEAPON_TABLE:
        entry = weapon_table + int(weapon.weapon_id) * _WEAPON_STRIDE
        oracle.write_u32(entry + _WEAPON_SHOT_SFX, _SHOT_SFX_TAG + int(weapon.weapon_id))
        oracle.write_u32(entry + _WEAPON_RELOAD_SFX, _RELOAD_SFX_TAG + int(weapon.weapon_id))
    for name, perk_id in _TYPO_FIRE_PERKS.items():
        oracle.write_u32(name, int(perk_id))
    native_sfx: list[tuple[int, Vec2 | None]] = []

    def sfx_play_panned(call) -> int:
        pos = call.arg_u32(1)
        native_sfx.append((call.arg_u32(0), Vec2(oracle.read_f32(pos), oracle.read_f32(pos + 4))))
        return 0

    oracle.stub("sfx_play_panned", sfx_play_panned)
    pristine = oracle.snapshot()
    player_address = oracle.resolve("player_state_table")
    projectile_pool = oracle.resolve("projectile_pool")
    sprite_pool = oracle.resolve("sprite_effect_pool")
    aim_arg = oracle.alloc(8)

    rng = random.Random(0x444980)
    weapon_ids = [weapon.weapon_id for weapon in WEAPON_TABLE]
    mismatches: list[Mismatch] = []
    cases = 600
    for case_index in range(cases):
        weapon_id = WeaponId.SHOTGUN if rng.random() < 0.5 else rng.choice(weapon_ids)
        player = _random_typo_player(rng, weapon_id)
        perks = [perk_id for perk_id in _TYPO_FIRE_PERKS.values() if rng.random() < 0.25]
        aim = Vec2(f32(rng.uniform(0.0, 1024.0)), f32(rng.uniform(0.0, 1024.0)))
        dt = f32(rng.uniform(0.001, 0.1))
        damping = f32(rng.uniform(0.3, 1.0))
        weapon_power_up = f32(rng.uniform(0.1, 10.0)) if rng.random() < 0.2 else 0.0
        fire_requested = rng.random() < 0.8
        reload_requested = rng.random() < 0.3
        seed = rng.getrandbits(32)

        oracle.restore(pristine)
        native_sfx.clear()
        for name, value in (
            ("death_timer", player.death_timer),
            ("pos_x", player.pos.x),
            ("pos_y", player.pos.y),
            ("health", player.health),
            ("size", player.size),
            ("move_phase", player.move_phase),
            ("muzzle_flash_alpha", player.muzzle_flash_alpha),
            ("spread_heat", player.spread_heat),
            ("clip_size", float(player.weapon.clip_size)),
            ("ammo", player.weapon.ammo),
            ("reload_timer", player.weapon.reload_timer),
            ("reload_timer_max", player.weapon.reload_timer_max),
            ("shot_cooldown", player.weapon.shot_cooldown),
        ):
            oracle.write_f32(player_address + _TYPO_PLAYER_LAYOUT[name][0], value)
        oracle.write_u32(player_address + _TYPO_PLAYER_LAYOUT["experience"][0], player.experience)
        oracle.write_u32(player_address + _TYPO_PLAYER_LAYOUT["weapon_id"][0], int(weapon_id))
        oracle.write_u8(player_address + _TYPO_PLAYER_LAYOUT["reload_active"][0], int(player.weapon.reload_active))
        for perk_id in perks:
            oracle.write_u32(player_address + _PLAYER_PERK_COUNTS + 4 * int(perk_id), 1)
        oracle.write_f32("frame_dt", dt)
        oracle.write_f32("player_spread_damping_scalar", damping)
        oracle.write_f32("bonus_weapon_power_up_timer", weapon_power_up)
        oracle.write_f32(aim_arg, aim.x)
        oracle.write_f32(aim_arg + 4, aim.y)
        oracle.rand_state = seed
        oracle.call("player_fire_weapon", aim_arg, int(fire_requested), int(reload_requested))

        world = make_world()
        state = world.state
        state.rng = CrtRand(seed)
        state.sfx_queue.clear()
        state.player_spread_damping_scalar = damping
        state.bonuses.weapon_power_up = weapon_power_up
        for perk_id in perks:
            state.perks[perk_id] = 1
        world.players[:] = [player]
        player_fire_weapon(
            state,
            world.players,
            player,
            aim,
            fire_requested=fire_requested,
            reload_requested=reload_requested,
            dt=dt,
        )

        case = (
            f"case={case_index} {weapon_id.name} fire={fire_requested} reload={reload_requested} "
            f"perks={[perk.name for perk in perks]} seed=0x{seed:08x}"
        )
        native_player = oracle.read_fields(player_address, _TYPO_PLAYER_LAYOUT)
        mismatches += compare_fields(case, native_player, _python_typo_player(player), address=player_address)
        weapon = weapon_entry(weapon_id)
        python_sfx = [
            ((_SHOT_SFX_TAG if request.sfx_id == weapon.fire_sounds[0] else _RELOAD_SFX_TAG) + int(weapon_id), request.position)
            for request in state.sfx_queue
        ]
        if python_sfx != native_sfx:
            mismatches.append(Mismatch(case, f"sfx {native_sfx} != {python_sfx}", len(native_sfx), len(python_sfx), 0))
        for index, projectile in enumerate(state.projectiles.entries):
            address = projectile_pool + index * PROJECTILE_STRIDE
            native = oracle.read_fields(address, PROJECTILE_LAYOUT)
            if native["active"] or projectile.active:
                mismatches += compare_fields(f"{case} projectile[{index}]", native, _python_projectile(projectile), address=address)
        for index, sprite in enumerate(state.sprite_effects.entries):
            address = sprite_pool + index * SPRITE_STRIDE
            native = oracle.read_fields(address, SPRITE_LAYOUT)
            if native["active"] or sprite.active:
                mismatches += compare_fields(f"{case} sprite[{index}]", native, python_sprite(sprite), address=address)
        if oracle.rand_state != state.rng.state:
            mismatches.append(Mismatch(case, "rand_state", oracle.rand_state, state.rng.state, 0))
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

        world = make_world()
        state = world.state
        state.rng.srand(seed)
        python_player = PlayerState(index=0, pos=pos)
        world.players[:] = [python_player]
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
            fire_player_weapon(world, python_player, player_input(fire_down=True, aim=aim), 0.016)
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
