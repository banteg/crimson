"""Native `effect_spawn_*` helpers vs their `EffectPool` / projectile-hit ports.

Each case restores a pristine effect pool, runs the native spawner with a random
position, argument, detail preset and rand seed, and compares every entry it pops
off the effect free list, in order, with the entries the port spawns.

The native spawners fill the shared `effect_template` and leave fields they do not
set (`rotation_step` in the burst-style spawners) from the previous spawn; the port
passes 0.0 there, so the pristine template is primed with that value. An entry's
`rotation_step` is only compared when its flags enable rotation (`effects_update`
reads it under flag 0x4 alone).
"""

from __future__ import annotations

import random
import struct
from collections.abc import Callable

from crimson.effects import EffectEntry, EffectPool
from crimson.math_parity import f32, native_fire_muzzle_pos
from crimson.projectiles.effects import (
    _spawn_ion_hit_effects,
    _spawn_plasma_cannon_hit_effects,
    _spawn_shrinkifier_hit_effects,
    _spawn_splitter_hit_effects,
)
from crimson.projectiles.types import ProjectileTemplateId
from crimson.weapons import WeaponId
from grim.geom import Vec2
from grim.rand import CrtRand

from ._support import Mismatch, compare_fields, mismatch_report, prepare_gameplay

_ENTRY_NEXT_FREE = 0xB8
_TEMPLATE_ROTATION_STEP = 0x34
_EFFECT_LAYOUT: dict[str, tuple[int, str]] = {
    "pos_x": (0x00, "f"),
    "pos_y": (0x04, "f"),
    "effect_id": (0x08, "B"),
    "vel_x": (0x0C, "f"),
    "vel_y": (0x10, "f"),
    "rotation": (0x14, "f"),
    "scale": (0x18, "f"),
    "half_width": (0x1C, "f"),
    "half_height": (0x20, "f"),
    "age": (0x24, "f"),
    "lifetime": (0x28, "f"),
    "flags": (0x2C, "i"),
    "color_r": (0x30, "f"),
    "color_g": (0x34, "f"),
    "color_b": (0x38, "f"),
    "color_a": (0x3C, "f"),
    "rotation_step": (0x40, "f"),
    "scale_step": (0x44, "f"),
}
_CASES = 400


# `draw(rng)` picks the spawner's extra arguments; `native(oracle, pos_arg, *args)` runs the original and
# `python(pool, crand, pos, detail, *args)` the port.
Draw = Callable[[random.Random], tuple]
NativeSpawn = Callable[..., None]
PythonSpawn = Callable[..., None]


def _python_entry(entry: EffectEntry) -> dict[str, float | int | None]:
    return {
        "pos_x": entry.pos.x,
        "pos_y": entry.pos.y,
        "effect_id": entry.effect_id,
        "vel_x": entry.vel.x,
        "vel_y": entry.vel.y,
        "rotation": entry.rotation,
        "scale": entry.scale,
        "half_width": entry.half_width,
        "half_height": entry.half_height,
        "age": entry.age,
        "lifetime": entry.lifetime,
        "flags": entry.flags,
        "color_r": entry.color.r,
        "color_g": entry.color.g,
        "color_b": entry.color.b,
        "color_a": entry.color.a,
        "rotation_step": entry.rotation_step if entry.flags & 0x4 else None,
        "scale_step": entry.scale_step,
    }


def _check_spawns(oracle, *, seed: int, draw: Draw, native: NativeSpawn, python: PythonSpawn) -> None:
    prepare_gameplay(oracle)
    oracle.write_f32(oracle.resolve("effect_template") + _TEMPLATE_ROTATION_STEP, 0.0)
    pristine = oracle.snapshot()
    pos_arg = oracle.alloc(8)
    rng = random.Random(seed)
    mismatches: list[Mismatch] = []
    for case_index in range(_CASES):
        pos = Vec2(f32(rng.uniform(0.0, 1024.0)), f32(rng.uniform(0.0, 1024.0)))
        detail = rng.randrange(6)
        rand_seed = rng.getrandbits(32)
        args = draw(rng)

        oracle.restore(pristine)
        oracle.write_u32("config_detail_preset", detail)
        oracle.write_f32(pos_arg, pos.x)
        oracle.write_f32(pos_arg + 4, pos.y)
        oracle.rand_state = rand_seed
        head = oracle.read_u32("effect_free_list_head")
        native(oracle, pos_arg, *args)
        popped = []
        address = head
        while address != oracle.read_u32("effect_free_list_head"):
            popped.append(address)
            address = oracle.read_u32(address + _ENTRY_NEXT_FREE)

        crand = CrtRand(rand_seed)
        pool = EffectPool()
        python(pool, crand, pos, detail, *args)
        spawned = [entry for entry in pool.entries if entry.flags]
        label = f"case={case_index} detail={detail} args={args!r} seed=0x{rand_seed:08x}"
        if len(spawned) != len(popped):
            mismatches.append(Mismatch(label, "count", len(popped), len(spawned), head))
        for index, (entry_address, entry) in enumerate(zip(popped, spawned, strict=False)):
            native_fields = oracle.read_fields(entry_address, _EFFECT_LAYOUT)
            mismatches += compare_fields(f"{label} effect[{index}]", native_fields, _python_entry(entry), address=entry_address)
        if oracle.rand_state != crand.state:
            mismatches.append(Mismatch(label, "rand_state", oracle.rand_state, crand.state, 0))
    assert not mismatches, mismatch_report(mismatches, total_cases=_CASES)


def _no_args(_rng: random.Random) -> tuple:
    return ()


def test_shrinkifier_hit_matches_native(oracle) -> None:
    _check_spawns(
        oracle,
        seed=0x42F080,
        draw=_no_args,
        native=lambda oracle, pos_arg: oracle.call("effect_spawn_shrinkifier_hit", pos_arg),
        python=lambda pool, crand, pos, detail: _spawn_shrinkifier_hit_effects(pool, pos=pos, rng=crand, detail_preset=detail),
    )


# `projectile_update` ion hits: `effect_spawn_ion_hit_core(pos, scale_step, lifetime)` then `effect_spawn_ion_hit_sparks(pos, scale)`.
_ION_HIT_ARGS = {
    ProjectileTemplateId.ION_MINIGUN: (1.5, 0.1, 0.8),
    ProjectileTemplateId.ION_RIFLE: (1.2, 0.4, 1.2),
    ProjectileTemplateId.ION_CANNON: (1.0, 1.0, 2.2),
}


def _native_ion_hit(oracle, pos_arg: int, type_id: ProjectileTemplateId) -> None:
    core_scale_step, core_lifetime, sparks_scale = _ION_HIT_ARGS[type_id]
    oracle.call("effect_spawn_ion_hit_core", pos_arg, core_scale_step, core_lifetime)
    oracle.call("effect_spawn_ion_hit_sparks", pos_arg, sparks_scale)


def test_ion_hit_matches_native(oracle) -> None:
    _check_spawns(
        oracle,
        seed=0x42F270,
        draw=lambda rng: (rng.choice(tuple(_ION_HIT_ARGS)),),
        native=_native_ion_hit,
        python=lambda pool, crand, pos, detail, type_id: _spawn_ion_hit_effects(
            pool, [], type_id=type_id, pos=pos, rng=crand, detail_preset=detail,
        ),
    )


def test_plasma_cannon_hit_matches_native(oracle) -> None:
    def native(oracle, pos_arg: int) -> None:
        oracle.call("effect_spawn_plasma_hit_core", pos_arg, 1.5, 1.0)
        oracle.call("effect_spawn_plasma_hit_core", pos_arg, 1.0, 1.0)

    _check_spawns(
        oracle,
        seed=0x42F5A0,
        draw=_no_args,
        native=native,
        python=lambda pool, crand, pos, detail: _spawn_plasma_cannon_hit_effects(pool, [], pos=pos, detail_preset=detail),
    )


def test_splitter_hit_burst_matches_native(oracle) -> None:
    _check_spawns(
        oracle,
        seed=0x42F3F0,
        draw=_no_args,
        native=lambda oracle, pos_arg: oracle.call("effect_spawn_splitter_hit_burst", pos_arg, 26.0, 3),
        python=lambda pool, crand, pos, detail: _spawn_splitter_hit_effects(pool, pos=pos, rng=crand, detail_preset=detail),
    )


def test_burst_matches_native(oracle) -> None:
    _check_spawns(
        oracle,
        seed=0x42EF60,
        draw=lambda rng: (rng.randrange(1, 17),),
        native=lambda oracle, pos_arg, count: oracle.call("effect_spawn_burst", pos_arg, count),
        python=lambda pool, crand, pos, detail, count: pool.spawn_burst(pos=pos, count=count, rng=crand, detail_preset=detail),
    )


def test_blood_splatter_matches_native(oracle) -> None:
    _check_spawns(
        oracle,
        seed=0x42EB10,
        draw=lambda rng: (f32(rng.uniform(-7.0, 7.0)), f32(rng.choice((0.0, rng.uniform(0.0, 0.25))))),
        native=lambda oracle, pos_arg, angle, age: oracle.call("effect_spawn_blood_splatter", pos_arg, angle, age),
        python=lambda pool, crand, pos, detail, angle, age: pool.spawn_blood_splatter(
            pos=pos, angle=angle, age=age, rng=crand, detail_preset=detail, violence_disabled=0,
        ),
    )


def test_explosion_burst_matches_native(oracle) -> None:
    _check_spawns(
        oracle,
        seed=0x42F6C0,
        draw=lambda rng: (f32(rng.choice((0.4, 1.0, 1.8, rng.uniform(0.1, 3.0)))),),
        native=lambda oracle, pos_arg, scale: oracle.call("effect_spawn_explosion_burst", pos_arg, scale),
        python=lambda pool, crand, pos, detail, scale: pool.spawn_explosion_burst(pos=pos, scale=scale, rng=crand, detail_preset=detail),
    )


# `player_update` fire block (0x00415a1f..0x00415bcf): the muzzle offset, then the weapon-flag-1 shell casing.
_CASING_START = 0x00415A1F
_CASING_STOP = 0x00415BCF
_FRAME_FIRE_HEADING = 0x1C


def _native_shell_casing(oracle, pos_arg: int, aim_heading: float) -> None:
    player = oracle.resolve("player_state_table")
    oracle.write(player + 0x14, oracle.read(pos_arg, 8))
    oracle.write_u32(player + 0x2C0, int(WeaponId.ASSAULT_RIFLE))
    frame = bytearray(0x80)
    struct.pack_into("<f", frame, _FRAME_FIRE_HEADING, aim_heading)
    oracle.run(_CASING_START, _CASING_STOP, regs={"edi": player, "esi": player + 0x14}, frame=bytes(frame))


def _python_shell_casing(pool: EffectPool, crand: CrtRand, pos: Vec2, detail: int, aim_heading: float) -> None:
    draws = (crand.rand(), crand.rand(), crand.rand(), crand.rand())
    pool.spawn_shell_casing(
        pos=native_fire_muzzle_pos(pos, aim_heading), aim_heading=aim_heading, draws=draws, detail_preset=detail,
    )


def test_shell_casing_matches_native(oracle) -> None:
    _check_spawns(
        oracle,
        seed=0x415A1F,
        draw=lambda rng: (f32(rng.uniform(-1.0, 7.3)),),
        native=_native_shell_casing,
        python=_python_shell_casing,
    )
