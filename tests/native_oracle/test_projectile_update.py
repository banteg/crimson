"""`projectile_update` (0x00420b90) steps vs the port's primary and secondary pools.

Each case seeds one projectile and a few creatures on both sides, runs one native
`projectile_update` and the matching port step from the same `crt_rand` seed, and
compares projectiles, creatures, the shock-chain globals and the RNG state.
"""

from __future__ import annotations

import math
import random

import pytest

from crimson.creatures.lifecycle import CREATURE_LIFECYCLE_ALIVE
from crimson.effects import FxQueue
from crimson.game_modes import GameMode
from crimson.math_parity import f32
from crimson.owner_ref import OwnerRef
from crimson.projectiles.runtime import PrimaryStepCtx, ProjectileUpdateOptions, SecondaryStepCtx
from crimson.projectiles.types import ProjectileTemplateId, SecondaryProjectile, SecondaryProjectileTypeId
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState, _WorldStepRuntime
from crimson.weapons import build_damage_scale_by_type
from grim.geom import Vec2

from ._support import (
    CREATURE_LAYOUT,
    CREATURE_STRIDE,
    PROJECTILE_LAYOUT,
    PROJECTILE_STRIDE,
    SECONDARY_PROJECTILE_LAYOUT,
    Mismatch,
    compare_fields,
    mismatch_report,
    prepare_gameplay,
)
from .test_projectiles import _python_projectile

_WORLD_SIZE = 1024.0
_LOCAL_PLAYER_OWNER_ID = -100


def _python_world(seed: int) -> WorldState:
    world = WorldState.build(world_size=_WORLD_SIZE, demo_mode_active=True, hardcore=False, quest_fail_retry_count=0)
    # Native `creature_find_nearest` falls back to slot 0 (shock chain retargets).
    world.state.preserve_bugs = True
    world.state.rng.srand(seed)
    world.players.append(PlayerState(index=0, pos=Vec2(900.0, 900.0)))
    return world


def _step_runtime(world: WorldState, dt: float) -> _WorldStepRuntime:
    return _WorldStepRuntime(
        world=world,
        dt=dt,
        world_size=_WORLD_SIZE,
        detail_preset=5,
        violence_disabled=0,
        fx_queue=FxQueue(),
        game_mode=GameMode.SURVIVAL,
        hit_audio_game_tune_started=True,
        deaths=[],
        sfx=[],
    )


def _place_creature(
    oracle,
    world: WorldState,
    index: int,
    *,
    pos: Vec2,
    health: float,
    size: float,
    lifecycle: float = CREATURE_LIFECYCLE_ALIVE,
) -> None:
    address = oracle.resolve("creature_pool") + index * CREATURE_STRIDE
    oracle.write_u8(address, 1)
    oracle.write_f32(address + CREATURE_LAYOUT["lifecycle_stage"][0], lifecycle)
    oracle.write_f32(address + CREATURE_LAYOUT["pos_x"][0], pos.x)
    oracle.write_f32(address + CREATURE_LAYOUT["pos_y"][0], pos.y)
    oracle.write_f32(address + CREATURE_LAYOUT["health"][0], health)
    oracle.write_f32(address + CREATURE_LAYOUT["max_health"][0], health)
    oracle.write_f32(address + CREATURE_LAYOUT["size"][0], size)
    creature = world.creatures.entries[index]
    creature.active = True
    creature.lifecycle_stage = lifecycle
    creature.pos = pos
    creature.hp = health
    creature.max_hp = health
    creature.size = size


def _compare_creatures(oracle, world: WorldState, count: int, case: str) -> list[Mismatch]:
    pool = oracle.resolve("creature_pool")
    mismatches = []
    for index in range(count):
        address = pool + index * CREATURE_STRIDE
        creature = world.creatures.entries[index]
        python = {
            "active": int(creature.active),
            "lifecycle_stage": creature.lifecycle_stage,
            "health": creature.hp,
            "size": creature.size,
            "vel_x": creature.vel.x,
            "vel_y": creature.vel.y,
        }
        mismatches += compare_fields(
            f"{case} creature[{index}]", oracle.read_fields(address, CREATURE_LAYOUT), python, address=address,
        )
    return mismatches


def _rand_mismatch(oracle, world: WorldState, case: str) -> list[Mismatch]:
    if oracle.rand_state == world.state.rng.state:
        return []
    return [Mismatch(case, "rand_state", oracle.rand_state, world.state.rng.state, 0)]


def _python_secondary(entry: SecondaryProjectile) -> dict[str, float | int | None]:
    detonation = entry.type_id == SecondaryProjectileTypeId.DETONATION
    return {
        "active": int(entry.active),
        "angle": entry.angle,
        "life_timer": entry.speed,
        "pos_x": entry.pos.x,
        "pos_y": entry.pos.y,
        "vel_x": entry.detonation_t if detonation else entry.vel.x,
        "vel_y": entry.detonation_scale if detonation else entry.vel.y,
        "type_id": int(entry.type_id),
        "trail_timer": entry.trail_timer,
        "target_id": None if detonation else entry.target_id,
    }


def _seed_secondary(
    oracle,
    entry: SecondaryProjectile,
    *,
    type_id: SecondaryProjectileTypeId,
    pos: Vec2,
    vel: Vec2,
    angle: float = 0.0,
    life_timer: float = 0.0,
    trail_timer: float = 0.0,
    target_id: int = 0,
) -> None:
    address = oracle.resolve("secondary_projectile_pool")
    values = {
        "angle": angle,
        "life_timer": life_timer,
        "pos_x": pos.x,
        "pos_y": pos.y,
        "vel_x": vel.x,
        "vel_y": vel.y,
        "trail_timer": trail_timer,
    }
    oracle.write_u8(address, 1)
    for name, value in values.items():
        oracle.write_f32(address + SECONDARY_PROJECTILE_LAYOUT[name][0], value)
    oracle.write_u32(address + SECONDARY_PROJECTILE_LAYOUT["type_id"][0], int(type_id))
    oracle.write_u32(address + SECONDARY_PROJECTILE_LAYOUT["target_id"][0], target_id)

    entry.active = True
    entry.type_id = type_id
    entry.angle = angle
    entry.speed = life_timer
    entry.pos = pos
    entry.vel = vel
    entry.trail_timer = trail_timer
    entry.target_id = target_id
    if type_id == SecondaryProjectileTypeId.DETONATION:
        entry.detonation_t = vel.x
        entry.detonation_scale = vel.y


def _step_secondary(oracle, world: WorldState, dt: float) -> None:
    oracle.write_f32("frame_dt", dt)
    oracle.call("projectile_update")
    runtime = _step_runtime(world, dt)
    world.state.secondary_projectiles.step(
        SecondaryStepCtx(
            dt=dt,
            creatures=world.creatures.entries,
            runtime_state=world.state,
            fx_queue=runtime.fx_queue,
            detail_preset=5,
            creature_damage_runtime=runtime,
        ),
    )


def test_secondary_rockets_match_native(oracle) -> None:
    """Rocket, seeker and rocket-minigun flight: speed caps, acceleration, homing and trail timers."""

    prepare_gameplay(oracle)
    pristine = oracle.snapshot()
    secondary = oracle.resolve("secondary_projectile_pool")
    rng = random.Random(0x422000)
    mismatches: list[Mismatch] = []
    cases = 0
    for _ in range(120):
        cases += 1
        seed = rng.getrandbits(32)
        oracle.restore(pristine)
        oracle.rand_state = seed
        world = _python_world(seed)
        type_id = rng.choice(
            (
                SecondaryProjectileTypeId.ROCKET,
                SecondaryProjectileTypeId.HOMING_ROCKET,
                SecondaryProjectileTypeId.ROCKET_MINIGUN,
            ),
        )
        speed = rng.uniform(0.0, 700.0)
        # The seeker's target sits far enough away that no step hits it.
        _place_creature(
            oracle,
            world,
            0,
            pos=Vec2(f32(rng.uniform(0.0, 60.0)), f32(rng.uniform(0.0, 60.0))),
            health=100.0,
            size=50.0,
        )
        entry = world.state.secondary_projectiles.entries[0]
        _seed_secondary(
            oracle,
            entry,
            type_id=type_id,
            pos=Vec2(f32(rng.uniform(400.0, 600.0)), f32(rng.uniform(400.0, 600.0))),
            vel=Vec2(f32(speed * rng.uniform(-1.0, 1.0)), f32(speed * rng.uniform(-1.0, 1.0))),
            angle=f32(rng.uniform(-7.0, 7.0)),
            life_timer=f32(rng.uniform(0.2, 2.0)),
            trail_timer=f32(rng.uniform(0.0, 0.06)),
        )
        for step in range(10):
            _step_secondary(oracle, world, f32(rng.uniform(0.005, 0.04)))
            case = f"{type_id.name} seed=0x{seed:08x} step {step}"
            native = oracle.read_fields(secondary, SECONDARY_PROJECTILE_LAYOUT)
            mismatches += compare_fields(case, native, _python_secondary(entry), address=secondary)
            mismatches += _rand_mismatch(oracle, world, case)
    assert not mismatches, mismatch_report(mismatches, total_cases=cases)


def test_secondary_detonation_matches_native(oracle) -> None:
    """Detonation blast radius, distance test, damage and impulse over live creatures and shrunk corpses.

    Native gates the blast only on `active && health > 0`: Shrinkifier kills keep
    positive health, so their corpses take blast damage at any lifecycle stage.
    """

    prepare_gameplay(oracle)
    pristine = oracle.snapshot()
    secondary = oracle.resolve("secondary_projectile_pool")
    rng = random.Random(0x420F00)
    mismatches: list[Mismatch] = []
    cases = 0
    for _ in range(250):
        cases += 1
        seed = rng.getrandbits(32)
        oracle.restore(pristine)
        oracle.rand_state = seed
        world = _python_world(seed)
        center = Vec2(512.0, 512.0)
        timer = f32(rng.uniform(0.0, 1.05))
        scale = f32(rng.uniform(0.3, 1.5))
        radius = timer * scale * 80.0
        creature_count = 12
        for index in range(creature_count):
            distance = radius * rng.uniform(0.5, 1.3) + rng.uniform(-1.0, 1.0)
            direction = rng.uniform(0.0, math.tau)
            lifecycle = rng.choice(
                (
                    CREATURE_LIFECYCLE_ALIVE,
                    CREATURE_LIFECYCLE_ALIVE,
                    f32(rng.uniform(5.5, 15.9)),
                    f32(rng.uniform(-9.0, 5.0)),
                ),
            )
            _place_creature(
                oracle,
                world,
                index,
                pos=Vec2(
                    f32(center.x + distance * math.cos(direction)),
                    f32(center.y + distance * math.sin(direction)),
                ),
                health=f32(rng.uniform(0.5, 40.0)),
                size=f32(rng.uniform(20.0, 60.0)),
                lifecycle=lifecycle,
            )
        entry = world.state.secondary_projectiles.entries[0]
        _seed_secondary(oracle, entry, type_id=SecondaryProjectileTypeId.DETONATION, pos=center, vel=Vec2(timer, scale))
        _step_secondary(oracle, world, f32(rng.uniform(0.005, 0.04)))

        case = f"detonation seed=0x{seed:08x} t={timer!r} scale={scale!r}"
        native = oracle.read_fields(secondary, SECONDARY_PROJECTILE_LAYOUT)
        mismatches += compare_fields(case, native, _python_secondary(entry), address=secondary)
        mismatches += _compare_creatures(oracle, world, creature_count, case)
        mismatches += _rand_mismatch(oracle, world, case)
    assert not mismatches, mismatch_report(mismatches, total_cases=cases)


@pytest.mark.parametrize(
    "type_id",
    [
        ProjectileTemplateId.SHRINKIFIER,
        ProjectileTemplateId.SPLITTER_GUN,
        ProjectileTemplateId.PLASMA_CANNON,
        ProjectileTemplateId.ION_RIFLE,
    ],
    ids=lambda type_id: type_id.name.lower(),
)
def test_primary_special_hits_match_native(oracle, type_id: ProjectileTemplateId) -> None:
    """Shrinkifier size/death, Splitter children, Plasma Cannon ring and Ion Rifle chain links."""

    prepare_gameplay(oracle)
    pristine = oracle.snapshot()
    pool_base = oracle.resolve("projectile_pool")
    pos_arg = oracle.alloc(8)
    rng = random.Random(0x420B90 + int(type_id))
    mismatches: list[Mismatch] = []
    cases = 0
    for _ in range(150):
        cases += 1
        seed = rng.getrandbits(32)
        oracle.restore(pristine)
        oracle.rand_state = seed
        world = _python_world(seed)
        state = world.state

        target = Vec2(f32(rng.uniform(300.0, 700.0)), f32(rng.uniform(300.0, 700.0)))
        # Small sizes let the Shrinkifier kill; others are chain candidates.
        _place_creature(
            oracle, world, 0, pos=target, health=f32(rng.uniform(50.0, 500.0)), size=f32(rng.uniform(14.0, 70.0)),
        )
        creature_count = 1 + rng.randrange(0, 6)
        for index in range(1, creature_count):
            _place_creature(
                oracle,
                world,
                index,
                pos=Vec2(f32(target.x + rng.uniform(-300.0, 300.0)), f32(target.y + rng.uniform(-300.0, 300.0))),
                health=f32(rng.uniform(50.0, 500.0)),
                size=f32(rng.uniform(20.0, 70.0)),
            )

        # Spawn just short of the target, heading at it.
        approach = rng.uniform(-math.pi, math.pi)
        distance = rng.uniform(5.0, 25.0)
        start = Vec2(f32(target.x - distance * math.cos(approach)), f32(target.y - distance * math.sin(approach)))
        angle = f32(approach + math.pi / 2.0 + rng.uniform(-0.05, 0.05))
        oracle.write_f32(pos_arg, start.x)
        oracle.write_f32(pos_arg + 4, start.y)
        index = oracle.call("projectile_spawn", pos_arg, angle, int(type_id), _LOCAL_PLAYER_OWNER_ID).eax
        python_index = state.projectiles.spawn(
            pos=start, angle=angle, type_id=type_id, owner=OwnerRef.from_local_player(0),
        )
        assert python_index == index
        if type_id == ProjectileTemplateId.ION_RIFLE:
            links = rng.randrange(1, 5)
            oracle.write_u32("shock_chain_projectile_id", index)
            oracle.write_u32("shock_chain_links_left", links)
            state.shock_chain_projectile_id = index
            state.shock_chain_links_left = links

        dt = f32(rng.uniform(0.01, 0.03))
        oracle.write_f32("frame_dt", dt)
        oracle.call("projectile_update")
        runtime = _step_runtime(world, dt)
        state.projectiles.step(
            PrimaryStepCtx(
                dt=dt,
                creatures=world.creatures.entries,
                options=ProjectileUpdateOptions(
                    world_size=_WORLD_SIZE,
                    damage_scale_by_type=build_damage_scale_by_type(),
                    detail_preset=5,
                    rng=state.rng,
                    runtime_state=state,
                    players=world.players,
                    hit_runtime=runtime,
                    creature_damage_runtime=runtime,
                ),
            ),
        )

        case = f"{type_id.name} seed=0x{seed:08x}"
        for slot, projectile in enumerate(state.projectiles.entries):
            address = pool_base + slot * PROJECTILE_STRIDE
            native = oracle.read_fields(address, PROJECTILE_LAYOUT)
            if native["active"] or projectile.active:
                mismatches += compare_fields(
                    f"{case} projectile[{slot}]", native, _python_projectile(projectile), address=address,
                )
        mismatches += _compare_creatures(oracle, world, creature_count, case)
        for name, python_value in (
            ("shock_chain_projectile_id", state.shock_chain_projectile_id),
            ("shock_chain_links_left", state.shock_chain_links_left),
        ):
            native_value = oracle.read_i32(name)
            if native_value != python_value:
                mismatches.append(Mismatch(case, name, native_value, python_value, oracle.resolve(name)))
        mismatches += _rand_mismatch(oracle, world, case)
    assert not mismatches, mismatch_report(mismatches, total_cases=cases)


# `bonus_entry_t` (0x1c bytes): bonus id and the pickup position.
_BONUS_ENTRY_SIZE = 0x1C
_BONUS_ENTRY_POS_X = 0x10


def test_shock_chain_bonus_matches_native(oracle) -> None:
    """Shock Chain pickup (`bonus_apply` 0x00409890): first Ion Rifle link toward the nearest creature."""

    from crimson.bonuses import BonusId
    from crimson.bonuses.apply import bonus_apply

    prepare_gameplay(oracle)
    oracle.stub("sfx_play", 0)
    pristine = oracle.snapshot()
    pool_base = oracle.resolve("projectile_pool")
    entry_arg = oracle.alloc(_BONUS_ENTRY_SIZE)
    rng = random.Random(0x409890)
    mismatches: list[Mismatch] = []
    cases = 0
    for _ in range(200):
        cases += 1
        seed = rng.getrandbits(32)
        oracle.restore(pristine)
        oracle.rand_state = seed
        world = _python_world(seed)
        origin = Vec2(f32(rng.uniform(0.0, 1024.0)), f32(rng.uniform(0.0, 1024.0)))
        creature_count = 1 + rng.randrange(0, 5)
        for index in range(creature_count):
            _place_creature(
                oracle,
                world,
                index,
                pos=Vec2(f32(origin.x + rng.uniform(-400.0, 400.0)), f32(origin.y + rng.uniform(-400.0, 400.0))),
                health=100.0,
                size=50.0,
            )
        oracle.write_u32(entry_arg, int(BonusId.SHOCK_CHAIN))
        oracle.write_f32(entry_arg + _BONUS_ENTRY_POS_X, origin.x)
        oracle.write_f32(entry_arg + _BONUS_ENTRY_POS_X + 4, origin.y)
        oracle.call("bonus_apply", 0, entry_arg)

        state = world.state
        bonus_apply(
            state,
            world.players[0],
            BonusId.SHOCK_CHAIN,
            creature_damage_runtime=_step_runtime(world, 0.0),
            origin=origin,
            creatures=world.creatures.entries,
            players=world.players,
        )

        case = f"shock chain seed=0x{seed:08x} origin=({origin.x!r}, {origin.y!r})"
        for slot, projectile in enumerate(state.projectiles.entries):
            address = pool_base + slot * PROJECTILE_STRIDE
            native = oracle.read_fields(address, PROJECTILE_LAYOUT)
            if native["active"] or projectile.active:
                mismatches += compare_fields(f"{case} projectile[{slot}]", native, _python_projectile(projectile), address=address)
        for name, python_value in (
            ("shock_chain_projectile_id", state.shock_chain_projectile_id),
            ("shock_chain_links_left", state.shock_chain_links_left),
        ):
            native_value = oracle.read_i32(name)
            if native_value != python_value:
                mismatches.append(Mismatch(case, name, native_value, python_value, oracle.resolve(name)))
    assert not mismatches, mismatch_report(mismatches, total_cases=cases)
