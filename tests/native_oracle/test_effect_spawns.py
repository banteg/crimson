"""Native effect spawners vs their `EffectPool` / projectile-hit / bonus ports, through the shared template.

Every native spawner fills only some fields of the global `effect_template` and
`effect_spawn` copies all of it, so a spawn inherits the rest from whichever
spawner ran before. Each case starts both sides from `effect_defaults_reset`,
runs the same random sequence of spawners and `effects_update` ticks, and after
every step compares all 512 pool entries field for field (free-list links
included), the free-list head, the template, the low-detail skip counter and the
rand state.
"""

from __future__ import annotations

import random
import struct
from collections.abc import Callable

from crimson.bonuses import BonusId
from crimson.bonuses.apply import bonus_apply
from crimson.effects import EffectPool, FxQueue
from crimson.math_parity import f32, native_fire_muzzle_pos
from crimson.projectiles.effects import (
    _spawn_ion_hit_effects,
    _spawn_plasma_cannon_hit_effects,
    _spawn_shrinkifier_hit_effects,
    _spawn_splitter_hit_effects,
)
from crimson.projectiles.types import ProjectileTemplateId
from crimson.sim.world_state import WorldState
from crimson.weapons import WeaponId
from grim.geom import Vec2

from ._support import Mismatch, compare_effect_pool, mismatch_report, prepare_gameplay
from .test_projectile_update import _python_world, _seed_native_player, _step_runtime

# `bonus_entry_t` (0x1c bytes): bonus id, pickup position and amount.
_BONUS_ENTRY_SIZE = 0x1C
_BONUS_ENTRY_POS_X = 0x10
_BONUS_ENTRY_AMOUNT = 0x18

# `player_update` fire block (0x00415a1f..0x00415bcf): the muzzle offset, then the weapon-flag-1 shell casing.
_CASING_START = 0x00415A1F
_CASING_STOP = 0x00415BCF
_FRAME_FIRE_HEADING = 0x1C

# `projectile_update` ion hits: `effect_spawn_ion_hit_core(pos, scale_step, lifetime)` then `effect_spawn_ion_hit_sparks(pos, scale)`.
_ION_HIT_ARGS = {
    ProjectileTemplateId.ION_MINIGUN: (1.5, 0.1, 0.8),
    ProjectileTemplateId.ION_RIFLE: (1.2, 0.4, 1.2),
    ProjectileTemplateId.ION_CANNON: (1.0, 1.0, 2.2),
}


class _Case:
    """One native/port pair: the oracle with its argument buffers and the Python world."""

    def __init__(self, oracle, world: WorldState, detail: int, *, pos_arg: int, bonus_arg: int) -> None:
        self.oracle = oracle
        self.world = world
        self.detail = detail
        self.pos_arg = pos_arg
        self.bonus_arg = bonus_arg

    @property
    def pool(self) -> EffectPool:
        return self.world.state.effects

    def set_pos(self, pos: Vec2) -> None:
        self.oracle.write_f32(self.pos_arg, pos.x)
        self.oracle.write_f32(self.pos_arg + 4, pos.y)


def _burst(case: _Case, pos: Vec2, rng: random.Random) -> str:
    count = rng.randrange(1, 33)
    case.oracle.call("effect_spawn_burst", case.pos_arg, count)
    case.pool.spawn_burst(pos=pos, count=count, rng=case.world.state.rng, detail_preset=case.detail)
    return f"burst({count})"


def _blood_splatter(case: _Case, pos: Vec2, rng: random.Random) -> str:
    angle = f32(rng.uniform(-7.0, 7.0))
    age = f32(rng.choice((0.0, rng.uniform(0.0, 0.25))))
    case.oracle.call("effect_spawn_blood_splatter", case.pos_arg, angle, age)
    case.pool.spawn_blood_splatter(
        pos=pos, angle=angle, age=age, rng=case.world.state.rng, detail_preset=case.detail, violence_disabled=0,
    )
    return f"blood_splatter({angle!r}, {age!r})"


def _explosion_burst(case: _Case, pos: Vec2, rng: random.Random) -> str:
    scale = f32(rng.choice((0.4, 1.0, 1.8, rng.uniform(0.1, 3.0))))
    case.oracle.call("effect_spawn_explosion_burst", case.pos_arg, scale)
    case.pool.spawn_explosion_burst(pos=pos, scale=scale, rng=case.world.state.rng, detail_preset=case.detail)
    return f"explosion_burst({scale!r})"


def _freeze_shard(case: _Case, pos: Vec2, rng: random.Random) -> str:
    angle = f32(rng.uniform(0.0, 6.2831855))
    case.oracle.call("effect_spawn_freeze_shard", case.pos_arg, angle)
    case.pool.spawn_freeze_shard(pos=pos, angle=angle, rng=case.world.state.rng, detail_preset=case.detail)
    return f"freeze_shard({angle!r})"


def _freeze_shatter(case: _Case, pos: Vec2, rng: random.Random) -> str:
    angle = f32(rng.uniform(0.0, 6.2831855))
    case.oracle.call("effect_spawn_freeze_shatter", case.pos_arg, angle)
    case.pool.spawn_freeze_shatter(pos=pos, angle=angle, rng=case.world.state.rng, detail_preset=case.detail)
    return f"freeze_shatter({angle!r})"


def _ion_hit(case: _Case, pos: Vec2, rng: random.Random) -> str:
    type_id = rng.choice(tuple(_ION_HIT_ARGS))
    core_scale_step, core_lifetime, sparks_scale = _ION_HIT_ARGS[type_id]
    case.oracle.call("effect_spawn_ion_hit_core", case.pos_arg, core_scale_step, core_lifetime)
    case.oracle.call("effect_spawn_ion_hit_sparks", case.pos_arg, sparks_scale)
    _spawn_ion_hit_effects(case.pool, [], type_id=type_id, pos=pos, rng=case.world.state.rng, detail_preset=case.detail)
    return f"ion_hit({type_id.name})"


def _plasma_cannon_hit(case: _Case, pos: Vec2, rng: random.Random) -> str:
    del rng
    case.oracle.call("effect_spawn_plasma_hit_core", case.pos_arg, 1.5, 1.0)
    case.oracle.call("effect_spawn_plasma_hit_core", case.pos_arg, 1.0, 1.0)
    _spawn_plasma_cannon_hit_effects(case.pool, [], pos=pos, detail_preset=case.detail)
    return "plasma_cannon_hit"


def _shrinkifier_hit(case: _Case, pos: Vec2, rng: random.Random) -> str:
    del rng
    case.oracle.call("effect_spawn_shrinkifier_hit", case.pos_arg)
    _spawn_shrinkifier_hit_effects(case.pool, pos=pos, rng=case.world.state.rng, detail_preset=case.detail)
    return "shrinkifier_hit"


def _splitter_hit(case: _Case, pos: Vec2, rng: random.Random) -> str:
    del rng
    case.oracle.call("effect_spawn_splitter_hit_burst", case.pos_arg, 26.0, 3)
    _spawn_splitter_hit_effects(case.pool, pos=pos, rng=case.world.state.rng, detail_preset=case.detail)
    return "splitter_hit"


def _shell_casing(case: _Case, pos: Vec2, rng: random.Random) -> str:
    aim_heading = f32(rng.uniform(-1.0, 7.3))
    oracle = case.oracle
    player = oracle.resolve("player_state_table")
    oracle.write(player + 0x14, oracle.read(case.pos_arg, 8))
    oracle.write_u32(player + 0x2C0, int(WeaponId.ASSAULT_RIFLE))
    frame = bytearray(0x80)
    struct.pack_into("<f", frame, _FRAME_FIRE_HEADING, aim_heading)
    oracle.run(_CASING_START, _CASING_STOP, regs={"edi": player, "esi": player + 0x14}, frame=bytes(frame))
    case.pool.spawn_shell_casing(
        pos=native_fire_muzzle_pos(pos, aim_heading),
        aim_heading=aim_heading,
        rng=case.world.state.rng,
        detail_preset=case.detail,
    )
    return f"shell_casing({aim_heading!r})"


def _bonus_spawn_at(case: _Case, pos: Vec2, rng: random.Random) -> str:
    del rng
    case.oracle.call("bonus_spawn_at", case.pos_arg, int(BonusId.POINTS), 500)
    case.world.state.bonus_pool.spawn_at(pos, BonusId.POINTS, 500, state=case.world.state, detail_preset=case.detail)
    return "bonus_spawn_at"


def _bonus_apply(case: _Case, pos: Vec2, rng: random.Random) -> str:
    bonus_id = rng.choice((BonusId.POINTS, BonusId.REFLEX_BOOST, BonusId.FREEZE))
    oracle = case.oracle
    oracle.write_u32(case.bonus_arg, int(bonus_id))
    oracle.write_f32(case.bonus_arg + _BONUS_ENTRY_POS_X, pos.x)
    oracle.write_f32(case.bonus_arg + _BONUS_ENTRY_POS_X + 4, pos.y)
    oracle.write_u32(case.bonus_arg + _BONUS_ENTRY_AMOUNT, 5)
    oracle.call("bonus_apply", 0, case.bonus_arg)
    world = case.world
    bonus_apply(
        world.state,
        world.players[0],
        bonus_id,
        amount=5,
        origin=pos,
        creatures=world.creatures.entries,
        players=world.players,
        detail_preset=case.detail,
        step_runtime=_step_runtime(world, 0.0),
    )
    return f"bonus_apply({bonus_id.name})"


def _update(case: _Case, pos: Vec2, rng: random.Random) -> str:
    del pos
    dt = f32(rng.uniform(0.005, 0.12))
    case.oracle.write_f32("frame_dt", dt)
    case.oracle.call("effects_update")
    case.pool.update(dt, fx_queue=FxQueue())
    return f"update({dt!r})"


Step = Callable[[_Case, Vec2, random.Random], str]
_SPAWNERS: tuple[Step, ...] = (
    _burst,
    _blood_splatter,
    _explosion_burst,
    _freeze_shard,
    _freeze_shatter,
    _ion_hit,
    _plasma_cannon_hit,
    _shrinkifier_hit,
    _splitter_hit,
    _shell_casing,
    _bonus_spawn_at,
    _bonus_apply,
)


def _compare_state(case: _Case, label: str) -> list[Mismatch]:
    mismatches = compare_effect_pool(case.oracle, case.pool, label)
    if case.oracle.rand_state != case.world.state.rng.state:
        mismatches.append(Mismatch(label, "rand_state", case.oracle.rand_state, case.world.state.rng.state, 0))
    return mismatches


def _run_cases(oracle, *, seed: int, cases: int, steps: int, pick: Callable[[random.Random], Step]) -> int:
    """Run `cases` random step sequences; return how many of them exhausted the pool."""

    prepare_gameplay(oracle)
    _seed_native_player(oracle)
    oracle.stub("sfx_play", 0)
    pos_arg = oracle.alloc(8)
    bonus_arg = oracle.alloc(_BONUS_ENTRY_SIZE)
    pristine = oracle.snapshot()
    rng = random.Random(seed)
    mismatches: list[Mismatch] = []
    exhausted = 0
    for case_index in range(cases):
        detail = rng.randrange(6)
        rand_seed = rng.getrandbits(32)
        oracle.restore(pristine)
        oracle.write_u32("config_detail_preset", detail)
        oracle.rand_state = rand_seed
        world = _python_world(rand_seed)
        world.state.detail_preset = detail
        case = _Case(oracle, world, detail, pos_arg=pos_arg, bonus_arg=bonus_arg)
        history: list[str] = []
        case_exhausted = False
        for _ in range(steps):
            pos = Vec2(f32(rng.uniform(40.0, 980.0)), f32(rng.uniform(40.0, 980.0)))
            case.set_pos(pos)
            history.append(pick(rng)(case, pos, rng))
            case_exhausted |= case.pool.entries[case.pool._free_head].next_free == -1
            label = f"case={case_index} detail={detail} seed=0x{rand_seed:08x} steps={' '.join(history[-4:])}"
            step_mismatches = _compare_state(case, label)
            if step_mismatches:
                mismatches += step_mismatches
                break
        exhausted += case_exhausted
    assert not mismatches, mismatch_report(mismatches, total_cases=cases)
    return exhausted


def test_effect_spawner_sequences_match_native(oracle) -> None:
    def pick(rng: random.Random) -> Step:
        return _update if rng.random() < 0.3 else rng.choice(_SPAWNERS)

    _run_cases(oracle, seed=0x42E120, cases=40, steps=60, pick=pick)


def test_effect_pool_exhaustion_matches_native(oracle) -> None:
    """Flood the pool past its 511 live entries, let some expire, and flood again."""

    def pick(rng: random.Random) -> Step:
        return _update if rng.random() < 0.08 else rng.choice((_burst, _explosion_burst, _freeze_shatter, _bonus_spawn_at))

    exhausted = _run_cases(oracle, seed=0x42E1A0, cases=12, steps=120, pick=pick)
    assert exhausted >= 6
