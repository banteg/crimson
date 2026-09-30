"""Creature spawning: `creature_spawn_template` and the mode spawners.

`creature_spawn_template` is an algorithm (formations, spawn slots, tail modifiers), ported
here as direct writes into the creature pool in native order. The spawn-id index in
`spawn_templates` only labels templates for debug UIs.

See also: `docs/creatures/spawning.md`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import msgspec

from grim.color import RGBA
from grim.geom import Vec2
from grim.rand import CrandLike

from ..bonuses import BonusId
from ..math_parity import (
    f32,
    f32_from_bits,
    f32_vec2,
    x87_pc24_add,
    x87_pc24_cos_mul,
    x87_pc24_div,
    x87_pc24_mul,
    x87_pc24_sin_mul,
    x87_pc24_sub,
)
from ..rng_caller_static import RngCallerStatic
from ..sim.state_types import TERRAIN_SIZE
from .lifecycle import CREATURE_LIFECYCLE_ALIVE
from .spawn_ids import (
    HAS_SPAWN_SLOT_FLAG,
    RANDOM_HEADING_SENTINEL,
    CreatureAiMode,
    CreatureFlags,
    CreatureTypeId,
    SpawnId,
)
from .spawn_templates import SPAWN_ID_TO_TEMPLATE, SPAWN_TEMPLATES, TYPE_ID_TO_NAME, SpawnTemplate

if TYPE_CHECKING:
    from ..sim.gameplay_state import GameplayState
    from .runtime import CreaturePool, CreatureState

_NATIVE_CREATURE_SPAWN_ELAPSED_SCALE = f32_from_bits(0x3727C5AD)
_NATIVE_CREATURE_SPAWN_HEALTH_SCALE = f32_from_bits(0x38D1B718)  # 0x0046f310
NATIVE_SPAWN_SLOT_COUNT = 0x20

__all__ = [
    "HAS_SPAWN_SLOT_FLAG",
    "NATIVE_SPAWN_SLOT_COUNT",
    "RANDOM_HEADING_SENTINEL",
    "SPAWN_ID_TO_TEMPLATE",
    "SPAWN_TEMPLATES",
    "TYPE_ID_TO_NAME",
    "CreatureAiMode",
    "CreatureFlags",
    "CreatureTypeId",
    "SpawnId",
    "SpawnSlot",
    "SpawnTemplate",
    "creature_spawn",
    "creature_spawn_template",
    "pack_bonus_on_death_args",
    "spawn_id_label",
    "survival_spawn_creature",
    "tick_spawn_slot",
]


def spawn_id_label(spawn_id: SpawnId) -> str:
    entry = SPAWN_ID_TO_TEMPLATE.get(spawn_id)
    if entry is None or entry.creature is None:
        return "unknown"
    return entry.creature


class SpawnSlot(msgspec.Struct):
    """`creature_spawn_slot_t`: a spawner's deferred child spawns.

    Defaults are `creature_spawn_slot_table_global_init`; `owner_creature` -1 is the native null owner.
    """

    owner_creature: int = -1
    timer: float = 0.5
    count: int = 0
    limit: int = -1
    interval: float = 0.5
    child_template_id: SpawnId = SpawnId.ZOMBIE_BOSS_SPAWNER_00


def tick_spawn_slot(slot: SpawnSlot, frame_dt: float) -> SpawnId | None:
    """Advance a spawn slot timer by `frame_dt`, returning a spawned template id if triggered.

    Modeled after `creature_update_all`'s spawn-slot tick:
      timer -= dt
      if timer < 0:
        timer += interval
        if count < limit:
          count += 1
          spawn child_template_id

    Note: the original only adds `interval` once (no loop), so large dt can keep the timer negative.
    """
    timer = f32(slot.timer)
    interval = f32(slot.interval)
    dt = f32(frame_dt)
    timer = f32(timer - dt)
    slot.timer = timer
    if slot.timer < 0.0:
        slot.timer = f32(float(slot.timer) + interval)
        if slot.count < slot.limit:
            slot.count += 1
            return slot.child_template_id
    return None


def pack_bonus_on_death_args(bonus_id: BonusId, amount_override: int) -> int:
    """Native `link_index` encoding for BONUS_ON_DEATH carriers: low i16 holds
    the bonus id, high i16 the amount/duration override (-1 = default)."""

    packed = ((int(amount_override) & 0xFFFF) << 16) | (int(bonus_id) & 0xFFFF)
    return packed - 0x1_0000_0000 if packed >= 0x8000_0000 else packed


def clamp01(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value


# `creature_spawn_template` (0x00430af0) stores float literals into float creature fields, and
# its x87 math runs at PC24: every op rounds to f32.


def _rand_field(rng: CrandLike, caller: RngCallerStatic, modulo: int, scale: float, base: float) -> float:
    """Template `RAND_FIELD`: `(float)(crt_rand() % modulo) * scale + base`."""
    return x87_pc24_add(x87_pc24_mul(float(rng.rand_tagged(caller) % modulo), f32(scale)), f32(base))


def _tint(r: float, g: float, b: float, a: float) -> RGBA:
    return RGBA(f32(r), f32(g), f32(b), f32(a))


def _set_stats(
    creature: CreatureState,
    type_id: CreatureTypeId,
    health: float,
    move_speed: float,
    reward_value: float,
    tint: RGBA,
    size: float,
    contact_damage: float,
) -> None:
    """Template `SET_ROOT_STATS_WITH_TINT`."""
    creature.type_id = type_id
    creature.hp = f32(health)
    creature.move_speed = f32(move_speed)
    creature.reward_value = f32(reward_value)
    creature.tint = tint
    creature.size = f32(size)
    creature.contact_damage = f32(contact_damage)


def _activate(creature: CreatureState) -> None:
    """The per-member resets every formation loop writes: velocity, collision, active, lifecycle, cooldown."""
    creature.vel = Vec2()
    creature.plague_infected = False
    creature.collision_timer = 0.0
    creature.active = True
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.attack_cooldown = 0.0


def _init_alien_spawner(
    pool: CreaturePool,
    creature: CreatureState,
    owner: int,
    *,
    timer: float,
    limit: int,
    interval: float,
    child_template_id: SpawnId,
    size: float,
    health: float,
    move_speed: float,
    reward_value: float,
    tint: RGBA,
) -> None:
    """Template `INIT_ALIEN_SPAWNER`: an alien spawner and the spawn slot it owns (its `link_index`)."""
    creature.type_id = CreatureTypeId.ALIEN
    creature.flags = CreatureFlags.ANIM_PING_PONG
    slot_index = pool.spawn_slot_alloc()
    creature.link_index = slot_index
    pool.spawn_slots[slot_index] = SpawnSlot(
        owner_creature=owner,
        timer=f32(timer),
        count=0,
        limit=limit,
        interval=f32(interval),
        child_template_id=child_template_id,
    )
    creature.size = f32(size)
    creature.hp = f32(health)
    creature.move_speed = f32(move_speed)
    creature.reward_value = f32(reward_value)
    creature.tint = tint
    creature.contact_damage = 0.0


def _size_health(creature: CreatureState, size: float, health_scale: float, health_add: float) -> None:
    creature.size = size
    creature.hp = x87_pc24_add(x87_pc24_mul(size, f32(health_scale)), f32(health_add))


def _size_reward(creature: CreatureState) -> None:
    """`reward_value = size + size + 50.0f`."""
    creature.reward_value = x87_pc24_add(x87_pc24_add(creature.size, creature.size), 50.0)


def _scale(value: float, factor: float) -> float:
    """The tail reads a float field back and multiplies it by a float literal."""
    return x87_pc24_mul(f32(value), f32(factor))


def _spawn_slot_of(pool: CreaturePool, creature: CreatureState) -> SpawnSlot | None:
    """`&creature_spawn_slot_table[creature->link_index]` for the tail's spawner tweaks.

    Only the phantom slot can carry the spawner flag with a `link_index` that is no slot index (a
    formation link written over a stale spawner); native then writes past the 32-entry table,
    which the port does not model.
    """
    slot_index = creature.link_index
    if 0 <= slot_index < NATIVE_SPAWN_SLOT_COUNT:
        return pool.spawn_slots[slot_index]
    return None


def _init_grid_root(
    creature: CreatureState,
    pos: Vec2,
    type_id: CreatureTypeId,
    tint: RGBA,
    health: float,
    move_speed: float,
    size: float,
) -> None:
    """Template `INIT_GRID_ROOT`."""
    creature.type_id = type_id
    creature.pos = f32_vec2(pos)
    creature.ai_mode = CreatureAiMode.CHASE_PLAYER
    creature.hp = f32(health)
    creature.tint = tint
    creature.move_speed = f32(move_speed)
    creature.reward_value = 600.0
    creature.size = f32(size)
    creature.contact_damage = 40.0
    creature.max_hp = f32(health)


def _spawn_grid(
    pool: CreaturePool,
    rng: CrandLike,
    pos: Vec2,
    root_slot_idx: int,
    ai_mode: CreatureAiMode,
    type_id: CreatureTypeId,
    health: float,
    tint: RGBA,
    move_speed: float,
    size: float,
    contact_damage: float,
) -> int:
    """Template `SPAWN_GRID`: nine columns of three members, 64 units apart; returns the last member."""
    child_slot_idx = root_slot_idx
    for formation_offset in range(0, -0x240, -0x40):
        for ring_member_idx in range(0x80, 0x101, 0x40):
            child_slot_idx = pool.alloc_slot(rng)
            creature = pool.creature(child_slot_idx)
            creature.ai_mode = ai_mode
            creature.heading = 0.0
            creature.anim_phase = 0.0
            creature.link_index = root_slot_idx
            offset = Vec2(float(formation_offset), float(ring_member_idx))
            creature.target_offset = offset
            creature.pos = Vec2(x87_pc24_add(f32(pos.x), offset.x), x87_pc24_add(f32(pos.y), offset.y))
            _activate(creature)
            _set_stats(creature, type_id, health, move_speed, 60.0, tint, size, contact_damage)
            creature.max_hp = f32(health)
    return child_slot_idx


def creature_spawn_template(
    pool: CreaturePool,
    template_id: SpawnId,
    pos: Vec2,
    heading: float,
    *,
    state: GameplayState,
    detail_preset: int,
) -> int:
    """Port of `creature_spawn_template` (0x00430af0); returns the index of the creature native returns.

    Every creature is written straight into the slot `creature_alloc_slot` hands out, in native
    order, so the fields a path leaves alone keep the recycled slot's values. There is no failure
    path: a full pool hands out the phantom slot one past the end, which each later member
    overwrites.
    """

    rng = state.rng
    root_slot_idx = pool.alloc_slot(rng)
    if heading == RANDOM_HEADING_SENTINEL:
        random_roll = rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_RANDOM_HEADING)
        heading = x87_pc24_mul(float(random_roll % 0x274), f32(0.01))

    creature_idx = root_slot_idx
    creature = pool.creature(creature_idx)
    creature.ai_mode = CreatureAiMode.ORBIT_PLAYER
    creature.pos = f32_vec2(pos)
    creature.plague_infected = False
    creature.collision_timer = 0.0
    creature.active = True
    creature.force_target = 0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.vel = Vec2()
    random_roll = rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_BASE_HEADING)
    creature.attack_cooldown = 0.0
    creature.heading = x87_pc24_mul(float(random_roll % 0x13A), f32(0.01))

    if template_id == SpawnId.FORMATION_RING_ALIEN_8_12:
        _set_stats(creature, CreatureTypeId.ALIEN, 200.0, 2.2, 600.0, _tint(0.65, 0.85, 0.97, 1.0), 55.0, 14.0)
        creature.max_hp = 200.0
        for ring_member_idx in range(8):
            creature_idx = pool.alloc_slot(rng)
            creature = pool.creature(creature_idx)
            angle = x87_pc24_mul(float(ring_member_idx), f32(0.78539819))
            creature.ai_mode = CreatureAiMode.FOLLOW_LINK
            creature.link_index = root_slot_idx
            creature.target_offset = Vec2(x87_pc24_cos_mul(angle, 100.0), x87_pc24_sin_mul(angle, 100.0))
            creature.pos = f32_vec2(pos)
            _activate(creature)
            _set_stats(
                creature,
                CreatureTypeId.ALIEN,
                40.0,
                2.4,
                60.0,
                # Native float literals 0x3ea3d70b / 0x3f16872c, one ulp above f32(0.32) / f32(0.588).
                _tint(0.32000002, 0.58800006, 0.426, 1.0),
                50.0,
                4.0,
            )
            creature.max_hp = 40.0

    if template_id == SpawnId.FORMATION_RING_ALIEN_5_19:
        _set_stats(creature, CreatureTypeId.ALIEN, 50.0, 3.8, 300.0, _tint(0.95, 0.55, 0.37, 1.0), 55.0, 40.0)
        creature.max_hp = 50.0
        for ring_member_idx in range(5):
            creature_idx = pool.alloc_slot(rng)
            creature = pool.creature(creature_idx)
            angle = x87_pc24_mul(float(ring_member_idx), f32(1.2566371))
            creature.ai_mode = CreatureAiMode.FOLLOW_LINK_TETHERED
            creature.link_index = root_slot_idx
            offset = Vec2(x87_pc24_cos_mul(angle, 110.0), x87_pc24_sin_mul(angle, 110.0))
            creature.target_offset = offset
            creature.pos = Vec2(x87_pc24_add(offset.x, f32(pos.x)), x87_pc24_add(offset.y, f32(pos.y)))
            _activate(creature)
            # Native float literal 0.41250002f (0x3ed33334), one ulp above f32(0.4125).
            _set_stats(creature, CreatureTypeId.ALIEN, 220.0, 3.8, 60.0, _tint(0.7125, 0.41250002, 0.2775, 0.6), 50.0, 35.0)
            creature.max_hp = 220.0

    if template_id == SpawnId.FORMATION_CHAIN_LIZARD_4_11:
        creature.ai_mode = CreatureAiMode.ORBIT_PLAYER_TIGHT
        _set_stats(creature, CreatureTypeId.LIZARD, 1500.0, 2.1, 1000.0, _tint(0.99, 0.99, 0.21, 1.0), 69.0, 150.0)
        creature.max_hp = 1500.0
        chain_link_idx = root_slot_idx
        for chain_member_idx in range(4):
            creature_idx = pool.alloc_slot(rng)
            creature = pool.creature(creature_idx)
            creature.target_offset = Vec2(float(-0x100 + chain_member_idx * 0x40), -256.0)
            creature.ai_mode = CreatureAiMode.FOLLOW_LINK
            creature.link_index = chain_link_idx
            angle = x87_pc24_mul(float(2 + chain_member_idx * 2), f32(0.39269909))
            creature.pos = Vec2(
                x87_pc24_add(x87_pc24_cos_mul(angle, 256.0), f32(pos.x)),
                x87_pc24_add(x87_pc24_sin_mul(angle, 256.0), f32(pos.y)),
            )
            _activate(creature)
            _set_stats(creature, CreatureTypeId.LIZARD, 60.0, 2.4, 60.0, _tint(0.6, 0.6, 0.31, 1.0), 50.0, 14.0)
            creature.max_hp = 60.0
            chain_link_idx = creature_idx
        pool.creature(root_slot_idx).link_index = creature_idx

    if template_id == SpawnId.FORMATION_CHAIN_ALIEN_10_13:
        # Native first parks the root at (-10, terrain_height / 2), then overwrites it.
        _set_stats(creature, CreatureTypeId.ALIEN, 200.0, 2.0, 600.0, _tint(0.6, 0.8, 0.91, 1.0), 40.0, 20.0)
        creature.pos = Vec2(
            x87_pc24_add(x87_pc24_cos_mul(0.0, 256.0), f32(pos.x)),
            x87_pc24_add(x87_pc24_sin_mul(0.0, 256.0), f32(pos.y)),
        )
        creature.max_hp = 200.0
        creature.ai_mode = CreatureAiMode.ORBIT_LINK
        chain_link_idx = root_slot_idx
        for alien_chain_cursor in range(2, 0x16, 2):
            creature_idx = pool.alloc_slot(rng)
            creature = pool.creature(creature_idx)
            angle = x87_pc24_mul(float(alien_chain_cursor), f32(0.34906587))
            creature.ai_mode = CreatureAiMode.ORBIT_LINK
            creature.link_index = chain_link_idx
            creature.orbit_angle = f32(3.1415927)
            creature.orbit_radius = 10.0
            creature.pos = Vec2(
                x87_pc24_add(x87_pc24_cos_mul(angle, 256.0), f32(pos.x)),
                x87_pc24_add(x87_pc24_sin_mul(angle, 256.0), f32(pos.y)),
            )
            _activate(creature)
            _set_stats(creature, CreatureTypeId.ALIEN, 60.0, 2.0, 60.0, _tint(0.4, 0.7, 0.11, 1.0), 50.0, 4.0)
            creature.max_hp = 60.0
            chain_link_idx = creature_idx
        pool.creature(root_slot_idx).link_index = creature_idx

    match template_id:
        case SpawnId.FORMATION_GRID_ALIEN_GREEN_14:
            _init_grid_root(creature, pos, CreatureTypeId.ALIEN, _tint(0.7, 0.8, 0.31, 1.0), 1500.0, 2.0, 50.0)
            creature_idx = _spawn_grid(
                pool, rng, pos, root_slot_idx, CreatureAiMode.FOLLOW_LINK_TETHERED, CreatureTypeId.ALIEN, 40.0,
                _tint(0.4, 0.7, 0.11, 1.0), 2.0, 50.0, 4.0,
            )
            creature = pool.creature(creature_idx)
        case SpawnId.FORMATION_GRID_ALIEN_WHITE_15:
            _init_grid_root(creature, pos, CreatureTypeId.ALIEN, _tint(1.0, 1.0, 1.0, 1.0), 1500.0, 2.0, 60.0)
            creature_idx = _spawn_grid(
                pool, rng, pos, root_slot_idx, CreatureAiMode.LINK_GUARD, CreatureTypeId.ALIEN, 40.0,
                _tint(0.4, 0.7, 0.11, 1.0), 2.0, 50.0, 4.0,
            )
            creature = pool.creature(creature_idx)
        case SpawnId.FORMATION_GRID_SPIDER_SP1_WHITE_17:
            _init_grid_root(creature, pos, CreatureTypeId.SPIDER_SP1, _tint(1.0, 1.0, 1.0, 1.0), 1500.0, 2.0, 60.0)
            creature_idx = _spawn_grid(
                pool, rng, pos, root_slot_idx, CreatureAiMode.LINK_GUARD, CreatureTypeId.SPIDER_SP1, 40.0,
                _tint(0.4, 0.7, 0.11, 1.0), 2.0, 50.0, 4.0,
            )
            creature = pool.creature(creature_idx)
        case SpawnId.FORMATION_GRID_LIZARD_WHITE_16:
            _init_grid_root(creature, pos, CreatureTypeId.LIZARD, _tint(1.0, 1.0, 1.0, 1.0), 1500.0, 2.0, 64.0)
            creature_idx = _spawn_grid(
                pool, rng, pos, root_slot_idx, CreatureAiMode.LINK_GUARD, CreatureTypeId.LIZARD, 40.0,
                _tint(0.4, 0.7, 0.11, 1.0), 2.0, 60.0, 4.0,
            )
            creature = pool.creature(creature_idx)
        case SpawnId.ALIEN_GHOST_0F:
            creature.ai_mode = CreatureAiMode.ORBIT_PLAYER
            # Native float literal 0.66499996f (0x3f2a3d70), one ulp below f32(0.665).
            _set_stats(creature, CreatureTypeId.ALIEN, 20.0, 2.9, 60.0, _tint(0.66499996, 0.385, 0.259, 0.56), 50.0, 35.0)
            creature.max_hp = 20.0

    match template_id:
        case SpawnId.FORMATION_GRID_ALIEN_BRONZE_18:
            _init_grid_root(creature, pos, CreatureTypeId.ALIEN, _tint(0.7, 0.8, 0.31, 1.0), 500.0, 2.0, 40.0)
            creature_idx = _spawn_grid(
                pool, rng, pos, root_slot_idx, CreatureAiMode.FOLLOW_LINK, CreatureTypeId.ALIEN, 260.0,
                _tint(0.7125, 0.41250002, 0.2775, 0.6), 3.8, 50.0, 35.0,
            )
            creature = pool.creature(creature_idx)
        case SpawnId.SPIDER_SP2_SPLITTER_01:
            creature.flags = CreatureFlags.SPLIT_ON_DEATH
            _set_stats(creature, CreatureTypeId.SPIDER_SP2, 400.0, 2.0, 1000.0, _tint(0.8, 0.7, 0.4, 1.0), 80.0, 17.0)
        case SpawnId.DEN_SPIDER_BASIC_0A:
            _init_alien_spawner(
                pool, creature, creature_idx, timer=2.0, limit=100, interval=5.0,
                child_template_id=SpawnId.SPIDER_SP1_RANDOM_32, size=55.0, health=1000.0, move_speed=1.5,
                reward_value=3000.0, tint=_tint(0.8, 0.7, 0.4, 1.0),
            )
        case SpawnId.DEN_SPIDER_PLASMA_SHOOTERS_0B:
            _init_alien_spawner(
                pool, creature, creature_idx, timer=2.0, limit=100, interval=6.0,
                child_template_id=SpawnId.SPIDER_PLASMA_SHOOTER_3C, size=65.0, health=3500.0, move_speed=1.5,
                reward_value=5000.0, tint=_tint(0.9, 0.1, 0.1, 1.0),
            )
        case SpawnId.DEN_SPIDER_WEAK_10:
            _init_alien_spawner(
                pool, creature, creature_idx, timer=1.5, limit=100, interval=2.3,
                child_template_id=SpawnId.SPIDER_SP1_RANDOM_32, size=32.0, health=50.0, move_speed=2.8,
                reward_value=800.0, tint=_tint(0.9, 0.8, 0.4, 1.0),
            )
        case SpawnId.ALIEN_SPAWNER_RING_24_0E:
            # The spawner keeps its recycled slot's `max_health`: the tail writes it on the last ring member.
            _init_alien_spawner(
                pool, creature, creature_idx, timer=1.5, limit=0x40, interval=1.05,
                child_template_id=SpawnId.AI1_LIZARD_BLUE_TINT_1C, size=32.0, health=50.0, move_speed=2.8,
                reward_value=5000.0, tint=_tint(0.9, 0.8, 0.4, 1.0),
            )
            for ring_member_idx in range(0x18):
                creature_idx = pool.alloc_slot(rng)
                creature = pool.creature(creature_idx)
                angle = x87_pc24_mul(float(ring_member_idx), f32(0.2617994))
                creature.ai_mode = CreatureAiMode.FOLLOW_LINK
                creature.heading = 0.0
                creature.anim_phase = 0.0
                creature.link_index = root_slot_idx
                creature.target_offset = Vec2(x87_pc24_cos_mul(angle, 100.0), x87_pc24_sin_mul(angle, 100.0))
                creature.pos = f32_vec2(pos)
                _activate(creature)
                _set_stats(creature, CreatureTypeId.ALIEN, 40.0, 4.0, 350.0, _tint(1.0, 0.3, 0.3, 1.0), 35.0, 30.0)
                creature.max_hp = 40.0
        case SpawnId.DEN_LIZARD_WEAK_0C:
            _init_alien_spawner(
                pool, creature, creature_idx, timer=1.5, limit=100, interval=2.0,
                child_template_id=SpawnId.LIZARD_RANDOM_31, size=32.0, health=50.0, move_speed=2.8,
                reward_value=1000.0, tint=_tint(0.9, 0.8, 0.4, 1.0),
            )
        case SpawnId.DEN_LIZARD_WEAK_SLOWER_0D:
            _init_alien_spawner(
                pool, creature, creature_idx, timer=2.0, limit=100, interval=6.0,
                child_template_id=SpawnId.LIZARD_RANDOM_31, size=32.0, health=50.0, move_speed=1.3,
                reward_value=1000.0, tint=_tint(0.9, 0.8, 0.4, 1.0),
            )
        case SpawnId.DEN_ALIEN_WEAK_SMALL_09:
            _init_alien_spawner(
                pool, creature, creature_idx, timer=1.0, limit=0x10, interval=2.0,
                child_template_id=SpawnId.ALIEN_RANDOM_1D, size=40.0, health=450.0, move_speed=2.0,
                reward_value=1000.0, tint=_tint(1.0, 1.0, 1.0, 1.0),
            )
        case SpawnId.DEN_ALIEN_BASIC_07:
            _init_alien_spawner(
                pool, creature, creature_idx, timer=1.0, limit=100, interval=2.2,
                child_template_id=SpawnId.ALIEN_RANDOM_1D, size=50.0, health=1000.0, move_speed=2.0,
                reward_value=3000.0, tint=_tint(1.0, 1.0, 1.0, 1.0),
            )
        case SpawnId.DEN_ALIEN_BASIC_SLOWER_08:
            _init_alien_spawner(
                pool, creature, creature_idx, timer=1.0, limit=100, interval=2.8,
                child_template_id=SpawnId.ALIEN_RANDOM_1D, size=50.0, health=1000.0, move_speed=2.0,
                reward_value=3000.0, tint=_tint(1.0, 1.0, 1.0, 1.0),
            )
        case SpawnId.AI1_ALIEN_BLUE_TINT_1A:
            creature.ai_mode = CreatureAiMode.ORBIT_PLAYER_TIGHT
            random_tint_scalar = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_AI1_BLUE_TINT_1A, 0x28, 0.01, 0.5)
            _set_stats(
                creature, CreatureTypeId.ALIEN, 50.0, 2.4, 125.0,
                RGBA(random_tint_scalar, random_tint_scalar, 1.0, 1.0), 50.0, 5.0,
            )
        case SpawnId.AI1_SPIDER_SP1_BLUE_TINT_1B:
            creature.ai_mode = CreatureAiMode.ORBIT_PLAYER_TIGHT
            random_tint_scalar = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_AI1_BLUE_TINT_1B, 0x28, 0.01, 0.5)
            _set_stats(
                creature, CreatureTypeId.SPIDER_SP1, 40.0, 2.4, 125.0,
                RGBA(random_tint_scalar, random_tint_scalar, 1.0, 1.0), 50.0, 5.0,
            )
        case SpawnId.AI1_LIZARD_BLUE_TINT_1C:
            creature.ai_mode = CreatureAiMode.ORBIT_PLAYER_TIGHT
            random_tint_scalar = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_AI1_BLUE_TINT_1C, 0x28, 0.01, 0.5)
            _set_stats(
                creature, CreatureTypeId.LIZARD, 50.0, 2.4, 125.0,
                RGBA(random_tint_scalar, random_tint_scalar, 1.0, 1.0), 50.0, 5.0,
            )
        case SpawnId.ZOMBIE_RANDOM_41:
            creature.type_id = CreatureTypeId.ZOMBIE
            random_size = float(rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ZOMBIE_RANDOM_41_SIZE) % 0x1E + 0x28)
            _size_health(creature, random_size, 1.1428572, 10.0)
            creature.move_speed = x87_pc24_add(x87_pc24_mul(random_size, f32(0.0025)), f32(0.9))
            _size_reward(creature)
            random_tint_scalar = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ZOMBIE_RANDOM_41_TINT, 0x28, 0.01, 0.6)
            creature.tint = RGBA(random_tint_scalar, random_tint_scalar, random_tint_scalar, 1.0)
            creature.contact_damage = float(
                rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ZOMBIE_RANDOM_41_CONTACT_DAMAGE) % 10 + 4,
            )
        case SpawnId.LIZARD_RANDOM_31:
            creature.type_id = CreatureTypeId.LIZARD
            random_size = float(rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_31_SIZE) % 0x1E + 0x28)
            _size_health(creature, random_size, 1.1428572, 10.0)
            creature.move_speed = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_31_MOVE_SPEED, 0x12, 0.1, 1.1)
            _size_reward(creature)
            random_tint_scalar = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_31_TINT, 0x1E, 0.01, 0.6)
            creature.tint = RGBA(random_tint_scalar, random_tint_scalar, f32(0.38), 1.0)
            creature.contact_damage = x87_pc24_add(x87_pc24_mul(creature.size, f32(0.14)), 4.0)
        case SpawnId.SPIDER_SP1_RANDOM_32:
            creature.type_id = CreatureTypeId.SPIDER_SP1
            random_size = float(rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_32_SIZE) % 0x19 + 0x28)
            creature.size = random_size
            creature.hp = x87_pc24_add(random_size, 10.0)
            creature.move_speed = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_32_MOVE_SPEED, 0x11, 0.1, 1.1)
            _size_reward(creature)
            random_tint_scalar = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_32_TINT, 0x28, 0.01, 0.6)
            creature.tint = RGBA(random_tint_scalar, random_tint_scalar, random_tint_scalar, 1.0)
            creature.contact_damage = x87_pc24_add(x87_pc24_mul(creature.size, f32(0.14)), 4.0)
        case SpawnId.SPIDER_SP1_RANDOM_RED_33:
            creature.type_id = CreatureTypeId.SPIDER_SP1
            random_size = float(rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_RED_33_SIZE) % 0x0F + 0x2D)
            _size_health(creature, random_size, 1.1428572, 20.0)
            creature.move_speed = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_RED_33_MOVE_SPEED, 0x12, 0.1, 1.1)
            _size_reward(creature)
            tint_r = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_RED_33_TINT_R, 0x28, 0.01, 0.6)
            creature.tint = RGBA(tint_r, 0.5, 0.5, 1.0)
            creature.contact_damage = float(
                rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_RED_33_CONTACT_DAMAGE) % 10 + 4,
            )
        case SpawnId.SPIDER_SP1_RANDOM_GREEN_34:
            creature.type_id = CreatureTypeId.SPIDER_SP1
            random_size = float(rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_GREEN_34_SIZE) % 0x14 + 0x28)
            _size_health(creature, random_size, 1.1428572, 20.0)
            creature.move_speed = _rand_field(
                rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_GREEN_34_MOVE_SPEED, 0x12, 0.1, 1.1,
            )
            _size_reward(creature)
            tint_g = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_GREEN_34_TINT_G, 0x28, 0.01, 0.6)
            creature.tint = RGBA(0.5, tint_g, 0.5, 1.0)
            creature.contact_damage = float(
                rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_GREEN_34_CONTACT_DAMAGE) % 10 + 4,
            )
        case SpawnId.ALIEN_RANDOM_GREEN_20:
            creature.type_id = CreatureTypeId.ALIEN
            random_size = float(rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_GREEN_20_SIZE) % 0x1E + 0x28)
            _size_health(creature, random_size, 1.1428572, 20.0)
            creature.move_speed = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_GREEN_20_MOVE_SPEED, 0x12, 0.1, 1.1)
            _size_reward(creature)
            tint_g = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_GREEN_20_TINT_G, 0x28, 0.01, 0.6)
            creature.tint = RGBA(f32(0.3), tint_g, f32(0.3), 1.0)
            creature.contact_damage = float(
                rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_GREEN_20_CONTACT_DAMAGE) % 10 + 4,
            )
        case SpawnId.SPIDER_SP1_RANDOM_03:
            creature.type_id = CreatureTypeId.SPIDER_SP1
            creature.size = float(rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_03_SIZE) % 0x0F + 0x26)
            creature.hp = x87_pc24_add(x87_pc24_mul(creature.size, f32(1.1428572)), 20.0)
            creature.move_speed = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_03_MOVE_SPEED, 0x12, 0.1, 1.1)
            _size_reward(creature)
            tint_b = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_03_TINT_B, 0x19, 0.01, 0.8)
            creature.tint = RGBA(f32(0.6), f32(0.6), clamp01(tint_b), 1.0)
            creature.contact_damage = float(
                rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_03_CONTACT_DAMAGE) % 10 + 4,
            )
        case SpawnId.SPIDER_SP2_RANDOM_05:
            creature.type_id = CreatureTypeId.SPIDER_SP2
            creature.size = float(rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP2_RANDOM_05_SIZE) % 0x0F + 0x26)
            creature.hp = x87_pc24_add(x87_pc24_mul(creature.size, f32(1.1428572)), 20.0)
            creature.move_speed = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP2_RANDOM_05_MOVE_SPEED, 0x12, 0.1, 1.1)
            _size_reward(creature)
            tint_b = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP2_RANDOM_05_TINT_B, 0x19, 0.01, 0.8)
            creature.tint = RGBA(f32(0.6), f32(0.6), clamp01(tint_b), 1.0)
            creature.contact_damage = float(
                rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP2_RANDOM_05_CONTACT_DAMAGE) % 10 + 4,
            )
        case SpawnId.LIZARD_RANDOM_04:
            creature.type_id = CreatureTypeId.LIZARD
            creature.size = float(rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_04_SIZE) % 0x0F + 0x26)
            creature.hp = x87_pc24_add(x87_pc24_mul(creature.size, f32(1.1428572)), 20.0)
            creature.move_speed = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_04_MOVE_SPEED, 0x12, 0.1, 1.1)
            creature.tint = _tint(0.67, 0.67, 1.0, 1.0)
            _size_reward(creature)
            creature.contact_damage = float(
                rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_04_CONTACT_DAMAGE) % 10 + 4,
            )
        case SpawnId.ALIEN_RANDOM_06:
            creature.type_id = CreatureTypeId.ALIEN
            creature.size = float(rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_06_SIZE) % 0x0F + 0x26)
            creature.hp = x87_pc24_add(x87_pc24_mul(creature.size, f32(1.1428572)), 20.0)
            creature.move_speed = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_06_MOVE_SPEED, 0x12, 0.1, 1.1)
            _size_reward(creature)
            tint_b = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_06_TINT_B, 0x19, 0.01, 0.8)
            creature.tint = RGBA(f32(0.6), f32(0.6), clamp01(tint_b), 1.0)
            creature.contact_damage = float(
                rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_06_CONTACT_DAMAGE) % 10 + 4,
            )
        case SpawnId.SPIDER_SP2_RANDOM_35:
            creature.type_id = CreatureTypeId.SPIDER_SP2
            creature.size = float(rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP2_RANDOM_35_SIZE) % 10 + 0x1E)
            creature.hp = x87_pc24_add(x87_pc24_mul(creature.size, f32(1.1428572)), 20.0)
            creature.move_speed = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP2_RANDOM_35_MOVE_SPEED, 0x12, 0.1, 1.1)
            _size_reward(creature)
            tint_g = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP2_RANDOM_35_TINT_G, 0x14, 0.01, 0.8)
            creature.tint = RGBA(f32(0.8), tint_g, f32(0.8), 1.0)
            creature.contact_damage = float(
                rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP2_RANDOM_35_CONTACT_DAMAGE) % 10 + 4,
            )
        case SpawnId.LIZARD_RANDOM_2E:
            creature.type_id = CreatureTypeId.LIZARD
            creature.size = float(rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_2E_SIZE) % 0x1E + 0x28)
            creature.hp = x87_pc24_add(x87_pc24_mul(creature.size, f32(1.1428572)), 20.0)
            creature.move_speed = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_2E_MOVE_SPEED, 0x12, 0.1, 1.1)
            _size_reward(creature)
            creature.tint = RGBA(
                _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_2E_TINT_R, 0x28, 0.01, 0.6),
                _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_2E_TINT_G, 0x28, 0.01, 0.6),
                _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_2E_TINT_B, 0x28, 0.01, 0.6),
                1.0,
            )
            creature.contact_damage = float(
                rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_2E_CONTACT_DAMAGE) % 10 + 4,
            )
        case SpawnId.ALIEN_AI7_ORBITER_36:
            creature.ai_mode = CreatureAiMode.HOLD_TIMER
            creature.orbit_radius = 1.5
            tint_g = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_AI7_ORBITER_TINT_G, 5, 0.01, 0.65)
            _set_stats(creature, CreatureTypeId.ALIEN, 10.0, 1.8, 150.0, RGBA(f32(0.65), tint_g, f32(0.95), 1.0), 50.0, 40.0)
        case SpawnId.ALIEN_RANDOM_1D:
            creature.type_id = CreatureTypeId.ALIEN
            creature.size = float(rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_SIZE) % 0x14 + 0x23)
            creature.hp = x87_pc24_add(x87_pc24_mul(creature.size, f32(1.1428572)), 10.0)
            creature.move_speed = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_MOVE_SPEED, 0x0F, 0.1, 1.1)
            creature.reward_value = float(rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_REWARD) % 100 + 0x32)
            creature.tint = RGBA(
                _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_TINT_R, 0x32, 0.001, 0.6),
                _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_TINT_G, 0x32, 0.01, 0.5),
                _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_TINT_B, 0x32, 0.001, 0.6),
                1.0,
            )
            creature.contact_damage = float(
                rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_CONTACT_DAMAGE) % 10 + 4,
            )
        case SpawnId.ALIEN_RANDOM_1E:
            creature.type_id = CreatureTypeId.ALIEN
            creature.size = float(rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1E_SIZE) % 0x1E + 0x23)
            creature.hp = x87_pc24_add(x87_pc24_mul(creature.size, f32(2.2857144)), 10.0)
            creature.move_speed = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1E_MOVE_SPEED, 0x11, 0.1, 1.5)
            creature.reward_value = float(rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1E_REWARD) % 200 + 0x32)
            creature.tint = RGBA(
                _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1E_TINT_R, 0x32, 0.001, 0.6),
                _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1E_TINT_G, 0x32, 0.001, 0.6),
                _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1E_TINT_B, 0x32, 0.01, 0.5),
                1.0,
            )
            creature.contact_damage = float(
                rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1E_CONTACT_DAMAGE) % 0x1E + 4,
            )
        case SpawnId.ALIEN_RANDOM_1F:
            creature.type_id = CreatureTypeId.ALIEN
            creature.size = float(rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1F_SIZE) % 0x1E + 0x2D)
            creature.hp = x87_pc24_add(x87_pc24_mul(creature.size, f32(3.7142856)), 30.0)
            creature.move_speed = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1F_MOVE_SPEED, 0x15, 0.1, 1.6)
            creature.reward_value = float(rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1F_REWARD) % 200 + 0x50)
            creature.tint = RGBA(
                _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1F_TINT_R, 0x32, 0.01, 0.5),
                _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1F_TINT_G, 0x32, 0.001, 0.6),
                _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1F_TINT_B, 0x32, 0.001, 0.6),
                1.0,
            )
            creature.contact_damage = float(
                rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1F_CONTACT_DAMAGE) % 0x23 + 8,
            )
        case SpawnId.ALIEN_CONST_GREEN_24:
            _set_stats(creature, CreatureTypeId.ALIEN, 20.0, 2.0, 110.0, _tint(0.1, 0.7, 0.11, 1.0), 50.0, 4.0)
        case SpawnId.ALIEN_SMALL_GREEN_MAN_25:
            _set_stats(creature, CreatureTypeId.ALIEN, 25.0, 2.5, 125.0, _tint(0.1, 0.8, 0.11, 1.0), 30.0, 3.0)
        case SpawnId.ALIEN_SMALL_GRAY_26:
            _set_stats(creature, CreatureTypeId.ALIEN, 50.0, 2.2, 125.0, _tint(0.6, 0.8, 0.6, 1.0), 45.0, 10.0)
        case SpawnId.ALIEN_BONUS_CARRIER_27:
            creature.flags = CreatureFlags.BONUS_ON_DEATH
            # `bonus_args` overlays `link_index`: a Weapon drop with a 5 duration override.
            creature.link_index = pack_bonus_on_death_args(BonusId.WEAPON, 5)
            creature.bonus_id = BonusId.WEAPON
            creature.bonus_duration_override = 5
            _set_stats(creature, CreatureTypeId.ALIEN, 50.0, 2.1, 125.0, _tint(1.0, 0.8, 0.1, 1.0), 45.0, 10.0)
        case SpawnId.ALIEN_HIDDEN_1_21:
            _set_stats(creature, CreatureTypeId.ALIEN, 53.0, 1.7, 120.0, _tint(0.7, 0.1, 0.51, 0.5), 55.0, 8.0)
        case SpawnId.ALIEN_HIDDEN_2_22:
            _set_stats(creature, CreatureTypeId.ALIEN, 25.0, 1.7, 150.0, _tint(0.1, 0.7, 0.51, 0.05), 50.0, 8.0)
        case SpawnId.ALIEN_HIDDEN_3_23:
            _set_stats(creature, CreatureTypeId.ALIEN, 5.0, 1.7, 180.0, _tint(0.1, 0.7, 0.51, 0.04), 45.0, 8.0)
        case SpawnId.ALIEN_CONST_PURPLE_28:
            _set_stats(creature, CreatureTypeId.ALIEN, 50.0, 1.7, 150.0, _tint(0.7, 0.1, 0.51, 1.0), 55.0, 8.0)
        case SpawnId.ALIEN_BIG_GRAY_29:
            _set_stats(creature, CreatureTypeId.ALIEN, 800.0, 2.5, 450.0, _tint(0.8, 0.8, 0.8, 1.0), 70.0, 20.0)
        case SpawnId.ALIEN_CONST_GREY_FAST_2A:
            _set_stats(creature, CreatureTypeId.ALIEN, 50.0, 3.1, 300.0, _tint(0.3, 0.3, 0.3, 1.0), 60.0, 8.0)
        case SpawnId.ALIEN_DEADLY_FAST_2B:
            _set_stats(creature, CreatureTypeId.ALIEN, 30.0, 3.6, 450.0, _tint(1.0, 0.3, 0.3, 1.0), 35.0, 20.0)
        case SpawnId.ALIEN_CONST_RED_BOSS_2C:
            _set_stats(creature, CreatureTypeId.ALIEN, 3800.0, 2.0, 1500.0, _tint(0.85, 0.2, 0.2, 1.0), 80.0, 40.0)
        case SpawnId.ALIEN_CONST_CYAN_AI2_2D:
            _set_stats(creature, CreatureTypeId.ALIEN, 45.0, 3.1, 200.0, _tint(0.0, 0.9, 0.8, 1.0), 38.0, 3.0)
            creature.ai_mode = CreatureAiMode.CHASE_PLAYER
        case SpawnId.LIZARD_CONST_GREY_2F:
            _set_stats(creature, CreatureTypeId.LIZARD, 20.0, 2.5, 150.0, _tint(0.8, 0.8, 0.8, 1.0), 45.0, 4.0)
        case SpawnId.LIZARD_CONST_YELLOW_BOSS_30:
            _set_stats(creature, CreatureTypeId.LIZARD, 1000.0, 2.0, 400.0, _tint(0.9, 0.8, 0.1, 1.0), 65.0, 10.0)
        case SpawnId.SPIDER_SP1_CONST_RED_BOSS_3B:
            _set_stats(creature, CreatureTypeId.SPIDER_SP1, 1200.0, 2.0, 4000.0, _tint(0.9, 0.0, 0.0, 1.0), 70.0, 20.0)
        case SpawnId.SPIDER_PLASMA_SHOOTER_3C:
            creature.flags = CreatureFlags.RANGED_ATTACK_VARIANT
            creature.orbit_angle = f32(0.4)
            creature.ranged_projectile_type = 0x1A
            _set_stats(creature, CreatureTypeId.SPIDER_SP1, 200.0, 2.0, 200.0, _tint(0.9, 0.1, 0.1, 1.0), 40.0, 20.0)
            creature.ai_mode = CreatureAiMode.CHASE_PLAYER
        case SpawnId.SPIDER_SP1_RANDOM_3D:
            creature.type_id = CreatureTypeId.SPIDER_SP1
            creature.hp = 70.0
            creature.move_speed = f32(2.6)
            creature.reward_value = 120.0
            random_tint_scalar = _rand_field(rng, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_3D_TINT, 0x14, 0.01, 0.8)
            creature.tint = RGBA(random_tint_scalar, random_tint_scalar, random_tint_scalar, 1.0)
            creature.size = float(rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_3D_SIZE) % 7 + 0x2D)
            creature.contact_damage = x87_pc24_mul(creature.size, f32(0.22))
        case SpawnId.SPIDER_SP1_CONST_WHITE_FAST_3E:
            _set_stats(creature, CreatureTypeId.SPIDER_SP1, 1000.0, 2.8, 500.0, _tint(1.0, 1.0, 1.0, 1.0), 64.0, 40.0)
        case SpawnId.ZOMBIE_BOSS_SPAWNER_00:
            creature.flags = CreatureFlags.ANIM_PING_PONG | CreatureFlags.ANIM_LONG_STRIP
            _set_stats(creature, CreatureTypeId.ZOMBIE, 8500.0, 1.3, 6600.0, _tint(0.6, 0.6, 1.0, 0.8), 64.0, 50.0)
            slot_index = pool.spawn_slot_alloc()
            creature.link_index = slot_index
            pool.spawn_slots[slot_index] = SpawnSlot(
                owner_creature=creature_idx,
                timer=1.0,
                count=0,
                limit=0x32C,
                interval=f32(0.7),
                child_template_id=SpawnId.ZOMBIE_RANDOM_41,
            )
        case SpawnId.SPIDER_SP1_AI7_TIMER_38:
            creature.flags = CreatureFlags.AI7_LINK_TIMER
            creature.link_index = 0
            creature.type_id = CreatureTypeId.SPIDER_SP1
            creature.hp = 50.0
            creature.move_speed = f32(4.8)
            creature.reward_value = 433.0
            creature.tint = _tint(1.0, 0.75, 0.1, 1.0)
            creature.size = float(rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_AI7_TIMER_38_SIZE) % 4 + 0x29)
            creature.contact_damage = 10.0
        case SpawnId.SPIDER_SP2_RANGED_VARIANT_37:
            # Native zeroes `link_index` but leaves the `orbit_radius` union (the projectile type) stale.
            creature.flags = CreatureFlags.RANGED_ATTACK_VARIANT
            creature.link_index = 0
            creature.type_id = CreatureTypeId.SPIDER_SP2
            creature.hp = 50.0
            creature.move_speed = f32(3.2)
            creature.reward_value = 433.0
            creature.tint = _tint(1.0, 0.75, 0.1, 1.0)
            creature.size = float(
                rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP2_RANGED_VARIANT_37_SIZE) % 4 + 0x29,
            )
            creature.contact_damage = 10.0
        case SpawnId.SPIDER_SP1_AI7_TIMER_WEAK_39:
            creature.flags = CreatureFlags.AI7_LINK_TIMER
            creature.link_index = 0
            creature.type_id = CreatureTypeId.SPIDER_SP1
            creature.hp = 4.0
            creature.move_speed = f32(4.8)
            creature.reward_value = 50.0
            creature.tint = _tint(0.8, 0.65, 0.1, 1.0)
            creature.size = float(
                rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_AI7_TIMER_WEAK_39_SIZE) % 4 + 0x1A,
            )
            creature.contact_damage = 10.0
        case SpawnId.SPIDER_BOSS_3A:
            creature.flags = CreatureFlags.RANGED_ATTACK_SHOCK
            creature.orbit_angle = f32(0.9)
            creature.ranged_projectile_type = 9
            _set_stats(creature, CreatureTypeId.SPIDER_SP1, 4500.0, 2.0, 4500.0, _tint(1.0, 1.0, 1.0, 1.0), 64.0, 50.0)
        case SpawnId.SPIDER_SP1_CONST_BROWN_SMALL_3F:
            _set_stats(creature, CreatureTypeId.SPIDER_SP1, 200.0, 2.3, 210.0, _tint(0.7, 0.4, 0.1, 1.0), 35.0, 20.0)
        case SpawnId.SPIDER_SMALL_BLUE_40:
            _set_stats(creature, CreatureTypeId.SPIDER_SP1, 70.0, 2.2, 160.0, _tint(0.5, 0.6, 0.9, 1.0), 45.0, 5.0)
        case SpawnId.ZOMBIE_SMALL_WHITE_42:
            _set_stats(creature, CreatureTypeId.ZOMBIE, 200.0, 1.7, 160.0, _tint(0.9, 0.9, 0.9, 1.0), 45.0, 15.0)
        case SpawnId.ZOMBIE_CONST_GREEN_BRUTE_43:
            _set_stats(creature, CreatureTypeId.ZOMBIE, 2000.0, 2.1, 460.0, _tint(0.2, 0.6, 0.1, 1.0), 70.0, 15.0)
        case _:
            # "Unhandled creatureType": the rings, chains, the first four grids and the ghost all land
            # here with `creature` on their last member, as does the unused 0x02.
            creature.type_id = CreatureTypeId.ALIEN
            creature.hp = 20.0

    if 0.0 < creature.pos.x < TERRAIN_SIZE and 0.0 < creature.pos.y < TERRAIN_SIZE:
        state.effects.spawn_burst(pos=creature.pos, count=8, rng=rng, detail_preset=int(detail_preset))

    creature.max_hp = creature.hp
    flags = creature.flags
    if (
        (flags & CreatureFlags.RANGED_ATTACK_SHOCK) == 0
        and creature.type_id == CreatureTypeId.SPIDER_SP1
        and (flags & CreatureFlags.AI7_LINK_TIMER) == 0
    ):
        creature.flags = flags | CreatureFlags.AI7_LINK_TIMER
        creature.link_index = 0
        creature.move_speed = _scale(creature.move_speed, 1.2)

    if template_id == SpawnId.SPIDER_SP1_AI7_TIMER_38 and state.hardcore:
        creature.move_speed = _scale(creature.move_speed, 0.7)

    creature.heading = f32(heading)
    if not state.hardcore and creature.flags & HAS_SPAWN_SLOT_FLAG and (slot := _spawn_slot_of(pool, creature)) is not None:
        slot.interval = x87_pc24_add(slot.interval, f32(0.2))

    if state.hardcore:
        state.quest_fail_retry_count = 0
        creature.move_speed = _scale(creature.move_speed, 1.05)
        creature.contact_damage = _scale(creature.contact_damage, 1.4)
        creature.hp = _scale(creature.hp, 1.2)
        if creature.flags & HAS_SPAWN_SLOT_FLAG and (slot := _spawn_slot_of(pool, creature)) is not None:
            slot.interval = x87_pc24_sub(slot.interval, f32(0.2))
            if slot.interval < 0.1:
                slot.interval = f32(0.1)
    elif state.quest_fail_retry_count > 0:
        match state.quest_fail_retry_count:
            case 1:
                creature.reward_value = _scale(creature.reward_value, 0.9)
                creature.move_speed = _scale(creature.move_speed, 0.95)
                creature.contact_damage = _scale(creature.contact_damage, 0.95)
                creature.hp = _scale(creature.hp, 0.95)
            case 2:
                creature.reward_value = _scale(creature.reward_value, 0.85)
                creature.move_speed = _scale(creature.move_speed, 0.9)
                creature.contact_damage = _scale(creature.contact_damage, 0.9)
                creature.hp = _scale(creature.hp, 0.9)
            case 3:
                creature.reward_value = _scale(creature.reward_value, 0.85)
                creature.move_speed = _scale(creature.move_speed, 0.8)
                creature.contact_damage = _scale(creature.contact_damage, 0.8)
                creature.hp = _scale(creature.hp, 0.8)
            case 4:
                creature.reward_value = _scale(creature.reward_value, 0.8)
                creature.move_speed = _scale(creature.move_speed, 0.7)
                creature.contact_damage = _scale(creature.contact_damage, 0.7)
                creature.hp = _scale(creature.hp, 0.7)
            case _:
                creature.reward_value = _scale(creature.reward_value, 0.8)
                creature.move_speed = _scale(creature.move_speed, 0.6)
                creature.contact_damage = _scale(creature.contact_damage, 0.5)
                creature.hp = _scale(creature.hp, 0.5)
        if creature.flags & HAS_SPAWN_SLOT_FLAG and (slot := _spawn_slot_of(pool, creature)) is not None:
            retry_interval = x87_pc24_mul(float(state.quest_fail_retry_count), f32(0.35))
            if retry_interval > 3.0:
                retry_interval = 3.0
            slot.interval = x87_pc24_add(slot.interval, retry_interval)

    return creature_idx


def _survival_tint_roll(rng: CrandLike, caller: RngCallerStatic) -> float:
    return x87_pc24_mul(float(rng.rand_tagged(caller) % 10), f32(0.01))


def _survival_tint_inverse_bucket(xp: int, divisor: int) -> float:
    return x87_pc24_div(f32(1.0), x87_pc24_add(float(xp // divisor), f32(10.0)))


def survival_spawn_creature(pool: CreaturePool, pos: Vec2, rng: CrandLike, *, player_experience: int) -> int:
    """Port of `survival_spawn_creature` (0x00407510): a Survival wave creature scaled by player 1's XP."""
    xp = int(player_experience)

    creature_idx = pool.alloc_slot(rng)
    creature = pool.creature(creature_idx)
    creature.pos = f32_vec2(pos)
    creature.plague_infected = False
    creature.collision_timer = 0.0
    creature.ai_mode = CreatureAiMode.ORBIT_PLAYER

    r10 = rng.rand_tagged(RngCallerStatic.SURVIVAL_SPAWN_CREATURE_TYPE_ROLL) % 10

    if xp < 12000:
        type_id = 2 if r10 < 9 else 3
    elif xp < 25000:
        type_id = 0 if r10 < 4 else 3
        if r10 > 8:
            type_id = 2
    elif xp < 42000:
        if r10 < 5:
            type_id = 2
        else:
            # Decompiled as a sign-bit trick, but in practice this is a parity pick.
            type_id = (rng.rand_tagged(RngCallerStatic.SURVIVAL_SPAWN_CREATURE_PARITY_PICK) & 1) + 3
    elif xp < 50000:
        type_id = 2
    elif xp < 90000:
        type_id = 4
    else:
        if xp > 109999:
            if r10 < 6:
                type_id = 2
            elif r10 < 9:
                type_id = 4
            else:
                type_id = 0
        else:
            type_id = 0

    # Rare override: forces spider_sp1 when (rand() & 0x1f) == 2.
    if (rng.rand_tagged(RngCallerStatic.SURVIVAL_SPAWN_CREATURE_RARE_OVERRIDE) & 0x1F) == 2:
        type_id = 3
    creature.type_id = CreatureTypeId(type_id)

    size_roll = rng.rand_tagged(RngCallerStatic.SURVIVAL_SPAWN_CREATURE_SIZE)
    creature.active = True
    creature.force_target = 0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    creature.size = float(size_roll % 20 + 44)
    creature.vel = Vec2()
    creature.heading = f32(f32(rng.rand_tagged(RngCallerStatic.SURVIVAL_SPAWN_CREATURE_HEADING) % 314) * f32(0.01))

    move_speed = f32(f32(f32(xp // 4000) * f32(0.045)) + f32(0.9))
    if creature.type_id == CreatureTypeId.SPIDER_SP1:
        creature.flags |= CreatureFlags.AI7_LINK_TIMER
        move_speed = f32(f32(move_speed) * f32(1.3))

    r_health = rng.rand_tagged(RngCallerStatic.SURVIVAL_SPAWN_CREATURE_HEALTH)
    health_scaled = x87_pc24_mul(float(xp), f32(0.00125))
    health_rand = f32(r_health & 0xF)
    health = f32(f32(health_scaled + health_rand) + f32(52.0))

    if creature.type_id == CreatureTypeId.ZOMBIE:
        move_speed = f32(f32(move_speed) * f32(0.6))
        if float(move_speed) < 1.3:
            move_speed = f32(1.3)
        health = f32(f32(health) * f32(1.5))

    if float(move_speed) > 3.5:
        move_speed = f32(3.5)

    creature.move_speed = float(move_speed)
    creature.hp = float(health)
    creature.attack_cooldown = 0.0

    # Tint based on player_experience thresholds. Native keeps the x87 in
    # 24-bit precision, so each arithmetic instruction rounds to f32.
    inverse_1k_bucket = _survival_tint_inverse_bucket(xp, 1000)
    inverse_10k_bucket = _survival_tint_inverse_bucket(xp, 10_000)
    if xp < 50_000:
        tint_r = x87_pc24_sub(f32(1.0), inverse_1k_bucket)
        tint_g = x87_pc24_sub(
            x87_pc24_add(
                _survival_tint_roll(rng, RngCallerStatic.SURVIVAL_SPAWN_CREATURE_LOW_TINT_G),
                f32(0.9),
            ),
            inverse_10k_bucket,
        )
        tint_b = x87_pc24_add(
            _survival_tint_roll(rng, RngCallerStatic.SURVIVAL_SPAWN_CREATURE_LOW_TINT_B),
            f32(0.7),
        )
    elif xp < 100_000:
        tint_r = x87_pc24_sub(f32(0.9), inverse_1k_bucket)
        tint_g = x87_pc24_sub(
            x87_pc24_add(
                _survival_tint_roll(rng, RngCallerStatic.SURVIVAL_SPAWN_CREATURE_MID_TINT_G),
                f32(0.8),
            ),
            inverse_10k_bucket,
        )
        tint_b = x87_pc24_add(
            x87_pc24_add(
                _survival_tint_roll(rng, RngCallerStatic.SURVIVAL_SPAWN_CREATURE_MID_TINT_B),
                x87_pc24_mul(float(xp - 50_000), f32(6e-06)),
            ),
            f32(0.7),
        )
    else:
        tint_r = x87_pc24_sub(f32(1.0), inverse_1k_bucket)
        tint_g = x87_pc24_sub(
            x87_pc24_add(
                _survival_tint_roll(rng, RngCallerStatic.SURVIVAL_SPAWN_CREATURE_HIGH_TINT_G),
                f32(0.9),
            ),
            inverse_10k_bucket,
        )
        tint_b = x87_pc24_sub(
            x87_pc24_add(
                _survival_tint_roll(rng, RngCallerStatic.SURVIVAL_SPAWN_CREATURE_HIGH_TINT_B),
                f32(1.0),
            ),
            x87_pc24_mul(float(xp - 100_000), f32(3e-06)),
        )
        if tint_b < 0.5:
            tint_b = f32(0.5)
    tint = RGBA(tint_r, tint_g, tint_b, 1.0)

    # Native multiplies by the f32 literal 0.0952381 (one ulp above 2/21).
    creature.contact_damage = x87_pc24_mul(creature.size, f32(0.0952381))
    # `reward_value` was just zeroed, so native always takes its `== 0.0f` branch.
    reward_value = x87_pc24_add(
        float(rng.rand_tagged(RngCallerStatic.SURVIVAL_SPAWN_CREATURE_REWARD_BONUS) % 10 + 10),
        x87_pc24_mul(move_speed, f32(5.0)),
    )
    reward_value = x87_pc24_add(reward_value, x87_pc24_mul(creature.contact_damage, f32(0.8)))
    reward_value = x87_pc24_add(reward_value, x87_pc24_mul(creature.hp, f32(0.4)))

    # Rare stat overrides (color-coded variants).
    if rng.rand_tagged(RngCallerStatic.SURVIVAL_SPAWN_CREATURE_RARE_RED) % 180 < 2:
        tint = _tint(0.9, 0.4, 0.4, 1.0)
        creature.hp = 65.0
        reward_value = 320.0
    elif rng.rand_tagged(RngCallerStatic.SURVIVAL_SPAWN_CREATURE_RARE_GREEN) % 240 < 2:
        tint = _tint(0.4, 0.9, 0.4, 1.0)
        creature.hp = 85.0
        reward_value = 420.0
    elif rng.rand_tagged(RngCallerStatic.SURVIVAL_SPAWN_CREATURE_RARE_BLUE) % 360 < 2:
        tint = _tint(0.4, 0.4, 0.9, 1.0)
        creature.hp = 125.0
        reward_value = 520.0

    # Rare health/size boosts (do not recompute contact_damage).
    if rng.rand_tagged(RngCallerStatic.SURVIVAL_SPAWN_CREATURE_RARE_PURPLE) % 1320 < 4:
        creature.hp = x87_pc24_add(creature.hp, f32(230.0))
        tint = _tint(0.84, 0.24, 0.89, 1.0)
        creature.size = 80.0
        reward_value = 600.0
    elif rng.rand_tagged(RngCallerStatic.SURVIVAL_SPAWN_CREATURE_RARE_YELLOW) % 1620 < 4:
        creature.hp = x87_pc24_add(creature.hp, f32(2230.0))
        tint = _tint(0.94, 0.84, 0.29, 1.0)
        creature.size = 85.0
        reward_value = 900.0

    creature.max_hp = creature.hp
    creature.reward_value = x87_pc24_mul(reward_value, f32(0.8))
    creature.tint = RGBA(clamp01(tint.r), clamp01(tint.g), clamp01(tint.b), clamp01(tint.a))
    return creature_idx


def creature_spawn(
    pool: CreaturePool,
    pos: Vec2,
    tint: RGBA,
    type_id: CreatureTypeId,
    rng: CrandLike,
    *,
    survival_elapsed_ms: int,
) -> int:
    """Port of `creature_spawn` (0x00428240), the Rush spawner; stats grow with the elapsed time."""
    creature_idx = pool.alloc_slot(rng)
    creature = pool.creature(creature_idx)
    creature.pos = f32_vec2(pos)
    creature.type_id = type_id
    creature.ai_mode = CreatureAiMode.ORBIT_PLAYER
    creature.plague_infected = False
    creature.collision_timer = 0.0
    creature.active = True
    creature.force_target = 0
    creature.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
    # `fild survival_elapsed_ms` loads the int exactly; only the multiply rounds.
    elapsed = float(int(survival_elapsed_ms))
    creature.vel = Vec2()
    creature.hp = x87_pc24_add(x87_pc24_mul(elapsed, _NATIVE_CREATURE_SPAWN_HEALTH_SCALE), 10.0)
    creature.heading = f32(f32(rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_HEADING) % 314) * f32(0.01))
    creature.move_speed = x87_pc24_add(x87_pc24_mul(elapsed, _NATIVE_CREATURE_SPAWN_ELAPSED_SCALE), 2.5)
    reward_roll = rng.rand_tagged(RngCallerStatic.CREATURE_SPAWN_REWARD)
    creature.attack_cooldown = 0.0
    creature.reward_value = float(reward_roll % 30 + 140)
    creature.tint = tint
    creature.size = x87_pc24_add(x87_pc24_mul(elapsed, _NATIVE_CREATURE_SPAWN_ELAPSED_SCALE), 47.0)
    creature.contact_damage = 4.0
    creature.max_hp = creature.hp
    return creature_idx
