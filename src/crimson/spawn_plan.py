from __future__ import annotations

from dataclasses import dataclass
import math
import struct

from .crand import Crand
from .spawn_templates import CreatureFlags, CreatureTypeId


def _f32(u32: int) -> float:
    """Decode a float32 constant expressed as a u32 hex literal in decompiles."""
    return struct.unpack("<f", struct.pack("<I", u32 & 0xFFFFFFFF))[0]


@dataclass(frozen=True, slots=True, kw_only=True)
class SpawnEnv:
    terrain_width: float
    terrain_height: float
    demo_mode_active: bool
    hardcore: bool
    difficulty_level: int


@dataclass(frozen=True, slots=True, kw_only=True)
class BurstEffect:
    x: float
    y: float
    count: int


@dataclass(slots=True)
class CreatureInit:
    # Template id that produced this creature (not necessarily unique per creature in formations).
    origin_template_id: int

    pos_x: float
    pos_y: float

    # Headings are in radians. The original seeds a random heading early, then overwrites it
    # at the end with the function argument (or a randomized argument for `-100.0`).
    heading: float

    phase_seed: float

    type_id: CreatureTypeId | None = None
    flags: CreatureFlags = CreatureFlags(0)
    ai_mode: int = 0

    health: float | None = None
    max_health: float | None = None
    move_speed: float | None = None
    reward_value: float | None = None
    size: float | None = None
    contact_damage: float | None = None

    tint_r: float | None = None
    tint_g: float | None = None
    tint_b: float | None = None
    tint_a: float | None = None

    # AI link semantics:
    # - For formation children (ai_mode 3/5/...), `ai_link_parent` references the parent creature.
    # - For AI7 timer mode (flag 0x80), `ai_timer` is written into link_index.
    ai_link_parent: int | None = None
    ai_timer: int | None = None

    target_offset_x: float | None = None
    target_offset_y: float | None = None

    # Spawn slot reference (stored in link_index in the original when flags include 0x4).
    spawn_slot: int | None = None


@dataclass(slots=True)
class SpawnSlotInit:
    owner_creature: int
    timer: float
    count: int
    limit: int
    interval: float
    child_template_id: int


@dataclass(frozen=True, slots=True)
class SpawnPlan:
    creatures: tuple[CreatureInit, ...]
    spawn_slots: tuple[SpawnSlotInit, ...]
    effects: tuple[BurstEffect, ...]
    primary: int


def _alloc_creature(template_id: int, pos_x: float, pos_y: float, rng: Crand) -> CreatureInit:
    # creature_alloc_slot():
    # - clears flags
    # - seeds phase_seed = float(crt_rand() & 0x17f)
    phase_seed = float(rng.rand() & 0x17F)
    return CreatureInit(origin_template_id=template_id, pos_x=pos_x, pos_y=pos_y, heading=0.0, phase_seed=phase_seed)


def _apply_tail(
    template_id: int,
    plan_creatures: list[CreatureInit],
    plan_spawn_slots: list[SpawnSlotInit],
    plan_effects: list[BurstEffect],
    primary_idx: int,
    final_heading: float,
    env: SpawnEnv,
) -> None:
    c = plan_creatures[primary_idx]

    # Demo-burst effect (skipped when demo_mode_active != 0).
    if (
        not env.demo_mode_active
        and 0.0 < c.pos_x < env.terrain_width
        and 0.0 < c.pos_y < env.terrain_height
    ):
        plan_effects.append(BurstEffect(x=c.pos_x, y=c.pos_y, count=8))

    if c.health is not None:
        c.max_health = c.health

    # Spider_sp1 "AI7 timer" auto-enable (applies to the *return* creature).
    if (
        c.type_id == CreatureTypeId.SPIDER_SP1
        and (int(c.flags) & 0x10) == 0
        and (int(c.flags) & 0x80) == 0
    ):
        c.flags |= CreatureFlags.AI7_LINK_TIMER
        c.ai_link_parent = None
        c.spawn_slot = None
        c.ai_timer = 0
        if c.move_speed is not None:
            c.move_speed *= 1.2

    # Hardcore tweak for template 0x38 only.
    if template_id == 0x38 and env.hardcore and c.move_speed is not None:
        c.move_speed *= 0.7

    c.heading = final_heading

    # Difficulty modifiers.
    has_spawn_slot = c.spawn_slot is not None and 0 <= c.spawn_slot < len(plan_spawn_slots)

    if not env.hardcore:
        # This is written as a short-circuit expression in the original:
        # for flag 0x4 creatures, always bump their spawn-slot interval by +0.2 in non-hardcore.
        if (int(c.flags) & int(CreatureFlags.ANIM_PING_PONG)) != 0 and has_spawn_slot:
            plan_spawn_slots[c.spawn_slot].interval += 0.2

        if env.difficulty_level > 0:
            d = env.difficulty_level
            if c.reward_value is not None and c.move_speed is not None and c.contact_damage is not None and c.health is not None:
                if d == 1:
                    c.reward_value *= 0.9
                    c.move_speed *= 0.95
                    c.contact_damage *= 0.95
                    c.health *= 0.95
                elif d == 2:
                    c.reward_value *= 0.85
                    c.move_speed *= 0.9
                    c.contact_damage *= 0.9
                    c.health *= 0.9
                elif d == 3:
                    c.reward_value *= 0.85
                    c.move_speed *= 0.8
                    c.contact_damage *= 0.8
                    c.health *= 0.8
                elif d == 4:
                    c.reward_value *= 0.8
                    c.move_speed *= 0.7
                    c.contact_damage *= 0.7
                    c.health *= 0.7
                else:
                    c.reward_value *= 0.8
                    c.move_speed *= 0.6
                    c.contact_damage *= 0.5
                    c.health *= 0.5

            if has_spawn_slot and (int(c.flags) & int(CreatureFlags.ANIM_PING_PONG)) != 0:
                plan_spawn_slots[c.spawn_slot].interval += min(3.0, float(d) * 0.35)
    else:
        # In hardcore: difficulty level is forcibly cleared (global), and creature stats are buffed.
        if c.move_speed is not None:
            c.move_speed *= 1.05
        if c.contact_damage is not None:
            c.contact_damage *= 1.4
        if c.health is not None:
            c.health *= 1.2

        if has_spawn_slot and (int(c.flags) & int(CreatureFlags.ANIM_PING_PONG)) != 0:
            plan_spawn_slots[c.spawn_slot].interval = max(0.1, plan_spawn_slots[c.spawn_slot].interval - 0.2)


def build_spawn_plan(template_id: int, pos: tuple[float, float], heading: float, rng: Crand, env: SpawnEnv) -> SpawnPlan:
    """Pure plan builder modeled after `creature_spawn_template` (0x00430AF0).

    The plan lists:
      - every creature allocated and configured directly by the template
      - any spawn-slot configurations (deferred child spawns)
      - side-effects like burst FX
    """
    pos_x, pos_y = pos

    # creature_alloc_slot() for the base creature.
    creatures: list[CreatureInit] = [_alloc_creature(template_id, pos_x, pos_y, rng)]
    spawn_slots: list[SpawnSlotInit] = []
    effects: list[BurstEffect] = []
    primary_idx = 0

    # `heading == -100.0` uses a randomized heading.
    final_heading = heading
    if final_heading == -100.0:
        final_heading = float(rng.rand() % 0x274) * 0.01

    # Base initialization always consumes one rand() for a transient heading value.
    creatures[0].heading = float(rng.rand() % 0x13A) * 0.01

    # Template-specific init. We start with a small, representative batch:
    # - template 1: simple (no children/spawn slot)
    # - template 0x0A: spawn-slot spawner
    # - template 0x12: formation spawner (immediate children)
    if template_id == 1:
        c = creatures[0]
        c.type_id = CreatureTypeId.SPIDER_SP2
        c.flags = CreatureFlags.SPLIT_ON_DEATH
        c.size = 80.0
        c.health = 400.0
        c.move_speed = 2.0
        c.reward_value = 1000.0
        c.tint_a = 1.0
        c.tint_r = 0.8
        c.tint_g = 0.7
        c.tint_b = 0.4
        c.contact_damage = 17.0
        primary_idx = 0
    elif template_id == 0x0A:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        c.flags = CreatureFlags.ANIM_PING_PONG
        slot_idx = len(spawn_slots)
        c.spawn_slot = slot_idx
        spawn_slots.append(
            SpawnSlotInit(
                owner_creature=0,
                timer=2.0,
                count=0,
                limit=100,
                interval=5.0,
                child_template_id=0x32,
            )
        )
        c.size = 55.0
        c.health = 1000.0
        c.move_speed = 1.5
        c.reward_value = 3000.0
        c.tint_a = 1.0
        c.tint_r = 0.8
        c.tint_g = 0.7
        c.tint_b = 0.4
        c.contact_damage = 0.0
        primary_idx = 0
    elif template_id == 0x0B:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        c.flags = CreatureFlags.ANIM_PING_PONG
        slot_idx = len(spawn_slots)
        c.spawn_slot = slot_idx
        spawn_slots.append(
            SpawnSlotInit(
                owner_creature=0,
                timer=2.0,
                count=0,
                limit=100,
                interval=6.0,
                child_template_id=0x3C,
            )
        )
        c.size = 65.0
        c.health = 3500.0
        c.move_speed = 1.5
        c.reward_value = 5000.0
        c.tint_a = 1.0
        c.tint_r = 0.9
        c.tint_g = 0.1
        c.tint_b = 0.1
        c.contact_damage = 0.0
        primary_idx = 0
    elif template_id == 0x10:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        c.flags = CreatureFlags.ANIM_PING_PONG
        slot_idx = len(spawn_slots)
        c.spawn_slot = slot_idx
        spawn_slots.append(
            SpawnSlotInit(
                owner_creature=0,
                timer=_f32(0x3FC00000),  # 1.5
                count=0,
                limit=100,
                interval=_f32(0x40133333),  # ~2.3
                child_template_id=0x32,
            )
        )
        c.size = 32.0
        c.health = 50.0
        c.move_speed = 2.8
        c.reward_value = 800.0
        # Shared "alien spawner" tail for this branch sets these (before LAB_004310b8).
        c.tint_a = 1.0
        c.tint_r = 0.9
        c.tint_g = 0.8
        c.tint_b = 0.4
        c.contact_damage = 0.0
        primary_idx = 0
    elif template_id == 0x12:
        parent = creatures[0]
        parent.type_id = CreatureTypeId.ALIEN
        parent.tint_r = 0.65
        parent.tint_g = 0.85
        parent.tint_b = 0.97
        parent.tint_a = 1.0
        parent.health = 200.0
        parent.max_health = 200.0
        parent.move_speed = 2.2
        parent.reward_value = 600.0
        parent.size = 55.0
        parent.contact_damage = 14.0

        # Spawns 8 linked orbiters in a ring (step ~= pi/4).
        for i in range(8):
            child = _alloc_creature(template_id, pos_x, pos_y, rng)
            child.ai_mode = 3
            child.ai_link_parent = 0
            angle = float(i) * 0.7853982
            child.target_offset_x = float(math.cos(angle) * 100.0)
            child.target_offset_y = float(math.sin(angle) * 100.0)
            child.tint_r = 0.32000002
            child.tint_g = 0.58800006
            child.tint_b = 0.426
            child.tint_a = 1.0
            child.health = 40.0
            child.max_health = 40.0
            child.type_id = CreatureTypeId.ALIEN
            child.move_speed = 2.4
            child.reward_value = 60.0
            child.size = 50.0
            child.contact_damage = 4.0
            creatures.append(child)

        # The original function returns the last allocated creature pointer.
        primary_idx = len(creatures) - 1
    elif template_id == 0x19:
        parent = creatures[0]
        parent.type_id = CreatureTypeId.ALIEN
        parent.tint_r = 0.95
        parent.tint_g = 0.55
        parent.tint_b = 0.37
        parent.tint_a = 1.0
        parent.health = 50.0
        parent.max_health = 50.0
        parent.move_speed = 3.8
        parent.reward_value = 300.0
        parent.size = 55.0
        parent.contact_damage = 40.0

        for i in range(5):
            child = _alloc_creature(template_id, pos_x, pos_y, rng)
            child.ai_mode = 5
            child.ai_link_parent = 0
            angle = float(i) * 1.2566371
            child.target_offset_x = float(math.cos(angle) * 110.0)
            child.target_offset_y = float(math.sin(angle) * 110.0)
            child.pos_x = pos_x + (child.target_offset_x or 0.0)
            child.pos_y = pos_y + (child.target_offset_y or 0.0)
            child.tint_r = 0.7125
            child.tint_g = 0.41250002
            child.tint_b = 0.2775
            child.tint_a = 0.6
            child.health = 220.0
            child.max_health = 220.0
            child.type_id = CreatureTypeId.ALIEN
            child.move_speed = 3.8
            child.reward_value = 60.0
            child.size = 50.0
            child.contact_damage = 35.0
            creatures.append(child)

        primary_idx = len(creatures) - 1
    else:
        raise NotImplementedError(f"spawn plan not implemented for template_id=0x{template_id:x}")

    _apply_tail(
        template_id=template_id,
        plan_creatures=creatures,
        plan_spawn_slots=spawn_slots,
        plan_effects=effects,
        primary_idx=primary_idx,
        final_heading=final_heading,
        env=env,
    )
    return SpawnPlan(
        creatures=tuple(creatures),
        spawn_slots=tuple(spawn_slots),
        effects=tuple(effects),
        primary=primary_idx,
    )
