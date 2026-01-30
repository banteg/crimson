from __future__ import annotations

"""Creature realtime simulation glue.

This module materializes pure spawn plans (`creatures.spawn`) into a fixed-size
runtime pool and advances creatures each frame using the AI helpers.

It is intentionally minimal: the goal is to unblock a playable Survival loop,
not to perfectly match every edge case in `creature_update_all`.
See: `docs/creatures/update.md`.
"""

from dataclasses import dataclass, replace
import math
from typing import Callable, Sequence

from grim.rand import Crand
from ..effects import FxQueue, FxQueueRotated
from ..gameplay import GameplayState, PlayerState, award_experience, perk_active
from ..perks import PerkId
from ..player_damage import player_take_damage
from .ai import creature_ai7_tick_link_timer, creature_ai_update_target
from .spawn import (
    CreatureFlags,
    CreatureInit,
    SpawnEnv,
    SpawnPlan,
    SpawnSlotInit,
    build_spawn_plan,
    resolve_tint,
    tick_spawn_slot,
)

__all__ = [
    "CONTACT_DAMAGE_PERIOD",
    "CREATURE_POOL_SIZE",
    "CreatureDeath",
    "CreaturePool",
    "CreatureState",
    "CreatureUpdateResult",
]


CREATURE_POOL_SIZE = 0x180

CONTACT_DAMAGE_PERIOD = 0.5

# The native uses per-type speed scaling; until we port the exact table, keep a
# single global factor (native multiplies `move_speed * 30.0` in creature_update_all).
CREATURE_SPEED_SCALE = 30.0

# Base heading turn rate multiplier (angle_approach clamps by frame_dt internally).
CREATURE_TURN_RATE_SCALE = 4.0 / 3.0

# Native uses hitbox_size as a lifecycle sentinel:
# - 16.0 means "alive" (normal AI/movement/anim update)
# - once HP <= 0 it ramps down quickly and drives the death slide + corpse decal timing.
CREATURE_HITBOX_ALIVE = 16.0
CREATURE_DEATH_TIMER_DECAY = 28.0
CREATURE_CORPSE_FADE_DECAY = 20.0
CREATURE_CORPSE_DESPAWN_HITBOX = -10.0
CREATURE_DEATH_SLIDE_SCALE = 9.0


def _clamp(value: float, lo: float, hi: float) -> float:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def _wrap_angle(angle: float) -> float:
    return (angle + math.pi) % math.tau - math.pi


def _angle_approach(current: float, target: float, rate: float, dt: float) -> float:
    delta = _wrap_angle(target - current)
    step_scale = min(1.0, abs(delta))
    step = float(dt) * step_scale * float(rate)
    if delta >= 0.0:
        current += step
    else:
        current -= step
    return _wrap_angle(current)


def _distance_sq(x0: float, y0: float, x1: float, y1: float) -> float:
    dx = x1 - x0
    dy = y1 - y0
    return dx * dx + dy * dy


def _owner_id_to_player_index(owner_id: int) -> int | None:
    # Native uses `-1/-2/-3/-4` for player indices and `-100` as a player-owned sentinel.
    if owner_id == -100:
        return 0
    if owner_id < 0:
        return -1 - owner_id
    return None


@dataclass(slots=True)
class CreatureState:
    # Core identity/alive flags.
    active: bool = False
    type_id: int = 0

    # Movement / AI.
    x: float = 0.0
    y: float = 0.0
    vel_x: float = 0.0
    vel_y: float = 0.0
    heading: float = 0.0
    target_heading: float = 0.0
    force_target: int = 0
    target_x: float = 0.0
    target_y: float = 0.0
    target_player: int = 0
    ai_mode: int = 0
    flags: CreatureFlags = CreatureFlags(0)

    link_index: int = 0
    target_offset_x: float | None = None
    target_offset_y: float | None = None
    orbit_angle: float = 0.0
    orbit_radius: float = 0.0
    phase_seed: float = 0.0
    move_scale: float = 1.0

    # Combat / timers.
    hp: float = 0.0
    max_hp: float = 0.0
    move_speed: float = 1.0
    contact_damage: float = 0.0
    attack_cooldown: float = 0.0
    reward_value: float = 0.0

    # Contact damage gate.
    collision_flag: int = 0
    collision_timer: float = CONTACT_DAMAGE_PERIOD
    hitbox_size: float = CREATURE_HITBOX_ALIVE

    # Presentation.
    size: float = 50.0
    anim_phase: float = 0.0
    hit_flash_timer: float = 0.0
    last_hit_owner_id: int = -100
    tint_r: float = 1.0
    tint_g: float = 1.0
    tint_b: float = 1.0
    tint_a: float = 1.0

    # Rewrite-only helpers (not in native struct, but derived from spawn plans).
    spawn_slot_index: int | None = None
    bonus_id: int | None = None
    bonus_duration_override: int | None = None


@dataclass(frozen=True, slots=True)
class CreatureDeath:
    index: int
    x: float
    y: float
    type_id: int
    reward_value: float
    xp_awarded: int


@dataclass(frozen=True, slots=True)
class CreatureUpdateResult:
    deaths: tuple[CreatureDeath, ...] = ()
    spawned: tuple[int, ...] = ()
    sfx: tuple[str, ...] = ()


class CreaturePool:
    def __init__(self, *, size: int = CREATURE_POOL_SIZE, env: SpawnEnv | None = None) -> None:
        self._entries = [CreatureState() for _ in range(int(size))]
        self.spawn_slots: list[SpawnSlotInit] = []
        self.env = env
        self.kill_count = 0
        self.spawned_count = 0

    @property
    def entries(self) -> list[CreatureState]:
        return self._entries

    def reset(self) -> None:
        for i in range(len(self._entries)):
            self._entries[i] = CreatureState()
        self.spawn_slots.clear()
        self.kill_count = 0
        self.spawned_count = 0

    def iter_active(self) -> list[CreatureState]:
        return [entry for entry in self._entries if entry.active and entry.hp > 0.0]

    def _plaguebearer_spread_infection(self, origin_index: int) -> None:
        """Port of `FUN_00425d80` (infects nearby creatures when Plaguebearer is active)."""

        origin_index = int(origin_index)
        if not (0 <= origin_index < len(self._entries)):
            return
        origin = self._entries[origin_index]
        if not origin.active:
            return

        for idx, creature in enumerate(self._entries):
            if not creature.active:
                continue

            if math.hypot(float(creature.x) - float(origin.x), float(creature.y) - float(origin.y)) < 45.0:
                if creature.collision_flag != 0 and float(origin.hp) < 150.0:
                    origin.collision_flag = 1
                if origin.collision_flag != 0 and float(creature.hp) < 150.0:
                    creature.collision_flag = 1
                return

    def _alloc_slot(self, *, rand: Callable[[], int] | None = None) -> int:
        for i, entry in enumerate(self._entries):
            if not entry.active:
                return i
        if not self._entries:
            raise ValueError("Creature pool has zero entries")
        if rand is not None:
            return int(rand()) % len(self._entries)
        return len(self._entries) - 1

    def spawn_init(self, init: CreatureInit, *, rand: Callable[[], int] | None = None) -> int:
        """Materialize a single `CreatureInit` into the runtime pool."""

        idx = self._alloc_slot(rand=rand)
        entry = CreatureState()
        self._apply_init(entry, init)

        # Direct init does not have plan-local indices; preserve any raw linkage.
        if init.ai_timer is not None:
            entry.link_index = int(init.ai_timer)
        elif init.ai_link_parent is not None:
            entry.link_index = int(init.ai_link_parent)
        if init.spawn_slot is not None:
            # Plan-local slot ids must be remapped by `spawn_plan`; keep explicit.
            entry.spawn_slot_index = int(init.spawn_slot)
            entry.link_index = int(init.spawn_slot)

        self._entries[idx] = entry
        self.spawned_count += 1
        return idx

    def spawn_inits(self, inits: Sequence[CreatureInit], *, rand: Callable[[], int] | None = None) -> list[int]:
        return [self.spawn_init(init, rand=rand) for init in inits]

    def spawn_plan(
        self,
        plan: SpawnPlan,
        *,
        rand: Callable[[], int] | None = None,
    ) -> tuple[list[int], int | None]:
        """Materialize a pure `SpawnPlan` into the runtime pool.

        Returns:
          (plan_index_to_pool_index, primary_pool_index_or_none)
        """

        mapping: list[int] = []
        pending_ai_links: list[int | None] = []
        pending_ai_timers: list[int | None] = []
        pending_spawn_slots: list[int | None] = []

        # 1) Allocate pool slots for every creature.
        for init in plan.creatures:
            pool_idx = self._alloc_slot(rand=rand)
            entry = CreatureState()
            self._apply_init(entry, init)
            self._entries[pool_idx] = entry
            self.spawned_count += 1

            mapping.append(pool_idx)
            pending_ai_links.append(init.ai_link_parent)
            pending_ai_timers.append(init.ai_timer)
            pending_spawn_slots.append(init.spawn_slot)

        # 2) Allocate and remap spawn slots.
        slot_mapping: list[int] = []
        for slot in plan.spawn_slots:
            owner_plan = int(slot.owner_creature)
            owner_pool = mapping[owner_plan] if 0 <= owner_plan < len(mapping) else -1
            self.spawn_slots.append(
                SpawnSlotInit(
                    owner_creature=int(owner_pool),
                    timer=float(slot.timer),
                    count=int(slot.count),
                    limit=int(slot.limit),
                    interval=float(slot.interval),
                    child_template_id=int(slot.child_template_id),
                )
            )
            slot_mapping.append(len(self.spawn_slots) - 1)

        # 3) Patch link indices now that we have global indices.
        for plan_idx, pool_idx in enumerate(mapping):
            entry = self._entries[pool_idx]

            slot_plan = pending_spawn_slots[plan_idx]
            if slot_plan is not None:
                global_slot = slot_mapping[int(slot_plan)]
                entry.spawn_slot_index = int(global_slot)
                entry.link_index = int(global_slot)
                continue

            timer = pending_ai_timers[plan_idx]
            if timer is not None:
                entry.link_index = int(timer)
                continue

            link_plan = pending_ai_links[plan_idx]
            if link_plan is not None:
                entry.link_index = mapping[int(link_plan)]

        primary_pool = None
        if 0 <= int(plan.primary) < len(mapping):
            primary_pool = mapping[int(plan.primary)]
        return mapping, primary_pool

    def spawn_template(
        self,
        template_id: int,
        pos: tuple[float, float],
        heading: float,
        rng: Crand,
        *,
        rand: Callable[[], int] | None = None,
        env: SpawnEnv | None = None,
    ) -> tuple[list[int], int | None]:
        """Build a spawn plan and materialize it into the pool."""

        spawn_env = env or self.env
        if spawn_env is None:
            raise ValueError("CreaturePool.spawn_template requires SpawnEnv (set CreaturePool.env or pass env=...)")
        plan = build_spawn_plan(template_id, pos, heading, rng, spawn_env)
        return self.spawn_plan(plan, rand=rand)

    def update(
        self,
        dt: float,
        *,
        state: GameplayState,
        players: list[PlayerState],
        rand: Callable[[], int] | None = None,
        detail_preset: int = 5,
        env: SpawnEnv | None = None,
        world_width: float = 1024.0,
        world_height: float = 1024.0,
        fx_queue: FxQueue | None = None,
        fx_queue_rotated: FxQueueRotated | None = None,
    ) -> CreatureUpdateResult:
        """Advance the creature runtime pool by `dt` seconds.

        Notes:
        - Death side effects should be initiated by damage call sites.
        - This is not a full port of `creature_update_all`; it targets the Survival subset.
        """

        if rand is None:
            rand = state.rng.rand
        spawn_env = env or self.env

        deaths: list[CreatureDeath] = []
        spawned: list[int] = []
        sfx: list[str] = []

        evil_target = -1
        if players and perk_active(players[0], PerkId.EVIL_EYES):
            evil_target = int(players[0].evil_eyes_target_creature)

        # Movement + AI. Dead creatures keep updating (death slide + corpse decals)
        # even when `players` is empty so debug views remain deterministic.
        dt_ms = int(dt * 1000.0) if dt > 0.0 else 0
        for idx, creature in enumerate(self._entries):
            if not creature.active:
                continue

            if creature.hitbox_size != CREATURE_HITBOX_ALIVE or creature.hp <= 0.0:
                if creature.hitbox_size == CREATURE_HITBOX_ALIVE:
                    creature.hitbox_size = CREATURE_HITBOX_ALIVE - 0.001
                if dt > 0.0:
                    self._tick_dead(
                        creature,
                        dt=dt,
                        world_width=world_width,
                        world_height=world_height,
                        fx_queue_rotated=fx_queue_rotated,
                    )
                continue

            if dt <= 0.0 or not players:
                continue

            if creature.flags & CreatureFlags.SELF_DAMAGE_TICK_STRONG:
                creature.hp -= dt * 180.0
            elif creature.flags & CreatureFlags.SELF_DAMAGE_TICK:
                creature.hp -= dt * 60.0
            if creature.hp <= 0.0:
                deaths.append(
                    self.handle_death(
                        idx,
                        state=state,
                        players=players,
                        rand=rand,
                        detail_preset=int(detail_preset),
                        world_width=world_width,
                        world_height=world_height,
                        fx_queue=fx_queue,
                    )
                )
                if creature.active:
                    self._tick_dead(
                        creature,
                        dt=dt,
                        world_width=world_width,
                        world_height=world_height,
                        fx_queue_rotated=fx_queue_rotated,
                    )
                continue

            if creature.collision_flag != 0:
                creature.collision_timer -= float(dt)
                if creature.collision_timer < 0.0:
                    creature.collision_timer += CONTACT_DAMAGE_PERIOD
                    creature.hp -= 15.0
                    if fx_queue is not None:
                        fx_queue.add_random(pos_x=creature.x, pos_y=creature.y, rand=rand)

                    if creature.hp < 0.0:
                        state.plaguebearer_infection_count += 1
                        deaths.append(
                            self.handle_death(
                                idx,
                                state=state,
                                players=players,
                                rand=rand,
                                detail_preset=int(detail_preset),
                                world_width=world_width,
                                world_height=world_height,
                                fx_queue=fx_queue,
                            )
                        )
                        if creature.active:
                            self._tick_dead(
                                creature,
                                dt=dt,
                                world_width=world_width,
                                world_height=world_height,
                                fx_queue_rotated=fx_queue_rotated,
                            )
                        continue

            target_player = int(creature.target_player)
            if not (0 <= target_player < len(players)):
                target_player = 0
                creature.target_player = 0
            player = players[target_player]

            if players and perk_active(players[0], PerkId.RADIOACTIVE):
                radioactive_player = players[0]
                dist = math.hypot(
                    float(creature.x) - float(radioactive_player.pos_x),
                    float(creature.y) - float(radioactive_player.pos_y),
                )
                if dist < 100.0:
                    creature.collision_timer -= float(dt) * 1.5
                    if creature.collision_timer < 0.0:
                        creature.collision_timer = CONTACT_DAMAGE_PERIOD
                        creature.hp -= (100.0 - dist) * 0.3
                        if fx_queue is not None:
                            fx_queue.add_random(pos_x=creature.x, pos_y=creature.y, rand=rand)

                        if creature.hp < 0.0:
                            if creature.type_id == 1:
                                creature.hp = 1.0
                            else:
                                radioactive_player.experience = int(
                                    float(radioactive_player.experience) + float(creature.reward_value)
                                )
                                creature.hitbox_size -= float(dt)
                                continue

            frozen_by_evil_eyes = idx == evil_target
            if frozen_by_evil_eyes:
                creature.move_scale = 0.0
                creature.vel_x = 0.0
                creature.vel_y = 0.0
            else:
                creature_ai7_tick_link_timer(creature, dt_ms=dt_ms, rand=rand)
                ai = creature_ai_update_target(
                    creature,
                    player_x=player.pos_x,
                    player_y=player.pos_y,
                    creatures=self._entries,
                    dt=dt,
                )
                creature.move_scale = float(ai.move_scale)
                if ai.self_damage is not None and ai.self_damage > 0.0:
                    creature.hp -= float(ai.self_damage)
                    if creature.hp <= 0.0:
                        deaths.append(
                            self.handle_death(
                                idx,
                                state=state,
                                players=players,
                                rand=rand,
                                world_width=world_width,
                                world_height=world_height,
                                fx_queue=fx_queue,
                            )
                        )
                        if creature.active:
                            self._tick_dead(
                                creature,
                                dt=dt,
                                world_width=world_width,
                                world_height=world_height,
                                fx_queue_rotated=fx_queue_rotated,
                            )
                        continue

                if (float(state.bonuses.energizer) > 0.0 and float(creature.max_hp) < 500.0) or creature.collision_flag != 0:
                    creature.target_heading = _wrap_angle(float(creature.target_heading) + math.pi)

                turn_rate = float(creature.move_speed) * CREATURE_TURN_RATE_SCALE
                speed = float(creature.move_speed) * CREATURE_SPEED_SCALE * creature.move_scale

                if (creature.flags & CreatureFlags.ANIM_PING_PONG) == 0:
                    if creature.ai_mode == 7:
                        creature.vel_x = 0.0
                        creature.vel_y = 0.0
                    else:
                        creature.heading = _angle_approach(creature.heading, creature.target_heading, turn_rate, dt)
                        dir_x = math.cos(creature.heading - math.pi / 2.0)
                        dir_y = math.sin(creature.heading - math.pi / 2.0)
                        creature.vel_x = dir_x * speed
                        creature.vel_y = dir_y * speed
                        creature.x = _clamp(creature.x + creature.vel_x * dt, 0.0, float(world_width))
                        creature.y = _clamp(creature.y + creature.vel_y * dt, 0.0, float(world_height))
                else:
                    # Spawner/short-strip creatures clamp to bounds using `size` as a radius; most are stationary
                    # unless ANIM_LONG_STRIP is set (see creature_update_all).
                    radius = max(0.0, float(creature.size))
                    max_x = max(radius, float(world_width) - radius)
                    max_y = max(radius, float(world_height) - radius)
                    creature.x = _clamp(creature.x, radius, max_x)
                    creature.y = _clamp(creature.y, radius, max_y)
                    if (creature.flags & CreatureFlags.ANIM_LONG_STRIP) == 0:
                        creature.vel_x = 0.0
                        creature.vel_y = 0.0
                    else:
                        creature.heading = _angle_approach(creature.heading, creature.target_heading, turn_rate, dt)
                        dir_x = math.cos(creature.heading - math.pi / 2.0)
                        dir_y = math.sin(creature.heading - math.pi / 2.0)
                        creature.vel_x = dir_x * speed
                        creature.vel_y = dir_y * speed
                        creature.x = _clamp(creature.x + creature.vel_x * dt, radius, max_x)
                        creature.y = _clamp(creature.y + creature.vel_y * dt, radius, max_y)

            if (
                players
                and perk_active(players[0], PerkId.PLAGUEBEARER)
                and int(state.plaguebearer_infection_count) < 0x3C
            ):
                self._plaguebearer_spread_infection(idx)

            if float(state.bonuses.energizer) > 0.0 and float(creature.max_hp) < 380.0 and float(player.health) > 0.0:
                eat_dist_sq = _distance_sq(creature.x, creature.y, player.pos_x, player.pos_y)
                if eat_dist_sq < 20.0 * 20.0:
                    creature.x = _clamp(creature.x - creature.vel_x * dt, 0.0, float(world_width))
                    creature.y = _clamp(creature.y - creature.vel_y * dt, 0.0, float(world_height))

                    state.effects.spawn_burst(
                        pos_x=float(creature.x),
                        pos_y=float(creature.y),
                        count=6,
                        rand=rand,
                        detail_preset=int(detail_preset),
                    )
                    sfx.append("sfx_ui_bonus")

                    prev_guard = bool(state.bonus_spawn_guard)
                    state.bonus_spawn_guard = True
                    creature.last_hit_owner_id = -1 - int(player.index)
                    deaths.append(
                        self.handle_death(
                            idx,
                            state=state,
                            players=players,
                            rand=rand,
                            detail_preset=int(detail_preset),
                            world_width=world_width,
                            world_height=world_height,
                            fx_queue=fx_queue,
                            keep_corpse=False,
                        )
                    )
                    state.bonus_spawn_guard = prev_guard
                    continue

            # Contact damage throttle. While Energizer is active, the native suppresses
            # contact/melee interactions for most creatures (and instead allows "eat" kills).
            if float(state.bonuses.energizer) <= 0.0:
                dist_sq = _distance_sq(creature.x, creature.y, player.pos_x, player.pos_y)
                contact_r = (float(creature.size) + float(player.size)) * 0.25 + 20.0
                in_contact = dist_sq <= contact_r * contact_r
                if in_contact:
                    creature.collision_timer -= dt
                    if creature.collision_timer < 0.0:
                        creature.collision_timer += CONTACT_DAMAGE_PERIOD
                        if float(player.shield_timer) <= 0.0:
                            if perk_active(player, PerkId.TOXIC_AVENGER):
                                creature.flags |= (
                                    CreatureFlags.SELF_DAMAGE_TICK | CreatureFlags.SELF_DAMAGE_TICK_STRONG
                                )
                            elif perk_active(player, PerkId.VEINS_OF_POISON):
                                creature.flags |= CreatureFlags.SELF_DAMAGE_TICK
                        player_take_damage(state, player, float(creature.contact_damage), dt=dt, rand=rand)

                if (
                    bool(player.plaguebearer_active)
                    and float(creature.hp) < 150.0
                    and int(state.plaguebearer_infection_count) < 0x32
                    and dist_sq < 30.0 * 30.0
                ):
                    creature.collision_flag = 1

            if (not frozen_by_evil_eyes) and (creature.flags & (CreatureFlags.RANGED_ATTACK_SHOCK | CreatureFlags.RANGED_ATTACK_VARIANT)):
                # Ported from creature_update_all (see `analysis/ghidra/raw/crimsonland.exe_decompiled.c`
                # around the 0x004276xx ranged-fire branch).
                if creature.attack_cooldown <= 0.0:
                    creature.attack_cooldown = 0.0
                else:
                    creature.attack_cooldown -= dt

                dist = math.hypot(creature.x - player.pos_x, creature.y - player.pos_y)
                if dist > 64.0 and creature.attack_cooldown <= 0.0:
                    if creature.flags & CreatureFlags.RANGED_ATTACK_SHOCK:
                        state.projectiles.spawn(
                            pos_x=creature.x,
                            pos_y=creature.y,
                            angle=float(creature.heading),
                            type_id=9,
                            owner_id=idx,
                            base_damage=45.0,
                            hits_players=True,
                        )
                        sfx.append("sfx_shock_fire")
                        creature.attack_cooldown += 1.0

                    if (creature.flags & CreatureFlags.RANGED_ATTACK_VARIANT) and creature.attack_cooldown <= 0.0:
                        projectile_type = int(creature.orbit_radius)
                        state.projectiles.spawn(
                            pos_x=creature.x,
                            pos_y=creature.y,
                            angle=float(creature.heading),
                            type_id=projectile_type,
                            owner_id=idx,
                            base_damage=45.0,
                            hits_players=True,
                        )
                        sfx.append("sfx_plasmaminigun_fire")
                        creature.attack_cooldown = (
                            float(rand() & 3) * 0.1 + float(creature.orbit_angle) + float(creature.attack_cooldown)
                        )

        # Spawn-slot ticking (spawns child templates while owner stays alive).
        if dt > 0.0 and spawn_env is not None and self.spawn_slots:
            for slot in self.spawn_slots:
                owner_idx = int(slot.owner_creature)
                if not (0 <= owner_idx < len(self._entries)):
                    continue
                owner = self._entries[owner_idx]
                if not (owner.active and owner.hp > 0.0):
                    continue
                child_template_id = tick_spawn_slot(slot, dt)
                if child_template_id is None:
                    continue

                plan = build_spawn_plan(
                    int(child_template_id),
                    (owner.x, owner.y),
                    float(owner.heading),
                    state.rng,
                    spawn_env,
                )
                mapping, _ = self.spawn_plan(plan, rand=rand)
                spawned.extend(mapping)

        return CreatureUpdateResult(deaths=tuple(deaths), spawned=tuple(spawned), sfx=tuple(sfx))

    def handle_death(
        self,
        idx: int,
        *,
        state: GameplayState,
        players: list[PlayerState],
        rand: Callable[[], int],
        detail_preset: int = 5,
        world_width: float,
        world_height: float,
        fx_queue: FxQueue | None,
        keep_corpse: bool = True,  # noqa: FBT001, FBT002
    ) -> CreatureDeath:
        """Run one-shot death side effects and return the `CreatureDeath` event."""

        creature = self._entries[int(idx)]
        death = self._start_death(
            int(idx),
            creature,
            state=state,
            players=players,
            rand=rand,
            detail_preset=int(detail_preset),
            world_width=world_width,
            world_height=world_height,
            fx_queue=fx_queue,
        )

        if keep_corpse:
            if creature.hitbox_size == CREATURE_HITBOX_ALIVE:
                creature.hitbox_size = CREATURE_HITBOX_ALIVE - 0.001
        else:
            creature.active = False

        if float(state.bonuses.freeze) > 0.0:
            pos_x = float(creature.x)
            pos_y = float(creature.y)
            for _ in range(8):
                angle = float(int(rand()) % 0x264) * 0.01
                state.effects.spawn_freeze_shard(
                    pos_x=pos_x,
                    pos_y=pos_y,
                    angle=angle,
                    rand=rand,
                    detail_preset=int(detail_preset),
                )
            angle = float(int(rand()) % 0x264) * 0.01
            state.effects.spawn_freeze_shatter(
                pos_x=pos_x,
                pos_y=pos_y,
                angle=angle,
                rand=rand,
                detail_preset=int(detail_preset),
            )
            self.kill_count += 1
            creature.active = False

        return death

    def _apply_init(self, entry: CreatureState, init: CreatureInit) -> None:
        entry.active = True
        entry.type_id = int(init.type_id.value) if init.type_id is not None else 0
        entry.x = float(init.pos_x)
        entry.y = float(init.pos_y)
        entry.heading = float(init.heading)
        entry.target_heading = float(init.heading)
        entry.target_x = float(init.pos_x)
        entry.target_y = float(init.pos_y)
        entry.phase_seed = float(init.phase_seed)

        entry.flags = init.flags or CreatureFlags(0)
        entry.ai_mode = int(init.ai_mode)

        hp = float(init.health or 0.0)
        if hp <= 0.0:
            hp = 1.0
        entry.hp = hp
        entry.max_hp = float(init.max_health or hp)

        entry.move_speed = float(init.move_speed or 1.0)
        entry.reward_value = float(init.reward_value or 0.0)
        entry.size = float(init.size or 50.0)
        entry.contact_damage = float(init.contact_damage or 0.0)

        entry.target_offset_x = init.target_offset_x
        entry.target_offset_y = init.target_offset_y
        entry.orbit_angle = float(init.orbit_angle or 0.0)
        if init.orbit_radius is not None:
            orbit_radius = float(init.orbit_radius)
        elif init.ranged_projectile_type is not None:
            orbit_radius = float(init.ranged_projectile_type)
        else:
            orbit_radius = 0.0
        entry.orbit_radius = orbit_radius

        entry.spawn_slot_index = None
        entry.link_index = 0

        entry.bonus_id = int(init.bonus_id) if init.bonus_id is not None else None
        entry.bonus_duration_override = int(init.bonus_duration_override) if init.bonus_duration_override is not None else None

        tint = resolve_tint(init.tint)
        entry.tint_r = float(tint[0])
        entry.tint_g = float(tint[1])
        entry.tint_b = float(tint[2])
        entry.tint_a = float(tint[3])

        entry.collision_flag = 0
        entry.collision_timer = CONTACT_DAMAGE_PERIOD
        entry.hitbox_size = CREATURE_HITBOX_ALIVE

    def _disable_spawn_slot(self, slot_index: int) -> None:
        if not (0 <= slot_index < len(self.spawn_slots)):
            return
        slot = self.spawn_slots[slot_index]
        slot.owner_creature = -1
        slot.limit = 0

    def _tick_dead(
        self,
        creature: CreatureState,
        *,
        dt: float,
        world_width: float,
        world_height: float,
        fx_queue_rotated: FxQueueRotated | None,
    ) -> None:
        """Advance the post-death hitbox_size ramp and queue corpse decals.

        This matches the `hitbox_size` death staging inside `creature_update_all`:
        - while hitbox_size > 0: decrement quickly and slide backwards
        - once hitbox_size <= 0: queue a corpse decal and fade out until < -10, then deactivate.
        """

        if dt <= 0.0:
            return

        hitbox = float(creature.hitbox_size)
        if hitbox <= 0.0:
            creature.hitbox_size = hitbox - float(dt) * CREATURE_CORPSE_FADE_DECAY
            if creature.hitbox_size < CREATURE_CORPSE_DESPAWN_HITBOX:
                creature.active = False
            return

        long_strip = (creature.flags & CreatureFlags.ANIM_PING_PONG) == 0 or (creature.flags & CreatureFlags.ANIM_LONG_STRIP) != 0

        new_hitbox = hitbox - float(dt) * CREATURE_DEATH_TIMER_DECAY
        creature.hitbox_size = new_hitbox
        if new_hitbox > 0.0:
            if long_strip:
                dir_x = math.cos(creature.heading - math.pi / 2.0)
                dir_y = math.sin(creature.heading - math.pi / 2.0)
                creature.vel_x = dir_x * new_hitbox * float(dt) * CREATURE_DEATH_SLIDE_SCALE
                creature.vel_y = dir_y * new_hitbox * float(dt) * CREATURE_DEATH_SLIDE_SCALE
                creature.x = _clamp(creature.x - creature.vel_x, 0.0, float(world_width))
                creature.y = _clamp(creature.y - creature.vel_y, 0.0, float(world_height))
            else:
                creature.vel_x = 0.0
                creature.vel_y = 0.0
            return

        # hitbox_size just crossed <= 0: bake a persistent corpse decal into the ground.
        if fx_queue_rotated is not None:
            corpse_size = max(1.0, float(creature.size))
            # Native uses a special fallback corpse id for ping-pong strip creatures.
            corpse_type_id = int(creature.type_id) if long_strip else 7
            ok = fx_queue_rotated.add(
                top_left_x=creature.x - corpse_size * 0.5,
                top_left_y=creature.y - corpse_size * 0.5,
                rgba=(creature.tint_r, creature.tint_g, creature.tint_b, creature.tint_a),
                rotation=float(creature.heading),
                scale=corpse_size,
                creature_type_id=corpse_type_id,
            )
            if not ok:
                creature.hitbox_size = 0.001
                return

        self.kill_count += 1

    def _start_death(
        self,
        idx: int,
        creature: CreatureState,
        *,
        state: GameplayState,
        players: list[PlayerState],
        rand: Callable[[], int],
        detail_preset: int = 5,
        world_width: float,
        world_height: float,
        fx_queue: FxQueue | None,
    ) -> CreatureDeath:
        creature.hp = 0.0

        if creature.spawn_slot_index is not None:
            self._disable_spawn_slot(int(creature.spawn_slot_index))

        if (creature.flags & CreatureFlags.SPLIT_ON_DEATH) and float(creature.size) > 35.0:
            for heading_offset in (-math.pi / 2.0, math.pi / 2.0):
                child_idx = self._alloc_slot(rand=rand)
                child = replace(creature)
                child.phase_seed = float(int(rand()) & 0xFF)
                child.heading = _wrap_angle(float(creature.heading) + float(heading_offset))
                child.target_heading = float(child.heading)
                child.hp = float(creature.max_hp) * 0.25
                child.reward_value = float(child.reward_value) * (2.0 / 3.0)
                child.size = float(child.size) - 8.0
                child.move_speed = float(child.move_speed) + 0.1
                child.contact_damage = float(child.contact_damage) * 0.7
                child.hitbox_size = CREATURE_HITBOX_ALIVE
                self._entries[child_idx] = child
                self.spawned_count += 1

            state.effects.spawn_burst(
                pos_x=float(creature.x),
                pos_y=float(creature.y),
                count=8,
                rand=rand,
                detail_preset=int(detail_preset),
            )

        xp_base = int(creature.reward_value)
        killer: PlayerState | None = None
        if players:
            player_index = _owner_id_to_player_index(int(creature.last_hit_owner_id))
            if player_index is None or not (0 <= player_index < len(players)):
                player_index = 0
            killer = players[player_index]

        if killer is not None and perk_active(killer, PerkId.BLOODY_MESS_QUICK_LEARNER):
            xp_base = int(float(creature.reward_value) * 1.3)

        xp_awarded = 0
        if killer is not None:
            xp_awarded = award_experience(state, killer, xp_base)

        if players:
            spawned_bonus = None
            if (creature.flags & CreatureFlags.BONUS_ON_DEATH) and creature.bonus_id is not None:
                spawned_bonus = state.bonus_pool.spawn_at(
                    creature.x,
                    creature.y,
                    int(creature.bonus_id),
                    int(creature.bonus_duration_override) if creature.bonus_duration_override is not None else -1,
                    world_width=world_width,
                    world_height=world_height,
                )
            else:
                spawned_bonus = state.bonus_pool.try_spawn_on_kill(
                    creature.x,
                    creature.y,
                    state=state,
                    players=players,
                    world_width=world_width,
                    world_height=world_height,
                )
            if spawned_bonus is not None:
                state.effects.spawn_burst(
                    pos_x=float(spawned_bonus.pos_x),
                    pos_y=float(spawned_bonus.pos_y),
                    count=16,
                    rand=rand,
                    detail_preset=int(detail_preset),
                )

        if fx_queue is not None:
            fx_queue.add_random(pos_x=creature.x, pos_y=creature.y, rand=rand)

        return CreatureDeath(
            index=int(idx),
            x=float(creature.x),
            y=float(creature.y),
            type_id=int(creature.type_id),
            reward_value=float(creature.reward_value),
            xp_awarded=int(xp_awarded),
        )
