from __future__ import annotations

"""Creature realtime simulation glue.

This module materializes pure spawn plans (`creatures.spawn`) into a fixed-size
runtime pool and advances creatures each frame using the AI helpers.

It is intentionally minimal: the goal is to unblock a playable Survival loop,
not to perfectly match every edge case in `creature_update_all`.
See: `docs/creatures/update.md`.
"""

from dataclasses import dataclass, field, replace
import math
from typing import Callable, Protocol, Sequence

from grim.color import RGBA
from grim.geom import Vec2
from grim.rand import Crand
from ..effects import FxQueue, FxQueueRotated
from ..gameplay import award_experience
from ..math_parity import (
    NATIVE_PI,
    NATIVE_TAU,
    NATIVE_TURN_RATE_SCALE,
    f32,
    f32_vec2,
    heading_add_pi_f32,
    heading_to_direction_f32,
)
from ..perks import PerkId
from ..perks.helpers import perk_active
from ..player_damage import player_take_damage
from ..projectiles import ProjectileTypeId
from ..sim.state_types import GameplayState, PlayerState
from ..weapons import weapon_entry_for_projectile_type_id
from .ai import creature_ai7_tick_link_timer, creature_ai_update_target
from .spawn import (
    CreatureFlags,
    CreatureInit,
    CreatureTypeId,
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
CREATURE_TURN_RATE_SCALE = NATIVE_TURN_RATE_SCALE

# Native uses hitbox_size as a lifecycle sentinel:
# - 16.0 means "alive" (normal AI/movement/anim update)
# - once HP <= 0 it ramps down quickly and drives death slide + corpse decal timing.
# - final deactivation (`hitbox_size < -10.0`) happens during render (creature_render_type),
#   not during creature_update_all.
CREATURE_HITBOX_ALIVE = 16.0
CREATURE_DEATH_TIMER_DECAY = 28.0
CREATURE_CORPSE_FADE_DECAY = 20.0
CREATURE_CORPSE_DESPAWN_HITBOX = -10.0
CREATURE_DEATH_SLIDE_SCALE = 9.0
_TARGET_REEVAL_PERIOD = 0x46

_CREATURE_CONTACT_SFX: dict[CreatureTypeId, tuple[str, str]] = {
    CreatureTypeId.ZOMBIE: ("sfx_zombie_attack_01", "sfx_zombie_attack_02"),
    CreatureTypeId.LIZARD: ("sfx_lizard_attack_01", "sfx_lizard_attack_02"),
    CreatureTypeId.ALIEN: ("sfx_alien_attack_01", "sfx_alien_attack_02"),
    CreatureTypeId.SPIDER_SP1: ("sfx_spider_attack_01", "sfx_spider_attack_02"),
    CreatureTypeId.SPIDER_SP2: ("sfx_spider_attack_01", "sfx_spider_attack_02"),
}


class _EffectsForCreatureSpawns(Protocol):
    def spawn_burst(
        self,
        *,
        pos: Vec2,
        count: int,
        rand: Callable[[], int],
        detail_preset: int,
    ) -> None: ...


def _wrap_angle(angle: float) -> float:
    return f32((f32(angle) + NATIVE_PI) % NATIVE_TAU - NATIVE_PI)


def _angle_approach(current: float, target: float, rate: float, dt: float) -> float:
    # Native parity (`angle_approach`, 0x0041f430):
    # - normalize to [0, 2*pi]
    # - choose shortest arc using direct/wrap distances
    # - advance by `frame_dt * min(1, dist) * rate`
    # - do not re-wrap after the step (next call normalizes again)
    angle = f32(current)
    target = f32(target)
    tau = NATIVE_TAU

    while angle < 0.0:
        angle = f32(angle + tau)
    while angle > tau:
        angle = f32(angle - tau)

    direct = abs(float(target) - float(angle))
    hi = target if angle < target else angle
    lo = target if target < angle else angle
    wrap = abs((float(tau) - float(hi)) + float(lo))

    step_scale = direct if direct < wrap else wrap
    if step_scale > 1.0:
        step_scale = 1.0
    step = float(dt) * float(step_scale) * float(rate)

    if direct <= wrap:
        if angle < target:
            return f32(float(angle) + float(step))
    else:
        if target < angle:
            return f32(float(angle) + float(step))
    return f32(float(angle) - float(step))


def _movement_delta_from_heading_f32(
    heading: float,
    *,
    dt: float,
    move_scale: float,
    move_speed: float,
) -> Vec2:
    direction = heading_to_direction_f32(heading)
    step_scale = float(dt) * float(move_scale) * float(move_speed) * float(CREATURE_SPEED_SCALE)
    return Vec2(f32(float(direction.x) * step_scale), f32(float(direction.y) * step_scale))


def _velocity_from_delta_f32(delta: Vec2, *, dt: float) -> Vec2:
    if dt <= 0.0:
        return Vec2()
    inv_dt = 1.0 / float(dt)
    return Vec2(f32(float(delta.x) * inv_dt), f32(float(delta.y) * inv_dt))


def _advance_pos_by_delta_f32(pos: Vec2, delta: Vec2) -> Vec2:
    return Vec2(
        f32(float(pos.x) + float(delta.x)),
        f32(float(pos.y) + float(delta.y)),
    )


def _owner_id_to_player_index(owner_id: int) -> int | None:
    # Native uses `-1/-2/-3/-4` for player indices and `-100` as a player-owned sentinel.
    if owner_id == -100:
        return 0
    if owner_id < 0:
        return -1 - owner_id
    return None


def _projectile_meta_for_type_id(type_id: int) -> float:
    entry = weapon_entry_for_projectile_type_id(int(type_id))
    meta = entry.projectile_meta if entry is not None else None
    return float(meta if meta is not None else 45.0)


@dataclass(slots=True)
class CreatureState:
    # Core identity/alive flags.
    active: bool = False
    type_id: int = 0

    # Movement / AI.
    pos: Vec2 = field(default_factory=Vec2)
    vel: Vec2 = field(default_factory=Vec2)
    heading: float = 0.0
    target_heading: float = 0.0
    force_target: int = 0
    target: Vec2 = field(default_factory=Vec2)
    target_player: int = 0
    ai_mode: int = 0
    flags: CreatureFlags = CreatureFlags(0)

    # Native `creature_alloc_slot` does not clear `link_index`; many spawn paths
    # leave it untouched (notably survival_spawn_creature AI7 spiders), so stale
    # values can affect early AI7 timer phase.
    link_index: int = -1
    target_offset: Vec2 | None = None
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

    # Plaguebearer infection state (native: `collision_flag` byte).
    plague_infected: bool = False
    collision_timer: float = CONTACT_DAMAGE_PERIOD
    hitbox_size: float = CREATURE_HITBOX_ALIVE

    # Presentation.
    size: float = 50.0
    anim_phase: float = 0.0
    hit_flash_timer: float = 0.0
    last_hit_owner_id: int = -100
    tint: RGBA = field(default_factory=RGBA)

    # Rewrite-only helpers (not in native struct, but derived from spawn plans).
    spawn_slot_index: int | None = None
    bonus_id: int | None = None
    bonus_duration_override: int | None = None


@dataclass(frozen=True, slots=True)
class CreatureDeath:
    index: int
    pos: Vec2
    type_id: int
    reward_value: float
    xp_awarded: int
    owner_id: int


@dataclass(frozen=True, slots=True)
class CreatureUpdateResult:
    deaths: tuple[CreatureDeath, ...] = ()
    spawned: tuple[int, ...] = ()
    sfx: tuple[str, ...] = ()


@dataclass(slots=True)
class _CreatureInteractionCtx:
    pool: CreaturePool
    creature_index: int
    creature: CreatureState
    state: GameplayState
    players: list[PlayerState]
    player: PlayerState
    dt: float
    rand: Callable[[], int]
    detail_preset: int
    world_width: float
    world_height: float
    fx_queue: FxQueue | None
    fx_queue_rotated: FxQueueRotated | None
    deaths: list[CreatureDeath]
    sfx: list[str]
    skip_creature: bool = False
    contact_dist_sq: float = 0.0


_CreatureInteractionStep = Callable[[_CreatureInteractionCtx], None]


def _creature_interaction_plaguebearer_spread(ctx: _CreatureInteractionCtx) -> None:
    if ctx.players and perk_active(ctx.players[0], PerkId.PLAGUEBEARER) and int(ctx.state.plaguebearer_infection_count) < 0x3C:
        ctx.pool._plaguebearer_spread_infection(ctx.creature_index)


def _creature_interaction_energizer_eat(ctx: _CreatureInteractionCtx) -> None:
    creature = ctx.creature
    creature_pos = creature.pos
    eat_dist_sq = Vec2.distance_sq(creature_pos, ctx.player.pos)
    if eat_dist_sq >= 20.0 * 20.0:
        return

    creature.pos = (creature.pos - creature.vel * ctx.dt).clamp_rect(
        0.0,
        0.0,
        float(ctx.world_width),
        float(ctx.world_height),
    )

    # Native reverts the just-applied movement whenever a creature gets within
    # 20 units of the target player, regardless of Energizer.
    if float(ctx.state.bonuses.energizer) <= 0.0:
        return
    if float(creature.max_hp) >= 380.0:
        return

    ctx.state.effects.spawn_burst(
        pos=creature.pos,
        count=6,
        rand=ctx.rand,
        detail_preset=int(ctx.detail_preset),
    )
    ctx.sfx.append("sfx_ui_bonus")

    prev_guard = bool(ctx.state.bonus_spawn_guard)
    ctx.state.bonus_spawn_guard = True
    creature.last_hit_owner_id = -1 - int(ctx.player.index)
    ctx.deaths.append(
        ctx.pool.handle_death(
            ctx.creature_index,
            state=ctx.state,
            players=ctx.players,
            rand=ctx.rand,
            dt=float(ctx.dt),
            detail_preset=int(ctx.detail_preset),
            world_width=float(ctx.world_width),
            world_height=float(ctx.world_height),
            fx_queue=ctx.fx_queue,
            keep_corpse=False,
        )
    )
    ctx.state.bonus_spawn_guard = prev_guard
    ctx.skip_creature = True


def _creature_interaction_contact_damage(ctx: _CreatureInteractionCtx) -> None:
    creature = ctx.creature
    ctx.contact_dist_sq = Vec2.distance_sq(creature.pos, ctx.player.pos)
    if creature.hitbox_size != CREATURE_HITBOX_ALIVE:
        return
    if float(creature.size) <= 16.0:
        return
    if float(ctx.state.bonuses.energizer) > 0.0:
        return

    if ctx.contact_dist_sq >= 30.0 * 30.0:
        return
    if float(ctx.player.health) <= 0.0:
        return
    if float(creature.attack_cooldown) > 0.0:
        return

    # Native contact-damage path consumes one `crt_rand()` draw for attack SFX
    # (creature_type_table[*].sfx_bank_b[rand & 1]) before applying damage.
    try:
        creature_type = CreatureTypeId(int(creature.type_id))
    except ValueError:
        creature_type = None
    if creature_type is not None:
        options = _CREATURE_CONTACT_SFX.get(creature_type)
        if options is not None:
            ctx.sfx.append(options[int(ctx.rand()) & 1])

    mr_melee_killed = False
    mr_melee_death_start_needed = False
    if perk_active(ctx.player, PerkId.MR_MELEE):
        mr_melee_death_start_needed = creature.hp > 0.0 and creature.hitbox_size == CREATURE_HITBOX_ALIVE

        from .damage import creature_apply_damage

        mr_melee_killed = creature_apply_damage(
            creature,
            damage_amount=25.0,
            damage_type=2,
            impulse=Vec2(),
            owner_id=-1 - int(ctx.player.index),
            dt=ctx.dt,
            players=ctx.players,
            rand=ctx.rand,
        )

    if float(ctx.player.shield_timer) <= 0.0:
        if perk_active(ctx.player, PerkId.TOXIC_AVENGER):
            creature.flags |= CreatureFlags.SELF_DAMAGE_TICK | CreatureFlags.SELF_DAMAGE_TICK_STRONG
        elif perk_active(ctx.player, PerkId.VEINS_OF_POISON):
            creature.flags |= CreatureFlags.SELF_DAMAGE_TICK

    player_take_damage(ctx.state, ctx.player, float(creature.contact_damage), dt=ctx.dt, rand=ctx.rand)

    if ctx.fx_queue is not None:
        push_dir = (ctx.player.pos - creature.pos).normalized()
        ctx.fx_queue.add_random(
            pos=ctx.player.pos + push_dir * 3.0,
            rand=ctx.rand,
        )

    creature.attack_cooldown = float(creature.attack_cooldown) + 1.0

    if mr_melee_killed and mr_melee_death_start_needed:
        ctx.deaths.append(
            ctx.pool.handle_death(
                ctx.creature_index,
                state=ctx.state,
                players=ctx.players,
                rand=ctx.rand,
                dt=float(ctx.dt),
                detail_preset=int(ctx.detail_preset),
                world_width=float(ctx.world_width),
                world_height=float(ctx.world_height),
                fx_queue=ctx.fx_queue,
            )
        )
        if creature.active:
            ctx.pool._tick_dead(
                creature,
                dt=ctx.dt,
                world_width=float(ctx.world_width),
                world_height=float(ctx.world_height),
                fx_queue_rotated=ctx.fx_queue_rotated,
            )
        ctx.skip_creature = True


def _creature_interaction_plaguebearer_contact_flag(ctx: _CreatureInteractionCtx) -> None:
    if float(ctx.state.bonuses.energizer) > 0.0:
        return

    creature = ctx.creature
    if bool(ctx.player.plaguebearer_active) and float(creature.hp) < 150.0 and int(ctx.state.plaguebearer_infection_count) < 0x32:
        if ctx.contact_dist_sq < 30.0 * 30.0:
            creature.plague_infected = True


_CREATURE_INTERACTION_STEPS: tuple[_CreatureInteractionStep, ...] = (
    _creature_interaction_plaguebearer_spread,
    _creature_interaction_energizer_eat,
    _creature_interaction_contact_damage,
    _creature_interaction_plaguebearer_contact_flag,
)


class CreaturePool:
    def __init__(
        self,
        *,
        size: int = CREATURE_POOL_SIZE,
        env: SpawnEnv | None = None,
        effects: _EffectsForCreatureSpawns | None = None,
    ) -> None:
        self._entries = [CreatureState() for _ in range(int(size))]
        self.spawn_slots: list[SpawnSlotInit] = []
        self.env = env
        self.effects = effects
        self.kill_count = 0
        self.spawned_count = 0
        self._update_tick = 0

    @property
    def entries(self) -> list[CreatureState]:
        return self._entries

    def reset(self) -> None:
        for i in range(len(self._entries)):
            self._entries[i] = CreatureState()
        self.spawn_slots.clear()
        self.kill_count = 0
        self.spawned_count = 0
        self._update_tick = 0

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

            if Vec2.distance_sq(creature.pos, origin.pos) < 45.0 * 45.0:
                if creature.plague_infected and float(origin.hp) < 150.0:
                    origin.plague_infected = True
                if origin.plague_infected and float(creature.hp) < 150.0:
                    creature.plague_infected = True
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

    def _resolve_target_player_index(self, creature: CreatureState, players: list[PlayerState]) -> int:
        player_count = len(players)
        if player_count <= 1:
            creature.target_player = 0
            return 0

        target_player = int(creature.target_player)
        if not (0 <= target_player < player_count):
            target_player = 0

        # Native 2-player behavior: periodically switch to P2 if alive and closer,
        # and always flip when the current target dies.
        if player_count == 2:
            if (self._update_tick % _TARGET_REEVAL_PERIOD) != 0:
                other = 1 - target_player
                if float(players[other].health) > 0.0:
                    cur_dist_sq = Vec2.distance_sq(creature.pos, players[target_player].pos)
                    other_dist_sq = Vec2.distance_sq(creature.pos, players[other].pos)
                    if other_dist_sq < cur_dist_sq:
                        target_player = other
            if float(players[target_player].health) <= 0.0:
                target_player = 1 - target_player
            creature.target_player = int(target_player)
            return int(target_player)

        # 3/4-player extension: keep deterministic nearest-alive targeting with the
        # same periodic refresh/dead-target refresh policy as native 2-player mode.
        needs_refresh = (self._update_tick % _TARGET_REEVAL_PERIOD) != 0 or float(players[target_player].health) <= 0.0
        if needs_refresh:
            nearest_idx = -1
            nearest_dist_sq = 0.0
            for idx, player in enumerate(players):
                if float(player.health) <= 0.0:
                    continue
                dist_sq = Vec2.distance_sq(creature.pos, player.pos)
                if nearest_idx < 0 or dist_sq < nearest_dist_sq:
                    nearest_idx = int(idx)
                    nearest_dist_sq = float(dist_sq)
            if nearest_idx >= 0:
                target_player = nearest_idx

        creature.target_player = int(target_player)
        return int(target_player)

    def spawn_init(self, init: CreatureInit, *, rand: Callable[[], int] | None = None) -> int:
        """Materialize a single `CreatureInit` into the runtime pool."""

        idx = self._alloc_slot(rand=rand)
        # Reuse the allocated slot so fields that native spawn paths do not touch
        # (e.g. link_index for survival AI7 spiders) retain stale values.
        entry = self._entries[idx]
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
        detail_preset: int = 5,
        effects: _EffectsForCreatureSpawns | None = None,
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
            # Reuse the allocated slot so untouched fields keep native-like stale state.
            entry = self._entries[pool_idx]
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

        effect_pool = self.effects if effects is None else effects
        if effect_pool is not None and plan.effects:
            fx_rand = rand if rand is not None else (lambda: 0)
            for fx in plan.effects:
                effect_pool.spawn_burst(
                    pos=fx.pos,
                    count=int(fx.count),
                    rand=fx_rand,
                    detail_preset=int(detail_preset),
                )
        return mapping, primary_pool

    def spawn_template(
        self,
        template_id: int,
        pos: Vec2,
        heading: float,
        rng: Crand,
        *,
        rand: Callable[[], int] | None = None,
        env: SpawnEnv | None = None,
        detail_preset: int = 5,
        effects: _EffectsForCreatureSpawns | None = None,
    ) -> tuple[list[int], int | None]:
        """Build a spawn plan and materialize it into the pool."""

        spawn_env = env or self.env
        if spawn_env is None:
            raise ValueError("CreaturePool.spawn_template requires SpawnEnv (set CreaturePool.env or pass env=...)")
        plan = build_spawn_plan(template_id, pos, heading, rng, spawn_env)
        return self.spawn_plan(
            plan,
            rand=rng.rand if rand is None else rand,
            detail_preset=int(detail_preset),
            effects=effects,
        )

    def update(
        self,
        dt: float,
        *,
        dt_ms_i32: int | None = None,
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
        self._update_tick = int(self._update_tick) + 1

        evil_target = -1
        if players and perk_active(players[0], PerkId.EVIL_EYES):
            evil_target = int(players[0].evil_eyes_target_creature)

        # Movement + AI. Dead creatures keep updating (death slide + corpse decals)
        # even when `players` is empty so debug views remain deterministic.
        # Native AI7 timer math uses `frame_dt_ms` integer slots; round-to-nearest
        # keeps parity with captured `frame_dt` values such as 0.0329999998 -> 33.
        if dt_ms_i32 is not None:
            dt_ms = max(0, int(dt_ms_i32))
        else:
            dt_ms = int(round(dt * 1000.0)) if dt > 0.0 else 0
        for idx, creature in enumerate(self._entries):
            if not creature.active:
                continue

            if creature.hitbox_size != CREATURE_HITBOX_ALIVE or creature.hp <= 0.0:
                # Native still ticks AI7 link-timer state (and its RNG draws) for
                # dead creatures inside `creature_update_all`.
                if (
                    dt > 0.0
                    and float(state.bonuses.freeze) <= 0.0
                    and (creature.flags & CreatureFlags.AI7_LINK_TIMER)
                ):
                    creature_ai7_tick_link_timer(creature, dt_ms=dt_ms, rand=rand)
                if creature.hitbox_size == CREATURE_HITBOX_ALIVE:
                    creature.hitbox_size = f32(float(creature.hitbox_size) - float(dt))
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

            if float(state.bonuses.freeze) > 0.0:
                creature.move_scale = 0.0
                creature.vel = Vec2()
                continue

            poison_killed = False
            if creature.flags & CreatureFlags.SELF_DAMAGE_TICK_STRONG:
                from .damage import creature_apply_damage

                poison_killed = creature_apply_damage(
                    creature,
                    damage_amount=dt * 180.0,
                    damage_type=0,
                    impulse=Vec2(),
                    owner_id=int(creature.last_hit_owner_id),
                    dt=dt,
                    players=players,
                    rand=rand,
                )
            elif creature.flags & CreatureFlags.SELF_DAMAGE_TICK:
                from .damage import creature_apply_damage

                poison_killed = creature_apply_damage(
                    creature,
                    damage_amount=dt * 60.0,
                    damage_type=0,
                    impulse=Vec2(),
                    owner_id=int(creature.last_hit_owner_id),
                    dt=dt,
                    players=players,
                    rand=rand,
                )
            if poison_killed:
                deaths.append(
                    self.handle_death(
                        idx,
                        state=state,
                        players=players,
                        rand=rand,
                        dt=float(dt),
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

            if creature.plague_infected:
                creature.collision_timer -= float(dt)
                if creature.collision_timer < 0.0:
                    creature.collision_timer += CONTACT_DAMAGE_PERIOD
                    creature.hp -= 15.0
                    if fx_queue is not None:
                        fx_queue.add_random(pos=creature.pos, rand=rand)

                    if creature.hp < 0.0:
                        state.plaguebearer_infection_count += 1
                        deaths.append(
                            self.handle_death(
                                idx,
                                state=state,
                                players=players,
                                rand=rand,
                                dt=float(dt),
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

            target_player = self._resolve_target_player_index(creature, players)
            player = players[target_player]

            if players and perk_active(players[0], PerkId.RADIOACTIVE):
                radioactive_player = players[0]
                dist = (creature.pos - radioactive_player.pos).length()
                if dist < 100.0:
                    creature.collision_timer -= float(dt) * 1.5
                    if creature.collision_timer < 0.0:
                        creature.collision_timer = CONTACT_DAMAGE_PERIOD
                        creature.hp -= (100.0 - dist) * 0.3
                        if fx_queue is not None:
                            fx_queue.add_random(pos=creature.pos, rand=rand)

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
                creature.vel = Vec2()
            else:
                creature_ai7_tick_link_timer(creature, dt_ms=dt_ms, rand=rand)
                ai = creature_ai_update_target(
                    creature,
                    player_pos=player.pos,
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
                                dt=float(dt),
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

                if (float(state.bonuses.energizer) > 0.0 and float(creature.max_hp) < 500.0) or creature.plague_infected:
                    creature.target_heading = heading_add_pi_f32(float(creature.target_heading))

                turn_rate = f32(float(creature.move_speed) * CREATURE_TURN_RATE_SCALE)
                if (creature.flags & CreatureFlags.ANIM_PING_PONG) == 0:
                    if creature.ai_mode == 7:
                        creature.vel = Vec2()
                    else:
                        creature.heading = _angle_approach(creature.heading, creature.target_heading, turn_rate, dt)
                        move_delta = _movement_delta_from_heading_f32(
                            creature.heading,
                            dt=dt,
                            move_scale=creature.move_scale,
                            move_speed=creature.move_speed,
                        )
                        creature.vel = _velocity_from_delta_f32(move_delta, dt=dt)
                        # Native path (flags without 0x4): no bounds clamp here; offscreen spawns
                        # remain offscreen until their own velocity moves them in.
                        creature.pos = _advance_pos_by_delta_f32(creature.pos, move_delta)
                else:
                    # Spawner/short-strip creatures clamp to bounds using `size` as a radius; most are stationary
                    # unless ANIM_LONG_STRIP is set (see creature_update_all).
                    radius = max(0.0, float(creature.size))
                    max_x = max(radius, float(world_width) - radius)
                    max_y = max(radius, float(world_height) - radius)
                    creature.pos = f32_vec2(creature.pos.clamp_rect(radius, radius, max_x, max_y))
                    if (creature.flags & CreatureFlags.ANIM_LONG_STRIP) == 0:
                        creature.vel = Vec2()
                    else:
                        creature.heading = _angle_approach(creature.heading, creature.target_heading, turn_rate, dt)
                        move_delta = _movement_delta_from_heading_f32(
                            creature.heading,
                            dt=dt,
                            move_scale=creature.move_scale,
                            move_speed=creature.move_speed,
                        )
                        creature.vel = _velocity_from_delta_f32(move_delta, dt=dt)
                        creature.pos = f32_vec2(
                            _advance_pos_by_delta_f32(creature.pos, move_delta).clamp_rect(radius, radius, max_x, max_y)
                        )

            # Native decrements contact/ranged cooldown before interaction checks,
            # then lets contact hits raise it back by +1.0 in the same frame.
            if creature.attack_cooldown <= 0.0:
                creature.attack_cooldown = 0.0
            else:
                creature.attack_cooldown -= dt

            interaction_ctx = _CreatureInteractionCtx(
                pool=self,
                creature_index=int(idx),
                creature=creature,
                state=state,
                players=players,
                player=player,
                dt=dt,
                rand=rand,
                detail_preset=int(detail_preset),
                world_width=float(world_width),
                world_height=float(world_height),
                fx_queue=fx_queue,
                fx_queue_rotated=fx_queue_rotated,
                deaths=deaths,
                sfx=sfx,
            )
            for step in _CREATURE_INTERACTION_STEPS:
                step(interaction_ctx)
                if interaction_ctx.skip_creature:
                    break
            if interaction_ctx.skip_creature:
                continue

            if (not frozen_by_evil_eyes) and (creature.flags & (CreatureFlags.RANGED_ATTACK_SHOCK | CreatureFlags.RANGED_ATTACK_VARIANT)):
                # Ported from creature_update_all (see `analysis/ghidra/raw/crimsonland.exe_decompiled.c`
                # around the 0x004276xx ranged-fire branch).
                dist = (creature.pos - player.pos).length()
                if dist > 64.0 and creature.attack_cooldown <= 0.0:
                    if creature.flags & CreatureFlags.RANGED_ATTACK_SHOCK:
                        type_id = int(ProjectileTypeId.PLASMA_RIFLE)
                        state.projectiles.spawn(
                            pos=creature.pos,
                            angle=float(creature.heading),
                            type_id=type_id,
                            owner_id=idx,
                            base_damage=_projectile_meta_for_type_id(type_id),
                            hits_players=True,
                        )
                        sfx.append("sfx_shock_fire")
                        creature.attack_cooldown += 1.0

                    if (creature.flags & CreatureFlags.RANGED_ATTACK_VARIANT) and creature.attack_cooldown <= 0.0:
                        projectile_type = int(creature.orbit_radius)
                        state.projectiles.spawn(
                            pos=creature.pos,
                            angle=float(creature.heading),
                            type_id=projectile_type,
                            owner_id=idx,
                            base_damage=_projectile_meta_for_type_id(projectile_type),
                            hits_players=True,
                        )
                        sfx.append("sfx_plasmaminigun_fire")
                        creature.attack_cooldown = (
                            float(rand() & 3) * 0.1 + float(creature.orbit_angle) + float(creature.attack_cooldown)
                        )

        # Spawn-slot ticking (spawns child templates while owner stays alive).
        if dt > 0.0 and float(state.bonuses.freeze) <= 0.0 and spawn_env is not None and self.spawn_slots:
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
                    owner.pos,
                    float(owner.heading),
                    state.rng,
                    spawn_env,
                )
                mapping, _ = self.spawn_plan(
                    plan,
                    rand=rand,
                    detail_preset=int(detail_preset),
                )
                spawned.extend(mapping)

        return CreatureUpdateResult(deaths=tuple(deaths), spawned=tuple(spawned), sfx=tuple(sfx))

    def handle_death(
        self,
        idx: int,
        *,
        state: GameplayState,
        players: list[PlayerState],
        rand: Callable[[], int],
        dt: float = 0.0,
        detail_preset: int = 5,
        world_width: float,
        world_height: float,
        fx_queue: FxQueue | None,
        keep_corpse: bool = True,  # noqa: FBT001, FBT002
    ) -> CreatureDeath:
        """Run one-shot death side effects and return the `CreatureDeath` event."""

        creature = self._entries[int(idx)]
        if not bool(creature.active):
            # Native `creature_handle_death` gates its XP/bonus/freeze body under
            # `if (active != 0)`. Re-entrant callers (notably secondary
            # detonation follow-up) can invoke death handling after the first call
            # has already deactivated the creature.
            return CreatureDeath(
                index=int(idx),
                pos=creature.pos,
                type_id=int(creature.type_id),
                reward_value=float(creature.reward_value),
                xp_awarded=0,
                owner_id=int(creature.last_hit_owner_id),
            )
        death = self._start_death(
            int(idx),
            creature,
            state=state,
            players=players,
            rand=rand,
            detail_preset=int(detail_preset),
            world_width=world_width,
            world_height=world_height,
        )

        if keep_corpse:
            # Native `creature_handle_death` always decrements hitbox_size by
            # frame_dt for corpse-keeping deaths, independent of current value.
            creature.hitbox_size = float(creature.hitbox_size) - float(dt)
        else:
            creature.active = False

        if float(state.bonuses.freeze) > 0.0:
            creature_pos = creature.pos
            for _ in range(8):
                angle = float(int(rand()) % 0x264) * 0.01
                state.effects.spawn_freeze_shard(
                    pos=creature_pos,
                    angle=angle,
                    rand=rand,
                    detail_preset=int(detail_preset),
                )
            angle = float(int(rand()) % 0x264) * 0.01
            state.effects.spawn_freeze_shatter(
                pos=creature_pos,
                angle=angle,
                rand=rand,
                detail_preset=int(detail_preset),
            )
            if fx_queue is not None:
                fx_queue.add_random(pos=creature_pos, rand=rand)
            self.kill_count += 1
            creature.active = False

        return death

    def _apply_init(self, entry: CreatureState, init: CreatureInit) -> None:
        entry.active = True
        entry.type_id = int(init.type_id.value) if init.type_id is not None else 0
        entry.pos = init.pos
        entry.heading = float(init.heading)
        entry.target_heading = float(init.heading)
        entry.target = init.pos
        entry.phase_seed = float(init.phase_seed)
        # Native spawn paths zero velocity and a few per-frame state fields on every
        # allocation (`creature_spawn`, `survival_spawn_creature`, `creature_spawn_template`).
        entry.vel = Vec2()
        entry.force_target = 0

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

        entry.target_offset = init.target_offset
        entry.orbit_angle = float(init.orbit_angle or 0.0)
        if init.orbit_radius is not None:
            orbit_radius = float(init.orbit_radius)
        elif init.ranged_projectile_type is not None:
            orbit_radius = float(init.ranged_projectile_type)
        else:
            orbit_radius = 0.0
        entry.orbit_radius = orbit_radius

        entry.spawn_slot_index = None
        entry.attack_cooldown = 0.0

        entry.bonus_id = int(init.bonus_id) if init.bonus_id is not None else None
        entry.bonus_duration_override = int(init.bonus_duration_override) if init.bonus_duration_override is not None else None

        entry.tint = RGBA.from_rgba(resolve_tint(init.tint))

        entry.plague_infected = False
        entry.collision_timer = 0.0
        entry.hitbox_size = CREATURE_HITBOX_ALIVE
        entry.hit_flash_timer = 0.0
        entry.anim_phase = 0.0
        entry.last_hit_owner_id = -100

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

        hitbox = f32(float(creature.hitbox_size))
        if hitbox <= 0.0:
            creature.hitbox_size = f32(hitbox - f32(float(dt) * CREATURE_CORPSE_FADE_DECAY))
            return

        long_strip = (creature.flags & CreatureFlags.ANIM_PING_PONG) == 0 or (creature.flags & CreatureFlags.ANIM_LONG_STRIP) != 0

        new_hitbox = f32(hitbox - f32(float(dt) * CREATURE_DEATH_TIMER_DECAY))
        creature.hitbox_size = f32(new_hitbox)
        if new_hitbox > 0.0:
            if long_strip:
                slide = f32(new_hitbox * f32(float(dt)) * f32(CREATURE_DEATH_SLIDE_SCALE))
                direction = heading_to_direction_f32(float(creature.heading))
                creature.vel = Vec2(
                    f32(float(direction.x) * float(slide)),
                    f32(float(direction.y) * float(slide)),
                )
                creature.pos = Vec2(
                    f32(float(creature.pos.x) - float(creature.vel.x)),
                    f32(float(creature.pos.y) - float(creature.vel.y)),
                )
            else:
                creature.vel = Vec2()
            return

        # hitbox_size just crossed <= 0: bake a persistent corpse decal into the ground.
        if fx_queue_rotated is not None:
            corpse_size = max(1.0, float(creature.size))
            # Native uses a special fallback corpse id for ping-pong strip creatures.
            corpse_type_id = int(creature.type_id) if long_strip else 7
            ok = fx_queue_rotated.add(
                top_left=Vec2(creature.pos.x - corpse_size * 0.5, creature.pos.y - corpse_size * 0.5),
                rgba=creature.tint,
                rotation=float(creature.heading),
                scale=corpse_size,
                creature_type_id=corpse_type_id,
            )
            if not ok:
                creature.hitbox_size = 0.001
                return

        self.kill_count += 1

    def finalize_post_render_lifecycle(self) -> None:
        """Mirror render-time corpse culling from native `creature_render_type`.

        Native deactivates entries only after draw once `hitbox_size < -10.0`. Keeping
        this outside `creature_update_all` preserves slot-allocation timing for same-tick
        survival/rush spawns.
        """

        for creature in self._entries:
            if not creature.active:
                continue
            if float(creature.hitbox_size) >= CREATURE_CORPSE_DESPAWN_HITBOX:
                continue
            if creature.spawn_slot_index is not None:
                self._disable_spawn_slot(int(creature.spawn_slot_index))
            creature.active = False

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
    ) -> CreatureDeath:
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
                pos=creature.pos,
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
                    pos=creature.pos,
                    bonus_id=int(creature.bonus_id),
                    duration_override=int(creature.bonus_duration_override) if creature.bonus_duration_override is not None else -1,
                    state=state,
                    world_width=world_width,
                    world_height=world_height,
                )
            else:
                spawned_bonus = state.bonus_pool.try_spawn_on_kill(
                    pos=creature.pos,
                    state=state,
                    players=players,
                    world_width=world_width,
                    world_height=world_height,
                )
            if spawned_bonus is not None:
                state.effects.spawn_burst(
                    pos=spawned_bonus.pos,
                    count=16,
                    rand=rand,
                    detail_preset=int(detail_preset),
                )

        return CreatureDeath(
            index=int(idx),
            pos=creature.pos,
            type_id=int(creature.type_id),
            reward_value=float(creature.reward_value),
            xp_awarded=int(xp_awarded),
            owner_id=int(creature.last_hit_owner_id),
        )
