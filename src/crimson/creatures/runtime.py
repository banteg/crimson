from __future__ import annotations

"""Creature realtime simulation glue.

This module materializes pure spawn plans (`creatures.spawn`) into a fixed-size
runtime pool and advances creatures each frame using the AI helpers.

It is intentionally minimal: the goal is to unblock a playable Survival loop,
not to perfectly match every edge case in `creature_update_all`.
See: `docs/creatures/update.md`.
"""

import math
from collections.abc import Callable, Sequence

import msgspec

from grim.color import RGBA
from grim.geom import Vec2
from grim.rand import Crand, CrandLike
from grim.sfx_map import SfxId

from ..bonuses import BonusId
from ..bonuses.pool import BONUS_SPAWN_MARGIN
from ..effects import EffectPool, FxQueue, FxQueueRotated
from ..gameplay import (
    _award_experience_once_from_reward,
    award_experience,
    award_experience_from_reward,
    survival_record_recent_death,
)
from ..math_parity import (
    NATIVE_HALF_PI,
    NATIVE_PI,
    NATIVE_TAU,
    NATIVE_TURN_RATE_SCALE,
    f32,
    f32_vec2,
    heading_add_pi_f32,
    heading_to_direction_f32,
)
from ..owner_ref import OwnerRef
from ..perks import PerkId
from ..perks.helpers import perk_active
from ..player_damage import PlayerDeathRuntime, player_take_damage
from ..projectiles.types import ProjectileTemplateId
from ..rng_caller_static import RngCallerStatic
from ..sim.state_types import GameplayState, PlayerState
from ..sim.timing import ftol_ms_i32
from ..weapons import weapon_entry_for_projectile_type_id
from .ai import creature_ai7_tick_link_timer, creature_ai_update_target
from .damage_runtime import CreatureDamageRuntime
from .damage_types import CreatureDamageType
from .lifecycle import (
    CREATURE_LIFECYCLE_ALIVE,
    CreatureLifecyclePhase,
    classify_creature_lifecycle,
    creature_lifecycle_is_alive,
)
from .spawn import (
    HAS_SPAWN_SLOT_FLAG,
    RANDOM_HEADING_SENTINEL,
    CreatureAiMode,
    CreatureFlags,
    CreatureInit,
    CreatureTypeId,
    SpawnEnv,
    SpawnId,
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
    "CreatureUpdateOptions",
    "CreatureUpdateResult",
]


CREATURE_POOL_SIZE = 0x180

CONTACT_DAMAGE_PERIOD = 0.5

# Native movement path multiplies by a fixed `30.0` factor in `creature_update_all`.
CREATURE_SPEED_SCALE = 30.0

# Base heading turn rate multiplier (angle_approach clamps by frame_dt internally).
CREATURE_TURN_RATE_SCALE = NATIVE_TURN_RATE_SCALE

# Native uses lifecycle_stage as a lifecycle sentinel:
# - 16.0 means "alive" (normal AI/movement/anim update)
# - once HP <= 0 it ramps down quickly and drives death slide + corpse decal timing.
# - final deactivation (`lifecycle_stage < -10.0`) happens during render (creature_render_type),
#   not during creature_update_all.
CREATURE_DEATH_TIMER_DECAY = 28.0
CREATURE_CORPSE_FADE_DECAY = 20.0
CREATURE_DEATH_SLIDE_SCALE = 9.0
_TARGET_REEVAL_PERIOD = 0x46
_FLAG_SELF_DAMAGE_TICK = int(CreatureFlags.SELF_DAMAGE_TICK)
_FLAG_SELF_DAMAGE_TICK_STRONG = int(CreatureFlags.SELF_DAMAGE_TICK_STRONG)
_FLAG_AI7_LINK_TIMER = int(CreatureFlags.AI7_LINK_TIMER)

_CREATURE_CONTACT_SFX: dict[CreatureTypeId, tuple[SfxId, SfxId]] = {
    CreatureTypeId.ZOMBIE: (SfxId.ZOMBIE_ATTACK_01, SfxId.ZOMBIE_ATTACK_02),
    CreatureTypeId.LIZARD: (SfxId.LIZARD_ATTACK_01, SfxId.LIZARD_ATTACK_02),
    CreatureTypeId.ALIEN: (SfxId.ALIEN_ATTACK_01, SfxId.ALIEN_ATTACK_02),
    CreatureTypeId.SPIDER_SP1: (SfxId.SPIDER_ATTACK_01, SfxId.SPIDER_ATTACK_02),
    CreatureTypeId.SPIDER_SP2: (SfxId.SPIDER_ATTACK_01, SfxId.SPIDER_ATTACK_02),
}


def _wrap_angle(angle: float) -> float:
    return f32((f32(angle) + NATIVE_PI) % NATIVE_TAU - NATIVE_PI)


def _angle_approach(current: float, target: float, rate: float, dt: float) -> float:
    """Native `angle_approach` (0x0041f430).

    Keep this close to the decompile:
    - wrap angle into [0, 2pi]
    - choose direct-vs-wrapped arc
    - clamp arc scale to <= 1.0
    - step by `frame_dt * arc_scale * rate`
    """

    # Native keeps these values in float locals (`fVar*`) across the function.
    # Preserve that spill behavior to avoid branch flips near the `tau` boundary.
    angle = float(f32(current))
    target_f = float(f32(target))
    rate_f = float(f32(rate))
    dt_f = float(f32(dt))
    tau = float(NATIVE_TAU)

    while angle < 0.0:
        angle = float(f32(angle + tau))
    while tau < angle:
        angle = float(f32(angle - tau))

    direct = float(f32(abs(float(f32(target_f - angle)))))

    hi = angle
    if angle < target_f:
        hi = target_f
    lo = angle
    if target_f < angle:
        lo = target_f
    wrapped = float(f32(abs(float(f32(float(f32(tau - hi)) + lo)))))

    step_scale = wrapped
    if direct < wrapped:
        step_scale = direct
    if 1.0 < step_scale:
        step_scale = 1.0
    step_scale = float(f32(step_scale))

    step_delta = float(f32(float(f32(dt_f * step_scale)) * rate_f))

    if direct <= wrapped:
        if angle < target_f:
            return float(f32(angle + step_delta))
    else:
        if target_f < angle:
            return float(f32(angle + step_delta))
    return float(f32(angle - step_delta))


def _movement_delta_from_heading_f32(
    heading: float,
    *,
    dt: float,
    move_scale: float,
    move_speed: float,
) -> Vec2:
    # Native movement path computes cos/sin in x87 precision and rounds only on the
    # final velocity write (`creature_update_all` around 0x00426b85..0x00426bb1).
    # Avoid pre-rounding direction components to float32 here.
    radians = float(f32(heading)) - NATIVE_HALF_PI

    # Preserve native multiply order:
    # `vel = trig(heading - half_pi) * frame_dt * move_scale * move_speed * 30.0`
    vx = math.cos(radians)
    vx *= float(dt)
    vx *= float(move_scale)
    vx *= float(move_speed)
    vx *= float(CREATURE_SPEED_SCALE)

    vy = math.sin(radians)
    vy *= float(dt)
    vy *= float(move_scale)
    vy *= float(move_speed)
    vy *= float(CREATURE_SPEED_SCALE)

    return Vec2(f32(vx), f32(vy))


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


def _owner_to_player_index(owner: OwnerRef) -> int | None:
    return owner.player_index()


def _travel_budget_for_type_id(type_id: ProjectileTemplateId) -> float:
    return float(weapon_entry_for_projectile_type_id(type_id).travel_budget)


class CreatureState(msgspec.Struct):
    # Core identity/alive flags.
    active: bool = False
    type_id: CreatureTypeId = CreatureTypeId.ZOMBIE

    # Movement / AI.
    pos: Vec2 = Vec2()
    vel: Vec2 = Vec2()
    heading: float = 0.0
    target_heading: float = 0.0
    force_target: int = 0
    target: Vec2 = Vec2()
    target_player: int = 0
    ai_mode: CreatureAiMode = CreatureAiMode.ORBIT_PLAYER
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
    lifecycle_stage: float = CREATURE_LIFECYCLE_ALIVE

    # Presentation.
    size: float = 50.0
    anim_phase: float = 0.0
    hit_flash_timer: float = 0.0
    last_hit_owner: OwnerRef = msgspec.field(default_factory=lambda: OwnerRef.from_local_player(0))
    tint: RGBA = msgspec.field(default_factory=RGBA)

    # Rewrite-only helpers (not in native struct, but derived from spawn plans).
    spawn_slot_index: int | None = None
    bonus_id: BonusId | None = None
    bonus_duration_override: int | None = None


class CreatureDeath(msgspec.Struct, frozen=True):
    index: int
    pos: Vec2
    type_id: CreatureTypeId
    reward_value: float
    xp_awarded: int
    owner: OwnerRef


class CreatureUpdateResult(msgspec.Struct, frozen=True):
    deaths: tuple[CreatureDeath, ...] = ()
    spawned: tuple[int, ...] = ()
    sfx: tuple[SfxId, ...] = ()


class CreatureUpdateOptions(msgspec.Struct, frozen=True):
    state: GameplayState
    players: list[PlayerState]
    rng: CrandLike
    env: SpawnEnv
    world_width: float
    world_height: float
    fx_queue: FxQueue
    fx_queue_rotated: FxQueueRotated
    detail_preset: int = 5
    violence_disabled: int = 0


class _CreatureInteractionCtx(msgspec.Struct):
    pool: CreaturePool
    creature_index: int
    creature: CreatureState
    state: GameplayState
    players: list[PlayerState]
    player: PlayerState
    dt: float
    rng: CrandLike
    detail_preset: int
    violence_disabled: int
    world_width: float
    world_height: float
    fx_queue: FxQueue | None
    fx_queue_rotated: FxQueueRotated | None
    deaths: list[CreatureDeath]
    sfx: list[SfxId]
    skip_creature: bool = False
    contact_dist_sq: float = 0.0


class _CreatureInteractionPlayerDeathRuntime(PlayerDeathRuntime):
    ctx: _CreatureInteractionCtx

    def on_player_lethal(self, player: PlayerState, *, dt: float) -> None:
        _ = player
        from ..perks.impl.final_revenge import apply_final_revenge_on_player_death

        ctx = self.ctx
        apply_final_revenge_on_player_death(
            state=ctx.state,
            creatures=ctx.pool,
            players=ctx.players,
            player=ctx.player,
            dt=float(dt),
            world_size=float(max(float(ctx.world_width), float(ctx.world_height))),
            detail_preset=int(ctx.detail_preset),
            fx_queue=ctx.fx_queue,
            deaths=ctx.deaths,
            )


class _CreatureInteractionCreatureDamageRuntime(CreatureDamageRuntime):
    ctx: _CreatureInteractionCtx

    def on_creature_lethal(
        self,
        creature_index: int,
        resolve_death_sfx: Callable[[], tuple[SfxId, ...]],
    ) -> None:
        ctx = self.ctx
        creature = ctx.creature
        ctx.deaths.append(
            ctx.pool.handle_death(
                int(creature_index),
                state=ctx.state,
                players=ctx.players,
                rng=ctx.rng,
                dt=float(ctx.dt),
                detail_preset=int(ctx.detail_preset),
                world_width=float(ctx.world_width),
                world_height=float(ctx.world_height),
                fx_queue=ctx.fx_queue,
            ),
        )
        ctx.sfx.extend(resolve_death_sfx())
        if creature.active:
            ctx.pool._tick_dead(
                creature,
                dt=ctx.dt,
                world_width=float(ctx.world_width),
                world_height=float(ctx.world_height),
                fx_queue_rotated=ctx.fx_queue_rotated,
                rng=ctx.rng,
                detail_preset=int(ctx.detail_preset),
                violence_disabled=int(ctx.violence_disabled),
            )


_CreatureInteractionStep = Callable[[_CreatureInteractionCtx], None]


class _CreaturePoolCreatureDamageRuntime(CreatureDamageRuntime):
    pool: CreaturePool
    state: GameplayState
    players: list[PlayerState]
    rng: CrandLike
    dt: float
    detail_preset: int
    world_width: float
    world_height: float
    fx_queue: FxQueue | None
    deaths: list[CreatureDeath]
    sfx: list[SfxId]

    def on_creature_lethal(
        self,
        creature_index: int,
        resolve_death_sfx: Callable[[], tuple[SfxId, ...]],
    ) -> None:
        self.deaths.append(
            self.pool.handle_death(
                int(creature_index),
                state=self.state,
                players=self.players,
                rng=self.rng,
                dt=float(self.dt),
                detail_preset=int(self.detail_preset),
                world_width=float(self.world_width),
                world_height=float(self.world_height),
                fx_queue=self.fx_queue,
            ),
        )
        self.sfx.extend(resolve_death_sfx())


def _creature_interaction_plaguebearer_spread(ctx: _CreatureInteractionCtx) -> None:
    if (
        ctx.players
        and perk_active(ctx.players[0], PerkId.PLAGUEBEARER)
        and int(ctx.state.plaguebearer_infection_count) < 0x3C
    ):
        ctx.pool._plaguebearer_spread_infection(ctx.creature_index)


def _creature_interaction_energizer_eat(ctx: _CreatureInteractionCtx) -> None:
    creature = ctx.creature
    # Decompile parity (`creature_update_all`, 0x00426220): reuse the same
    # creature->target-player distance scalar for eat/contact branches.
    if ctx.contact_dist_sq >= 20.0 * 20.0:
        return

    # Native stores `vel` as per-tick delta (not per-second). It applies movement
    # as `pos += vel`, so reverting the just-applied movement subtracts `vel`
    # with no bounds clamp.
    creature.pos = creature.pos - creature.vel

    # Native reverts the just-applied movement whenever a creature gets within
    # 20 units of the target player, regardless of Energizer.
    if float(ctx.state.bonuses.energizer) <= 0.0:
        return
    if float(creature.max_hp) >= 380.0:
        return

    # Native double-pays the eat kill: a direct `exp += reward` store here,
    # plus creature_handle_death's own award below.
    if ctx.players:
        _award_experience_once_from_reward(ctx.players[0], float(creature.reward_value))

    ctx.state.effects.spawn_burst(
        pos=creature.pos,
        count=6,
        rng=ctx.rng,
        detail_preset=int(ctx.detail_preset),
    )
    ctx.sfx.append(SfxId.UI_BONUS)

    prev_guard = bool(ctx.state.bonus_spawn_guard)
    ctx.state.bonus_spawn_guard = True
    creature.last_hit_owner = OwnerRef.from_player(int(ctx.player.index))
    ctx.deaths.append(
        ctx.pool.handle_death(
            ctx.creature_index,
            state=ctx.state,
            players=ctx.players,
            rng=ctx.rng,
            dt=float(ctx.dt),
            detail_preset=int(ctx.detail_preset),
            world_width=float(ctx.world_width),
            world_height=float(ctx.world_height),
            fx_queue=ctx.fx_queue,
            keep_corpse=False,
        ),
    )
    ctx.state.bonus_spawn_guard = prev_guard
    ctx.skip_creature = True


def _creature_interaction_contact_damage(ctx: _CreatureInteractionCtx) -> None:
    # Native has no aliveness re-check here: a creature plague-killed earlier
    # in the same tick can still bite (the alive branch was chosen at tick
    # start), drawing the attack-SFX rand and damaging the player.
    creature = ctx.creature
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
    options = _CREATURE_CONTACT_SFX.get(creature.type_id)
    if options is not None:
        ctx.sfx.append(options[ctx.rng.rand_tagged(RngCallerStatic.CREATURE_UPDATE_ALL_CONTACT_SFX) & 1])

    mr_melee_killed = False
    if perk_active(ctx.player, PerkId.MR_MELEE):
        from .damage import creature_apply_damage_with_lethal_followup

        mr_melee_killed = creature_apply_damage_with_lethal_followup(
            creature,
            creature_index=int(ctx.creature_index),
            damage_amount=25.0,
            damage_type=CreatureDamageType.MELEE,
            impulse=Vec2(),
            owner=OwnerRef.from_player(int(ctx.player.index)),
            dt=ctx.dt,
            players=ctx.players,
            rng=ctx.rng,
            preserve_bugs=bool(ctx.state.preserve_bugs),
            effects=ctx.state.effects,
            detail_preset=int(ctx.detail_preset),
            creature_damage_runtime=_CreatureInteractionCreatureDamageRuntime(ctx=ctx),
        )

    if float(ctx.player.shield_timer) <= 0.0:
        if perk_active(ctx.player, PerkId.TOXIC_AVENGER):
            creature.flags |= CreatureFlags.SELF_DAMAGE_TICK | CreatureFlags.SELF_DAMAGE_TICK_STRONG
        elif perk_active(ctx.player, PerkId.VEINS_OF_POISON):
            creature.flags |= CreatureFlags.SELF_DAMAGE_TICK

    player_take_damage(
        ctx.state,
        ctx.player,
        float(creature.contact_damage),
        dt=ctx.dt,
        players=ctx.players,
        death_runtime=_CreatureInteractionPlayerDeathRuntime(ctx=ctx),
    )

    if ctx.fx_queue is not None:
        push_dir = (ctx.player.pos - creature.pos).normalized()
        ctx.fx_queue.add_random(
            pos=ctx.player.pos + push_dir * 3.0,
            rng=ctx.rng,
        )

    creature.attack_cooldown = float(creature.attack_cooldown) + 1.0

    if mr_melee_killed:
        ctx.skip_creature = True


def _creature_interaction_plaguebearer_contact_flag(ctx: _CreatureInteractionCtx) -> None:
    # Native nests this inside the contact gates: size > 16, distance < 30,
    # target player alive, and no Energizer.
    creature = ctx.creature
    if float(creature.size) <= 16.0:
        return
    if ctx.contact_dist_sq >= 30.0 * 30.0:
        return
    if float(ctx.player.health) <= 0.0:
        return
    if float(ctx.state.bonuses.energizer) > 0.0:
        return

    if (
        bool(ctx.player.plaguebearer_active)
        and float(creature.hp) < 150.0
        and int(ctx.state.plaguebearer_infection_count) < 0x32
    ):
        creature.plague_infected = True


def _creature_interaction_contact_kill_small(ctx: _CreatureInteractionCtx) -> None:
    """Kill small creatures that make contact, matching native `creature_update_all`.

    Native logic (see decompile around 0x004276d6) sets `health = 0.0` and
    decrements lifecycle_stage by frame_dt whenever:
    - distance to the target player is < 30.0, and
    - creature `size` is <= 30.0.

    This path does not call `creature_handle_death`, so it intentionally skips XP
    awards + bonus spawns. The corpse staging still increments kill_count later.
    """

    creature = ctx.creature
    if not creature_lifecycle_is_alive(creature.lifecycle_stage):
        return
    if ctx.contact_dist_sq >= 30.0 * 30.0:
        return
    if float(creature.size) > 30.0:
        return

    creature.hp = 0.0
    creature.lifecycle_stage = f32(float(creature.lifecycle_stage) - float(ctx.dt))
    ctx.skip_creature = True


_CREATURE_INTERACTION_STEPS: tuple[_CreatureInteractionStep, ...] = (
    _creature_interaction_energizer_eat,
    _creature_interaction_contact_damage,
    _creature_interaction_plaguebearer_contact_flag,
    _creature_interaction_contact_kill_small,
)


class CreaturePool:
    def __init__(
        self,
        *,
        size: int = CREATURE_POOL_SIZE,
        env: SpawnEnv | None = None,
        effects: EffectPool | None = None,
    ) -> None:
        self._entries: list[CreatureState] = [CreatureState() for _ in range(int(size))]
        self.spawn_slots: list[SpawnSlotInit] = []
        self.env = env
        self.effects = effects
        self.capture_spawn_events_authoritative = False
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

        for creature in self._entries:
            if not creature.active:
                continue

            if Vec2.distance_sq(creature.pos, origin.pos) < 45.0 * 45.0:
                if creature.plague_infected and float(origin.hp) < 150.0:
                    origin.plague_infected = True
                if origin.plague_infected and float(creature.hp) < 150.0:
                    creature.plague_infected = True
                return

    def _alloc_slot(self) -> int | None:
        for i, entry in enumerate(self._entries):
            if not entry.active:
                return i
        return None

    def _free_slot_count(self) -> int:
        return sum(1 for entry in self._entries if not entry.active)

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

    def _update_player_auto_target(
        self,
        *,
        players: list[PlayerState],
        preserve_bugs: bool,
        player_index: int,
        creature_index: int,
        creature: CreatureState,
    ) -> None:
        if not (0 <= int(player_index) < len(players)):
            return
        player = players[int(player_index)]
        if float(player.health) <= 0.0:
            return

        auto_target = int(player.auto_target)
        if not (0 <= auto_target < len(self._entries)):
            player.auto_target = int(creature_index)
            return

        current = self._entries[int(auto_target)]
        if not current.active or float(current.hp) <= 0.0:
            player.auto_target = int(creature_index)
            return

        dist_new = Vec2.distance_sq(player.pos, creature.pos)
        current_origin = player.pos
        if preserve_bugs and int(player_index) != 0 and players:
            # Native compares player 2 auto-target replacement against player 1's
            # coordinates here, which can block closer replacements for player 2.
            current_origin = players[0].pos
        dist_current = Vec2.distance_sq(current_origin, current.pos)
        if float(dist_new) < float(dist_current):
            player.auto_target = int(creature_index)

    def spawn_init(
        self,
        init: CreatureInit,
    ) -> int | None:
        """Materialize a single `CreatureInit` into the runtime pool."""

        idx = self._alloc_slot()
        if idx is None:
            return None
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

    def spawn_inits(
        self,
        inits: Sequence[CreatureInit],
    ) -> list[int]:
        mapping: list[int] = []
        for init in inits:
            idx = self.spawn_init(init)
            if idx is not None:
                mapping.append(idx)
        return mapping

    def spawn_plan(
        self,
        plan: SpawnPlan,
        *,
        rng: CrandLike | None = None,
        detail_preset: int = 5,
        effects: EffectPool | None = None,
    ) -> tuple[list[int], int | None]:
        """Materialize a pure `SpawnPlan` into the runtime pool.

        Returns:
          (plan_index_to_pool_index, primary_pool_index_or_none)
        """

        if self._free_slot_count() < len(plan.creatures):
            return [], None

        mapping: list[int] = []
        pending_ai_links: list[int | None] = []
        pending_ai_timers: list[int | None] = []
        pending_spawn_slots: list[int | None] = []

        # 1) Allocate pool slots for every creature.
        for init in plan.creatures:
            pool_idx = self._alloc_slot()
            if pool_idx is None:
                return [], None
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
                    child_template_id=slot.child_template_id,
                ),
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
            fx_rng = Crand(0) if rng is None else rng
            for fx in plan.effects:
                effect_pool.spawn_burst(
                    pos=fx.pos,
                    count=int(fx.count),
                    rng=fx_rng,
                    detail_preset=int(detail_preset),
                )
        return mapping, primary_pool

    def spawn_template(
        self,
        template_id: SpawnId,
        pos: Vec2,
        heading: float,
        rng: CrandLike,
        *,
        env: SpawnEnv | None = None,
        detail_preset: int = 5,
        effects: EffectPool | None = None,
    ) -> tuple[list[int], int | None]:
        """Build a spawn plan and materialize it into the pool."""

        spawn_env = env or self.env
        if spawn_env is None:
            raise ValueError("CreaturePool.spawn_template requires SpawnEnv (set CreaturePool.env or pass env=...)")
        plan = build_spawn_plan(template_id, pos, heading, rng, spawn_env)
        return self.spawn_plan(
            plan,
            rng=rng,
            detail_preset=int(detail_preset),
            effects=effects,
        )

    def update(
        self,
        dt: float,
        *,
        options: CreatureUpdateOptions,
    ) -> CreatureUpdateResult:
        """Advance the creature runtime pool by `dt` seconds.

        Notes:
        - Death side effects should be initiated by damage call sites.
        - This is not a full port of `creature_update_all`; it targets the Survival subset.
        """
        dt = float(f32(float(dt)))
        state = options.state
        players = options.players
        rng = options.rng
        detail_preset = int(options.detail_preset)
        violence_disabled = int(options.violence_disabled)
        env = options.env
        world_width = float(options.world_width)
        world_height = float(options.world_height)
        fx_queue = options.fx_queue
        fx_queue_rotated = options.fx_queue_rotated

        spawn_env = env

        deaths: list[CreatureDeath] = []
        spawned: list[int] = []
        sfx: list[SfxId] = []
        self._update_tick = int(self._update_tick) + 1
        single_player_dead_target_pos: Vec2 | None = None
        if len(players) == 1:
            single_player_dead_target_pos = Vec2(
                float(world_width) * (27.0 / 64.0),
                float(world_height) * (27.0 / 64.0),
            )

        evil_targets: set[int] = set()
        if players:
            if bool(state.preserve_bugs):
                # Native `creature_update_all` reads one global
                # `evil_eyes_target_creature` slot (player-0 storage), even in
                # multiplayer runs.
                if perk_active(players[0], PerkId.EVIL_EYES):
                    evil_target = int(players[0].evil_eyes_target_creature)
                    if evil_target >= 0:
                        evil_targets.add(int(evil_target))
            else:
                # Bug-fixed path: apply all alive Evil Eyes owners.
                for player in players:
                    if float(player.health) <= 0.0:
                        continue
                    if not perk_active(player, PerkId.EVIL_EYES):
                        continue
                    evil_target = int(player.evil_eyes_target_creature)
                    if evil_target >= 0:
                        evil_targets.add(int(evil_target))

        # Movement + AI. Dead creatures keep updating (death slide + corpse decals)
        # even when `players` is empty so debug views remain deterministic.
        # Native AI7 timer math uses `frame_dt_ms` integer slots with ftol-style
        # truncation semantics.
        dt_ms = ftol_ms_i32(float(dt)) if dt > 0.0 else 0
        creature_damage_runtime = _CreaturePoolCreatureDamageRuntime(
            pool=self,
            state=state,
            players=players,
            rng=rng,
            dt=float(dt),
            detail_preset=int(detail_preset),
            world_width=float(world_width),
            world_height=float(world_height),
            fx_queue=fx_queue,
            deaths=deaths,
            sfx=sfx,
        )

        def _apply_self_damage_tick(creature_index: int, creature: CreatureState) -> bool:
            if dt <= 0.0 or float(state.bonuses.freeze) > 0.0:
                return False
            damage_amount = 0.0
            creature_flags = int(creature.flags)
            if (creature_flags & _FLAG_SELF_DAMAGE_TICK_STRONG) != 0:
                damage_amount = dt * 180.0
            elif (creature_flags & _FLAG_SELF_DAMAGE_TICK) != 0:
                damage_amount = dt * 60.0
            if damage_amount <= 0.0:
                return False

            from .damage import creature_apply_damage_with_lethal_followup

            return creature_apply_damage_with_lethal_followup(
                creature,
                creature_index=int(creature_index),
                damage_amount=float(damage_amount),
                damage_type=CreatureDamageType.SELF_TICK,
                impulse=Vec2(),
                owner=creature.last_hit_owner,
                dt=dt,
                players=players,
                rng=rng,
                preserve_bugs=bool(state.preserve_bugs),
                effects=state.effects,
                detail_preset=int(detail_preset),
                creature_damage_runtime=creature_damage_runtime,
            )

        for idx, creature in enumerate(self._entries):
            if not creature.active:
                continue

            if float(creature.hit_flash_timer) > 0.0:
                creature.hit_flash_timer = f32(float(creature.hit_flash_timer) - float(dt))

            # Native `creature_update_all` gates the full per-creature body under
            # freeze; only bookkeeping outside this branch still advances.
            if float(state.bonuses.freeze) > 0.0:
                continue

            if not creature_lifecycle_is_alive(creature.lifecycle_stage) or creature.hp <= 0.0:
                _apply_self_damage_tick(idx, creature)
                # Native still ticks AI7 link-timer state (and its RNG draws) for
                # dead creatures inside `creature_update_all`.
                if (
                    dt > 0.0
                    and float(state.bonuses.freeze) <= 0.0
                    and (int(creature.flags) & _FLAG_AI7_LINK_TIMER) != 0
                ):
                    creature_ai7_tick_link_timer(creature, dt_ms=dt_ms, rng=rng)
                if creature_lifecycle_is_alive(creature.lifecycle_stage):
                    creature.lifecycle_stage = f32(float(creature.lifecycle_stage) - float(dt))
                if dt > 0.0:
                    self._tick_dead(
                        creature,
                        dt=dt,
                        world_width=world_width,
                        world_height=world_height,
                        fx_queue_rotated=fx_queue_rotated,
                        rng=rng,
                        detail_preset=int(detail_preset),
                        violence_disabled=int(violence_disabled),
                    )
                continue

            if dt <= 0.0 or not players:
                continue

            poison_killed = _apply_self_damage_tick(idx, creature)
            # Native order runs AI7 link timer update after periodic self-damage
            # and before any live-branch kill handling/retargeting.
            creature_ai7_tick_link_timer(creature, dt_ms=dt_ms, rng=rng)
            if poison_killed:
                if creature.active:
                    self._tick_dead(
                        creature,
                        dt=dt,
                        world_width=world_width,
                        world_height=world_height,
                        fx_queue_rotated=fx_queue_rotated,
                        rng=rng,
                        detail_preset=int(detail_preset),
                        violence_disabled=int(violence_disabled),
                    )
                continue

            if creature.plague_infected:
                creature.collision_timer -= float(dt)
                if creature.collision_timer < 0.0:
                    creature.collision_timer += CONTACT_DAMAGE_PERIOD
                    creature.hp -= 15.0
                    plague_killed = False
                    if creature.hp < 0.0:
                        state.plaguebearer_infection_count += 1
                        deaths.append(
                            self.handle_death(
                                idx,
                                state=state,
                                players=players,
                                rng=rng,
                                dt=float(dt),
                                detail_preset=int(detail_preset),
                                world_width=world_width,
                                world_height=world_height,
                                fx_queue=fx_queue,
                            ),
                        )
                        # Native plague-kill path consumes one rand draw for
                        # creature attack SFX bank-b selection after death side effects.
                        contact_sfx_options = _CREATURE_CONTACT_SFX.get(creature.type_id)
                        if contact_sfx_options is not None:
                            sfx_index = int(rng.rand_tagged(RngCallerStatic.CREATURE_UPDATE_ALL_PLAGUE_KILL_SFX)) & 1
                            sfx.append(contact_sfx_options[sfx_index])
                        plague_killed = True

                    if fx_queue is not None:
                        fx_queue.add_random(pos=creature.pos, rng=rng)
                    if plague_killed:
                        # Native keeps executing the current live-branch body after
                        # `creature_handle_death` in this timer-wrap kill path.
                        # Do not run `_tick_dead` immediately here.
                        pass

            target_player = self._resolve_target_player_index(creature, players)
            # Native only updates player auto-target feedback inside the
            # `creature_update_tick % 0x46 != 0` retarget cadence block.
            if (self._update_tick % _TARGET_REEVAL_PERIOD) != 0:
                self._update_player_auto_target(
                    players=players,
                    preserve_bugs=bool(state.preserve_bugs),
                    player_index=int(target_player),
                    creature_index=int(idx),
                    creature=creature,
                )
            player = players[target_player]
            player_pos = player.pos
            if single_player_dead_target_pos is not None and float(players[0].health) <= 0.0:
                creature.target_player = 1
                player_pos = single_player_dead_target_pos

            frozen_by_evil_eyes = idx in evil_targets
            if frozen_by_evil_eyes:
                # Native branch (`creature_update_all`, around 0x0042665f): when the
                # current creature is the Evil Eyes target, the update path jumps to
                # the loop tail before cooldown/interaction/ranged logic.
                creature.force_target = 0
                continue

            ai = creature_ai_update_target(
                creature,
                player_pos=player_pos,
                creatures=self._entries,
                dt=dt,
            )
            creature.move_scale = float(ai.move_scale)
            if ai.self_damage is not None and ai.self_damage > 0.0:
                # Native link-death cleanup calls creature_apply_damage(idx,
                # 1000.0, 1, zero): the full bullet path with heading-jitter
                # rand, hit flash, and the lethal death-SFX roll.
                from .damage import creature_apply_damage_with_lethal_followup

                killed = creature_apply_damage_with_lethal_followup(
                    creature,
                    creature_index=int(idx),
                    damage_amount=float(ai.self_damage),
                    damage_type=CreatureDamageType.BULLET,
                    impulse=Vec2(),
                    owner=creature.last_hit_owner,
                    dt=float(dt),
                    players=players,
                    rng=rng,
                    preserve_bugs=bool(state.preserve_bugs),
                    effects=state.effects,
                    detail_preset=int(detail_preset),
                    creature_damage_runtime=creature_damage_runtime,
                )
                if killed:
                    if creature.active:
                        self._tick_dead(
                            creature,
                            dt=dt,
                            world_width=world_width,
                            world_height=world_height,
                            fx_queue_rotated=fx_queue_rotated,
                            rng=rng,
                            detail_preset=int(detail_preset),
                            violence_disabled=int(violence_disabled),
                        )
                    continue

            if (float(state.bonuses.energizer) > 0.0 and float(creature.max_hp) < 500.0) or creature.plague_infected:
                creature.target_heading = heading_add_pi_f32(float(creature.target_heading))

            turn_rate = f32(float(creature.move_speed) * CREATURE_TURN_RATE_SCALE)
            if (creature.flags & CreatureFlags.ANIM_PING_PONG) == 0:
                if creature.ai_mode != CreatureAiMode.HOLD_TIMER:
                    creature.heading = _angle_approach(creature.heading, creature.target_heading, turn_rate, dt)
                    move_delta = _movement_delta_from_heading_f32(
                        creature.heading,
                        dt=dt,
                        move_scale=creature.move_scale,
                        move_speed=creature.move_speed,
                    )
                    creature.vel = move_delta
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
                    creature.vel = move_delta
                    creature.pos = f32_vec2(
                        _advance_pos_by_delta_f32(creature.pos, move_delta).clamp_rect(radius, radius, max_x, max_y),
                    )

                # Native ticks owner-bound spawn slots inside the spawner movement
                # branch, before this creature's plaguebearer/anim/ranged/contact
                # rand draws; children spawned here are visited later in the same
                # pass when their slot index is above the current one.
                if (
                    dt > 0.0
                    and float(state.bonuses.freeze) <= 0.0
                    and not bool(self.capture_spawn_events_authoritative)
                    and (creature.flags & HAS_SPAWN_SLOT_FLAG) != 0
                ):
                    slot_index = creature.spawn_slot_index
                    if slot_index is not None and 0 <= int(slot_index) < len(self.spawn_slots):
                        slot = self.spawn_slots[int(slot_index)]
                        if int(slot.owner_creature) == int(idx):
                            child_template_id = tick_spawn_slot(slot, dt)
                            if child_template_id is not None:
                                plan = build_spawn_plan(
                                    child_template_id,
                                    creature.pos,
                                    float(RANDOM_HEADING_SENTINEL),
                                    rng,
                                    spawn_env,
                                )
                                mapping, _ = self.spawn_plan(
                                    plan,
                                    rng=rng,
                                    detail_preset=int(detail_preset),
                                )
                                spawned.extend(mapping)

            if (
                players
                and perk_active(players[0], PerkId.PLAGUEBEARER)
                and int(state.plaguebearer_infection_count) < 0x3C
            ):
                self._plaguebearer_spread_infection(int(idx))

            # Native decrements contact/ranged cooldown before interaction checks,
            # then lets contact hits raise it back by +1.0 in the same frame.
            if creature.attack_cooldown <= 0.0:
                creature.attack_cooldown = 0.0
            else:
                creature.attack_cooldown -= dt

            # Native radioactive contact pulse runs after movement/AI/cooldown
            # synthesis inside the live-creature branch. The distance is measured
            # to the creature's target player, the perk gate reads the global
            # count (any player), the kill XP is credited to player 1, and the
            # timer-fire requires the creature to still be alive (hp > 0).
            if players and any(perk_active(p, PerkId.RADIOACTIVE) for p in players):
                dist = (creature.pos - player.pos).length()
                if dist < 100.0:
                    creature.collision_timer -= float(dt) * 1.5
                    if creature.collision_timer < 0.0 and float(creature.hp) > 0.0:
                        creature.collision_timer = CONTACT_DAMAGE_PERIOD
                        creature.hp -= (100.0 - dist) * 0.3
                        if fx_queue is not None:
                            fx_queue.add_random(pos=creature.pos, rng=rng)

                        if creature.hp < 0.0:
                            if creature.type_id == CreatureTypeId.LIZARD:
                                creature.hp = 1.0
                            else:
                                players[0].experience = int(
                                    float(players[0].experience) + float(creature.reward_value),
                                )
                                creature.lifecycle_stage -= float(dt)

            # Decompile parity (`creature_update_all`, 0x00426220): compute
            # creature->target-player distance once, then reuse that value for
            # ranged attacks and all contact/eat checks in this creature tick.
            target_dist_sq = Vec2.distance_sq(creature.pos, player.pos)
            target_dist = math.sqrt(float(target_dist_sq))

            if (not frozen_by_evil_eyes) and (
                creature.flags & (CreatureFlags.RANGED_ATTACK_SHOCK | CreatureFlags.RANGED_ATTACK_VARIANT)
            ):
                # Ported from creature_update_all (see `analysis/ghidra/raw/crimsonland.exe_decompiled.c`
                # around the 0x004276xx ranged-fire branch).
                if target_dist > 64.0 and creature.attack_cooldown <= 0.0:
                    if creature.flags & CreatureFlags.RANGED_ATTACK_SHOCK:
                        type_id = ProjectileTemplateId.PLASMA_RIFLE
                        state.projectiles.spawn(
                            pos=creature.pos,
                            angle=float(creature.heading),
                            type_id=type_id,
                            owner=OwnerRef.from_creature(int(idx)),
                            travel_budget=_travel_budget_for_type_id(type_id),
                            hits_players=True,
                        )
                        sfx.append(SfxId.SHOCK_FIRE)
                        creature.attack_cooldown += 1.0

                    if (creature.flags & CreatureFlags.RANGED_ATTACK_VARIANT) and creature.attack_cooldown <= 0.0:
                        projectile_type = ProjectileTemplateId(creature.orbit_radius)
                        state.projectiles.spawn(
                            pos=creature.pos,
                            angle=float(creature.heading),
                            type_id=projectile_type,
                            owner=OwnerRef.from_creature(int(idx)),
                            travel_budget=_travel_budget_for_type_id(projectile_type),
                            hits_players=True,
                        )
                        sfx.append(SfxId.PLASMAMINIGUN_FIRE)
                        creature.attack_cooldown = (
                            float(rng.rand_tagged(RngCallerStatic.CREATURE_UPDATE_ALL_PLASMAMINIGUN_COOLDOWN) & 3)
                            * 0.1
                            + float(creature.orbit_angle)
                            + float(creature.attack_cooldown)
                        )

            interaction_ctx = _CreatureInteractionCtx(
                pool=self,
                creature_index=int(idx),
                creature=creature,
                state=state,
                players=players,
                player=player,
                dt=dt,
                rng=rng,
                detail_preset=int(detail_preset),
                violence_disabled=int(violence_disabled),
                world_width=float(world_width),
                world_height=float(world_height),
                fx_queue=fx_queue,
                fx_queue_rotated=fx_queue_rotated,
                deaths=deaths,
                sfx=sfx,
                contact_dist_sq=float(target_dist_sq),
            )
            for step in _CREATURE_INTERACTION_STEPS:
                step(interaction_ctx)
                if interaction_ctx.skip_creature:
                    break
            if interaction_ctx.skip_creature:
                continue

        return CreatureUpdateResult(deaths=tuple(deaths), spawned=tuple(spawned), sfx=tuple(sfx))

    def handle_death(
        self,
        idx: int,
        *,
        state: GameplayState,
        players: list[PlayerState],
        rng: CrandLike,
        dt: float = 0.0,
        detail_preset: int = 5,
        world_width: float,
        world_height: float,
        fx_queue: FxQueue | None,
        keep_corpse: bool = True,
    ) -> CreatureDeath:
        """Run one-shot death side effects and return the `CreatureDeath` event."""

        creature = self._entries[int(idx)]
        if (creature.flags & CreatureFlags.BONUS_ON_DEATH) and creature.bonus_id is not None:
            # Native `bonus_spawn_at` clamps through the creature pos pointer
            # (also in rush, where no bonus spawns), moving the corpse to the
            # 32-px world margin, and spawns a 16-particle pickup burst.
            creature.pos = creature.pos.clamp_rect(
                BONUS_SPAWN_MARGIN,
                BONUS_SPAWN_MARGIN,
                float(world_width) - BONUS_SPAWN_MARGIN,
                float(world_height) - BONUS_SPAWN_MARGIN,
            )
            state.bonus_pool.spawn_at(
                pos=creature.pos,
                bonus_id=creature.bonus_id,
                duration_override=int(creature.bonus_duration_override)
                if creature.bonus_duration_override is not None
                else -1,
                state=state,
                world_width=world_width,
                world_height=world_height,
                detail_preset=int(detail_preset),
            )
            if not bool(state.preserve_bugs):
                creature.bonus_id = None
                creature.bonus_duration_override = None
        survival_record_recent_death(state, pos=creature.pos)
        if not creature.active:
            # Native `creature_handle_death` gates its XP/bonus/freeze body under
            # `if (active != 0)`. Re-entrant callers (notably secondary
            # detonation follow-up) can invoke death handling after the first call
            # has already deactivated the creature.
            return CreatureDeath(
                index=int(idx),
                pos=creature.pos,
                type_id=creature.type_id,
                reward_value=float(creature.reward_value),
                xp_awarded=0,
                owner=creature.last_hit_owner,
            )
        death = self._start_death(
            int(idx),
            creature,
            state=state,
            players=players,
            rng=rng,
            detail_preset=int(detail_preset),
            world_width=world_width,
            world_height=world_height,
        )

        if keep_corpse:
            # Native `creature_handle_death` always decrements lifecycle_stage by
            # frame_dt for corpse-keeping deaths, independent of current value.
            creature.lifecycle_stage = float(creature.lifecycle_stage) - float(dt)
        else:
            creature.active = False

        if float(state.bonuses.freeze) > 0.0:
            creature_pos = creature.pos
            for _ in range(8):
                angle = (
                    float(int(rng.rand_tagged(RngCallerStatic.CREATURE_HANDLE_DEATH_FREEZE_SHARD_ANGLE)) % 612) * 0.01
                )
                state.effects.spawn_freeze_shard(
                    pos=creature_pos,
                    angle=angle,
                    rng=rng,
                    detail_preset=int(detail_preset),
                )
            angle = (
                float(int(rng.rand_tagged(RngCallerStatic.CREATURE_HANDLE_DEATH_FREEZE_SHATTER_ANGLE)) % 612) * 0.01
            )
            state.effects.spawn_freeze_shatter(
                pos=creature_pos,
                angle=angle,
                rng=rng,
                detail_preset=int(detail_preset),
            )
            if fx_queue is not None:
                fx_queue.add_random(pos=creature_pos, rng=rng)
            self.kill_count += 1
            creature.active = False

        return death

    def _apply_init(self, entry: CreatureState, init: CreatureInit) -> None:
        entry.active = True
        entry.type_id = init.type_id if init.type_id is not None else CreatureTypeId.ZOMBIE
        entry.pos = f32_vec2(init.pos)
        if init.heading is not None:
            # Native spawn paths write heading but keep target_heading stale from
            # the recycled slot (capture lifecycle shows added entries retaining
            # prior target_heading values).
            entry.heading = f32(float(init.heading))
        entry.target = f32_vec2(init.pos)
        entry.phase_seed = f32(float(init.phase_seed))
        # Native spawn paths zero velocity and a few per-frame state fields on every
        # allocation (`creature_spawn`, `survival_spawn_creature`, `creature_spawn_template`).
        entry.vel = Vec2()
        entry.force_target = 0

        entry.flags = init.flags or CreatureFlags(0)
        entry.ai_mode = CreatureAiMode(init.ai_mode)

        hp = float(init.health or 0.0)
        if hp <= 0.0:
            hp = 1.0
        entry.hp = f32(hp)
        entry.max_hp = f32(float(init.max_health or hp))

        entry.move_speed = f32(float(init.move_speed or 1.0))
        entry.reward_value = f32(float(init.reward_value or 0.0))
        entry.size = f32(float(init.size or 50.0))
        entry.contact_damage = f32(float(init.contact_damage or 0.0))

        entry.target_offset = f32_vec2(init.target_offset) if init.target_offset is not None else None
        entry.orbit_angle = f32(float(init.orbit_angle or 0.0))
        if init.orbit_radius is not None:
            orbit_radius = float(init.orbit_radius)
        elif init.ranged_projectile_type is not None:
            orbit_radius = float(init.ranged_projectile_type)
        else:
            orbit_radius = 0.0
        entry.orbit_radius = f32(orbit_radius)

        entry.spawn_slot_index = None
        entry.attack_cooldown = 0.0

        entry.bonus_id = init.bonus_id
        entry.bonus_duration_override = (
            int(init.bonus_duration_override) if init.bonus_duration_override is not None else None
        )

        entry.tint = RGBA.from_rgba(resolve_tint(init.tint))

        entry.plague_infected = False
        entry.collision_timer = 0.0
        entry.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
        entry.hit_flash_timer = 0.0
        entry.anim_phase = 0.0
        entry.last_hit_owner = OwnerRef.from_local_player(0)

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
        rng: CrandLike | None = None,
        detail_preset: int = 5,
        violence_disabled: int = 0,
    ) -> None:
        """Advance the post-death lifecycle_stage ramp and queue corpse decals.

        This matches the `lifecycle_stage` death staging inside `creature_update_all`:
        - while lifecycle_stage > 0: decrement quickly and slide backwards
        - once lifecycle_stage <= 0: queue a corpse decal and fade out until < -10, then deactivate.
        """

        if dt <= 0.0:
            return

        dt_f32 = f32(float(dt))
        hitbox = f32(float(creature.lifecycle_stage))
        if hitbox <= 0.0:
            creature.lifecycle_stage = f32(hitbox - f32(float(dt_f32) * CREATURE_CORPSE_FADE_DECAY))
            return

        long_strip = (creature.flags & CreatureFlags.ANIM_PING_PONG) == 0 or (
            creature.flags & CreatureFlags.ANIM_LONG_STRIP
        ) != 0

        new_hitbox = f32(hitbox - f32(float(dt_f32) * CREATURE_DEATH_TIMER_DECAY))
        creature.lifecycle_stage = f32(new_hitbox)
        if new_hitbox > 0.0:
            if long_strip:
                # Match float-local multiply chain in `creature_update_all`:
                # slide = (float)((float)(hitbox * dt) * 9.0f)
                slide = f32(f32(float(new_hitbox) * float(dt_f32)) * f32(CREATURE_DEATH_SLIDE_SCALE))
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

        # lifecycle_stage just crossed <= 0: bake a persistent corpse decal into the ground.
        if int(violence_disabled) == 0 and fx_queue_rotated is not None:
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
                creature.lifecycle_stage = 0.001
                return

        self.kill_count += 1

        # Native `creature_update_all` emits a 19-splatter blood burst when a
        # ping-pong corpse first reaches this staged kill point.
        if (
            int(violence_disabled) == 0
            and (creature.flags & CreatureFlags.ANIM_PING_PONG) != 0
            and rng is not None
            and self.effects is not None
        ):
            for count, age, angle_caller in (
                (8, 0.0, RngCallerStatic.CREATURE_UPDATE_ALL_PING_PONG_BLOOD_8_ANGLE),
                (6, -0.07, RngCallerStatic.CREATURE_UPDATE_ALL_PING_PONG_BLOOD_6_ANGLE),
                (5, -0.12, RngCallerStatic.CREATURE_UPDATE_ALL_PING_PONG_BLOOD_5_ANGLE),
            ):
                for _ in range(int(count)):
                    angle = float(int(rng.rand_tagged(angle_caller)) % 612) * 0.01
                    self.effects.spawn_blood_splatter(
                        pos=creature.pos,
                        angle=float(angle),
                        age=float(age),
                        rng=rng,
                        detail_preset=int(detail_preset),
                        violence_disabled=int(violence_disabled),
                    )

    def finalize_post_render_lifecycle(self) -> None:
        """Mirror render-time corpse culling from native `creature_render_type`.

        Native deactivates entries only after draw once `lifecycle_stage < -10.0`. Keeping
        this outside `creature_update_all` preserves slot-allocation timing for same-tick
        survival/rush spawns.
        """

        for creature in self._entries:
            if not creature.active:
                continue
            if classify_creature_lifecycle(creature.lifecycle_stage) != CreatureLifecyclePhase.DESPAWNED:
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
        rng: CrandLike,
        detail_preset: int = 5,
        world_width: float,
        world_height: float,
    ) -> CreatureDeath:
        if creature.spawn_slot_index is not None:
            self._disable_spawn_slot(int(creature.spawn_slot_index))

        if (creature.flags & CreatureFlags.SPLIT_ON_DEATH) and float(creature.size) > 35.0:
            for heading_offset, phase_seed_caller in (
                (-float(NATIVE_HALF_PI), RngCallerStatic.CREATURE_HANDLE_DEATH_SPLIT_CHILD_1_PHASE_SEED),
                (float(NATIVE_HALF_PI), RngCallerStatic.CREATURE_HANDLE_DEATH_SPLIT_CHILD_2_PHASE_SEED),
            ):
                child_idx = self._alloc_slot()
                if child_idx is None:
                    continue
                # Native `creature_alloc_slot` draws a phase seed (rand & 0x17f) that the
                # subsequent struct copy from the parent immediately overwrites; only the
                # draw itself matters for the stream.
                rng.rand_tagged(RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED)
                child = msgspec.structs.replace(creature)
                child.phase_seed = float(int(rng.rand_tagged(phase_seed_caller)) & 0xFF)
                # Native stores `heading +- 1.5707964f` unwrapped and leaves
                # `target_heading` as the parent's stale copy.
                child.heading = float(f32(float(creature.heading) + float(heading_offset)))
                child.hp = float(creature.max_hp) * 0.25
                # Native multiplies by the f32 literal 0.6666667.
                child.reward_value = float(child.reward_value) * float(f32(0.6666667))
                child.size = float(child.size) - 8.0
                child.move_speed = float(child.move_speed) + 0.1
                child.contact_damage = float(child.contact_damage) * 0.7
                child.lifecycle_stage = CREATURE_LIFECYCLE_ALIVE
                self._entries[child_idx] = child
                self.spawned_count += 1

            state.effects.spawn_burst(
                pos=creature.pos,
                count=8,
                rng=rng,
                detail_preset=int(detail_preset),
            )

        killer: PlayerState | None = None
        if players:
            player_index = _owner_to_player_index(creature.last_hit_owner)
            if player_index is None or not (0 <= player_index < len(players)):
                player_index = 0
            killer = players[player_index]

        xp_awarded = 0
        if killer is not None:
            if perk_active(killer, PerkId.BLOODY_MESS_QUICK_LEARNER):
                xp_awarded = award_experience(state, killer, int(float(creature.reward_value) * 1.3))
            else:
                xp_awarded = award_experience_from_reward(state, killer, float(creature.reward_value))

        if players:
            state.bonus_pool.try_spawn_on_kill(
                pos=creature.pos,
                state=state,
                players=players,
                detail_preset=detail_preset,
                world_width=world_width,
                world_height=world_height,
            )

        return CreatureDeath(
            index=int(idx),
            pos=creature.pos,
            type_id=creature.type_id,
            reward_value=float(creature.reward_value),
            xp_awarded=int(xp_awarded),
            owner=creature.last_hit_owner,
        )
