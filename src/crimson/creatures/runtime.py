"""Creature realtime simulation: the fixed-size creature pool and `creature_update_all`.

Spawners (`creatures.spawn`) write straight into the pool's slots.
See: `docs/creatures/update.md`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import msgspec

from grim.color import RGBA
from grim.geom import Vec2
from grim.rand import CrandLike
from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest

from ..bonuses import BonusId
from ..bonuses.pool import BONUS_SPAWN_MARGIN
from ..effects import EffectPool, FxQueueRotated
from ..gameplay import (
    experience_plus_reward,
    survival_record_first_kill,
)
from ..math_parity import (
    NATIVE_HALF_PI,
    NATIVE_TAU,
    NATIVE_TURN_RATE_SCALE,
    f32,
    f32_bits_i32,
    f32_from_bits,
    heading_add_pi_f32,
    x87_d3dx_vec2_normalize,
    x87_pc24_add,
    x87_pc24_cos_mul,
    x87_pc24_hypot,
    x87_pc24_mul,
    x87_pc24_sin_mul,
    x87_pc24_sub,
)
from ..perks import PerkId
from ..player_damage import player_take_damage
from ..projectiles.runtime import projectile_spawn
from ..projectiles.types import ProjectileTemplateId
from ..rng_caller_static import RngCallerStatic
from ..sim.state_types import TERRAIN_SIZE, PlayerState
from ..sim.timing import ftol_ms_i32
from .ai import creature_ai7_tick_link_timer, creature_ai_update_target
from .anim import CREATURE_ANIM, creature_anim_advance_phase
from .damage import creature_apply_damage
from .damage_types import CreatureDamageType
from .lifecycle import (
    CREATURE_LIFECYCLE_ALIVE,
    CreatureLifecyclePhase,
    classify_creature_lifecycle,
    creature_lifecycle_is_alive,
)
from .spawn import (
    NATIVE_SPAWN_SLOT_COUNT,
    RANDOM_HEADING_SENTINEL,
    CreatureAiMode,
    CreatureFlags,
    CreatureTypeId,
    SpawnId,
    SpawnSlot,
    creature_spawn_template,
    tick_spawn_slot,
)

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState

    from ..sim.world_state import WorldStepRuntime


__all__ = [
    "CREATURE_POOL_SIZE",
    "DOT_TICK_PERIOD",
    "PHANTOM_CREATURE_INDEX",
    "CreatureDeath",
    "CreaturePool",
    "CreatureState",
]


CREATURE_POOL_SIZE = 0x180
# `creature_alloc_slot` returns one past the pool when every slot is active, and its callers write
# that creature anyway: into the unnamed padding after `creature_pool`, which nothing iterates.
PHANTOM_CREATURE_INDEX = CREATURE_POOL_SIZE

# Shared damage-over-time tick: plague infection, the Radioactive aura and Pyrokinetic particles.
# Contact damage runs on `attack_cooldown` instead.
DOT_TICK_PERIOD = 0.5

# Native movement path multiplies by a fixed `30.0` factor in `creature_update_all`.
CREATURE_SPEED_SCALE = 30.0

# Base heading turn rate multiplier (angle_approach clamps by frame_dt internally).
CREATURE_TURN_RATE_SCALE = NATIVE_TURN_RATE_SCALE

# The death timer:
# - 16.0 means "alive" (normal AI/movement/anim update)
# - once HP <= 0 it ramps down quickly and drives death slide + corpse decal timing.
# - final deactivation (`death_timer < -10.0`) happens during render (creature_render_type), and also
#   in creature_update_all when corpses don't fade (`cv_bodiesFade == 0`).
CREATURE_DEATH_TIMER_DECAY = 28.0
CREATURE_CORPSE_FADE_DECAY = 20.0
CREATURE_DEATH_SLIDE_SCALE = 9.0
# Native re-picks the target on every tick except multiples of 70.
_TARGET_REEVAL_SKIP_MODULUS = 0x46
_FLAG_POISONED = int(CreatureFlags.POISONED)
_FLAG_POISONED_STRONG = int(CreatureFlags.POISONED_STRONG)
_FLAG_STOP_AND_GO = int(CreatureFlags.STOP_AND_GO)
_FLAG_SPAWNER = int(CreatureFlags.SPAWNER)
_FLAG_SPAWNER_MOBILE = int(CreatureFlags.SPAWNER_MOBILE)
_FLAG_RANGED = int(CreatureFlags.RANGED_PLASMA_RIFLE | CreatureFlags.RANGED_TEMPLATE_PROJECTILE)

_CREATURE_CONTACT_SFX: dict[CreatureTypeId, tuple[SfxId, SfxId]] = {
    CreatureTypeId.ZOMBIE: (SfxId.ZOMBIE_ATTACK_01, SfxId.ZOMBIE_ATTACK_02),
    CreatureTypeId.LIZARD: (SfxId.LIZARD_ATTACK_01, SfxId.LIZARD_ATTACK_02),
    CreatureTypeId.ALIEN: (SfxId.ALIEN_ATTACK_01, SfxId.ALIEN_ATTACK_02),
    CreatureTypeId.SPIDER_SP1: (SfxId.SPIDER_ATTACK_01, SfxId.SPIDER_ATTACK_02),
    CreatureTypeId.SPIDER_SP2: (SfxId.SPIDER_ATTACK_01, SfxId.SPIDER_ATTACK_02),
}


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
    angle = f32(current)
    target_f = f32(target)
    rate_f = f32(rate)
    dt_f = f32(dt)
    tau = float(NATIVE_TAU)

    while angle < 0.0:
        angle = f32(angle + tau)
    while tau < angle:
        angle = f32(angle - tau)

    direct = f32(abs(f32(target_f - angle)))

    hi = angle
    if angle < target_f:
        hi = target_f
    lo = angle
    if target_f < angle:
        lo = target_f
    wrapped = f32(abs(f32(f32(tau - hi) + lo)))

    step_scale = wrapped
    if direct < wrapped:
        step_scale = direct
    if step_scale > 1.0:
        step_scale = 1.0
    step_scale = f32(step_scale)

    step_delta = f32(f32(dt_f * step_scale) * rate_f)

    if direct <= wrapped:
        if angle < target_f:
            return f32(angle + step_delta)
    else:
        if target_f < angle:
            return f32(angle + step_delta)
    return f32(angle - step_delta)


def _movement_delta_from_heading_f32(
    heading: float,
    *,
    dt: float,
    move_scale: float,
    move_speed: float,
) -> Vec2:
    # The game leaves the x87 in single-precision mode (the Direct3D 8 device
    # init does not pass D3DCREATE_FPU_PRESERVE), so every multiply in the
    # velocity chain rounds to f32; fsin/fcos still evaluate in extended
    # precision internally, so their rounding lands in the first multiply
    # (`creature_update_all` 0x426dab..0x426de6, validated against captured
    # walker velocity channels).
    radians = x87_pc24_sub(f32(heading), NATIVE_HALF_PI)

    # Preserve native multiply order:
    # `vel = trig(heading - half_pi) * frame_dt * move_scale * move_speed * 30.0`
    vx = x87_pc24_cos_mul(radians, float(dt), float(move_scale), float(move_speed), float(CREATURE_SPEED_SCALE))
    vy = x87_pc24_sin_mul(radians, float(dt), float(move_scale), float(move_speed), float(CREATURE_SPEED_SCALE))

    return Vec2(vx, vy)


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


_QUICK_LEARNER_REWARD_SCALE = f32(1.3)


def quick_learner_kill_xp(reward_value: float) -> int:
    """`__ftol(reward * 1.3f)` at PC24 (creature_handle_death 0x0041eb45)."""

    return int(x87_pc24_mul(float(reward_value), _QUICK_LEARNER_REWARD_SCALE))


def _clamp_to_size_bounds(value: float, size: float, world_extent: float) -> float:
    """Native spawner clamp: `< size` first, then `> extent - size` (PC24 subtract)."""

    if value < size:
        value = size
    max_value = x87_pc24_sub(world_extent, size)
    if value > max_value:
        value = max_value
    return value


class CreatureState(msgspec.Struct):
    generation: int = 0
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
    ai_mode: CreatureAiMode = CreatureAiMode.FLANK_PLAYER
    flags: CreatureFlags = CreatureFlags(0)

    # Native `creature_alloc_slot` does not clear `link_index`; many spawn paths
    # leave it untouched (notably survival_spawn_creature AI7 spiders), so stale
    # values can affect early AI7 timer phase.
    link_index: int = -1
    target_offset: Vec2 | None = None
    orbit_angle: float = 0.0
    # Native `orbit_radius` union: the float radius arm; `ranged_projectile_type`
    # reads and writes the int32 arm through the same bits.
    orbit_radius: float = 0.0
    # Native stores this as int32 and uses `fild` when forming orbit phase.
    phase_seed: int = 0

    # Combat / timers.
    hp: float = 0.0
    max_hp: float = 0.0
    move_speed: float = 1.0
    contact_damage: float = 0.0
    attack_cooldown: float = 0.0
    reward_value: float = 0.0

    # Plaguebearer infection state (native: `plague_infected` byte).
    plague_infected: bool = False
    dot_tick_timer: float = DOT_TICK_PERIOD
    death_timer: float = CREATURE_LIFECYCLE_ALIVE

    # Presentation.
    size: float = 50.0
    anim_phase: float = 0.0
    hit_flash_timer: float = 0.0
    tint: RGBA = msgspec.field(default_factory=RGBA)

    # Rewrite-only view of the BONUS_ON_DEATH args native packs into `link_index`.
    bonus_id: BonusId | None = None
    bonus_amount_override: int | None = None

    @property
    def ranged_projectile_type(self) -> int:
        """The int32 arm of the native `orbit_radius` union (RANGED_TEMPLATE_PROJECTILE fire)."""

        return f32_bits_i32(self.orbit_radius)

    @ranged_projectile_type.setter
    def ranged_projectile_type(self, projectile_type: int) -> None:
        self.orbit_radius = f32_from_bits(projectile_type)


class CreatureDeath(msgspec.Struct, frozen=True):
    index: int
    pos: Vec2
    type_id: CreatureTypeId
    reward_value: float
    xp_awarded: int


class _TargetPlayerResolution(msgspec.Struct, frozen=True):
    target_player: int
    auto_target_player: int
    native_auto_target_distance: float | None = None


def _phantom_creature() -> CreatureState:
    """The phantom slot at process start: `creature_pool_global_init` covers 0x181 entries,
    so it is zeroed static memory with `link_index` -1."""

    return CreatureState(
        target_offset=Vec2(),
        move_speed=0.0,
        dot_tick_timer=0.0,
        death_timer=0.0,
        size=0.0,
        tint=RGBA(0.0, 0.0, 0.0, 0.0),
    )


class CreaturePool:
    def __init__(self) -> None:
        self._entries: list[CreatureState] = [CreatureState() for _ in range(CREATURE_POOL_SIZE)]
        # The phantom slot `creature_alloc_slot` hands out when the pool is full. Nothing resets
        # it, so its fields persist between the writes that land there.
        self.phantom = _phantom_creature()
        self.spawn_slots: list[SpawnSlot] = [SpawnSlot() for _ in range(NATIVE_SPAWN_SLOT_COUNT)]
        self.kill_count = 0
        self.spawned_count = 0
        # Counts every slot allocation, so lookups built over the pool can tell
        # when a creature appeared since they last looked.
        self.alloc_count = 0
        self._update_tick = 0

    @property
    def entries(self) -> list[CreatureState]:
        return self._entries

    def reset(self) -> None:
        for i in range(len(self._entries)):
            self._entries[i] = CreatureState()
        for slot in self.spawn_slots:
            slot.owner_creature = -1
        self.kill_count = 0
        self.spawned_count = 0
        self._update_tick = 0

    def apply_gameplay_reset_target_players(self, player_count: int) -> None:
        """Apply the native reset-time round-robin creature target assignment."""

        count = int(player_count)
        for index, creature in enumerate(self._entries):
            creature.target_player = index % count if count > 0 else 0

    def iter_active(self) -> list[CreatureState]:
        return [entry for entry in self._entries if entry.active and entry.hp > 0.0]

    def _plaguebearer_spread_infection(self, origin_index: int) -> None:
        """Port of `plaguebearer_spread_infection`."""

        origin_index = int(origin_index)
        if not (0 <= origin_index < len(self._entries)):
            return
        origin = self._entries[origin_index]
        if not origin.active:
            return
        # A strong, uninfected origin can neither catch nor pass on infection.
        if not origin.plague_infected and float(origin.hp) >= 150.0:
            return

        origin_x, origin_y = origin.pos.x, origin.pos.y
        for creature in self._entries:
            if not creature.active:
                continue

            # Rounding an axis at or beyond 45 to F32 cannot put it inside
            # the native radius. Cull those candidates before the PC24 math;
            # nearby candidates still use its exact distance and pool order.
            dx = creature.pos.x - origin_x
            if dx <= -45.0 or dx >= 45.0:
                continue
            dy = creature.pos.y - origin_y
            if dy <= -45.0 or dy >= 45.0:
                continue
            if x87_pc24_hypot(f32(dx), f32(dy)) >= 45.0:
                continue
            if creature.plague_infected and float(origin.hp) < 150.0:
                origin.plague_infected = True
            if origin.plague_infected and float(creature.hp) < 150.0:
                creature.plague_infected = True
            return

    def creature(self, index: int) -> CreatureState:
        """`&creature_pool[index]`, where `PHANTOM_CREATURE_INDEX` is the phantom slot."""

        if index == PHANTOM_CREATURE_INDEX:
            return self.phantom
        return self._entries[index]

    def alloc_slot(self, rng: CrandLike) -> int:
        """Port of `creature_alloc_slot` (0x00428140).

        Clears the first inactive slot's flags and draws its phase seed; a full pool returns
        `PHANTOM_CREATURE_INDEX` without touching the phantom slot or the RNG.
        """

        for index, entry in enumerate(self._entries):
            if not entry.active:
                entry.flags = CreatureFlags(0)
                entry.phase_seed = rng.rand_tagged(RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED) & 0x17F
                entry.anim_phase = 0.0
                entry.generation += 1
                self.alloc_count += 1
                self.spawned_count += 1
                return index
        return PHANTOM_CREATURE_INDEX

    def spawn_slot_alloc(self) -> int:
        """Port of `creature_spawn_slot_alloc`: the first ownerless slot, else the last one."""

        for slot_index, slot in enumerate(self.spawn_slots):
            if slot.owner_creature < 0:
                return slot_index
        return NATIVE_SPAWN_SLOT_COUNT - 1

    def _resolve_target_player(
        self,
        creature: CreatureState,
        players: list[PlayerState],
        player_count: int,
    ) -> _TargetPlayerResolution:
        """`players` is the native two-slot player table for one or two players (see `update`)."""

        if player_count == 0:
            creature.target_player = 0
            return _TargetPlayerResolution(target_player=0, auto_target_player=0)

        target_player = int(creature.target_player)
        if not (0 <= target_player < len(players)):
            target_player = 0

        # Native periodically switches a two-player target to the other player if alive and closer,
        # and always flips off a dead target. A one-player run flips onto the dormant second slot
        # and keeps chasing it until that slot dies too, even if player one gets back up.
        if player_count <= 2:
            native_auto_target_distance = None
            reevaluate = (self._update_tick % _TARGET_REEVAL_SKIP_MODULUS) != 0
            if reevaluate and player_count == 1:
                dx = x87_pc24_sub(players[0].pos.x, creature.pos.x)
                dy = x87_pc24_sub(players[0].pos.y, creature.pos.y)
                native_auto_target_distance = x87_pc24_hypot(dx, dy)
            elif reevaluate:
                other = 1 - target_player
                if float(players[other].health) > 0.0:
                    cur_dx = x87_pc24_sub(players[target_player].pos.x, creature.pos.x)
                    cur_dy = x87_pc24_sub(players[target_player].pos.y, creature.pos.y)
                    cur_distance = x87_pc24_hypot(cur_dx, cur_dy)
                    other_dx = x87_pc24_sub(players[other].pos.x, creature.pos.x)
                    other_dy = x87_pc24_sub(players[other].pos.y, creature.pos.y)
                    other_distance = x87_pc24_hypot(other_dx, other_dy)
                    native_auto_target_distance = other_distance
                    if other_distance < cur_distance:
                        target_player = other
            auto_target_player = target_player
            if float(players[target_player].health) <= 0.0:
                target_player = 1 - target_player
            creature.target_player = int(target_player)
            return _TargetPlayerResolution(
                target_player=int(target_player),
                auto_target_player=int(auto_target_player),
                native_auto_target_distance=native_auto_target_distance,
            )

        # 3/4-player extension: keep deterministic nearest-alive targeting with the
        # same refresh policy as native 2-player mode: every tick but multiples of 70, or a dead target.
        needs_refresh = (self._update_tick % _TARGET_REEVAL_SKIP_MODULUS) != 0 or float(players[target_player].health) <= 0.0
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
        return _TargetPlayerResolution(
            target_player=int(target_player),
            auto_target_player=int(target_player),
        )

    def _update_player_auto_target(
        self,
        *,
        players: list[PlayerState],
        native: bool,
        resolution: _TargetPlayerResolution,
        creature_index: int,
        creature: CreatureState,
    ) -> None:
        """Feed the targeted player's auto-target on native's reevaluation cadence.

        `native` keeps the original slot choice and distances: bug 19 under preserve_bugs, and
        always in a one-player run, where its fix does not apply.
        """

        if (self._update_tick % _TARGET_REEVAL_SKIP_MODULUS) == 0:
            return
        player_index = int(resolution.auto_target_player if native else resolution.target_player)
        if not (0 <= player_index < len(players)):
            return
        player = players[player_index]

        # Native has no hp filters here: dead players' slots still update, and
        # the current auto-target is used purely for its (possibly stale)
        # position - corpses and recycled slots included. The demo auto-aim
        # consumer re-scans with an hp filter.
        auto_target = int(player.auto_target)
        if not (0 <= auto_target < len(self._entries)):
            player.auto_target = int(creature_index)
            return

        current = self._entries[int(auto_target)]
        if resolution.native_auto_target_distance is not None and native:
            # Single-player reevaluation already measured this distance. In
            # native two-player bug mode it instead measured the opposite player.
            dist_new = float(resolution.native_auto_target_distance)
        else:
            # Native leaves the alternate-distance stack local untouched when
            # the opposite player is dead. Its first value is unknowable, so
            # bug mode uses this deterministic selected-player fallback rather
            # than fabricating stack residue.
            new_dx = x87_pc24_sub(player.pos.x, creature.pos.x)
            new_dy = x87_pc24_sub(player.pos.y, creature.pos.y)
            dist_new = x87_pc24_hypot(new_dx, new_dy)
        current_origin = player.pos
        if native:
            # Native always measures the previous auto-target from player 1's
            # coordinates, even when it writes player 2's auto-target slot.
            current_origin = players[0].pos
        current_dx = x87_pc24_sub(current_origin.x, current.pos.x)
        current_dy = x87_pc24_sub(current_origin.y, current.pos.y)
        dist_current = x87_pc24_hypot(current_dx, current_dy)
        if dist_new < dist_current:
            player.auto_target = int(creature_index)

    def spawn_template(
        self,
        template_id: SpawnId,
        pos: Vec2,
        heading: float,
        *,
        state: GameplayState,
        detail_preset: int,
    ) -> int:
        """`creature_spawn_template`; returns the index of the creature it returns."""

        return creature_spawn_template(self, template_id, pos, heading, state=state, detail_preset=detail_preset)

    def _apply_poison_tick(
        self,
        creature_index: int,
        creature: CreatureState,
        *,
        dt: float,
        step_runtime: WorldStepRuntime,
    ) -> bool:
        state = step_runtime.world.state
        if dt <= 0.0 or float(state.bonuses.freeze) > 0.0:
            return False
        damage_amount = 0.0
        creature_flags = int(creature.flags)
        if (creature_flags & _FLAG_POISONED_STRONG) != 0:
            damage_amount = x87_pc24_mul(dt, 180.0)
        elif (creature_flags & _FLAG_POISONED) != 0:
            damage_amount = x87_pc24_mul(dt, 60.0)
        if damage_amount <= 0.0:
            return False

        return creature_apply_damage(
            step_runtime, creature_index, damage_amount, CreatureDamageType.SELF_TICK, Vec2(),
        )

    def _tick_corpse(
        self,
        idx: int,
        creature: CreatureState,
        *,
        dt: float,
        dt_ms: int,
        step_runtime: WorldStepRuntime,
        player_slots: list[PlayerState],
    ) -> None:
        state, players = step_runtime.world.state, step_runtime.world.players
        rng = state.rng
        detail_preset, violence_disabled = int(step_runtime.world.state.detail_preset), int(step_runtime.world.state.violence_disabled)
        fx_queue_rotated = step_runtime.fx_queue_rotated
        # Native performs this first death-stage tick before calling
        # creature_apply_damage for periodic poison flags.  Keeping it
        # ahead of that call matters when a corpse enters the sweep at
        # exactly 16.0: creature_apply_damage then applies its separate
        # dead-entry dt * 15 decrement before the usual dt * 28 decay.
        if creature.hp <= 0.0 and creature_lifecycle_is_alive(creature.death_timer):
            creature.death_timer = x87_pc24_sub(float(creature.death_timer), float(dt))
        self._apply_poison_tick(idx, creature, dt=dt, step_runtime=step_runtime)
        # Native still ticks AI7 link-timer state (and its RNG draws) for
        # dead creatures inside `creature_update_all`.
        if dt > 0.0 and float(state.bonuses.freeze) <= 0.0 and (int(creature.flags) & _FLAG_STOP_AND_GO) != 0:
            creature_ai7_tick_link_timer(creature, dt_ms=dt_ms, rng=rng)
        # Native's targeting block runs before the alive/dead split:
        # fading corpses still switch their target player and feed the
        # auto-target comparison.
        self._update_player_auto_target(
            players=player_slots,
            native=bool(state.preserve_bugs) or len(players) == 1,
            resolution=self._resolve_target_player(creature, player_slots, len(players)),
            creature_index=int(idx),
            creature=creature,
        )
        if dt > 0.0:
            self._tick_dead(
                creature,
                dt=dt,
                fx_queue_rotated=fx_queue_rotated,
                rng=rng,
                effects=state.effects,
                detail_preset=int(detail_preset),
                violence_disabled=int(violence_disabled),
            )

    def update(self, step_runtime: WorldStepRuntime) -> None:
        """Port of `creature_update_all` for one frame of the step runtime.

        Death side effects are initiated by damage call sites.
        """
        dt = f32(step_runtime.dt)
        world = step_runtime.world
        state = world.state
        players = world.players
        rng = state.rng
        detail_preset = int(step_runtime.world.state.detail_preset)
        violence_disabled = int(step_runtime.world.state.violence_disabled)
        fx_queue = step_runtime.fx_queue
        fx_queue_rotated = step_runtime.fx_queue_rotated
        sfx = step_runtime.sfx
        self._update_tick = int(self._update_tick) + 1
        # Native's player table always has two slots; a one-player run leaves the second dormant.
        player_slots = players
        if len(players) == 1:
            dormant = state.dormant_player
            dormant.pos = Vec2(TERRAIN_SIZE * (27.0 / 64.0), TERRAIN_SIZE * (27.0 / 64.0))
            player_slots = [players[0], dormant]
        native_auto_target = bool(state.preserve_bugs) or len(players) == 1

        evil_targets: set[int] = set()
        if bool(state.preserve_bugs):
            # Native `creature_update_all` reads one global
            # `evil_eyes_target_creature` slot (player-0 storage), even in
            # multiplayer runs.
            if PerkId.EVIL_EYES in state.perks:
                evil_target = int(players[0].evil_eyes_target_creature)
                if evil_target >= 0:
                    evil_targets.add(int(evil_target))
        else:
            # Bug-fixed path: apply all alive Evil Eyes owners.
            for player in players:
                if float(player.health) <= 0.0:
                    continue
                if PerkId.EVIL_EYES not in state.perks:
                    continue
                evil_target = int(player.evil_eyes_target_creature)
                if evil_target >= 0:
                    evil_targets.add(int(evil_target))

        # Movement + AI. Dead creatures keep updating (death slide + corpse decals)
        # even when `players` is empty so debug views remain deterministic.
        # Native AI7 timer math uses `frame_dt_ms` integer slots with ftol-style
        # truncation semantics.
        dt_ms = ftol_ms_i32(float(dt)) if dt > 0.0 else 0
        for idx, creature in enumerate(self._entries):
            if not creature.active:
                continue

            if float(creature.hit_flash_timer) > 0.0:
                creature.hit_flash_timer = f32(float(creature.hit_flash_timer) - float(dt))

            # Native `creature_update_all` gates the full per-creature body under
            # freeze; only bookkeeping outside this branch still advances.
            if float(state.bonuses.freeze) > 0.0:
                continue

            if not creature_lifecycle_is_alive(creature.death_timer) or creature.hp <= 0.0:
                self._tick_corpse(
                    idx,
                    creature,
                    dt=dt,
                    dt_ms=dt_ms,
                    step_runtime=step_runtime,
                    player_slots=player_slots,
                )
                continue

            if dt <= 0.0:
                continue

            poison_killed = self._apply_poison_tick(
                idx,
                creature,
                dt=dt,
                step_runtime=step_runtime,
            )
            # Native order runs AI7 link timer update after periodic self-damage
            # and before any live-branch kill handling/retargeting.
            creature_ai7_tick_link_timer(creature, dt_ms=dt_ms, rng=rng)

            target_resolution = self._resolve_target_player(creature, player_slots, len(players))
            self._update_player_auto_target(
                players=player_slots,
                native=native_auto_target,
                resolution=target_resolution,
                creature_index=int(idx),
                creature=creature,
            )
            player = player_slots[target_resolution.target_player]
            player_pos = player.pos
            # Native measures the AI distance before turning off a dead target.
            distance_player_pos = player_slots[target_resolution.auto_target_player].pos

            if poison_killed:
                if creature.active:
                    self._tick_dead(
                        creature,
                        dt=dt,
                        fx_queue_rotated=fx_queue_rotated,
                        rng=rng,
                        effects=state.effects,
                        detail_preset=int(detail_preset),
                        violence_disabled=int(violence_disabled),
                    )
                continue

            if creature.plague_infected:
                creature.dot_tick_timer = x87_pc24_sub(float(creature.dot_tick_timer), float(dt))
                if creature.dot_tick_timer < 0.0:
                    creature.dot_tick_timer = x87_pc24_add(
                        float(creature.dot_tick_timer),
                        f32(DOT_TICK_PERIOD),
                    )
                    creature.hp = x87_pc24_sub(float(creature.hp), f32(15.0))
                    plague_killed = False
                    if creature.hp < 0.0:
                        state.plaguebearer_infection_count += 1
                        self.handle_death(step_runtime, idx)
                        # Native plague-kill path consumes one rand draw for
                        # creature attack SFX bank-b selection after death side effects.
                        contact_sfx_options = _CREATURE_CONTACT_SFX.get(creature.type_id)
                        if contact_sfx_options is not None:
                            sfx_index = int(rng.rand_tagged(RngCallerStatic.CREATURE_UPDATE_ALL_PLAGUE_KILL_SFX)) & 1
                            sfx.append(SfxRequest(contact_sfx_options[sfx_index], creature.pos))
                        plague_killed = True

                    fx_queue.add_random(pos=creature.pos, rng=rng)
                    if plague_killed:
                        # Native keeps executing the current live-branch body after
                        # `creature_handle_death` in this timer-wrap kill path.
                        # Do not run `_tick_dead` immediately here.
                        pass

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
                distance_player_pos=distance_player_pos,
                creatures=self._entries,
                dt=dt,
            )
            move_scale = float(ai.move_scale)
            if ai.link_death_damage is not None and ai.link_death_damage > 0.0:
                # Native link-death cleanup calls creature_apply_damage(idx,
                # 1000.0, 1, zero): the full bullet path with heading-jitter
                # rand, hit flash, and the lethal death-SFX roll.
                creature_apply_damage(
                    step_runtime, idx, ai.link_death_damage, CreatureDamageType.BULLET, Vec2(),
                )

            if (float(state.bonuses.energizer) > 0.0 and float(creature.max_hp) < 500.0) or creature.plague_infected:
                creature.target_heading = heading_add_pi_f32(float(creature.target_heading))

            turn_rate = f32(float(creature.move_speed) * CREATURE_TURN_RATE_SCALE)
            if (int(creature.flags) & _FLAG_SPAWNER) == 0:
                if creature.ai_mode != CreatureAiMode.HOLD_TIMER:
                    creature.heading = _angle_approach(creature.heading, creature.target_heading, turn_rate, dt)
                    move_delta = _movement_delta_from_heading_f32(
                        creature.heading,
                        dt=dt,
                        move_scale=move_scale,
                        move_speed=creature.move_speed,
                    )
                    creature.vel = move_delta
                    # Native path (flags without 0x4): no bounds clamp here; offscreen spawns
                    # remain offscreen until their own velocity moves them in.
                    creature.pos = _advance_pos_by_delta_f32(creature.pos, move_delta)
            else:
                # Spawner/short-strip creatures clamp to bounds using `size` as a radius, once and
                # before moving (creature_update_all 0x00426220); most are stationary unless
                # SPAWNER_MOBILE is set, and a long-strip mover may step past the bound this frame.
                size = float(creature.size)
                creature.pos = Vec2(
                    _clamp_to_size_bounds(float(creature.pos.x), size, TERRAIN_SIZE),
                    _clamp_to_size_bounds(float(creature.pos.y), size, TERRAIN_SIZE),
                )
                if (int(creature.flags) & _FLAG_SPAWNER_MOBILE) == 0:
                    creature.vel = Vec2()
                else:
                    creature.heading = _angle_approach(creature.heading, creature.target_heading, turn_rate, dt)
                    move_delta = _movement_delta_from_heading_f32(
                        creature.heading,
                        dt=dt,
                        move_scale=move_scale,
                        move_speed=creature.move_speed,
                    )
                    creature.vel = move_delta
                    creature.pos = _advance_pos_by_delta_f32(creature.pos, move_delta)

                # Native ticks owner-bound spawn slots inside the spawner movement
                # branch, before this creature's plaguebearer/anim/ranged/contact
                # rand draws; children spawned here are visited later in the same
                # pass when their slot index is above the current one.
                if dt > 0.0 and float(state.bonuses.freeze) <= 0.0 and (int(creature.flags) & _FLAG_SPAWNER) != 0:
                    child_template_id = tick_spawn_slot(self.spawn_slots[creature.link_index], dt)
                    if child_template_id is not None:
                        self.spawn_template(
                            child_template_id,
                            creature.pos,
                            float(RANDOM_HEADING_SENTINEL),
                            state=state,
                            detail_preset=int(detail_preset),
                        )

            if (
                players
                and PerkId.PLAGUEBEARER in state.perks
                and int(state.plaguebearer_infection_count) < 0x3C
            ):
                self._plaguebearer_spread_infection(int(idx))

            creature.anim_phase, _ = creature_anim_advance_phase(
                creature.anim_phase,
                anim_rate=CREATURE_ANIM[creature.type_id].anim_rate,
                move_speed=float(creature.move_speed),
                dt=dt,
                size=float(creature.size),
                local_scale=move_scale,
                flags=creature.flags,
                ai_mode=int(creature.ai_mode),
            )

            # Native decrements contact/ranged cooldown before interaction checks,
            # then lets contact hits raise it back by +1.0 in the same frame.
            if creature.attack_cooldown <= 0.0:
                creature.attack_cooldown = 0.0
            else:
                creature.attack_cooldown = x87_pc24_sub(creature.attack_cooldown, dt)

            # Native computes this once at 0x00426f65..0x00426f9c, stores the
            # PC=24 fsqrt result as f32, and reuses that scalar for the 100,
            # 64, 20, and 30-unit interaction gates below.
            target_dx = x87_pc24_sub(float(creature.pos.x), float(player_pos.x))
            target_dy = x87_pc24_sub(float(creature.pos.y), float(player_pos.y))
            target_dist = x87_pc24_hypot(target_dx, target_dy)

            # Native radioactive contact pulse runs after movement/AI/cooldown
            # synthesis inside the live-creature branch. The distance is measured
            # to the creature's target player, the perk gate reads player slot
            # zero, the kill XP is credited to player 1, and the timer-fire
            # requires the creature to still be alive (hp > 0).
            if PerkId.RADIOACTIVE in state.perks and target_dist < 100.0:
                pulse_timer_step = x87_pc24_mul(float(dt), f32(1.5))
                creature.dot_tick_timer = x87_pc24_sub(
                    float(creature.dot_tick_timer),
                    pulse_timer_step,
                )
                if creature.dot_tick_timer < 0.0 and float(creature.hp) > 0.0:
                    creature.dot_tick_timer = DOT_TICK_PERIOD
                    pulse_damage = x87_pc24_mul(
                        x87_pc24_sub(f32(100.0), target_dist),
                        f32(0.3),
                    )
                    creature.hp = x87_pc24_sub(float(creature.hp), pulse_damage)
                    fx_queue.add_random(pos=creature.pos, rng=rng)

                    if creature.hp < 0.0:
                        if creature.type_id == CreatureTypeId.LIZARD:
                            creature.hp = 1.0
                        else:
                            players[0].experience = experience_plus_reward(
                                players[0].experience,
                                creature.reward_value,
                            )
                            creature.death_timer = x87_pc24_sub(
                                float(creature.death_timer),
                                float(dt),
                            )

            if (not frozen_by_evil_eyes) and (  # noqa: SIM102 - preserve the native ranged-fire branch shape
                int(creature.flags) & _FLAG_RANGED
            ):
                # Ported from creature_update_all @ 0x00426220, around the
                # 0x004276xx ranged-fire branch.
                if target_dist > 64.0 and creature.attack_cooldown <= 0.0:
                    if creature.flags & CreatureFlags.RANGED_PLASMA_RIFLE:
                        type_id = ProjectileTemplateId.PLASMA_RIFLE
                        projectile_spawn(
                            state,
                            players=players,
                            pos=creature.pos,
                            angle=float(creature.heading),
                            type_id=type_id,
                            owner_id=int(idx),
                            owner_player_index=0,
                        )
                        sfx.append(SfxRequest(SfxId.SHOCK_FIRE, creature.pos))
                        creature.attack_cooldown = x87_pc24_add(f32(creature.attack_cooldown), f32(1.0))

                    if (creature.flags & CreatureFlags.RANGED_TEMPLATE_PROJECTILE) and creature.attack_cooldown <= 0.0:
                        projectile_type = ProjectileTemplateId(creature.ranged_projectile_type)
                        projectile_spawn(
                            state,
                            players=players,
                            pos=creature.pos,
                            angle=float(creature.heading),
                            type_id=projectile_type,
                            owner_id=int(idx),
                            owner_player_index=0,
                        )
                        sfx.append(SfxRequest(SfxId.PLASMAMINIGUN_FIRE, creature.pos, gain=0.8))
                        randomized_cooldown = x87_pc24_mul(
                            float(rng.rand_tagged(RngCallerStatic.CREATURE_UPDATE_ALL_PLASMAMINIGUN_COOLDOWN) & 3),
                            f32(0.1),
                        )
                        creature.attack_cooldown = x87_pc24_add(
                            x87_pc24_add(randomized_cooldown, f32(creature.orbit_angle)),
                            f32(creature.attack_cooldown),
                        )

            # `creature_update_all` 0x00426f65..0x004276d6: the contact interactions reuse the stored
            # creature-to-target distance.
            if target_dist < 20.0:
                # Native stores `vel` as the per-tick delta, so this undoes the move just applied.
                creature.pos = Vec2(
                    x87_pc24_sub(creature.pos.x, creature.vel.x),
                    x87_pc24_sub(creature.pos.y, creature.vel.y),
                )
                if creature.max_hp < 380.0 and state.bonuses.energizer > 0.0:
                    # Native double-pays the eat kill: this direct store plus creature_handle_death's award.
                    players[0].experience = experience_plus_reward(players[0].experience, creature.reward_value)
                    state.effects.spawn_burst(pos=creature.pos, count=6, rng=rng, detail_preset=detail_preset)
                    sfx.append(SfxRequest(SfxId.UI_BONUS, creature.pos, gain=0.8))
                    state.scripted_burst_active = True
                    self.handle_death(step_runtime, idx, keep_corpse=False)
                    state.scripted_burst_active = False

            # Native has no aliveness re-check here: a creature plague-killed earlier in the tick
            # can still bite.
            if (
                creature.size > 16.0 and target_dist < 30.0 and player.health > 0.0 and state.bonuses.energizer <= 0.0
            ):
                if creature.attack_cooldown <= 0.0:
                    contact_sfx = _CREATURE_CONTACT_SFX.get(creature.type_id)
                    if contact_sfx is not None:
                        roll = rng.rand_tagged(RngCallerStatic.CREATURE_UPDATE_ALL_CONTACT_SFX)
                        sfx.append(SfxRequest(contact_sfx[roll & 1], creature.pos))
                    if PerkId.MR_MELEE in state.perks:
                        creature_apply_damage(
                            step_runtime, idx, 25.0, CreatureDamageType.MELEE, Vec2(),
                        )
                    if player.shield_timer <= 0.0:
                        if PerkId.TOXIC_AVENGER in state.perks:
                            creature.flags |= CreatureFlags.POISONED | CreatureFlags.POISONED_STRONG
                        elif PerkId.VEINS_OF_POISON in state.perks:
                            creature.flags |= CreatureFlags.POISONED
                    player_take_damage(step_runtime, player, creature.contact_damage, dt=dt)
                    push_dir = x87_d3dx_vec2_normalize(
                        Vec2(x87_pc24_sub(player.pos.x, creature.pos.x), x87_pc24_sub(player.pos.y, creature.pos.y)),
                    )
                    fx_queue.add_random(
                        pos=Vec2(
                            x87_pc24_add(player.pos.x, x87_pc24_mul(push_dir.x, f32(3.0))),
                            x87_pc24_add(player.pos.y, x87_pc24_mul(push_dir.y, f32(3.0))),
                        ),
                        rng=rng,
                    )
                    creature.attack_cooldown = x87_pc24_add(f32(creature.attack_cooldown), f32(1.0))

                if player.plaguebearer_active and creature.hp < 150.0 and state.plaguebearer_infection_count < 0x32:
                    creature.plague_infected = True

            # Small creatures die on contact without creature_handle_death (no XP, no bonus drop);
            # the corpse staging still counts the kill later.
            if target_dist < 30.0 and creature.size <= 30.0:
                creature.hp = 0.0
                creature.death_timer = f32(float(creature.death_timer) - float(dt))

    def handle_death(self, step_runtime: WorldStepRuntime, idx: int, *, keep_corpse: bool = True) -> None:
        """Port of `creature_handle_death` (0x0041e910), recording the frame's `CreatureDeath` event.

        The forced drop and the Survival death sample run on every call; the rest only for an
        active creature: spawn-slot release, split-on-death children, the corpse step (or
        deactivation), player one's XP, the kill-drop roll, then the Freeze shatter.
        """

        state = step_runtime.world.state
        players = step_runtime.world.players
        rng = state.rng
        detail_preset = state.detail_preset
        creature = self._entries[idx]
        if (creature.flags & CreatureFlags.BONUS_ON_DEATH) and creature.bonus_id is not None:
            # Native `bonus_spawn_at` clamps through the creature pos pointer
            # (also in rush, where no bonus spawns), moving the corpse to the
            # 32-px world margin, and spawns a 16-particle pickup burst.
            creature.pos = creature.pos.clamp_rect(
                BONUS_SPAWN_MARGIN,
                BONUS_SPAWN_MARGIN,
                TERRAIN_SIZE - BONUS_SPAWN_MARGIN,
                TERRAIN_SIZE - BONUS_SPAWN_MARGIN,
            )
            state.bonus_pool.spawn_at(
                pos=creature.pos,
                bonus_id=creature.bonus_id,
                amount_override=-1 if creature.bonus_amount_override is None else creature.bonus_amount_override,
                state=state,
                detail_preset=detail_preset,
            )
            # Native drops it again whenever this death is handled again (original bug 33).
            if not state.preserve_bugs:
                creature.bonus_id = None
                creature.bonus_amount_override = None
        survival_record_first_kill(state, pos=creature.pos)
        # Re-entrant calls (the secondary detonation follow-up) land on an already deactivated creature.
        if not creature.active:
            step_runtime.deaths.append(
                CreatureDeath(
                    index=idx,
                    pos=creature.pos,
                    type_id=creature.type_id,
                    reward_value=creature.reward_value,
                    xp_awarded=0,
                ),
            )
            return

        self._release_spawn_slot(creature)

        if (creature.flags & CreatureFlags.SPLIT_ON_DEATH) and creature.size > 35.0:
            for heading_offset, phase_seed_caller in (
                (-NATIVE_HALF_PI, RngCallerStatic.CREATURE_HANDLE_DEATH_SPLIT_CHILD_1_PHASE_SEED),
                (NATIVE_HALF_PI, RngCallerStatic.CREATURE_HANDLE_DEATH_SPLIT_CHILD_2_PHASE_SEED),
            ):
                # The struct copy from the parent overwrites what `creature_alloc_slot` seeded;
                # a full pool copies the child into the phantom slot.
                child_idx = self.alloc_slot(rng)
                child = msgspec.structs.replace(creature, generation=self.creature(child_idx).generation)
                child.phase_seed = rng.rand_tagged(phase_seed_caller) & 0xFF
                # Native stores `heading +- 1.5707964f` unwrapped and leaves
                # `target_heading` as the parent's stale copy.
                child.heading = f32(creature.heading + heading_offset)
                child.hp = f32(creature.max_hp * f32(0.25))
                # Native multiplies by the f32 literal 0.6666667.
                child.reward_value = f32(child.reward_value * f32(0.6666667))
                child.size = f32(child.size - f32(8.0))
                child.move_speed = f32(child.move_speed + f32(0.1))
                child.contact_damage = f32(child.contact_damage * f32(0.7))
                child.death_timer = CREATURE_LIFECYCLE_ALIVE
                if child_idx == PHANTOM_CREATURE_INDEX:
                    self.phantom = child
                else:
                    self._entries[child_idx] = child
            state.effects.spawn_burst(pos=creature.pos, count=8, rng=rng, detail_preset=detail_preset)

        if keep_corpse:
            creature.death_timer = x87_pc24_sub(creature.death_timer, f32(step_runtime.dt))
        else:
            creature.active = False

        # Native credits every kill to player one; score and level-ups read only that player.
        killer = players[0]
        experience_before = killer.experience
        quick_learner = PerkId.BLOODY_MESS_QUICK_LEARNER in state.perks
        # Double Experience repeats the whole award block.
        for _ in range(2 if state.bonuses.double_experience > 0.0 else 1):
            if quick_learner:
                killer.experience += quick_learner_kill_xp(creature.reward_value)
            else:
                killer.experience = experience_plus_reward(killer.experience, creature.reward_value)

        if not state.scripted_burst_active:
            state.bonus_pool.try_spawn_on_kill(pos=creature.pos, state=state, players=players, detail_preset=detail_preset)

        if state.bonuses.freeze > 0.0:
            for _ in range(8):
                angle = x87_pc24_mul(
                    float(rng.rand_tagged(RngCallerStatic.CREATURE_HANDLE_DEATH_FREEZE_SHARD_ANGLE) % 612),
                    f32(0.01),
                )
                state.effects.spawn_freeze_shard(pos=creature.pos, angle=angle, rng=rng, detail_preset=detail_preset)
            angle = x87_pc24_mul(
                float(rng.rand_tagged(RngCallerStatic.CREATURE_HANDLE_DEATH_FREEZE_SHATTER_ANGLE) % 612),
                f32(0.01),
            )
            state.effects.spawn_freeze_shatter(pos=creature.pos, angle=angle, rng=rng, detail_preset=detail_preset)
            self.kill_count += 1
            creature.active = False
            step_runtime.fx_queue.add_random(pos=creature.pos, rng=rng)

        step_runtime.deaths.append(
            CreatureDeath(
                index=idx,
                pos=creature.pos,
                type_id=creature.type_id,
                reward_value=creature.reward_value,
                xp_awarded=killer.experience - experience_before,
            ),
        )

    def _release_spawn_slot(self, creature: CreatureState) -> None:
        """A dying or culled spawner (flag 0x4) frees the spawn slot in its `link_index`."""

        if int(creature.flags) & _FLAG_SPAWNER:
            self.spawn_slots[creature.link_index].owner_creature = -1

    def _tick_dead(
        self,
        creature: CreatureState,
        *,
        dt: float,
        fx_queue_rotated: FxQueueRotated,
        rng: CrandLike,
        effects: EffectPool,
        detail_preset: int,
        violence_disabled: int,
    ) -> None:
        """Advance the post-death death_timer ramp and queue corpse decals.

        This matches the `death_timer` death staging inside `creature_update_all`:
        - while death_timer > 0: decrement quickly and slide backwards
        - once death_timer <= 0: queue a corpse decal and fade out until < -10, then deactivate.
        """

        if dt <= 0.0:
            return

        dt_f32 = f32(dt)
        death_timer = f32(creature.death_timer)
        if death_timer <= 0.0:
            creature.death_timer = f32(
                death_timer - f32(float(dt_f32) * CREATURE_CORPSE_FADE_DECAY),
            )
            return

        mobile = (int(creature.flags) & _FLAG_SPAWNER) == 0 or (
            int(creature.flags) & _FLAG_SPAWNER_MOBILE
        ) != 0

        next_death_timer = f32(
            death_timer - f32(float(dt_f32) * CREATURE_DEATH_TIMER_DECAY),
        )
        creature.death_timer = f32(next_death_timer)
        if next_death_timer > 0.0:
            if mobile:
                # Preserve native x87 operation order for the death-slide
                # velocity: trig * lifecycle * frame_dt * 9, narrowing after
                # each multiply in the game's 24-bit precision mode.
                radians = x87_pc24_sub(f32(creature.heading), NATIVE_HALF_PI)
                vel_x = x87_pc24_cos_mul(
                    radians,
                    float(next_death_timer),
                    float(dt_f32),
                    f32(CREATURE_DEATH_SLIDE_SCALE),
                )
                vel_y = x87_pc24_sin_mul(
                    radians,
                    float(next_death_timer),
                    float(dt_f32),
                    f32(CREATURE_DEATH_SLIDE_SCALE),
                )
                creature.vel = Vec2(
                    vel_x,
                    vel_y,
                )
                creature.pos = Vec2(
                    f32(float(creature.pos.x) - float(creature.vel.x)),
                    f32(float(creature.pos.y) - float(creature.vel.y)),
                )
            else:
                creature.vel = Vec2()
            return

        # death_timer just crossed <= 0: bake a persistent corpse decal into the ground.
        if int(violence_disabled) == 0:
            corpse_size = f32(creature.size)
            corpse_half_size = x87_pc24_mul(corpse_size, 0.5)
            # Native gives pinned spawners the fallback corpse id 7.
            corpse_type_id = int(creature.type_id) if mobile else 7
            ok = fx_queue_rotated.add(
                top_left=Vec2(
                    x87_pc24_sub(f32(creature.pos.x), corpse_half_size),
                    x87_pc24_sub(f32(creature.pos.y), corpse_half_size),
                ),
                rgba=creature.tint,
                rotation=float(creature.heading),
                scale=corpse_size,
                creature_type_id=corpse_type_id,
            )
            if not ok:
                creature.death_timer = f32(0.001)
                return

        self.kill_count += 1

        # Native `creature_update_all` emits a 19-splatter blood burst when a
        # spawner corpse first reaches this staged kill point.
        if (
            int(violence_disabled) == 0
            and (int(creature.flags) & _FLAG_SPAWNER) != 0
        ):
            for count, age, angle_caller in (
                (8, 0.0, RngCallerStatic.CREATURE_UPDATE_ALL_SPAWNER_BLOOD_8_ANGLE),
                (6, -0.07, RngCallerStatic.CREATURE_UPDATE_ALL_SPAWNER_BLOOD_6_ANGLE),
                (5, -0.12, RngCallerStatic.CREATURE_UPDATE_ALL_SPAWNER_BLOOD_5_ANGLE),
            ):
                for _ in range(int(count)):
                    angle = x87_pc24_mul(float(int(rng.rand_tagged(angle_caller)) % 612), f32(0.01))
                    effects.spawn_blood_splatter(
                        pos=creature.pos,
                        angle=float(angle),
                        age=float(age),
                        rng=rng,
                        detail_preset=int(detail_preset),
                        violence_disabled=int(violence_disabled),
                    )

    def finalize_post_render_lifecycle(self) -> None:
        """Mirror render-time corpse culling from native `creature_render_type`.

        Native deactivates entries only after draw once `death_timer < -10.0`. Keeping
        this outside `creature_update_all` preserves slot-allocation timing for same-tick
        survival/rush spawns.
        """

        for creature in self._entries:
            if not creature.active:
                continue
            if classify_creature_lifecycle(creature.death_timer) != CreatureLifecyclePhase.DESPAWNED:
                continue
            self._release_spawn_slot(creature)
            creature.active = False
