from __future__ import annotations

from dataclasses import dataclass, field
import math
from typing import TYPE_CHECKING, Sequence

from grim.geom import Vec2
from grim.rand import Crand
from .bonuses.freeze import DeferredFreezeCorpseFx
from .bonuses.hud import BonusHudState
from .bonuses.pool import BonusPool
from .effects import EffectPool, ParticlePool, SpriteEffectPool
from .game_modes import GameMode
from .math_parity import f32
from .perks import PerkId
from .perks.helpers import perk_active
from .perks.runtime.player_ticks import apply_player_perk_ticks
from .perks.selection import perk_auto_pick
from .perks.state import CreatureForPerks, PerkEffectIntervals, PerkSelectionState
from .projectiles import (
    Damageable,
    ProjectilePool,
    ProjectileTypeId,
    SecondaryProjectilePool,
)
from .weapon_runtime import (
    owner_id_for_player as _owner_id_for_player,
    owner_id_for_player_projectiles as _owner_id_for_player_projectiles,
    player_fire_weapon as _player_fire_weapon,
    player_start_reload as _player_start_reload,
    player_swap_alt_weapon as _player_swap_alt_weapon,
    projectile_spawn as _projectile_spawn,
    spawn_projectile_ring as _spawn_projectile_ring,
    weapon_entry as _weapon_entry,
    weapon_assign_player as _weapon_assign_player,
)
from .weapons import WEAPON_TABLE, WeaponId
from .sim.state_types import PERK_COUNT_SIZE

if TYPE_CHECKING:
    from .persistence.save_status import GameStatus
    from .sim.input import PlayerInput
    from .sim.state_types import PlayerState


WEAPON_COUNT_SIZE = max(int(entry.weapon_id) for entry in WEAPON_TABLE) + 1


@dataclass(slots=True)
class BonusTimers:
    weapon_power_up: float = 0.0
    reflex_boost: float = 0.0
    energizer: float = 0.0
    double_experience: float = 0.0
    freeze: float = 0.0


_RELOAD_PRELOAD_UNDERFLOW_EPS = 1e-7


@dataclass(slots=True)
class GameplayState:
    rng: Crand = field(default_factory=lambda: Crand(0xBEEF))
    effects: EffectPool = field(default_factory=EffectPool)
    particles: ParticlePool = field(init=False)
    sprite_effects: SpriteEffectPool = field(init=False)
    projectiles: ProjectilePool = field(default_factory=ProjectilePool)
    secondary_projectiles: SecondaryProjectilePool = field(default_factory=SecondaryProjectilePool)
    bonuses: BonusTimers = field(default_factory=BonusTimers)
    time_scale_active: bool = False
    perk_intervals: PerkEffectIntervals = field(default_factory=PerkEffectIntervals)
    lean_mean_exp_timer: float = 0.25
    jinxed_timer: float = 0.0
    plaguebearer_infection_count: int = 0
    perk_selection: PerkSelectionState = field(default_factory=PerkSelectionState)
    sfx_queue: list[str] = field(default_factory=list)
    game_mode: int = int(GameMode.SURVIVAL)
    demo_mode_active: bool = False
    hardcore: bool = False
    preserve_bugs: bool = False
    status: GameStatus | None = None
    quest_stage_major: int = 0
    quest_stage_minor: int = 0
    perk_available: list[bool] = field(default_factory=lambda: [False] * PERK_COUNT_SIZE)
    _perk_available_unlock_index: int = -1
    weapon_available: list[bool] = field(default_factory=lambda: [False] * WEAPON_COUNT_SIZE)
    _weapon_available_game_mode: int = -1
    _weapon_available_unlock_index: int = -1
    _weapon_available_unlock_index_full: int = -1
    friendly_fire_enabled: bool = False
    bonus_spawn_guard: bool = False
    bonus_hud: BonusHudState = field(default_factory=BonusHudState)
    bonus_pool: BonusPool = field(default_factory=BonusPool)
    deferred_freeze_corpse_fx: list[DeferredFreezeCorpseFx] = field(default_factory=list)
    shock_chain_links_left: int = 0
    shock_chain_projectile_id: int = -1
    survival_reward_weapon_guard_id: int = int(WeaponId.PISTOL)
    survival_reward_handout_enabled: bool = True
    survival_reward_fire_seen: bool = False
    survival_reward_damage_seen: bool = False
    survival_recent_death_pos: list[Vec2] = field(default_factory=lambda: [Vec2(), Vec2(), Vec2()])
    survival_recent_death_count: int = 0
    camera_shake_offset: Vec2 = field(default_factory=Vec2)
    camera_shake_timer: float = 0.0
    camera_shake_pulses: int = 0
    shots_fired: list[int] = field(default_factory=lambda: [0] * 4)
    shots_hit: list[int] = field(default_factory=lambda: [0] * 4)
    weapon_shots_fired: list[list[int]] = field(default_factory=lambda: [[0] * WEAPON_COUNT_SIZE for _ in range(4)])
    debug_god_mode: bool = False

    def __post_init__(self) -> None:
        rand = self.rng.rand
        self.particles = ParticlePool(rand=rand)
        self.sprite_effects = SpriteEffectPool(rand=rand)


def build_gameplay_state() -> GameplayState:
    return GameplayState()


def player_frame_dt_after_roundtrip(*, dt: float, time_scale_active: bool, reflex_boost_timer: float) -> float:
    """Mirror `player_update` frame_dt round-trip under Reflex Boost.

    Native scales frame_dt for movement (`* 0.6 / _time_scale_factor`) and then
    restores it with `* _time_scale_factor * 1.6666666` before returning.
    """

    dt_f32 = float(f32(float(dt)))
    if not bool(time_scale_active) or dt_f32 <= 0.0:
        return float(dt_f32)

    reflex_f32 = float(f32(float(reflex_boost_timer)))
    time_scale_factor = float(f32(0.3))
    if reflex_f32 < 1.0:
        time_scale_factor = float(f32((1.0 - float(reflex_f32)) * 0.7 + 0.3))
    if time_scale_factor <= 0.0:
        return float(dt_f32)

    movement_dt = float(f32((0.6 / float(time_scale_factor)) * float(dt_f32)))
    roundtrip_dt = float(f32(float(time_scale_factor) * float(movement_dt) * 1.6666666))
    return float(roundtrip_dt)


def award_experience(state: GameplayState, player: PlayerState, amount: int) -> int:
    """Grant XP while honoring active bonus multipliers."""

    xp = int(amount)
    if xp <= 0:
        return 0
    if state.bonuses.double_experience > 0.0:
        xp *= 2
    player.experience += xp
    return xp


def _award_experience_once_from_reward(player: PlayerState, reward_value: float) -> int:
    """Mirror native `__ftol(player_xp + reward_value)` accumulation for one award."""

    reward_f32 = f32(float(reward_value))
    if float(reward_f32) <= 0.0:
        return 0

    before = int(player.experience)
    total_f32 = f32(f32(float(before)) + float(reward_f32))
    after = int(float(total_f32))
    player.experience = int(after)
    return int(after - before)


def award_experience_from_reward(state: GameplayState, player: PlayerState, reward_value: float) -> int:
    """Grant kill XP from floating reward values with native float32 store semantics."""

    gained = _award_experience_once_from_reward(player, float(reward_value))
    if gained <= 0:
        return 0
    if state.bonuses.double_experience > 0.0:
        gained += _award_experience_once_from_reward(player, float(reward_value))
    return int(gained)


def survival_level_threshold(level: int) -> int:
    """Return the XP threshold for advancing past the given level."""

    level = max(1, int(level))
    return int(1000.0 + (math.pow(float(level), 1.8) * 1000.0))


def survival_check_level_up(player: PlayerState, perk_state: PerkSelectionState) -> int:
    """Advance survival levels if XP exceeds thresholds, returning number of level-ups."""

    advanced = 0
    while player.experience > survival_level_threshold(player.level):
        player.level += 1
        perk_state.pending_count += 1
        perk_state.choices_dirty = True
        advanced += 1
    return advanced


def survival_progression_update(
    state: GameplayState,
    players: list[PlayerState],
    *,
    game_mode: int,
    player_count: int | None = None,
    auto_pick: bool = True,
    dt: float | None = None,
    creatures: Sequence[CreatureForPerks] | None = None,
) -> list[PerkId]:
    """Advance survival level/perk progression and optionally auto-pick perks."""

    if not players:
        return []
    if player_count is None:
        player_count = len(players)
    survival_check_level_up(players[0], state.perk_selection)
    if auto_pick:
        return perk_auto_pick(
            state,
            players,
            state.perk_selection,
            game_mode=game_mode,
            player_count=player_count,
            dt=dt,
            creatures=creatures,
        )
    return []


_SURVIVAL_RECENT_DEATH_CENTROID_SCALE = 0.33333334


def survival_record_recent_death(state: GameplayState, *, pos: Vec2) -> None:
    """Track Survival recent-death samples used by one-off weapon handout gating."""

    recent_count = int(state.survival_recent_death_count)
    if recent_count >= 6:
        return

    if recent_count < 3:
        state.survival_recent_death_pos[recent_count] = Vec2(
            f32(float(pos.x)),
            f32(float(pos.y)),
        )

    recent_count += 1
    state.survival_recent_death_count = int(recent_count)
    if recent_count == 3:
        state.survival_reward_fire_seen = False
        state.survival_reward_handout_enabled = False


def survival_update_weapon_handouts(
    state: GameplayState,
    players: list[PlayerState],
    *,
    survival_elapsed_ms: float,
) -> None:
    """Apply native `survival_update` one-off Survival weapon handout checks."""

    if len(players) != 1:
        return
    player = players[0]

    if (
        (not bool(state.survival_reward_damage_seen))
        and (not bool(state.survival_reward_fire_seen))
        and int(float(survival_elapsed_ms)) > 64000
        and bool(state.survival_reward_handout_enabled)
    ):
        if int(player.weapon_id) == int(WeaponId.PISTOL):
            _weapon_assign_player(player, int(WeaponId.SHRINKIFIER_5K), state=state)
            state.survival_reward_weapon_guard_id = int(WeaponId.SHRINKIFIER_5K)
        state.survival_reward_handout_enabled = False
        state.survival_reward_damage_seen = True
        state.survival_reward_fire_seen = True

    if int(state.survival_recent_death_count) == 3 and (not bool(state.survival_reward_fire_seen)):
        pos0, pos1, pos2 = state.survival_recent_death_pos
        centroid_x = f32(float(f32(float(pos0.x) + float(pos1.x) + float(pos2.x))) * _SURVIVAL_RECENT_DEATH_CENTROID_SCALE)
        centroid_y = f32(float(f32(float(pos0.y) + float(pos1.y) + float(pos2.y))) * _SURVIVAL_RECENT_DEATH_CENTROID_SCALE)
        dx = float(player.pos.x) - float(centroid_x)
        dy = float(player.pos.y) - float(centroid_y)
        if math.sqrt(dx * dx + dy * dy) < 16.0 and float(player.health) < 15.0:
            _weapon_assign_player(player, int(WeaponId.BLADE_GUN), state=state)
            state.survival_reward_weapon_guard_id = int(WeaponId.BLADE_GUN)
            state.survival_reward_fire_seen = True
            state.survival_reward_handout_enabled = False


def survival_enforce_reward_weapon_guard(state: GameplayState, players: Sequence[PlayerState]) -> None:
    """Revoke temporary Survival handout weapons when guard id mismatches."""

    guard_id = int(state.survival_reward_weapon_guard_id)
    for player in players:
        weapon_id = int(player.weapon_id)
        if weapon_id == int(WeaponId.BLADE_GUN) and guard_id != int(WeaponId.BLADE_GUN):
            _weapon_assign_player(player, int(WeaponId.PISTOL))
        if weapon_id == int(WeaponId.SHRINKIFIER_5K) and guard_id != int(WeaponId.SHRINKIFIER_5K):
            _weapon_assign_player(player, int(WeaponId.PISTOL))


def player_update(
    player: PlayerState,
    input_state: PlayerInput,
    dt: float,
    state: GameplayState,
    *,
    detail_preset: int = 5,
    world_size: float = 1024.0,
    players: list[PlayerState] | None = None,
    creatures: Sequence[Damageable] | None = None,
) -> None:
    """Port of `player_update` (0x004136b0) for the rewrite runtime."""

    dt = float(f32(float(dt)))
    if dt <= 0.0:
        return

    prev_pos = player.pos

    if player.health <= 0.0:
        player.death_timer -= dt * 20.0
        return

    player.muzzle_flash_alpha = max(0.0, player.muzzle_flash_alpha - dt * 2.0)
    cooldown_decay = float(f32(float(dt) * (1.5 if state.bonuses.weapon_power_up > 0.0 else 1.0)))
    next_shot_cooldown = float(f32(float(player.shot_cooldown) - float(cooldown_decay)))
    player.shot_cooldown = max(0.0, float(next_shot_cooldown))
    if 0.0 < float(player.shot_cooldown) < 1e-6:
        player.shot_cooldown = 0.0

    if perk_active(player, PerkId.SHARPSHOOTER):
        player.spread_heat = 0.02
    else:
        player.spread_heat = max(0.01, player.spread_heat - dt * 0.4)

    speed_bonus_active = player.speed_bonus_timer > 0.0
    if player.aux_timer > 0.0:
        aux_decay = 1.4 if player.aux_timer >= 1.0 else 0.5
        player.aux_timer = max(0.0, player.aux_timer - dt * aux_decay)

    # Aim: compute direction from (player -> aim point).
    player.aim = input_state.aim
    aim_dir = (player.aim - player.pos).normalized()
    if aim_dir.length_sq() > 0.0:
        player.aim_dir = aim_dir
        player.aim_heading = aim_dir.to_heading()

    speed_multiplier = float(player.speed_multiplier)
    if speed_bonus_active:
        speed_multiplier += 1.0

    movement_dt = float(dt)
    if state.time_scale_active and movement_dt > 0.0:
        reflex_f32 = float(f32(float(state.bonuses.reflex_boost)))
        time_scale_factor = float(f32(0.3))
        if reflex_f32 < 1.0:
            time_scale_factor = float(f32((1.0 - float(reflex_f32)) * 0.7 + 0.3))
        if time_scale_factor > 0.0:
            # Native computes `frame_dt = (0.6 / _time_scale_factor) * frame_dt`
            # and stores back to float before movement/heading logic.
            movement_dt = float(f32((0.6 / float(time_scale_factor)) * float(movement_dt)))

    # Movement.
    raw_move = input_state.move
    raw_mag = raw_move.length()
    use_digital_move = (
        input_state.move_forward_pressed is not None
        and input_state.move_backward_pressed is not None
        and input_state.turn_left_pressed is not None
        and input_state.turn_right_pressed is not None
    )
    phase_sign = 1.0
    if use_digital_move:
        moving_forward = bool(input_state.move_forward_pressed)
        moving_backward = bool(input_state.move_backward_pressed)
        turning_left = bool(input_state.turn_left_pressed)
        turning_right = bool(input_state.turn_right_pressed)

        player.turn_speed = min(7.0, max(1.0, float(player.turn_speed)))
        turned = False
        # Native keyboard mode checks left first, then right (`player_update` mode 1),
        # so simultaneous turn keys resolve to left turn.
        if turning_left:
            player.turn_speed = float(player.turn_speed + movement_dt * 10.0)
            turn_delta = float(player.turn_speed) * movement_dt * 0.5
            player.heading = float(player.heading - turn_delta)
            player.aim_heading = float(player.aim_heading - turn_delta)
            turned = True
        elif turning_right:
            player.turn_speed = float(player.turn_speed + movement_dt * 10.0)
            turn_delta = float(player.turn_speed) * movement_dt * 0.5
            player.heading = float(player.heading + turn_delta)
            player.aim_heading = float(player.aim_heading + turn_delta)
            turned = True

        move_sign = 1.0
        # Native movement-key precedence is forward before backward.
        if moving_forward:
            if perk_active(player, PerkId.LONG_DISTANCE_RUNNER):
                if player.move_speed < 2.0:
                    player.move_speed = float(player.move_speed + movement_dt * 4.0)
                player.move_speed = float(player.move_speed + movement_dt)
                if player.move_speed > 2.8:
                    player.move_speed = 2.8
            else:
                player.move_speed = float(player.move_speed + movement_dt * 5.0)
                if player.move_speed > 2.0:
                    player.move_speed = 2.0
        elif moving_backward:
            if perk_active(player, PerkId.LONG_DISTANCE_RUNNER):
                if player.move_speed < 2.0:
                    player.move_speed = float(player.move_speed + movement_dt * 4.0)
                player.move_speed = float(player.move_speed + movement_dt)
                if player.move_speed > 2.8:
                    player.move_speed = 2.8
            else:
                player.move_speed = float(player.move_speed + movement_dt * 5.0)
                if player.move_speed > 2.0:
                    player.move_speed = 2.0
            move_sign = -1.0
            phase_sign = -1.0
        else:
            if not turned:
                player.turn_speed = 1.0
            player.move_speed = float(player.move_speed - movement_dt * 15.0)
            if player.move_speed < 0.0:
                player.move_speed = 0.0

        if player.weapon_id == WeaponId.MEAN_MINIGUN and player.move_speed > 0.8:
            player.move_speed = 0.8

        move = Vec2.from_heading(player.heading)
        speed = player.move_speed * speed_multiplier * 25.0 * move_sign
        if perk_active(player, PerkId.ALTERNATE_WEAPON):
            speed *= 0.8
    else:
        # Demo/autoplay uses very small analog magnitudes to represent turn-in-place and
        # heading alignment slowdown; don't apply a deadzone there.
        moving_input = raw_mag > (0.0 if state.demo_mode_active else 0.2)

        turn_alignment_scale = 1.0
        if moving_input:
            inv = 1.0 / raw_mag if raw_mag > 1e-9 else 0.0
            move = raw_move * inv
            # Native normalizes this heading into [0, 2pi] before calling
            # `player_heading_approach_target` (see ghidra @ 0x00413fxx).
            target_heading = _normalize_heading_angle(move.to_heading())
            angle_diff = _player_heading_approach_target(player, target_heading, movement_dt)
            move = Vec2.from_heading(player.heading)
            turn_alignment_scale = max(0.0, (math.pi - angle_diff) / math.pi)
            if perk_active(player, PerkId.LONG_DISTANCE_RUNNER):
                if player.move_speed < 2.0:
                    player.move_speed = float(player.move_speed + movement_dt * 4.0)
                player.move_speed = float(player.move_speed + movement_dt)
                if player.move_speed > 2.8:
                    player.move_speed = 2.8
            else:
                player.move_speed = float(player.move_speed + movement_dt * 5.0)
                if player.move_speed > 2.0:
                    player.move_speed = 2.0
        else:
            player.move_speed = float(player.move_speed - movement_dt * 15.0)
            if player.move_speed < 0.0:
                player.move_speed = 0.0
            move = Vec2.from_heading(player.heading)

        if player.weapon_id == WeaponId.MEAN_MINIGUN and player.move_speed > 0.8:
            player.move_speed = 0.8

        speed = player.move_speed * speed_multiplier * 25.0
        if moving_input:
            speed *= min(1.0, raw_mag)
            speed *= turn_alignment_scale
        if perk_active(player, PerkId.ALTERNATE_WEAPON):
            speed *= 0.8

    # Native movement stores through float32 velocity/delta slots before writing
    # player position; mirror those store boundaries for replay parity.
    move_step = f32(float(speed) * float(movement_dt))
    move_delta = Vec2(
        f32(float(move.x) * float(move_step)),
        f32(float(move.y) * float(move_step)),
    )
    next_pos = Vec2(
        f32(float(player.pos.x) + float(move_delta.x)),
        f32(float(player.pos.y) + float(move_delta.y)),
    )

    # Native clamps player world bounds at the end of `player_update`, after
    # firing/reload logic has consumed the in-frame movement position.
    player.pos = next_pos

    player.move_phase += phase_sign * movement_dt * player.move_speed * 19.0

    move_delta = player.pos - prev_pos
    stationary = abs(move_delta.x) <= 1e-9 and abs(move_delta.y) <= 1e-9
    reload_scale = 1.0
    if stationary and perk_active(player, PerkId.STATIONARY_RELOADER):
        reload_scale = 3.0

    apply_player_perk_ticks(
        player=player,
        dt=dt,
        state=state,
        players=players,
        stationary=stationary,
        owner_id_for_player=_owner_id_for_player,
        owner_id_for_player_projectiles=_owner_id_for_player_projectiles,
        projectile_spawn=_projectile_spawn,
    )

    # Reload + reload perks.
    if perk_active(player, PerkId.ANXIOUS_LOADER) and input_state.fire_pressed and player.reload_timer > 0.0:
        anxious_next = f32(float(player.reload_timer) - 0.05)
        player.reload_timer = float(anxious_next)
        if float(anxious_next) <= 0.0:
            # Native restarts the tail of the reload at `frame_dt * 0.8` when
            # Anxious Loader overcuts the timer.
            player.reload_timer = float(f32(float(dt) * 0.8))

    # Native preloads ammo one frame before reload timer underflows, using
    # unscaled `frame_dt` (before Stationary Reloader scale is applied).
    reload_timer_now = float(f32(float(player.reload_timer)))
    dt_f32 = float(f32(float(dt)))
    reload_preload_underflow = float(f32(reload_timer_now - dt_f32))
    if (
        player.reload_active
        and reload_timer_now > 0.0
        and reload_preload_underflow < -_RELOAD_PRELOAD_UNDERFLOW_EPS
    ):
        player.ammo = float(player.clip_size)

    if player.reload_timer > 0.0:
        if (
            perk_active(player, PerkId.ANGRY_RELOADER)
            and player.reload_timer_max > 0.5
            and (player.reload_timer_max * 0.5) < player.reload_timer
        ):
            half = player.reload_timer_max * 0.5
            next_timer = float(f32(float(player.reload_timer) - float(reload_scale) * float(dt)))
            player.reload_timer = next_timer
            if next_timer <= half:
                count = 7 + int(player.reload_timer_max * 4.0)
                state.bonus_spawn_guard = True
                _spawn_projectile_ring(
                    state,
                    player,
                    count=count,
                    angle_offset=0.1,
                    type_id=ProjectileTypeId.PLASMA_MINIGUN,
                    owner_id=_owner_id_for_player_projectiles(state, player.index),
                    players=players,
                )
                state.bonus_spawn_guard = False
                state.sfx_queue.append("sfx_explosion_small")
        else:
            player.reload_timer = float(f32(float(player.reload_timer) - float(reload_scale) * float(dt)))

    if player.reload_timer < 0.0:
        player.reload_timer = 0.0

    # Native clears `reload_active` whenever the cooldown/timer gates are open,
    # even if ammo is empty and perk firing paths can still proceed.
    if player.shot_cooldown <= 0.0 and player.reload_timer == 0.0:
        player.reload_active = False

    if input_state.reload_pressed:
        if perk_active(player, PerkId.ALTERNATE_WEAPON) and _player_swap_alt_weapon(player):
            weapon = _weapon_entry(player.weapon_id)
            if weapon is not None and weapon.reload_sound is not None:
                from .weapon_sfx import resolve_weapon_sfx_ref

                key = resolve_weapon_sfx_ref(weapon.reload_sound)
                if key is not None:
                    state.sfx_queue.append(key)
            player.shot_cooldown = float(player.shot_cooldown) + 0.1
        elif player.reload_timer == 0.0 and not input_state.move_to_cursor_pressed:
            _player_start_reload(player, state)

    if input_state.fire_down:
        state.survival_reward_fire_seen = True

    _player_fire_weapon(
        player,
        input_state,
        dt,
        state,
        detail_preset=int(detail_preset),
        creatures=creatures,
    )

    while player.move_phase > 14.0:
        player.move_phase -= 14.0
    while player.move_phase < 0.0:
        player.move_phase += 14.0

    half_size = max(0.0, float(player.size) * 0.5)
    clamped_pos = player.pos.clamp_rect(
        half_size,
        half_size,
        float(world_size) - half_size,
        float(world_size) - half_size,
    )
    player.pos = Vec2(f32(float(clamped_pos.x)), f32(float(clamped_pos.y)))
    if player.muzzle_flash_alpha > 0.8:
        player.muzzle_flash_alpha = 0.8


def _player_heading_approach_target(player: PlayerState, target_heading: float, dt: float) -> float:
    """Native `player_heading_approach_target`: ease heading and return angular diff."""

    # Native runs this through float32 temporaries (`var_8`/`edx_1`) before the
    # direct-vs-wrapped compare and turn-sign branch. That quantization matters
    # near opposite-heading ties.
    heading = float(f32(float(_normalize_heading_angle(float(player.heading)))))
    player.heading = float(heading)
    target = float(f32(float(target_heading)))

    direct = float(f32(abs(float(f32(float(target - heading))))))
    high = heading
    if target > high:
        high = target
    low = heading
    if target < low:
        low = target
    wrapped = float(f32(abs(float(f32(float(f32(6.2831855 - high)) + low)))))
    diff = wrapped if direct >= wrapped else direct

    scaled = float(f32(float(f32(float(dt))) * float(diff)))
    if direct <= wrapped:
        if target > heading:
            turn_delta = float(f32(float(scaled) * 5.0))
        else:
            turn_delta = float(f32(float(scaled) * -5.0))
    else:
        if target >= heading:
            turn_delta = float(f32(float(scaled) * -5.0))
        else:
            turn_delta = float(f32(float(scaled) * 5.0))

    player.heading = float(f32(float(heading) + float(turn_delta)))
    return float(diff)

def _normalize_heading_angle(value: float) -> float:
    while value < 0.0:
        value += math.tau
    while value > math.tau:
        value -= math.tau
    return value
