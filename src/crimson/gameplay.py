from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from grim.geom import Vec2
from grim.rand import Crand, CrandLike

from .aim_schemes import AimScheme
from .bonuses.freeze import DeferredFreezeCorpseFx
from .bonuses.hud import BonusHudState
from .bonuses.pool import BonusPool
from .effects import EffectPool, ParticlePool, SpriteEffectPool
from .game_modes import GameMode
from .math_parity import NATIVE_HALF_PI, NATIVE_PI, NATIVE_TAU, f32
from .movement_controls import MovementControlType
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
from .sim.state_types import PERK_COUNT_SIZE
from .weapon_runtime import (
    owner_id_for_player as _owner_id_for_player,
)
from .weapon_runtime import (
    owner_id_for_player_projectiles as _owner_id_for_player_projectiles,
)
from .weapon_runtime import (
    player_fire_weapon as _player_fire_weapon,
)
from .weapon_runtime import (
    player_start_reload as _player_start_reload,
)
from .weapon_runtime import (
    player_swap_alt_weapon as _player_swap_alt_weapon,
)
from .weapon_runtime import (
    projectile_spawn as _projectile_spawn,
)
from .weapon_runtime import (
    spawn_projectile_ring as _spawn_projectile_ring,
)
from .weapon_runtime import (
    weapon_assign_player as _weapon_assign_player,
)
from .weapon_runtime import (
    weapon_entry as _weapon_entry,
)
from .weapons import WEAPON_TABLE, WeaponId

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
_RELATIVE_MOVE_HEADING_NONE = -1.0
_RELATIVE_MOVE_HEADING_FORWARD = 0.0
_RELATIVE_MOVE_HEADING_FORWARD_RIGHT = float(f32(0.7853982))
_RELATIVE_MOVE_HEADING_RIGHT = float(f32(1.5707964))
_RELATIVE_MOVE_HEADING_BACKWARD_RIGHT = float(f32(2.3561945))
_RELATIVE_MOVE_HEADING_BACKWARD = float(NATIVE_PI)
_RELATIVE_MOVE_HEADING_BACKWARD_LEFT = float(f32(3.926991))
_RELATIVE_MOVE_HEADING_LEFT = float(f32(4.712389))
_RELATIVE_MOVE_HEADING_FORWARD_LEFT = float(f32(5.4977875))
_RELATIVE_MOVE_TURN_ALIGN_SCALE = float(f32(7.957747))
_AIM_POINT_RADIUS = 60.0
_AIM_KEYBOARD_TURN_RATE = 3.0
_AIM_JOYSTICK_TURN_RATE = 4.0


@dataclass(slots=True)
class GameplayState:
    rng: CrandLike = field(default_factory=lambda: Crand(0xBEEF))
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


def _distance_f32_xy(ax: float, ay: float, bx: float, by: float) -> float:
    dx = f32(float(ax) - float(bx))
    dy = f32(float(ay) - float(by))
    dist_sq = f32(f32(float(dx) * float(dx)) + f32(float(dy) * float(dy)))
    return f32(math.sqrt(float(dist_sq)))


def _player_apply_move_with_spawn_avoidance(
    player: PlayerState,
    *,
    delta: Vec2,
    spawn_slots: Sequence[object] | None,
    creatures: Sequence[Damageable] | None,
) -> None:
    """Port of native `player_apply_move_with_spawn_avoidance` (0x0041e290)."""

    dx = float(delta.x)
    dy = float(delta.y)
    if perk_active(player, PerkId.ALTERNATE_WEAPON):
        dx = float(f32(float(dx) * 0.8))
        dy = float(f32(float(dy) * 0.8))

    pos_x = float(f32(float(player.pos.x) + float(dx)))
    pos_y = float(f32(float(player.pos.y) + float(dy)))

    if spawn_slots and creatures:
        for slot in spawn_slots:
            owner_index = int(getattr(slot, "owner_creature", -1))
            if not (0 <= owner_index < len(creatures)):
                continue
            owner = creatures[owner_index]
            owner_pos = getattr(owner, "pos", None)
            if owner_pos is None:
                continue

            radius = float(
                f32((float(getattr(owner, "size", 0.0)) + float(player.size)) * 0.33333334),
            )
            if _distance_f32_xy(float(owner_pos.x), float(owner_pos.y), float(pos_x), float(pos_y)) > float(radius):
                continue

            # Collision: revert, then try axis resolution.
            old_x = float(f32(float(pos_x) - float(dx)))
            old_y = float(f32(float(pos_y) - float(dy)))
            old_dist = _distance_f32_xy(float(owner_pos.x), float(owner_pos.y), float(old_x), float(old_y))
            x_candidate = float(f32(float(old_x) + float(dx)))
            y_candidate = float(f32(float(old_y) + float(dy)))

            if float(radius) < float(old_dist):
                # X-only move.
                pos_x = x_candidate
                pos_y = old_y
                if _distance_f32_xy(float(owner_pos.x), float(owner_pos.y), float(pos_x), float(pos_y)) <= float(radius):
                    # Y-only move.
                    pos_x = float(f32(float(x_candidate) - float(dx)))
                    pos_y = y_candidate
                    if _distance_f32_xy(float(owner_pos.x), float(owner_pos.y), float(pos_x), float(pos_y)) <= float(
                        radius,
                    ):
                        pos_y = float(f32(float(y_candidate) - float(dy)))
            else:
                pos_x = x_candidate
                pos_y = y_candidate

    player.pos = Vec2(float(pos_x), float(pos_y))


def _direction_from_heading_native(heading: float) -> Vec2:
    # Native uses `fcos/fsin(heading - 1.5707964f)` (float32 half-pi literal).
    radians = float(heading) - float(NATIVE_HALF_PI)
    return Vec2(math.cos(radians), math.sin(radians))


def _resolve_move_mode_for_update(input_state: PlayerInput, state: GameplayState) -> int:
    move_mode = input_state.move_mode
    if move_mode is not None:
        return int(move_mode)
    if state.demo_mode_active:
        return int(MovementControlType.COMPUTER)
    if (
        input_state.move_forward_pressed is not None
        and input_state.move_backward_pressed is not None
        and input_state.turn_left_pressed is not None
        and input_state.turn_right_pressed is not None
    ):
        return int(MovementControlType.STATIC)
    if bool(input_state.move_to_cursor_pressed):
        return int(MovementControlType.MOUSE_POINT_CLICK)
    return int(MovementControlType.DUAL_ACTION_PAD)


def _resolve_aim_scheme_for_update(input_state: PlayerInput, state: GameplayState) -> int:
    aim_scheme = input_state.aim_scheme
    if aim_scheme is not None:
        return int(aim_scheme)
    if state.demo_mode_active:
        return int(AimScheme.COMPUTER)
    return int(AimScheme.MOUSE)


def _player_accelerate_move_speed(player: PlayerState, dt: float) -> None:
    dt = float(f32(float(dt)))
    if perk_active(player, PerkId.LONG_DISTANCE_RUNNER):
        if player.move_speed < 2.0:
            player.move_speed = float(f32(float(player.move_speed) + float(dt) * 4.0))
        player.move_speed = float(f32(float(player.move_speed) + float(dt)))
        if player.move_speed > 2.8:
            player.move_speed = 2.8
    else:
        player.move_speed = float(f32(float(player.move_speed) + float(dt) * 5.0))
        if player.move_speed > 2.0:
            player.move_speed = 2.0


def _player_decelerate_move_speed(player: PlayerState, dt: float) -> None:
    dt = float(f32(float(dt)))
    player.move_speed = float(f32(float(player.move_speed) - float(dt) * 15.0))
    if player.move_speed < 0.0:
        player.move_speed = 0.0


def _player_apply_move_speed_caps(player: PlayerState) -> None:
    if player.weapon_id == WeaponId.MEAN_MINIGUN and player.move_speed > 0.8:
        player.move_speed = 0.8


def _player_move_delta_from_heading(
    *,
    player: PlayerState,
    movement_dt: float,
    speed_scale: float,
) -> Vec2:
    move = _direction_from_heading_native(float(player.heading))
    move_dx = float(f32(float(move.x) * float(player.move_speed) * float(speed_scale)))
    move_dy = float(f32(float(move.y) * float(player.move_speed) * float(speed_scale)))
    return Vec2(
        f32(float(movement_dt) * float(move_dx)),
        f32(float(movement_dt) * float(move_dy)),
    )


def _player_aim_point_from_heading(player: PlayerState, heading: float, *, radius: float = _AIM_POINT_RADIUS) -> Vec2:
    aim_dir = _direction_from_heading_native(float(heading))
    return Vec2(
        f32(float(player.pos.x) + float(aim_dir.x) * float(radius)),
        f32(float(player.pos.y) + float(aim_dir.y) * float(radius)),
    )


def _player_update_aim_by_scheme(
    *,
    player: PlayerState,
    input_state: PlayerInput,
    dt: float,
    movement_mode: int,
    aim_scheme: int,
    demo_mode_active: bool,
) -> None:
    target_aim = input_state.aim

    if not bool(demo_mode_active) and int(aim_scheme) != int(AimScheme.COMPUTER):
        if int(aim_scheme) == int(AimScheme.KEYBOARD):
            if int(movement_mode) in (int(MovementControlType.RELATIVE), int(MovementControlType.STATIC)):
                if bool(input_state.turn_right_pressed):
                    player.aim_heading = float(f32(float(player.aim_heading) + float(f32(float(dt) * _AIM_KEYBOARD_TURN_RATE))))
                if bool(input_state.turn_left_pressed):
                    player.aim_heading = float(f32(float(player.aim_heading) - float(f32(float(dt) * _AIM_KEYBOARD_TURN_RATE))))
                target_aim = _player_aim_point_from_heading(player, float(player.aim_heading))
        elif int(aim_scheme) == int(AimScheme.JOYSTICK):
            if bool(input_state.turn_right_pressed):
                player.aim_heading = float(f32(float(player.aim_heading) + float(f32(float(dt) * _AIM_JOYSTICK_TURN_RATE))))
            if bool(input_state.turn_left_pressed):
                player.aim_heading = float(f32(float(player.aim_heading) - float(f32(float(dt) * _AIM_JOYSTICK_TURN_RATE))))
            target_aim = _player_aim_point_from_heading(player, float(player.aim_heading))
        elif int(aim_scheme) == int(AimScheme.UNKNOWN):
            target_aim = _player_aim_point_from_heading(player, float(player.aim_heading))

    player.aim = target_aim
    aim_dir = (player.aim - player.pos).normalized()
    if aim_dir.length_sq() > 0.0:
        player.aim_dir = aim_dir
        player.aim_heading = aim_dir.to_heading()


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
    spawn_slots: Sequence[object] | None = None,
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

    move_mode = _resolve_move_mode_for_update(input_state, state)
    aim_scheme = _resolve_aim_scheme_for_update(input_state, state)

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
    phase_sign = 1.0
    move = _direction_from_heading_native(float(player.heading))
    speed = 0.0
    move_delta_override: Vec2 | None = None
    player_controlled_movement = (
        (not state.demo_mode_active)
        and int(move_mode) != int(MovementControlType.COMPUTER)
        and int(aim_scheme) != int(AimScheme.COMPUTER)
    )
    if player_controlled_movement:
        if int(move_mode) == int(MovementControlType.RELATIVE):
            turning_left = bool(input_state.turn_left_pressed)
            turning_right = bool(input_state.turn_right_pressed)
            moving_forward = bool(input_state.move_forward_pressed)
            moving_backward = bool(input_state.move_backward_pressed)
            turned = False

            if player.turn_speed < 1.0:
                player.turn_speed = 1.0
            if player.turn_speed > 7.0:
                player.turn_speed = 7.0

            if turning_left:
                player.turn_speed = float(f32(float(player.turn_speed) + float(movement_dt) * 10.0))
                turn_step = float(f32(float(player.turn_speed) * float(movement_dt) * 0.5))
                player.heading = float(f32(float(player.heading) - float(turn_step)))
                player.aim_heading = float(f32(float(player.aim_heading) - float(turn_step)))
                turned = True
            elif turning_right:
                player.turn_speed = float(f32(float(player.turn_speed) + float(movement_dt) * 10.0))
                turn_step = float(f32(float(player.turn_speed) * float(movement_dt) * 0.5))
                player.heading = float(f32(float(player.heading) + float(turn_step)))
                player.aim_heading = float(f32(float(player.aim_heading) + float(turn_step)))
                turned = True

            if moving_forward:
                _player_accelerate_move_speed(player, movement_dt)
                _player_apply_move_speed_caps(player)
                move_delta_override = _player_move_delta_from_heading(
                    player=player,
                    movement_dt=movement_dt,
                    speed_scale=25.0,
                )
            elif moving_backward:
                _player_accelerate_move_speed(player, movement_dt)
                phase_sign = -1.0
                move_delta_override = _player_move_delta_from_heading(
                    player=player,
                    movement_dt=movement_dt,
                    speed_scale=-25.0,
                )
            else:
                if not turned:
                    player.turn_speed = 1.0
                _player_decelerate_move_speed(player, movement_dt)
                move_delta_override = _player_move_delta_from_heading(
                    player=player,
                    movement_dt=movement_dt,
                    speed_scale=25.0,
                )
        elif int(move_mode) == int(MovementControlType.STATIC):
            moving_forward = (
                bool(input_state.move_forward_pressed)
                if input_state.move_forward_pressed is not None
                else bool(raw_move.y < -0.5)
            )
            moving_backward = (
                bool(input_state.move_backward_pressed)
                if input_state.move_backward_pressed is not None
                else bool(raw_move.y > 0.5)
            )
            turning_left = (
                bool(input_state.turn_left_pressed)
                if input_state.turn_left_pressed is not None
                else bool(raw_move.x < -0.5)
            )
            turning_right = (
                bool(input_state.turn_right_pressed)
                if input_state.turn_right_pressed is not None
                else bool(raw_move.x > 0.5)
            )

            target_heading = float(_RELATIVE_MOVE_HEADING_NONE)
            if turning_left:
                target_heading = float(_RELATIVE_MOVE_HEADING_LEFT)
            if turning_right:
                target_heading = float(_RELATIVE_MOVE_HEADING_RIGHT)

            if moving_forward:
                if turning_left:
                    target_heading = float(_RELATIVE_MOVE_HEADING_FORWARD_LEFT)
                elif turning_right:
                    target_heading = float(_RELATIVE_MOVE_HEADING_FORWARD_RIGHT)
                else:
                    target_heading = float(_RELATIVE_MOVE_HEADING_FORWARD)
            if moving_backward:
                if turning_left:
                    target_heading = float(_RELATIVE_MOVE_HEADING_BACKWARD_LEFT)
                elif turning_right:
                    target_heading = float(_RELATIVE_MOVE_HEADING_BACKWARD_RIGHT)
                else:
                    target_heading = float(_RELATIVE_MOVE_HEADING_BACKWARD)

            if (not moving_backward) and target_heading == float(_RELATIVE_MOVE_HEADING_NONE):
                _player_decelerate_move_speed(player, movement_dt)
                move = _direction_from_heading_native(float(player.heading))
                move_dx = float(f32(float(move.x) * float(player.move_speed) * float(speed_multiplier) * 25.0))
                move_dy = float(f32(float(move.y) * float(player.move_speed) * float(speed_multiplier) * 25.0))
            else:
                angle_diff, turn_delta = _player_heading_approach_target_with_delta(
                    player,
                    float(target_heading),
                    float(movement_dt),
                )
                player.aim_heading = float(f32(float(player.aim_heading) + float(turn_delta)))
                _player_accelerate_move_speed(player, movement_dt)
                _player_apply_move_speed_caps(player)
                move = _direction_from_heading_native(float(player.heading))
                turn_align = (
                    (float(NATIVE_PI) - float(angle_diff))
                    * float(speed_multiplier)
                    * float(_RELATIVE_MOVE_TURN_ALIGN_SCALE)
                )
                move_dx = float(
                    f32(float(move.x) * float(player.move_speed) * float(turn_align)),
                )
                move_dy = float(
                    f32(float(move.y) * float(player.move_speed) * float(turn_align)),
                )

            move_delta_override = Vec2(
                f32(float(movement_dt) * float(move_dx)),
                f32(float(movement_dt) * float(move_dy)),
            )
        else:
            moving_input = raw_mag > (
                0.0
                if int(move_mode) == int(MovementControlType.MOUSE_POINT_CLICK)
                else 0.2
            )
            turn_alignment_scale = 1.0
            if moving_input:
                inv = 1.0 / raw_mag if raw_mag > 1e-9 else 0.0
                move = raw_move * inv
                target_heading = _normalize_heading_angle(move.to_heading())
                angle_diff = _player_heading_approach_target(player, target_heading, movement_dt)
                move = _direction_from_heading_native(float(player.heading))
                turn_alignment_scale = max(0.0, (math.pi - angle_diff) / math.pi)
                _player_accelerate_move_speed(player, movement_dt)
            else:
                _player_decelerate_move_speed(player, movement_dt)
                move = _direction_from_heading_native(float(player.heading))

            _player_apply_move_speed_caps(player)
            speed = float(player.move_speed) * float(speed_multiplier) * 25.0
            if moving_input:
                speed *= min(1.0, raw_mag)
                speed *= turn_alignment_scale
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
            move = _direction_from_heading_native(float(player.heading))
            turn_alignment_scale = max(0.0, (math.pi - angle_diff) / math.pi)
            _player_accelerate_move_speed(player, movement_dt)
        else:
            _player_decelerate_move_speed(player, movement_dt)
            move = _direction_from_heading_native(float(player.heading))

        _player_apply_move_speed_caps(player)

        speed = float(player.move_speed) * float(speed_multiplier) * 25.0
        if moving_input:
            speed *= min(1.0, raw_mag)
            speed *= turn_alignment_scale

    if move_delta_override is None:
        # Native movement stores through float32 velocity/delta slots before writing
        # player position; mirror those store boundaries for replay parity.
        move_step = f32(float(speed) * float(movement_dt))
        move_delta = Vec2(
            f32(float(move.x) * float(move_step)),
            f32(float(move.y) * float(move_step)),
        )
    else:
        move_delta = move_delta_override
    _player_apply_move_with_spawn_avoidance(
        player,
        delta=move_delta,
        spawn_slots=spawn_slots,
        creatures=creatures,
    )

    player.move_phase += phase_sign * movement_dt * player.move_speed * 19.0

    move_delta = player.pos - prev_pos
    stationary = abs(move_delta.x) <= 1e-9 and abs(move_delta.y) <= 1e-9
    reload_scale = 1.0
    if stationary and perk_active(player, PerkId.STATIONARY_RELOADER):
        reload_scale = 3.0

    apply_player_perk_ticks(
        player=player,
        player_pos_before_move=prev_pos,
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

    reload_timer_now = float(f32(float(player.reload_timer)))
    dt_f32 = float(f32(float(dt)))
    # Native preloads ammo one frame before reload timer underflows using the
    # unscaled `frame_dt` (before Stationary Reloader scale is applied). That
    # can miss reload completion when Stationary Reloader is active, leaving the
    # clip empty and causing a one-shot reload loop (fixed by default).
    preload_dt = dt_f32
    if not bool(state.preserve_bugs):
        preload_dt = float(f32(float(reload_scale) * float(dt_f32)))

    reload_preload_underflow = float(f32(reload_timer_now - preload_dt))
    # Native can complete reload and fire on the same frame when held fire
    # meets an almost-zero reload boundary. Treat near-zero underflow as
    # completion for fire-held ticks to avoid a spurious empty-shot reload loop.
    preload_crossed = reload_preload_underflow < -_RELOAD_PRELOAD_UNDERFLOW_EPS
    preload_fire_boundary = input_state.fire_down and reload_preload_underflow <= _RELOAD_PRELOAD_UNDERFLOW_EPS
    if player.reload_active and reload_timer_now > 0.0 and (preload_crossed or preload_fire_boundary):
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
                    owner_player_index=player.index,
                    players=players,
                )
                state.bonus_spawn_guard = False
                state.sfx_queue.append("sfx_explosion_small")
        else:
            player.reload_timer = float(f32(float(player.reload_timer) - float(reload_scale) * float(dt)))

    if player.reload_timer < 0.0:
        player.reload_timer = 0.0

    has_alt_weapon_perk = perk_active(player, PerkId.ALTERNATE_WEAPON)
    single_player_mode = (len(players) == 1) if players is not None else True
    manual_reload_allowed = (
        bool(input_state.reload_pressed)
        and (not state.demo_mode_active)
        and (not has_alt_weapon_perk)
        and int(move_mode) != int(MovementControlType.MOUSE_POINT_CLICK)
        and float(player.reload_timer) == 0.0
        and bool(single_player_mode)
    )
    if manual_reload_allowed:
        _player_start_reload(player, state)

    _player_update_aim_by_scheme(
        player=player,
        input_state=input_state,
        dt=dt,
        movement_mode=int(move_mode),
        aim_scheme=int(aim_scheme),
        demo_mode_active=bool(state.demo_mode_active),
    )

    fire_gate_open_pre_reload = player.shot_cooldown <= 0.0 and player.reload_timer == 0.0

    # Native clears `reload_active` whenever the cooldown/timer gates are open,
    # even if ammo is empty and perk firing paths can still proceed.
    if fire_gate_open_pre_reload:
        player.reload_active = False

    swapped_alt_weapon = False
    if input_state.reload_pressed and has_alt_weapon_perk:
        if _player_swap_alt_weapon(player):
            swapped_alt_weapon = True
            weapon = _weapon_entry(player.weapon_id)
            if weapon is not None and weapon.reload_sound is not None:
                from .weapon_sfx import resolve_weapon_sfx_ref

                key = resolve_weapon_sfx_ref(weapon.reload_sound)
                if key is not None:
                    state.sfx_queue.append(key)
            player.shot_cooldown = float(player.shot_cooldown) + 0.1

    # Native computes the fire gate (`shot_cooldown <= 0 && reload_timer == 0`)
    # before alt-weapon swap mutates cooldown; preserve same-tick fire eligibility.
    force_pre_swap_fire_gate = swapped_alt_weapon and fire_gate_open_pre_reload and input_state.fire_down
    if force_pre_swap_fire_gate:
        player.shot_cooldown = 0.0

    if input_state.fire_down:
        state.survival_reward_fire_seen = True

    _player_fire_weapon(
        player,
        input_state,
        dt,
        state,
        detail_preset=int(detail_preset),
        creatures=creatures,
        players=players,
        force_pre_swap_fire_gate=bool(force_pre_swap_fire_gate),
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


def _player_heading_approach_target_with_delta(
    player: PlayerState,
    target_heading: float,
    dt: float,
) -> tuple[float, float]:
    """Native `player_heading_approach_target`: ease heading and return (diff, turn_delta)."""

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
    wrapped = float(f32(abs(float(f32(float(NATIVE_TAU) - float(high) + float(low))))))
    diff = wrapped if direct >= wrapped else direct

    dt_f32 = float(f32(float(dt)))
    # Native computes `player_heading_turn_delta = frame_dt * diff * 5.0` via
    # float32 temporaries/spills. Quantize `frame_dt * diff` to float32 before
    # applying the `* 5.0` to match x87 store boundaries.
    scaled = float(f32(float(dt_f32) * float(diff)))
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
    return float(diff), float(turn_delta)


def _player_heading_approach_target(player: PlayerState, target_heading: float, dt: float) -> float:
    diff, _ = _player_heading_approach_target_with_delta(player, target_heading, dt)
    return float(diff)


def _normalize_heading_angle(value: float) -> float:
    tau = float(NATIVE_TAU)
    angle = float(f32(float(value)))
    while angle < 0.0:
        angle = float(f32(float(angle) + float(tau)))
    while angle > tau:
        angle = float(f32(float(angle) - float(tau)))
    return float(angle)
