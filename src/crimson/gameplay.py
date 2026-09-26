from __future__ import annotations

import math
from collections.abc import Sequence
from typing import TYPE_CHECKING

from grim.geom import Vec2
from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest

from .aim_constants import _AIM_JOYSTICK_TURN_RATE, _AIM_KEYBOARD_TURN_RATE
from .aim_schemes import AimScheme
from .math_parity import (
    NATIVE_HALF_PI,
    NATIVE_PI,
    NATIVE_TAU,
    f32,
    native_aim_point_from_heading,
    x87_fpatan,
    x87_pc24_add,
    x87_pc24_crt_pow,
    x87_pc24_div,
    x87_pc24_hypot,
    x87_pc24_mul,
    x87_pc24_mul_chain,
    x87_pc24_sub,
)
from .movement_controls import MovementControlType
from .perks import PerkId
from .perks.helpers import perk_active
from .perks.runtime.player_ticks import apply_player_perk_ticks
from .perks.state import PerkSelectionState
from .player_damage import PlayerDeathRuntime
from .projectiles.types import ProjectileTemplateId
from .rng_caller_static import RngCallerStatic
from .sim.timing import ftol_ms_i32, reflex_boost_time_scale_factor
from .weapon_runtime import (
    WeaponFireCtx as _WeaponFireCtx,
)
from .weapon_runtime import (
    capture_fire_gate as _capture_fire_gate,
)
from .weapon_runtime import (
    fire_weapon as _fire_weapon,
)
from .weapon_runtime import (
    owner_ref_for_player as _owner_ref_for_player,
)
from .weapon_runtime import (
    owner_ref_for_player_projectiles as _owner_ref_for_player_projectiles,
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
from .weapons import WeaponId

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState

    from .creatures.runtime import CreatureState
    from .creatures.spawn import SpawnSlotInit
    from .sim.input import PlayerInput
    from .sim.state_types import PlayerState


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
_DUAL_ACTION_PAD_DEADZONE = f32(0.2)
_LOW_HEALTH_BLOODSPILL_SFX: tuple[SfxId, SfxId] = (SfxId.BLOODSPILL_01, SfxId.BLOODSPILL_02)


_REFLEX_MOVEMENT_DT_SCALE = f32(0.6)
_REFLEX_RESTORE_DT_SCALE = f32(1.6666666)


def _player_reflex_movement_dt(dt: float, time_scale_factor: float) -> float:
    # 0x00413e01: `frame_dt = (0.6f / time_scale_factor) * frame_dt` before movement.
    return x87_pc24_mul(x87_pc24_div(_REFLEX_MOVEMENT_DT_SCALE, time_scale_factor), dt)


def _player_reflex_restored_dt(movement_dt: float, time_scale_factor: float) -> float:
    # 0x00414f4d: `frame_dt = time_scale_factor * frame_dt * 1.6666666f` right after movement.
    return x87_pc24_mul(x87_pc24_mul(time_scale_factor, movement_dt), _REFLEX_RESTORE_DT_SCALE)


def player_frame_dt_after_roundtrip(*, dt: float, time_scale_active: bool, reflex_boost_timer: float) -> float:
    """Mirror the `player_update` frame_dt round-trip under Reflex Boost.

    Native scales frame_dt for movement (`* 0.6 / _time_scale_factor`) and then
    restores it with `* _time_scale_factor * 1.6666666` for the rest of the update.
    """

    dt_f32 = f32(dt)
    if not time_scale_active or dt_f32 <= 0.0:
        return dt_f32
    time_scale_factor = reflex_boost_time_scale_factor(reflex_boost_timer=reflex_boost_timer, time_scale_active=True)
    return _player_reflex_restored_dt(_player_reflex_movement_dt(dt_f32, time_scale_factor), time_scale_factor)


def award_experience(state: GameplayState, player: PlayerState, amount: int) -> int:
    """Grant XP while honoring active bonus multipliers."""

    xp = int(amount)
    if xp <= 0:
        return 0
    if state.bonuses.double_experience > 0.0:
        xp *= 2
    player.experience += xp
    return xp


def experience_plus_reward(experience: int, reward_value: float) -> int:
    """Native kill XP sum `__ftol(fild experience + reward)`.

    The int XP loads exactly with `fild`; only the PC24 `fadd` rounds, so past
    2^24 the sum snaps to the f32 grid (creature_handle_death 0x0041eb5b,
    Radioactive 0x0042704b, Jinxed 0x004070a6).
    """

    return int(x87_pc24_add(float(experience), f32(reward_value)))


def _award_experience_once_from_reward(player: PlayerState, reward_value: float) -> int:
    before = int(player.experience)
    player.experience = experience_plus_reward(before, reward_value)
    return player.experience - before


def award_experience_from_reward(state: GameplayState, player: PlayerState, reward_value: float) -> int:
    """Grant kill XP from floating reward values; Double Experience repeats the award (0x0041eba2)."""

    gained = _award_experience_once_from_reward(player, reward_value)
    if state.bonuses.double_experience > 0.0:
        gained += _award_experience_once_from_reward(player, reward_value)
    return gained


_SURVIVAL_LEVEL_EXPONENT = f32(1.8)
_SURVIVAL_LEVEL_XP_SCALE = f32(-1000.0)


def survival_level_threshold(level: int) -> int:
    """Return the XP threshold for advancing past the given level."""

    # gameplay_update_and_render (0x0040afae): `1000 - __ftol(__CIpow(level, (double)1.8f) * -1000.0f)`.
    level = max(1, int(level))
    power = x87_pc24_crt_pow(float(level), _SURVIVAL_LEVEL_EXPONENT)
    return 1000 - int(x87_pc24_mul(power, _SURVIVAL_LEVEL_XP_SCALE))


def survival_check_level_up(player: PlayerState, perk_state: PerkSelectionState) -> int:
    """Advance survival levels if XP exceeds thresholds, returning number of level-ups."""

    # Native progression advances at most one level per update tick even when
    # XP jumps across multiple thresholds in a single frame.
    if player.experience > survival_level_threshold(player.level):
        player.level += 1
        perk_state.pending_count += 1
        perk_state.choices_dirty = True
        return 1
    return 0


def survival_progression_update(
    state: GameplayState,
    players: list[PlayerState],
) -> None:
    """Advance survival level/perk progression."""

    if not players:
        return
    survival_check_level_up(players[0], state.perk_selection)


_SURVIVAL_RECENT_DEATH_CENTROID_SCALE = f32(0.33333334)


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
        if player.weapon.weapon_id == WeaponId.PISTOL:
            _weapon_assign_player(player, WeaponId.SHRINKIFIER_5K, state=state)
            state.survival_reward_weapon_guard_id = WeaponId.SHRINKIFIER_5K
        state.survival_reward_handout_enabled = False
        state.survival_reward_damage_seen = True
        state.survival_reward_fire_seen = True

    if int(state.survival_recent_death_count) == 3 and (not bool(state.survival_reward_fire_seen)):
        pos0, pos1, pos2 = state.survival_recent_death_pos
        centroid_x = x87_pc24_mul(
            x87_pc24_add(
                x87_pc24_add(float(pos0.x), float(pos1.x)),
                float(pos2.x),
            ),
            _SURVIVAL_RECENT_DEATH_CENTROID_SCALE,
        )
        centroid_y = x87_pc24_mul(
            x87_pc24_add(
                x87_pc24_add(float(pos0.y), float(pos1.y)),
                float(pos2.y),
            ),
            _SURVIVAL_RECENT_DEATH_CENTROID_SCALE,
        )
        dx = x87_pc24_sub(float(player.pos.x), centroid_x)
        dy = x87_pc24_sub(float(player.pos.y), centroid_y)
        if x87_pc24_hypot(dx, dy) < 16.0 and float(player.health) < 15.0:
            _weapon_assign_player(player, WeaponId.BLADE_GUN, state=state)
            state.survival_reward_weapon_guard_id = WeaponId.BLADE_GUN
            state.survival_reward_fire_seen = True
            state.survival_reward_handout_enabled = False


def survival_enforce_reward_weapon_guard(state: GameplayState, players: Sequence[PlayerState]) -> None:
    """Revoke temporary Survival handout weapons when guard id mismatches."""

    guard_id = state.survival_reward_weapon_guard_id
    for player in players:
        weapon_id = player.weapon.weapon_id
        if weapon_id == WeaponId.BLADE_GUN and guard_id != WeaponId.BLADE_GUN:
            _weapon_assign_player(player, WeaponId.PISTOL, state=state)
        if weapon_id == WeaponId.SHRINKIFIER_5K and guard_id != WeaponId.SHRINKIFIER_5K:
            _weapon_assign_player(player, WeaponId.PISTOL, state=state)


def gameplay_enforce_weapon_guards(state: GameplayState, players: Sequence[PlayerState]) -> None:
    """Apply the weapon revocation gates embedded in native world rendering."""

    # Native gameplay_render_world checks exactly the two fixed player slots.
    # Corrected mode extends the same entitlement policy to generalized co-op.
    guarded_players = players[:2] if state.preserve_bugs else players
    unlock_index_full = int(state.status.quest_unlock_index_full) if state.status is not None else 0
    if unlock_index_full < 40:
        for player in guarded_players:
            if player.weapon.weapon_id == WeaponId.SPLITTER_GUN:
                _weapon_assign_player(player, WeaponId.PISTOL, state=state)

    survival_enforce_reward_weapon_guard(state, guarded_players)


def gameplay_accumulate_weapon_usage_time(
    state: GameplayState,
    players: Sequence[PlayerState],
    frame_dt_ms: int,
) -> None:
    """Accumulate native high-score weapon time for the fixed player-0 slot."""

    if not players:
        return
    weapon_id = int(players[0].weapon.weapon_id)
    if not 0 <= weapon_id < len(state.weapon_usage_time):
        return
    state.weapon_usage_time[weapon_id] = (int(state.weapon_usage_time[weapon_id]) + int(frame_dt_ms)) & 0xFFFFFFFF


def _distance_f32_xy(ax: float, ay: float, bx: float, by: float) -> float:
    dx = f32(float(ax) - float(bx))
    dy = f32(float(ay) - float(by))
    dist_sq = f32(f32(float(dx) * float(dx)) + f32(float(dy) * float(dy)))
    return f32(math.sqrt(float(dist_sq)))


_ALT_WEAPON_MOVE_SCALE = f32(0.8)
_SPAWN_AVOIDANCE_RADIUS_SCALE = f32(0.33333334)


def _player_apply_move_with_spawn_avoidance(
    player: PlayerState,
    *,
    perk_player: PlayerState,
    delta: Vec2,
    spawn_slots: Sequence[SpawnSlotInit] | None,
    creatures: Sequence[CreatureState] | None,
) -> None:
    """Port of native `player_apply_move_with_spawn_avoidance` (0x0041e290)."""

    dx = float(delta.x)
    dy = float(delta.y)
    if perk_active(perk_player, PerkId.ALTERNATE_WEAPON):
        dx = x87_pc24_mul(dx, _ALT_WEAPON_MOVE_SCALE)
        dy = x87_pc24_mul(dy, _ALT_WEAPON_MOVE_SCALE)

    pos_x = float(f32(float(player.pos.x) + float(dx)))
    pos_y = float(f32(float(player.pos.y) + float(dy)))

    if spawn_slots and creatures:
        for slot in spawn_slots:
            owner_index = int(slot.owner_creature)
            if not (0 <= owner_index < len(creatures)):
                continue
            owner = creatures[owner_index]
            owner_pos = owner.pos

            radius = x87_pc24_mul(
                x87_pc24_add(float(owner.size), float(player.size)),
                _SPAWN_AVOIDANCE_RADIUS_SCALE,
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
                if _distance_f32_xy(float(owner_pos.x), float(owner_pos.y), float(pos_x), float(pos_y)) <= float(
                    radius,
                ):
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
    # Native uses `fcos/fsin(heading - 1.5707964f)` (float32 half-pi literal),
    # with gameplay's x87 arithmetic in 24-bit precision before the trig op.
    radians = x87_pc24_sub(float(heading), float(NATIVE_HALF_PI))
    return Vec2(math.cos(radians), math.sin(radians))


def _resolve_move_mode_for_update(input_state: PlayerInput, state: GameplayState) -> MovementControlType:
    move_mode = input_state.move_mode
    if move_mode is not None:
        return move_mode
    if state.demo_mode_active:
        return MovementControlType.COMPUTER
    if (
        input_state.move_forward_pressed is not None
        and input_state.move_backward_pressed is not None
        and input_state.turn_left_pressed is not None
        and input_state.turn_right_pressed is not None
    ):
        return MovementControlType.STATIC
    if input_state.move_to_cursor_pressed:
        return MovementControlType.MOUSE_POINT_CLICK
    return MovementControlType.DUAL_ACTION_PAD


def _resolve_aim_scheme_for_update(input_state: PlayerInput, state: GameplayState) -> AimScheme:
    aim_scheme = input_state.aim_scheme
    if aim_scheme is not None:
        return aim_scheme
    if state.demo_mode_active:
        return AimScheme.COMPUTER
    return AimScheme.MOUSE


def _player_accelerate_move_speed(player: PlayerState, perk_player: PlayerState, dt: float) -> None:
    dt = float(f32(float(dt)))
    if perk_active(perk_player, PerkId.LONG_DISTANCE_RUNNER):
        if player.move_speed < 2.0:
            acceleration = f32(float(dt) * 4.0)
            player.move_speed = float(f32(float(player.move_speed) + float(acceleration)))
        player.move_speed = float(f32(float(player.move_speed) + float(dt)))
        if player.move_speed > f32(2.8):
            player.move_speed = f32(2.8)
    else:
        acceleration = f32(float(dt) * 5.0)
        player.move_speed = float(f32(float(player.move_speed) + float(acceleration)))
        if player.move_speed > 2.0:
            player.move_speed = 2.0


def _player_decelerate_move_speed(player: PlayerState, dt: float) -> None:
    dt = float(f32(float(dt)))
    deceleration = f32(float(dt) * 15.0)
    player.move_speed = float(f32(float(player.move_speed) - float(deceleration)))
    if player.move_speed < 0.0:
        player.move_speed = 0.0


def _player_apply_move_speed_caps(player: PlayerState) -> None:
    if player.weapon.weapon_id == WeaponId.MEAN_MINIGUN and player.move_speed > f32(0.8):
        player.move_speed = f32(0.8)


def _player_heading_velocity(player: PlayerState, *, speed_multiplier: float, speed_scale: float) -> Vec2:
    # `move_d{x,y} = fcos/fsin(heading - 1.5707964f) * move_speed * scalar * +-25.0f`
    # (e.g. 0x00414152): the trig result stays wide, every fmul rounds at PC24.
    direction = _direction_from_heading_native(float(player.heading))

    def component(value: float) -> float:
        return x87_pc24_mul_chain(value, float(player.move_speed), float(speed_multiplier), float(speed_scale))

    return Vec2(component(direction.x), component(direction.y))


def _player_move_delta_from_velocity(movement_dt: float, velocity: Vec2) -> Vec2:
    # `move_delta = frame_dt * move_d{x,y}` after the float move_dx/move_dy stores.
    return Vec2(x87_pc24_mul(movement_dt, velocity.x), x87_pc24_mul(movement_dt, velocity.y))


def _player_move_delta_from_heading(
    *,
    player: PlayerState,
    movement_dt: float,
    speed_multiplier: float,
    speed_scale: float,
) -> Vec2:
    velocity = _player_heading_velocity(player, speed_multiplier=speed_multiplier, speed_scale=speed_scale)
    return _player_move_delta_from_velocity(movement_dt, velocity)


def _player_turn_aligned_velocity_native(
    *,
    direction: Vec2,
    move_speed: float,
    angle_diff: float,
    speed_multiplier: float,
) -> Vec2:
    # `player_update` evaluates this x87 chain in the game's 24-bit precision
    # mode. In particular, the direction*speed and subsequent alignment
    # product round before the remaining multipliers; keeping the whole chain
    # wide can move a backward-diagonal step one ULP too far.
    alignment = x87_pc24_sub(float(NATIVE_PI), float(angle_diff))

    def component(value: float) -> float:
        return x87_pc24_mul_chain(
            float(value),
            float(move_speed),
            float(alignment),
            float(speed_multiplier),
            float(_RELATIVE_MOVE_TURN_ALIGN_SCALE),
        )

    return Vec2(component(direction.x), component(direction.y))


def _player_aim_point_from_heading(player: PlayerState, heading: float, *, radius: float = _AIM_POINT_RADIUS) -> Vec2:
    return native_aim_point_from_heading(player.pos, heading, radius=radius)


def _aim_heading_from_aim_point_native(player_pos: Vec2, aim_pos: Vec2) -> float:
    # `player_update` (0x004136b0): aim_heading = (float)(fpatan(pos_y-aim_y, pos_x-aim_x) - 1.5707964)
    dy = x87_pc24_sub(player_pos.y, aim_pos.y)
    dx = x87_pc24_sub(player_pos.x, aim_pos.x)
    return x87_pc24_sub(x87_fpatan(dy, dx), NATIVE_HALF_PI)


def _player_update_aim_by_scheme(
    *,
    player: PlayerState,
    input_state: PlayerInput,
    dt: float,
    movement_mode: MovementControlType,
    aim_scheme: AimScheme,
    demo_mode_active: bool,
) -> None:
    target_aim = input_state.aim

    if not demo_mode_active and aim_scheme != AimScheme.COMPUTER:
        if aim_scheme == AimScheme.KEYBOARD:
            if movement_mode in (MovementControlType.RELATIVE, MovementControlType.STATIC):
                if bool(input_state.turn_right_pressed):
                    player.aim_heading = float(
                        f32(float(player.aim_heading) + float(f32(float(dt) * _AIM_KEYBOARD_TURN_RATE))),
                    )
                if bool(input_state.turn_left_pressed):
                    player.aim_heading = float(
                        f32(float(player.aim_heading) - float(f32(float(dt) * _AIM_KEYBOARD_TURN_RATE))),
                    )
                target_aim = _player_aim_point_from_heading(player, float(player.aim_heading))
        elif aim_scheme == AimScheme.JOYSTICK:
            if bool(input_state.turn_left_pressed):
                player.aim_heading = float(
                    f32(float(player.aim_heading) - float(f32(float(dt) * _AIM_JOYSTICK_TURN_RATE))),
                )
            if bool(input_state.turn_right_pressed):
                player.aim_heading = float(
                    f32(float(player.aim_heading) + float(f32(float(dt) * _AIM_JOYSTICK_TURN_RATE))),
                )
            target_aim = _player_aim_point_from_heading(player, float(player.aim_heading))
        elif aim_scheme == AimScheme.UNKNOWN:
            target_aim = _player_aim_point_from_heading(player, float(player.aim_heading))

    player.aim = target_aim
    aim_dir = (player.aim - player.pos).normalized()
    if aim_dir.length_sq() > 0.0:
        player.aim_dir = aim_dir
    # 0x0041572e: native recomputes the heading unconditionally; an aim point on
    # the player gives `fpatan(+0, +0) - 1.5707964f`.
    player.aim_heading = _aim_heading_from_aim_point_native(player.pos, player.aim)


def _player_tick_low_health(
    player: PlayerState,
    state: GameplayState,
    dt: float,
    detail_preset: int,
    violence_disabled: int,
) -> None:
    # Native low-health warning pulse (`player_update` @ 0x004136b0): once
    # `player_take_damage` has armed `low_health_timer` (!= 100.0), count down
    # while HP < 20 and emit a 3x blood splatter + bloodspill SFX burst.
    if player.low_health_timer != 100.0 and player.health < 20.0:
        next_low_health_timer = float(f32(float(player.low_health_timer) - float(dt)))
        player.low_health_timer = next_low_health_timer
        if next_low_health_timer < 0.0:
            bleed_dir_angle = x87_pc24_sub(
                x87_pc24_add(float(player.aim_heading), NATIVE_HALF_PI),
                f32(0.5),
            )
            bleed_pos = Vec2(
                x87_pc24_add(
                    x87_pc24_mul(math.cos(bleed_dir_angle), f32(-6.0)),
                    float(player.pos.x),
                ),
                x87_pc24_add(
                    x87_pc24_mul(math.sin(bleed_dir_angle), f32(-6.0)),
                    float(player.pos.y),
                ),
            )
            aim_heading = float(player.aim_heading)
            for _ in range(3):
                state.effects.spawn_blood_splatter(
                    pos=bleed_pos,
                    angle=aim_heading,
                    age=0.0,
                    rng=state.rng,
                    detail_preset=int(detail_preset),
                    violence_disabled=int(violence_disabled),
                )
            bloodspill_sfx = _LOW_HEALTH_BLOODSPILL_SFX[
                state.rng.rand_tagged(RngCallerStatic.PLAYER_UPDATE_LOW_HEALTH_BLOODSPILL) & 1
            ]
            state.sfx_queue.append(SfxRequest(bloodspill_sfx, player.pos))
            player.low_health_timer = 1.0



def _native_move_target_heading(move: Vec2, *, normalize: bool, wrap: bool) -> float:
    """Heading toward `move`, computed as native does from `movement_input = -move`.

    Native builds `movement_input` as `pos - move_target` (point click,
    computer) or the negated stick (dual action pad), then evaluates
    `atan2f(y, x) - 1.5707964f` (0x00413fd7, 0x00414235, 0x00414d4a).  Point
    click and the pad lift the result into [0, 2pi) with `+= 6.2831855f`; the
    computer path passes it through unwrapped.
    """

    # `0 - v` keeps a +0 component positive, like native `pos - target`.
    away = Vec2(x87_pc24_sub(0.0, move.x), x87_pc24_sub(0.0, move.y))
    if normalize:
        away = away.normalized()  # D3DXVec2Normalize
    heading = x87_pc24_sub(x87_fpatan(away.y, away.x), NATIVE_HALF_PI)
    if wrap:
        while heading < 0.0:
            heading = x87_pc24_add(heading, NATIVE_TAU)
    return heading


def _player_move_toward_heading(
    player: PlayerState,
    perk_player: PlayerState,
    *,
    target_heading: float | None,
    movement_dt: float,
    speed_multiplier: float,
) -> Vec2:
    """Shared native tail of the point-click, dual-pad and computer movement branches."""

    if target_heading is not None and target_heading != _RELATIVE_MOVE_HEADING_NONE:
        angle_diff = _player_heading_approach_target(player, target_heading, movement_dt)
        _player_accelerate_move_speed(player, perk_player, movement_dt)
        _player_apply_move_speed_caps(player)
        velocity = _player_turn_aligned_velocity_native(
            direction=_direction_from_heading_native(float(player.heading)),
            move_speed=float(player.move_speed),
            angle_diff=float(angle_diff),
            speed_multiplier=float(speed_multiplier),
        )
    else:
        _player_decelerate_move_speed(player, movement_dt)
        velocity = _player_heading_velocity(player, speed_multiplier=speed_multiplier, speed_scale=25.0)
    return _player_move_delta_from_velocity(movement_dt, velocity)


def _player_move(
    player: PlayerState, perk_player: PlayerState, input_state: PlayerInput,
    state: GameplayState, movement_dt: float, move_mode: MovementControlType,
    speed_multiplier: float, spawn_slots: Sequence[SpawnSlotInit] | None,
    creatures: Sequence[CreatureState] | None,
) -> None:
    # Movement.
    raw_move = input_state.move
    phase_sign = 1.0
    player_controlled_movement = (not state.demo_mode_active) and move_mode != MovementControlType.COMPUTER
    if player_controlled_movement and move_mode == MovementControlType.RELATIVE:
        turning_left = bool(input_state.turn_left_pressed)
        turning_right = bool(input_state.turn_right_pressed)
        moving_forward = bool(input_state.move_forward_pressed)
        moving_backward = bool(input_state.move_backward_pressed)
        turned = False

        if player.turn_speed < 1.0:
            player.turn_speed = 1.0
        if player.turn_speed > 7.0:
            player.turn_speed = 7.0

        if turning_left or turning_right:
            # 0x004144dc: `turn_speed += frame_dt * 10.0f`, then
            # `heading/aim_heading -+= turn_speed * frame_dt * 0.5f`, all at PC24.
            player.turn_speed = x87_pc24_add(x87_pc24_mul(movement_dt, 10.0), player.turn_speed)
            turn_step = x87_pc24_mul(x87_pc24_mul(player.turn_speed, movement_dt), 0.5)
            if turning_left:
                turn_step = -turn_step
            player.heading = x87_pc24_add(player.heading, turn_step)
            player.aim_heading = x87_pc24_add(player.aim_heading, turn_step)
            turned = True

        if moving_forward:
            _player_accelerate_move_speed(player, perk_player, movement_dt)
            _player_apply_move_speed_caps(player)
            speed_scale = 25.0
        elif moving_backward:
            _player_accelerate_move_speed(player, perk_player, movement_dt)
            phase_sign = -1.0
            speed_scale = -25.0
        else:
            if not turned:
                player.turn_speed = 1.0
            _player_decelerate_move_speed(player, movement_dt)
            speed_scale = 25.0
        move_delta = _player_move_delta_from_heading(
            player=player,
            movement_dt=movement_dt,
            speed_multiplier=speed_multiplier,
            speed_scale=speed_scale,
        )
    elif player_controlled_movement and move_mode == MovementControlType.STATIC:
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
            velocity = _player_heading_velocity(player, speed_multiplier=speed_multiplier, speed_scale=25.0)
        else:
            angle_diff, turn_delta = _player_heading_approach_target_with_delta(
                player,
                float(target_heading),
                float(movement_dt),
            )
            player.aim_heading = float(f32(float(player.aim_heading) + float(turn_delta)))
            _player_accelerate_move_speed(player, perk_player, movement_dt)
            _player_apply_move_speed_caps(player)
            velocity = _player_turn_aligned_velocity_native(
                direction=_direction_from_heading_native(float(player.heading)),
                move_speed=float(player.move_speed),
                angle_diff=float(angle_diff),
                speed_multiplier=float(speed_multiplier),
            )
        move_delta = _player_move_delta_from_velocity(movement_dt, velocity)
    else:
        # Point click, dual action pad and computer control steer toward the
        # input vector; native never scales speed by the stick magnitude.
        target_heading: float | None = None
        if not player_controlled_movement:
            if raw_move.x != 0.0 or raw_move.y != 0.0:
                target_heading = _native_move_target_heading(raw_move, normalize=False, wrap=False)
        elif move_mode == MovementControlType.MOUSE_POINT_CLICK:
            if raw_move.x != 0.0 or raw_move.y != 0.0:
                target_heading = _native_move_target_heading(raw_move, normalize=False, wrap=True)
        elif x87_pc24_hypot(raw_move.x, raw_move.y) > _DUAL_ACTION_PAD_DEADZONE:
            target_heading = _native_move_target_heading(raw_move, normalize=True, wrap=True)
        move_delta = _player_move_toward_heading(
            player,
            perk_player,
            target_heading=target_heading,
            movement_dt=movement_dt,
            speed_multiplier=speed_multiplier,
        )

    _player_apply_move_with_spawn_avoidance(
        player,
        perk_player=perk_player,
        delta=move_delta,
        spawn_slots=spawn_slots,
        creatures=creatures,
    )

    phase_speed_dt = f32(float(movement_dt) * float(player.move_speed))
    phase_step = f32(float(phase_speed_dt) * 19.0)
    player.move_phase = f32(float(player.move_phase) + float(phase_sign) * float(phase_step))



def _player_tick_reload(
    player: PlayerState, perk_player: PlayerState, input_state: PlayerInput,
    state: GameplayState, dt: float, prev_pos: Vec2, move_mode: MovementControlType,
    players: list[PlayerState] | None,
) -> bool:
    move_delta = player.pos - prev_pos
    reload_stationary = move_delta.x == 0.0 and move_delta.y == 0.0
    if not reload_stationary:
        # Native clears these post-perk-tick timers after movement when position changed.
        player.man_bomb_timer = 0.0
        player.living_fortress_timer = 0.0
    reload_scale = 1.0
    if reload_stationary and perk_active(perk_player, PerkId.STATIONARY_RELOADER):
        reload_scale = 3.0

    # Reload + reload perks.
    if (
        perk_active(perk_player, PerkId.ANXIOUS_LOADER)
        and input_state.fire_pressed
        and player.weapon.reload_timer > 0.0
    ):
        anxious_next = x87_pc24_sub(
            float(player.weapon.reload_timer),
            f32(0.05),
        )
        player.weapon.reload_timer = float(anxious_next)
        if float(anxious_next) <= 0.0:
            # Native restarts the tail of the reload at `frame_dt * 0.8` when
            # Anxious Loader overcuts the timer.
            player.weapon.reload_timer = x87_pc24_mul(float(dt), f32(0.8))

    reload_timer_now = float(f32(float(player.weapon.reload_timer)))
    dt_f32 = float(f32(float(dt)))
    reload_step = x87_pc24_mul(f32(float(reload_scale)), dt_f32)
    # Native preloads ammo one frame before reload timer underflows using the
    # unscaled `frame_dt` (before Stationary Reloader scale is applied). That
    # can miss reload completion when Stationary Reloader is active, leaving the
    # clip empty and causing a one-shot reload loop (fixed by default).
    preload_dt = dt_f32
    if not state.preserve_bugs:
        preload_dt = reload_step

    reload_preload_underflow = x87_pc24_sub(reload_timer_now, preload_dt)
    if reload_timer_now > 0.0 and reload_preload_underflow < 0.0:
        player.weapon.ammo = float(player.weapon.clip_size)

    if player.weapon.reload_timer > 0.0:
        if (
            perk_active(perk_player, PerkId.ANGRY_RELOADER)
            and player.weapon.reload_timer_max > 0.5
            and x87_pc24_mul(player.weapon.reload_timer_max, f32(0.5)) < player.weapon.reload_timer
        ):
            half = x87_pc24_mul(player.weapon.reload_timer_max, f32(0.5))
            next_timer = x87_pc24_sub(float(player.weapon.reload_timer), reload_step)
            player.weapon.reload_timer = next_timer
            if next_timer <= half:
                count = 7 + int(player.weapon.reload_timer_max * 4.0)
                state.bonus_spawn_guard = True
                _spawn_projectile_ring(
                    state,
                    player.pos,
                    count=count,
                    angle_offset=0.1,
                    type_id=ProjectileTemplateId.PLASMA_MINIGUN,
                    owner=_owner_ref_for_player_projectiles(state, player.index),
                    owner_player_index=player.index,
                    players=players,
                )
                state.bonus_spawn_guard = False
                state.sfx_queue.append(SfxRequest(SfxId.EXPLOSION_SMALL, player.pos))
        else:
            player.weapon.reload_timer = x87_pc24_sub(
                float(player.weapon.reload_timer),
                reload_step,
            )

    if player.weapon.reload_timer < 0.0:
        player.weapon.reload_timer = 0.0

    has_alt_weapon_perk = perk_active(perk_player, PerkId.ALTERNATE_WEAPON)
    single_player_mode = (len(players) == 1) if players is not None else True
    # Native gates on `grim_is_key_active` (key held), so holding reload chains
    # reloads back-to-back as each one completes.
    manual_reload_allowed = (
        bool(input_state.reload_down or input_state.reload_pressed)
        and (not state.demo_mode_active)
        and (not has_alt_weapon_perk)
        and move_mode != MovementControlType.MOUSE_POINT_CLICK
        and float(player.weapon.reload_timer) == 0.0
        and bool(single_player_mode)
    )
    if manual_reload_allowed:
        _player_start_reload(player, state, players=players)

    return has_alt_weapon_perk


def player_update(
    player: PlayerState,
    input_state: PlayerInput,
    dt: float,
    state: GameplayState,
    *,
    detail_preset: int = 5,
    violence_disabled: int = 0,
    world_size: float = 1024.0,
    players: list[PlayerState] | None = None,
    creatures: Sequence[CreatureState] | None = None,
    spawn_slots: Sequence[SpawnSlotInit] | None = None,
    player_death_runtime: PlayerDeathRuntime | None = None,
    reload_active_any: bool | None = None,
) -> float:
    """Port of `player_update` (0x004136b0) for the rewrite runtime.

    Returns the global frame_dt as native leaves it for the rest of the frame:
    Reflex Boost's movement scaling round-trips it for live players.
    """

    dt = float(f32(float(dt)))
    if dt <= 0.0:
        return dt

    prev_pos = player.pos

    if player.health <= 0.0:
        player.death_timer = x87_pc24_sub(
            player.death_timer,
            x87_pc24_mul(dt, f32(20.0)),
        )
        return dt

    # Native's player_update perk queries all read the global slot-zero table,
    # even while the overlay-selected player's fields are being updated.
    perk_player = players[0] if state.preserve_bugs and players else player

    _player_tick_low_health(player, state, dt, detail_preset, violence_disabled)

    damping_scalar = float(f32(float(state.player_spread_damping_scalar)))
    if float(state.player_spread_damping_gate) <= 0.0:
        damping_scalar = float(f32(float(damping_scalar) + float(f32(float(dt) * 0.8))))
        if damping_scalar > 1.0:
            damping_scalar = 1.0
    else:
        damping_scalar = float(f32(float(damping_scalar) - float(dt)))
        if damping_scalar < 0.3:
            damping_scalar = 0.3
    state.player_spread_damping_scalar = float(damping_scalar)

    player.muzzle_flash_alpha = max(
        0.0,
        x87_pc24_sub(
            player.muzzle_flash_alpha,
            x87_pc24_mul(dt, f32(2.0)),
        ),
    )
    cooldown_decay = float(f32(float(dt) * (1.5 if state.bonuses.weapon_power_up > 0.0 else 1.0)))
    next_shot_cooldown = float(f32(float(player.weapon.shot_cooldown) - float(cooldown_decay)))
    player.weapon.shot_cooldown = max(0.0, float(next_shot_cooldown))

    speed_bonus_active = player.speed_bonus_timer > 0.0
    if player.aux_timer > 0.0:
        aux_decay = 1.4 if player.aux_timer >= 1.0 else 0.5
        player.aux_timer = max(0.0, player.aux_timer - dt * aux_decay)

    move_mode = _resolve_move_mode_for_update(input_state, state)
    aim_scheme = _resolve_aim_scheme_for_update(input_state, state)

    speed_multiplier = float(player.speed_multiplier)
    if speed_bonus_active:
        speed_multiplier += 1.0

    time_scale_factor = reflex_boost_time_scale_factor(
        reflex_boost_timer=state.bonuses.reflex_boost,
        time_scale_active=bool(state.time_scale_active),
    )
    movement_dt = dt
    if state.time_scale_active:
        movement_dt = _player_reflex_movement_dt(dt, time_scale_factor)

    apply_player_perk_ticks(
        player=player,
        player_pos_before_move=prev_pos,
        dt=dt,
        state=state,
        players=players,
        owner_ref_for_player=_owner_ref_for_player,
        owner_ref_for_player_projectiles=_owner_ref_for_player_projectiles,
        projectile_spawn=_projectile_spawn,
    )

    _player_move(
        player, perk_player, input_state, state, movement_dt, move_mode,
        speed_multiplier, spawn_slots, creatures,
    )

    # Spread cooling, reload, aim and firing read the restored frame_dt.
    frame_dt = dt
    if state.time_scale_active:
        frame_dt = _player_reflex_restored_dt(movement_dt, time_scale_factor)

    has_alt_weapon_perk = _player_tick_reload(
        player, perk_player, input_state, state, frame_dt, prev_pos, move_mode, players,
    )

    _player_update_aim_by_scheme(
        player=player,
        input_state=input_state,
        dt=frame_dt,
        movement_mode=move_mode,
        aim_scheme=aim_scheme,
        demo_mode_active=bool(state.demo_mode_active),
    )

    # Native cools spread after perk timers/movement but before weapon fire.
    # Keeping this below `apply_player_perk_ticks` preserves Fire Cough spread
    # sampling order while still applying cooldown before `player_fire_weapon`.
    if perk_active(perk_player, PerkId.SHARPSHOOTER):
        player.spread_heat = f32(0.02)
    else:
        player.spread_heat = max(
            f32(0.01),
            x87_pc24_sub(player.spread_heat, x87_pc24_mul(frame_dt, f32(0.4))),
        )

    # Native latches both normal and perk readiness before exchanging weapon
    # slots; the old normal flag also decides whether the incoming shot costs XP/HP.
    fire_gate = _capture_fire_gate(player, perk_player)

    # Native clears `reload_active` whenever the cooldown/timer gates are open,
    # even if ammo is empty and perk firing paths can still proceed.
    if fire_gate.normal_ready:
        player.weapon.reload_active = False

    reload_key_active = bool(input_state.reload_down or input_state.reload_pressed)
    reload_key_released = (not bool(reload_active_any)) if reload_active_any is not None else (not reload_key_active)
    if has_alt_weapon_perk:
        cooldown_ms = int(state.player_alt_weapon_swap_cooldown_ms)
        dt_ms = ftol_ms_i32(float(dt)) if float(dt) > 0.0 else 0
        if cooldown_ms < 1:
            cooldown_ms = 0
        else:
            cooldown_ms -= dt_ms

        if cooldown_ms < 1 and reload_key_active:
            if _player_swap_alt_weapon(player):
                weapon = _weapon_entry(player.weapon.weapon_id)
                state.sfx_queue.append(SfxRequest(weapon.reload_sound, player.pos))
                player.weapon.shot_cooldown = x87_pc24_add(player.weapon.shot_cooldown, f32(0.1))
                state.player_alt_weapon_swap_cooldown_ms = 200
            else:
                state.player_alt_weapon_swap_cooldown_ms = 0
        else:
            state.player_alt_weapon_swap_cooldown_ms = max(0, int(cooldown_ms))
            if reload_key_released:
                state.player_alt_weapon_swap_cooldown_ms = 0

    _fire_weapon(
        _WeaponFireCtx(
            player=player,
            input_state=input_state,
            dt=frame_dt,
            state=state,
            detail_preset=int(detail_preset),
            creatures=creatures,
            players=players,
            fire_gate=fire_gate,
            player_death_runtime=player_death_runtime,
        ),
    )

    while player.move_phase > 14.0:
        player.move_phase = f32(float(player.move_phase) - 14.0)
    while player.move_phase < 0.0:
        player.move_phase = f32(float(player.move_phase) + 14.0)

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
    return frame_dt


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
    # 0x00413602: `fld 6.2831855f; fsub high; fadd low` rounds each op at PC24.
    wrapped = abs(x87_pc24_add(x87_pc24_sub(NATIVE_TAU, high), low))
    diff = wrapped if direct >= wrapped else direct

    dt_f32 = float(f32(float(dt)))
    # Native computes `frame_dt * diff * 5.0` under x87 PC=24. Quantize after
    # each multiply to model that precision even though the intermediate stays
    # on the x87 stack.
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
