from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from typing import Protocol

import msgspec

from grim.config import CrimsonConfig
from grim.geom import Vec2
from grim.raylib_api import rl

from .aim_constants import _AIM_JOYSTICK_TURN_RATE, _AIM_KEYBOARD_TURN_RATE
from .aim_schemes import AimScheme
from .input_codes import (
    input_axis_value,
    input_code_is_down,
    input_code_is_pressed,
)
from .movement_controls import MovementControlType
from .sim.input import PlayerInput
from .sim.state_types import PlayerState

_AIM_RADIUS_KEYBOARD = 60.0
_AIM_RADIUS_PAD_BASE = 42.0
# Native uses `cv_padAimDistMul` (default 96).
_AIM_RADIUS_PAD_SCALE = 96.0
_POINT_CLICK_STOP_RADIUS = 20.0
_COMPUTER_TARGET_SWITCH_HYSTERESIS = 64.0
_COMPUTER_ARENA_CENTER = Vec2(512.0, 512.0)
_COMPUTER_MOVE_TARGET_RADIUS = 300.0
_COMPUTER_AIM_SNAP_DISTANCE = 4.0
_COMPUTER_AIM_TRACK_GAIN = 6.0
_COMPUTER_AUTO_FIRE_DISTANCE = 128.0

_ALT_MOVE_KEY_UP = 0xC8
_ALT_MOVE_KEY_DOWN = 0xD0
_ALT_MOVE_KEY_LEFT = 0xCB
_ALT_MOVE_KEY_RIGHT = 0xCD
_AIM_POV_LEFT_CODE = 0x133
_AIM_POV_RIGHT_CODE = 0x134


class _PerPlayerInputState(msgspec.Struct):
    aim_heading: float = 0.0
    move_target: Vec2 = Vec2(-1.0, -1.0)
    computer_target_creature_index: int = -1


class _ComputerAimCreature(Protocol):
    active: bool
    hp: float
    pos: Vec2


def _is_finite(v: float) -> bool:
    return math.isfinite(float(v))


def _clamp_unit(v: float) -> float:
    value = float(v)
    if value < -1.0:
        return -1.0
    if value > 1.0:
        return 1.0
    return value


def _aim_point_from_heading(pos: Vec2, heading: float, *, radius: float = _AIM_RADIUS_KEYBOARD) -> Vec2:
    return pos + Vec2.from_heading(float(heading)) * float(radius)


def _resolve_static_move_vector(
    *,
    move_up: bool,
    move_down: bool,
    move_left: bool,
    move_right: bool,
) -> Vec2:
    """Mirror native move-mode 2 key precedence from `player_update`."""

    move = Vec2()
    if move_left:
        move = Vec2(-1.0, 0.0)
    if move_right:
        move = Vec2(1.0, 0.0)

    if move_up:
        if move_left:
            move = Vec2(-1.0, -1.0)
        elif move_right:
            move = Vec2(1.0, -1.0)
        else:
            move = Vec2(0.0, -1.0)

    # Native checks backward after forward, so it overrides on conflicts.
    if move_down:
        if move_left:
            move = Vec2(-1.0, 1.0)
        elif move_right:
            move = Vec2(1.0, 1.0)
        else:
            move = Vec2(0.0, 1.0)

    return move


def _config_player_count(config: CrimsonConfig) -> int:
    return max(1, int(config.gameplay.player_count))


def _single_player_alt_keys_enabled(config: CrimsonConfig, *, player_index: int) -> bool:
    return int(player_index) == 0 and _config_player_count(config) == 1


def _key_down_with_single_player_alt(
    primary_key: int,
    *,
    alt_key: int,
    config: CrimsonConfig,
    player_index: int,
) -> bool:
    if input_code_is_down(primary_key, player_index=int(player_index)):
        return True
    if _single_player_alt_keys_enabled(config, player_index=int(player_index)):
        return input_code_is_down(int(alt_key), player_index=int(player_index))
    return False


def _aim_pov_left_active(*, player_index: int, preserve_bugs: bool) -> bool:
    # Native `input_aim_pov_left_active` always reads joystick POV index 0.
    pov_index = 0 if preserve_bugs else int(player_index)
    return input_code_is_down(_AIM_POV_LEFT_CODE, player_index=pov_index)


def _aim_pov_right_active(*, player_index: int, preserve_bugs: bool) -> bool:
    # Native `input_aim_pov_right_active` always reads joystick POV index 0.
    pov_index = 0 if preserve_bugs else int(player_index)
    return input_code_is_down(_AIM_POV_RIGHT_CODE, player_index=pov_index)


def clear_input_edges(inputs: Sequence[PlayerInput]) -> list[PlayerInput]:
    return [
        PlayerInput(
            move=inp.move,
            aim=inp.aim,
            fire_down=inp.fire_down,
            fire_pressed=False,
            reload_pressed=False,
            move_to_cursor_pressed=False,
            move_forward_pressed=inp.move_forward_pressed,
            move_backward_pressed=inp.move_backward_pressed,
            turn_left_pressed=inp.turn_left_pressed,
            turn_right_pressed=inp.turn_right_pressed,
        )
        for inp in inputs
    ]


class LocalInputInterpreter:
    def __init__(self, *, preserve_bugs: bool = False) -> None:
        self._states: list[_PerPlayerInputState] = [_PerPlayerInputState() for _ in range(4)]
        self._preserve_bugs = preserve_bugs

    def set_preserve_bugs(self, enabled: bool) -> None:
        self._preserve_bugs = enabled

    @staticmethod
    def _state_slot_for_player(*, player_index: int, player: PlayerState | None = None) -> int:
        slot = int(player_index)
        if player is not None:
            slot = int(player.index)
        return max(0, min(3, slot))

    def reset(self, *, players: Sequence[PlayerState] | None = None) -> None:
        for idx in range(4):
            state = self._states[idx]
            state.move_target = Vec2(-1.0, -1.0)
            state.computer_target_creature_index = -1
            state.aim_heading = 0.0
        if players is None:
            return
        for idx, player in enumerate(players):
            slot = self._state_slot_for_player(player_index=int(idx), player=player)
            candidate = float(player.aim_heading)
            if _is_finite(candidate):
                self._states[slot].aim_heading = float(candidate)

    @staticmethod
    def _nearest_living_creature_index(pos: Vec2, creatures: Sequence[_ComputerAimCreature]) -> int | None:
        best_idx: int | None = None
        best_dist_sq = 0.0
        for idx, creature in enumerate(creatures):
            if not creature.active:
                continue
            if float(creature.hp) <= 0.0:
                continue
            dist_sq = Vec2.distance_sq(pos, creature.pos)
            if best_idx is None or float(dist_sq) < float(best_dist_sq):
                best_idx = int(idx)
                best_dist_sq = float(dist_sq)
        return best_idx

    def _select_computer_target(
        self,
        *,
        player_index: int,
        player: PlayerState,
        creatures: Sequence[_ComputerAimCreature],
    ) -> int | None:
        slot = self._state_slot_for_player(player_index=int(player_index), player=player)
        state = self._states[slot]
        candidate = self._nearest_living_creature_index(player.pos, creatures)
        current = int(state.computer_target_creature_index)

        if candidate is None:
            state.computer_target_creature_index = -1
            return None
        if current < 0 or current >= len(creatures):
            state.computer_target_creature_index = int(candidate)
            return int(candidate)

        current_creature = creatures[current]
        if not current_creature.active or float(current_creature.hp) <= 0.0:
            state.computer_target_creature_index = int(candidate)
            return int(candidate)
        if int(candidate) == int(current):
            return int(current)

        candidate_creature = creatures[int(candidate)]
        if not candidate_creature.active or float(candidate_creature.hp) <= 0.0:
            return int(current)

        current_dist = (current_creature.pos - player.pos).length()
        candidate_dist = (candidate_creature.pos - player.pos).length()
        if float(candidate_dist) + float(_COMPUTER_TARGET_SWITCH_HYSTERESIS) < float(current_dist):
            state.computer_target_creature_index = int(candidate)
            return int(candidate)
        return int(current)

    def _state_for_player(self, player_index: int, *, player: PlayerState | None = None) -> _PerPlayerInputState:
        slot = self._state_slot_for_player(player_index=int(player_index), player=player)
        state = self._states[slot]
        if player is not None and (not _is_finite(state.aim_heading)):
            state.aim_heading = float(player.aim_heading)
        return state

    def build_player_input(
        self,
        *,
        player_index: int,
        player: PlayerState,
        config: CrimsonConfig,
        mouse_screen: Vec2,
        mouse_world: Vec2,
        screen_center: Vec2,
        dt: float,
        creatures: Sequence[_ComputerAimCreature] | None = None,
    ) -> PlayerInput:
        idx = max(0, min(3, int(player_index)))
        state = self._state_for_player(idx, player=player)
        binds = config.controls.player(idx)
        aim_scheme = binds.aim_scheme
        move_mode_type = binds.movement
        reload_key = config.controls.reload_code

        move_forward_key, move_backward_key, turn_left_key, turn_right_key = binds.move_codes
        fire_key = binds.fire_code
        aim_left_key, aim_right_key = binds.keyboard_aim_codes
        aim_axis_y, aim_axis_x = binds.aim_axis_codes
        move_axis_y, move_axis_x = binds.move_axis_codes

        move_vec = Vec2()
        move_forward_pressed: bool | None = None
        move_backward_pressed: bool | None = None
        turn_left_pressed: bool | None = None
        turn_right_pressed: bool | None = None
        move_to_cursor_pressed = False
        computer_target_index: int | None = None
        computer_move_active = move_mode_type is MovementControlType.COMPUTER

        if computer_move_active:
            if creatures:
                computer_target_index = self._select_computer_target(
                    player_index=idx,
                    player=player,
                    creatures=creatures,
                )
            center_delta = _COMPUTER_ARENA_CENTER - player.pos
            center_dist = center_delta.length()
            has_live_target = (
                creatures is not None
                and computer_target_index is not None
                and 0 <= int(computer_target_index) < len(creatures)
            )
            if has_live_target and float(center_dist) <= _COMPUTER_MOVE_TARGET_RADIUS:
                assert creatures is not None
                assert computer_target_index is not None
                move_delta = Vec2(
                    float(creatures[int(computer_target_index)].pos.x),
                    float(creatures[int(computer_target_index)].pos.y),
                ) - player.pos
            elif has_live_target:
                move_delta = center_delta
            else:
                move_delta = (player.pos - _COMPUTER_ARENA_CENTER).perp_left()
                if move_delta.length_sq() <= 1e-12:
                    move_delta = Vec2(0.0, 1.0)

            move_dir, move_dist = move_delta.normalized_with_length()
            if float(move_dist) > 1e-6:
                move_vec = move_dir
        elif move_mode_type is MovementControlType.RELATIVE:
            move_forward_pressed = _key_down_with_single_player_alt(
                move_forward_key,
                alt_key=_ALT_MOVE_KEY_UP,
                config=config,
                player_index=idx,
            )
            move_backward_pressed = _key_down_with_single_player_alt(
                move_backward_key,
                alt_key=_ALT_MOVE_KEY_DOWN,
                config=config,
                player_index=idx,
            )
            turn_left_pressed = _key_down_with_single_player_alt(
                turn_left_key,
                alt_key=_ALT_MOVE_KEY_LEFT,
                config=config,
                player_index=idx,
            )
            turn_right_pressed = _key_down_with_single_player_alt(
                turn_right_key,
                alt_key=_ALT_MOVE_KEY_RIGHT,
                config=config,
                player_index=idx,
            )
            move_vec = Vec2(
                float(turn_right_pressed) - float(turn_left_pressed),
                float(move_backward_pressed) - float(move_forward_pressed),
            )
        elif move_mode_type is MovementControlType.DUAL_ACTION_PAD:
            axis_y = -input_axis_value(move_axis_y, player_index=idx)
            axis_x = -input_axis_value(move_axis_x, player_index=idx)
            move_vec = Vec2(_clamp_unit(axis_x), _clamp_unit(axis_y))
        elif move_mode_type is MovementControlType.MOUSE_POINT_CLICK:
            move_to_cursor_pressed = input_code_is_down(reload_key, player_index=idx)
            if move_to_cursor_pressed:
                state.move_target = mouse_world
            if float(state.move_target.x) >= 0.0 and float(state.move_target.y) >= 0.0:
                delta = state.move_target - player.pos
                _dir, dist = delta.normalized_with_length()
                if float(dist) > _POINT_CLICK_STOP_RADIUS:
                    move_vec = _dir
        elif move_mode_type is MovementControlType.STATIC:
            move_up_pressed = _key_down_with_single_player_alt(
                move_forward_key,
                alt_key=_ALT_MOVE_KEY_UP,
                config=config,
                player_index=idx,
            )
            move_down_pressed = _key_down_with_single_player_alt(
                move_backward_key,
                alt_key=_ALT_MOVE_KEY_DOWN,
                config=config,
                player_index=idx,
            )
            move_left_pressed = _key_down_with_single_player_alt(
                turn_left_key,
                alt_key=_ALT_MOVE_KEY_LEFT,
                config=config,
                player_index=idx,
            )
            move_right_pressed = _key_down_with_single_player_alt(
                turn_right_key,
                alt_key=_ALT_MOVE_KEY_RIGHT,
                config=config,
                player_index=idx,
            )
            move_forward_pressed = move_up_pressed
            move_backward_pressed = move_down_pressed
            turn_left_pressed = move_left_pressed
            turn_right_pressed = move_right_pressed
            move_vec = _resolve_static_move_vector(
                move_up=move_up_pressed,
                move_down=move_down_pressed,
                move_left=move_left_pressed,
                move_right=move_right_pressed,
            )
        else:
            move_vec = Vec2(
                float(input_code_is_down(turn_right_key, player_index=idx))
                - float(input_code_is_down(turn_left_key, player_index=idx)),
                float(input_code_is_down(move_backward_key, player_index=idx))
                - float(input_code_is_down(move_forward_key, player_index=idx)),
            )

        heading = float(state.aim_heading)
        if not _is_finite(heading):
            heading = float(player.aim_heading)
        aim = Vec2(float(player.aim.x), float(player.aim.y))
        computer_auto_fire = False
        if aim_scheme is AimScheme.MOUSE:
            aim = mouse_world
            delta = aim - player.pos
            if delta.length_sq() > 1e-9:
                heading = delta.to_heading()
        elif aim_scheme is AimScheme.KEYBOARD:
            if move_mode_type in {MovementControlType.RELATIVE, MovementControlType.STATIC}:
                if input_code_is_down(aim_right_key, player_index=idx):
                    heading = float(heading + float(dt) * _AIM_KEYBOARD_TURN_RATE)
                if input_code_is_down(aim_left_key, player_index=idx):
                    heading = float(heading - float(dt) * _AIM_KEYBOARD_TURN_RATE)
                aim = _aim_point_from_heading(player.pos, heading)
        elif aim_scheme is AimScheme.MOUSE_RELATIVE:
            rel = mouse_screen - screen_center
            if rel.length_sq() > 1.0:
                heading = rel.to_heading()
                aim = _aim_point_from_heading(player.pos, heading)
        elif aim_scheme is AimScheme.DUAL_ACTION_PAD:
            axis_y = input_axis_value(aim_axis_y, player_index=idx)
            axis_x = input_axis_value(aim_axis_x, player_index=idx)
            axis_vec = Vec2(axis_x, axis_y)
            mag_sq = axis_vec.length_sq()
            if mag_sq > 1e-9:
                axis_dir, mag = axis_vec.normalized_with_length()
                heading = axis_dir.to_heading()
                radius = _AIM_RADIUS_PAD_BASE + mag * _AIM_RADIUS_PAD_SCALE
                aim = player.pos + axis_dir * radius
            else:
                aim = _aim_point_from_heading(player.pos, heading)
        elif aim_scheme is AimScheme.JOYSTICK:
            if _aim_pov_right_active(player_index=idx, preserve_bugs=self._preserve_bugs):
                heading = float(heading + float(dt) * _AIM_JOYSTICK_TURN_RATE)
            if _aim_pov_left_active(player_index=idx, preserve_bugs=self._preserve_bugs):
                heading = float(heading - float(dt) * _AIM_JOYSTICK_TURN_RATE)
            aim = _aim_point_from_heading(player.pos, heading)
        elif aim_scheme is AimScheme.COMPUTER:
            target_index = computer_target_index
            if target_index is None and creatures:
                target_index = self._select_computer_target(
                    player_index=idx,
                    player=player,
                    creatures=creatures,
                )
            if creatures is not None and target_index is not None and 0 <= int(target_index) < len(creatures):
                target = creatures[int(target_index)]
                aim = Vec2(float(player.aim.x), float(player.aim.y))
                to_target = Vec2(float(target.pos.x), float(target.pos.y)) - aim
                target_dir, target_dist = to_target.normalized_with_length()
                if float(target_dist) >= _COMPUTER_AIM_SNAP_DISTANCE:
                    aim = aim + target_dir * (float(target_dist) * _COMPUTER_AIM_TRACK_GAIN * float(dt))
                else:
                    aim = Vec2(float(target.pos.x), float(target.pos.y))
                delta = aim - player.pos
                if delta.length_sq() > 1e-9:
                    heading = delta.to_heading()
                computer_auto_fire = float(target_dist) < _COMPUTER_AUTO_FIRE_DISTANCE
            else:
                away, away_mag = (player.pos - _COMPUTER_ARENA_CENTER).normalized_with_length()
                if float(away_mag) <= 1e-6:
                    away = Vec2(0.0, -1.0)
                aim = player.pos + away * _AIM_RADIUS_KEYBOARD
                heading = away.to_heading()

        delta = aim - player.pos
        if delta.length_sq() > 1e-9:
            heading = delta.to_heading()
        state.aim_heading = float(heading)

        fire_down = input_code_is_down(fire_key, player_index=idx)
        fire_pressed = input_code_is_pressed(fire_key, player_index=idx)
        if aim_scheme is AimScheme.COMPUTER and computer_auto_fire:
            fire_down = True
        reload_pressed = input_code_is_pressed(reload_key, player_index=idx)
        reload_down = input_code_is_down(reload_key, player_index=idx)

        return PlayerInput(
            move=move_vec,
            aim=aim,
            move_mode=move_mode_type,
            aim_scheme=aim_scheme,
            fire_down=fire_down,
            fire_pressed=fire_pressed,
            reload_pressed=reload_pressed,
            reload_down=reload_down,
            move_to_cursor_pressed=move_to_cursor_pressed,
            move_forward_pressed=move_forward_pressed,
            move_backward_pressed=move_backward_pressed,
            turn_left_pressed=turn_left_pressed,
            turn_right_pressed=turn_right_pressed,
        )

    def build_frame_inputs(
        self,
        *,
        players: Sequence[PlayerState],
        config: CrimsonConfig,
        mouse_screen: Vec2,
        screen_to_world: Callable[[Vec2], Vec2],
        dt: float,
        creatures: Sequence[_ComputerAimCreature] | None = None,
    ) -> list[PlayerInput]:
        mouse_world = screen_to_world(mouse_screen)
        screen_center = Vec2(float(rl.get_screen_width()) * 0.5, float(rl.get_screen_height()) * 0.5)
        out: list[PlayerInput] = []
        for idx, player in enumerate(players):
            out.append(
                self.build_player_input(
                    player_index=idx,
                    player=player,
                    config=config,
                    mouse_screen=mouse_screen,
                    mouse_world=mouse_world,
                    screen_center=screen_center,
                    dt=float(dt),
                    creatures=creatures,
                ),
            )
        return out
