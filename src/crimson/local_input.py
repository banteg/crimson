from __future__ import annotations

import math
from collections.abc import Callable, Sequence

import msgspec

from grim import canvas
from grim.config import CrimsonConfig
from grim.geom import Vec2

from .aim_schemes import AimScheme
from .input_codes import (
    input_axis_value,
    input_code_is_down,
    input_code_is_pressed,
)
from .math_parity import (
    f32,
    native_aim_point_from_heading,
)
from .movement_controls import MovementControlType
from .sim.input import PlayerInput
from .sim.state_types import PlayerState

_AIM_RADIUS_KEYBOARD = 60.0
_AIM_RADIUS_PAD_BASE = 42.0
# `cv_padAimDistMul`'s registered default.
PAD_AIM_DIST_MUL_DEFAULT = 96.0
# Port-only: native aims at the player when the stick centers; a resting stick
# instead keeps the last direction, and small drift inside this radius is ignored.
_PAD_AIM_DEADZONE = 0.2

_ALT_MOVE_KEY_UP = 0xC8
_ALT_MOVE_KEY_DOWN = 0xD0
_ALT_MOVE_KEY_LEFT = 0xCB
_ALT_MOVE_KEY_RIGHT = 0xCD
_AIM_POV_LEFT_CODE = 0x133
_AIM_POV_RIGHT_CODE = 0x134


class _PerPlayerInputState(msgspec.Struct):
    aim_heading: float = 0.0
    move_target: Vec2 = Vec2(-1.0, -1.0)


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
    return native_aim_point_from_heading(pos, heading, radius=radius)


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
            state.aim_heading = 0.0
        if players is None:
            return
        for idx, player in enumerate(players):
            slot = self._state_slot_for_player(player_index=int(idx), player=player)
            candidate = float(player.aim_heading)
            if _is_finite(candidate):
                self._states[slot].aim_heading = float(candidate)

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
        pad_aim_dist_mul: float = PAD_AIM_DIST_MUL_DEFAULT,
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
        move_forward_pressed = False
        move_backward_pressed = False
        turn_left_pressed = False
        turn_right_pressed = False

        # Computer control reads no device: the sim picks its target, steers and aims.
        if move_mode_type is MovementControlType.RELATIVE:
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
            # `move` is the direction to travel.  Native builds `movement_input`
            # from the negated axes and heads away from it (0x00414235); the sim
            # applies that negation and the 0.2 stick radius itself.
            axis_y = input_axis_value(move_axis_y, player_index=idx)
            axis_x = input_axis_value(move_axis_x, player_index=idx)
            move_vec = Vec2(_clamp_unit(axis_x), _clamp_unit(axis_y))
        elif move_mode_type is MovementControlType.MOUSE_POINT_CLICK:
            # The reload key drops the float move target at the cursor (0x00413f5e); the sim steers
            # toward it each tick from the player's position then.
            if input_code_is_down(reload_key, player_index=idx):
                state.move_target = Vec2(f32(mouse_world.x), f32(mouse_world.y))
            move_vec = state.move_target
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
        elif move_mode_type is not MovementControlType.COMPUTER:
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
        aim_turn_left = False
        aim_turn_right = False
        if aim_scheme is AimScheme.MOUSE:
            aim = mouse_world
            delta = aim - player.pos
            if delta.length_sq() > 1e-9:
                heading = delta.to_heading()
        elif aim_scheme is AimScheme.KEYBOARD:
            # The sim turns the heading (player_update reads `aim_key_left/right`).
            aim_turn_left = input_code_is_down(aim_left_key, player_index=idx)
            aim_turn_right = input_code_is_down(aim_right_key, player_index=idx)
        elif aim_scheme is AimScheme.MOUSE_RELATIVE:
            rel = mouse_screen - screen_center
            if rel.length_sq() > 1.0:
                heading = rel.to_heading()
                aim = _aim_point_from_heading(player.pos, heading)
        elif aim_scheme is AimScheme.DUAL_ACTION_PAD:
            axis_y = input_axis_value(aim_axis_y, player_index=idx)
            axis_x = input_axis_value(aim_axis_x, player_index=idx)
            axis_dir, mag = Vec2(axis_x, axis_y).normalized_with_length()
            if mag > _PAD_AIM_DEADZONE:
                heading = axis_dir.to_heading()
                # Native clamps the stick length to 1 before scaling the reach by `cv_padAimDistMul`.
                radius = _AIM_RADIUS_PAD_BASE + min(mag, 1.0) * pad_aim_dist_mul
                aim = player.pos + axis_dir * radius
            else:
                aim = _aim_point_from_heading(player.pos, heading)
        elif aim_scheme is AimScheme.JOYSTICK:
            # The sim turns the heading (player_update reads `input_aim_pov_left/right_active`).
            aim_turn_left = _aim_pov_left_active(player_index=idx, preserve_bugs=self._preserve_bugs)
            aim_turn_right = _aim_pov_right_active(player_index=idx, preserve_bugs=self._preserve_bugs)
        delta = aim - player.pos
        if delta.length_sq() > 1e-9:
            heading = delta.to_heading()
        state.aim_heading = float(heading)

        fire_down = input_code_is_down(fire_key, player_index=idx)
        fire_pressed = input_code_is_pressed(fire_key, player_index=idx)
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
            fire_bullets_key_down=input_code_is_down(0x22, player_index=idx),
            aim_turn_left=aim_turn_left,
            aim_turn_right=aim_turn_right,
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
        pad_aim_dist_mul: float,
    ) -> list[PlayerInput]:
        mouse_world = screen_to_world(mouse_screen)
        screen_center = Vec2(float(canvas.width()) * 0.5, float(canvas.height()) * 0.5)
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
                    pad_aim_dist_mul=pad_aim_dist_mul,
                ),
            )
        return out
