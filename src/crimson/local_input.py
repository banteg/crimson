from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
import math
from typing import Protocol

import pyray as rl

from grim.config import CrimsonConfig, default_player_keybind_block
from grim.geom import Vec2

from .frontend.panels.controls_labels import controls_method_values
from .gameplay import PlayerInput, PlayerState
from .input_codes import (
    config_keybinds_for_player,
    input_axis_value_for_player,
    input_code_is_down_for_player,
    input_code_is_pressed_for_player,
)
from .movement_controls import MovementControlType, movement_control_type_from_value

_AIM_RADIUS_KEYBOARD = 60.0
_AIM_RADIUS_PAD_BASE = 42.0
_AIM_RADIUS_PAD_SCALE = 20.0
_POINT_CLICK_STOP_RADIUS = 20.0
_AIM_KEYBOARD_TURN_RATE = 3.0
_AIM_JOYSTICK_TURN_RATE = 4.0
_COMPUTER_TARGET_SWITCH_HYSTERESIS = 64.0
_COMPUTER_ARENA_CENTER = Vec2(512.0, 512.0)
_COMPUTER_AIM_SNAP_DISTANCE = 4.0
_COMPUTER_AIM_TRACK_GAIN = 6.0
_COMPUTER_AUTO_FIRE_DISTANCE = 128.0

_MOVE_SLOT_UP = 0
_MOVE_SLOT_DOWN = 1
_MOVE_SLOT_LEFT = 2
_MOVE_SLOT_RIGHT = 3
_FIRE_SLOT = 4
_AIM_LEFT_SLOT = 7
_AIM_RIGHT_SLOT = 8
_AIM_AXIS_Y_SLOT = 9
_AIM_AXIS_X_SLOT = 10
_MOVE_AXIS_Y_SLOT = 11
_MOVE_AXIS_X_SLOT = 12


@dataclass(slots=True)
class _PerPlayerInputState:
    aim_heading: float = 0.0
    move_target: Vec2 = field(default_factory=lambda: Vec2(-1.0, -1.0))
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


def _load_player_bind_block(config: CrimsonConfig | None, *, player_index: int) -> tuple[int, ...]:
    binds = config_keybinds_for_player(config, player_index=int(player_index))
    if len(binds) >= 16:
        return tuple(int(v) for v in binds[:16])
    return tuple(int(v) for v in default_player_keybind_block(int(player_index)))


def clear_input_edges(inputs: Sequence[PlayerInput]) -> list[PlayerInput]:
    return [
        PlayerInput(
            move=inp.move,
            aim=inp.aim,
            fire_down=bool(inp.fire_down),
            fire_pressed=False,
            reload_pressed=False,
            move_forward_pressed=inp.move_forward_pressed,
            move_backward_pressed=inp.move_backward_pressed,
            turn_left_pressed=inp.turn_left_pressed,
            turn_right_pressed=inp.turn_right_pressed,
        )
        for inp in inputs
    ]


class LocalInputInterpreter:
    def __init__(self) -> None:
        self._states: list[_PerPlayerInputState] = [_PerPlayerInputState() for _ in range(4)]

    def reset(self, *, players: Sequence[PlayerState] | None = None) -> None:
        for idx in range(4):
            state = self._states[idx]
            state.move_target = Vec2(-1.0, -1.0)
            state.computer_target_creature_index = -1
            heading = 0.0
            if players is not None and idx < len(players):
                candidate = float(getattr(players[idx], "aim_heading", 0.0))
                if _is_finite(candidate):
                    heading = candidate
            state.aim_heading = float(heading)

    @staticmethod
    def _nearest_living_creature_index(pos: Vec2, creatures: Sequence[_ComputerAimCreature]) -> int | None:
        best_idx: int | None = None
        best_dist_sq = 0.0
        for idx, creature in enumerate(creatures):
            if not bool(getattr(creature, "active", False)):
                continue
            if float(getattr(creature, "hp", 0.0)) <= 0.0:
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
        idx = max(0, min(3, int(player_index)))
        state = self._states[idx]
        candidate = self._nearest_living_creature_index(player.pos, creatures)
        current = int(state.computer_target_creature_index)

        if candidate is None:
            state.computer_target_creature_index = -1
            return None
        if current < 0 or current >= len(creatures):
            state.computer_target_creature_index = int(candidate)
            return int(candidate)

        current_creature = creatures[current]
        if not bool(getattr(current_creature, "active", False)) or float(getattr(current_creature, "hp", 0.0)) <= 0.0:
            state.computer_target_creature_index = int(candidate)
            return int(candidate)
        if int(candidate) == int(current):
            return int(current)

        candidate_creature = creatures[int(candidate)]
        if not bool(getattr(candidate_creature, "active", False)) or float(getattr(candidate_creature, "hp", 0.0)) <= 0.0:
            return int(current)

        current_dist = (current_creature.pos - player.pos).length()
        candidate_dist = (candidate_creature.pos - player.pos).length()
        if float(candidate_dist) + float(_COMPUTER_TARGET_SWITCH_HYSTERESIS) < float(current_dist):
            state.computer_target_creature_index = int(candidate)
            return int(candidate)
        return int(current)

    def _state_for_player(self, player_index: int, *, player: PlayerState | None = None) -> _PerPlayerInputState:
        idx = max(0, min(3, int(player_index)))
        state = self._states[idx]
        if player is not None and (not _is_finite(state.aim_heading)):
            state.aim_heading = float(getattr(player, "aim_heading", 0.0) or 0.0)
        return state

    @staticmethod
    def _reload_key(config: CrimsonConfig | None) -> int:
        if config is None:
            return 0x102
        return int(config.data.get("keybind_reload", 0x102) or 0x102)

    @staticmethod
    def _safe_controls_modes(config: CrimsonConfig | None, *, player_index: int) -> tuple[int, int]:
        if config is None:
            return 0, 2
        aim_scheme, move_mode = controls_method_values(config.data, player_index=int(player_index))
        return int(aim_scheme), int(move_mode)

    def build_player_input(
        self,
        *,
        player_index: int,
        player: PlayerState,
        config: CrimsonConfig | None,
        mouse_screen: Vec2,
        mouse_world: Vec2,
        screen_center: Vec2,
        dt_frame: float,
        creatures: Sequence[_ComputerAimCreature] | None = None,
    ) -> PlayerInput:
        idx = max(0, min(3, int(player_index)))
        state = self._state_for_player(idx, player=player)
        binds = _load_player_bind_block(config, player_index=idx)
        aim_scheme, move_mode = self._safe_controls_modes(config, player_index=idx)
        move_mode_type = movement_control_type_from_value(move_mode)
        reload_key = self._reload_key(config)

        up_key = int(binds[_MOVE_SLOT_UP])
        down_key = int(binds[_MOVE_SLOT_DOWN])
        left_key = int(binds[_MOVE_SLOT_LEFT])
        right_key = int(binds[_MOVE_SLOT_RIGHT])
        fire_key = int(binds[_FIRE_SLOT])
        aim_left_key = int(binds[_AIM_LEFT_SLOT])
        aim_right_key = int(binds[_AIM_RIGHT_SLOT])
        aim_axis_y = int(binds[_AIM_AXIS_Y_SLOT])
        aim_axis_x = int(binds[_AIM_AXIS_X_SLOT])
        move_axis_y = int(binds[_MOVE_AXIS_Y_SLOT])
        move_axis_x = int(binds[_MOVE_AXIS_X_SLOT])

        move_vec = Vec2()
        move_forward_pressed: bool | None = None
        move_backward_pressed: bool | None = None
        turn_left_pressed: bool | None = None
        turn_right_pressed: bool | None = None

        if move_mode_type is MovementControlType.RELATIVE:
            move_forward_pressed = bool(input_code_is_down_for_player(up_key, player_index=idx))
            move_backward_pressed = bool(input_code_is_down_for_player(down_key, player_index=idx))
            turn_left_pressed = bool(input_code_is_down_for_player(left_key, player_index=idx))
            turn_right_pressed = bool(input_code_is_down_for_player(right_key, player_index=idx))
            move_vec = Vec2(
                float(turn_right_pressed) - float(turn_left_pressed),
                float(move_backward_pressed) - float(move_forward_pressed),
            )
        elif move_mode_type is MovementControlType.DUAL_ACTION_PAD:
            axis_y = -input_axis_value_for_player(move_axis_y, player_index=idx)
            axis_x = -input_axis_value_for_player(move_axis_x, player_index=idx)
            move_vec = Vec2(_clamp_unit(axis_x), _clamp_unit(axis_y))
        elif move_mode_type is MovementControlType.MOUSE_POINT_CLICK:
            if input_code_is_down_for_player(reload_key, player_index=idx):
                state.move_target = mouse_world
            if float(state.move_target.x) >= 0.0 and float(state.move_target.y) >= 0.0:
                delta = state.move_target - player.pos
                _dir, dist = delta.normalized_with_length()
                if float(dist) > _POINT_CLICK_STOP_RADIUS:
                    move_vec = _dir
        elif move_mode_type is MovementControlType.COMPUTER:
            move_vec = Vec2()
        elif move_mode_type is MovementControlType.STATIC:
            move_up_pressed = bool(input_code_is_down_for_player(up_key, player_index=idx))
            move_down_pressed = bool(input_code_is_down_for_player(down_key, player_index=idx))
            move_left_pressed = bool(input_code_is_down_for_player(left_key, player_index=idx))
            move_right_pressed = bool(input_code_is_down_for_player(right_key, player_index=idx))
            move_vec = _resolve_static_move_vector(
                move_up=move_up_pressed,
                move_down=move_down_pressed,
                move_left=move_left_pressed,
                move_right=move_right_pressed,
            )
        else:
            move_vec = Vec2(
                float(input_code_is_down_for_player(right_key, player_index=idx))
                - float(input_code_is_down_for_player(left_key, player_index=idx)),
                float(input_code_is_down_for_player(down_key, player_index=idx))
                - float(input_code_is_down_for_player(up_key, player_index=idx)),
            )

        heading = float(state.aim_heading)
        if not _is_finite(heading):
            heading = float(getattr(player, "aim_heading", 0.0) or 0.0)
        aim = _aim_point_from_heading(player.pos, heading)
        computer_auto_fire = False
        if int(aim_scheme) == 0:
            aim = mouse_world
            delta = aim - player.pos
            if delta.length_sq() > 1e-9:
                heading = delta.to_heading()
        elif int(aim_scheme) == 1:
            if move_mode_type in {MovementControlType.RELATIVE, MovementControlType.STATIC}:
                if input_code_is_down_for_player(aim_right_key, player_index=idx):
                    heading = float(heading + float(dt_frame) * _AIM_KEYBOARD_TURN_RATE)
                if input_code_is_down_for_player(aim_left_key, player_index=idx):
                    heading = float(heading - float(dt_frame) * _AIM_KEYBOARD_TURN_RATE)
            aim = _aim_point_from_heading(player.pos, heading)
        elif int(aim_scheme) == 3:
            rel = mouse_screen - screen_center
            if rel.length_sq() > 1.0:
                heading = rel.to_heading()
            aim = _aim_point_from_heading(player.pos, heading)
        elif int(aim_scheme) == 4:
            axis_y = input_axis_value_for_player(aim_axis_y, player_index=idx)
            axis_x = input_axis_value_for_player(aim_axis_x, player_index=idx)
            axis_vec = Vec2(axis_x, axis_y)
            mag_sq = axis_vec.length_sq()
            if mag_sq > 1e-9:
                axis_dir, mag = axis_vec.normalized_with_length()
                heading = axis_dir.to_heading()
                radius = _AIM_RADIUS_PAD_BASE + mag * _AIM_RADIUS_PAD_SCALE
                aim = player.pos + axis_dir * radius
            else:
                aim = _aim_point_from_heading(player.pos, heading)
        elif int(aim_scheme) == 2:
            if input_code_is_down_for_player(aim_right_key, player_index=idx):
                heading = float(heading + float(dt_frame) * _AIM_JOYSTICK_TURN_RATE)
            if input_code_is_down_for_player(aim_left_key, player_index=idx):
                heading = float(heading - float(dt_frame) * _AIM_JOYSTICK_TURN_RATE)
            aim = _aim_point_from_heading(player.pos, heading)
        elif int(aim_scheme) == 5:
            target_index = None
            if creatures:
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
                    aim = aim + target_dir * (float(target_dist) * _COMPUTER_AIM_TRACK_GAIN * float(dt_frame))
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

        state.aim_heading = float(heading)

        fire_down = bool(input_code_is_down_for_player(fire_key, player_index=idx))
        fire_pressed = bool(input_code_is_pressed_for_player(fire_key, player_index=idx))
        if int(aim_scheme) == 5 and computer_auto_fire:
            fire_down = True
        reload_pressed = bool(input_code_is_pressed_for_player(reload_key, player_index=idx)) if idx == 0 else False

        return PlayerInput(
            move=move_vec,
            aim=aim,
            fire_down=fire_down,
            fire_pressed=fire_pressed,
            reload_pressed=reload_pressed,
            move_forward_pressed=move_forward_pressed,
            move_backward_pressed=move_backward_pressed,
            turn_left_pressed=turn_left_pressed,
            turn_right_pressed=turn_right_pressed,
        )

    def build_frame_inputs(
        self,
        *,
        players: Sequence[PlayerState],
        config: CrimsonConfig | None,
        mouse_screen: Vec2,
        screen_to_world: Callable[[Vec2], Vec2],
        dt_frame: float,
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
                    dt_frame=float(dt_frame),
                    creatures=creatures,
                )
            )
        return out
