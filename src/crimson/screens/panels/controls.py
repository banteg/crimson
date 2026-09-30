from __future__ import annotations

import msgspec

from crimson.game_states import GameStateId
from crimson.screens.actions import Route
from crimson.ui.menu_chrome import draw_ui_quad
from grim import canvas
from grim.assets import RuntimeResources, TextureId
from grim.config import (
    default_crimson_cfg,
)
from grim.fonts.small import SmallFontData, draw_small_text, measure_small_text_width
from grim.geom import Rect, Vec2
from grim.raylib_api import rl

from ...aim_schemes import AimScheme
from ...game.types import GameState
from ...gamepad_profile import reset_player_controls
from ...input_codes import (
    INPUT_CODE_UNBOUND,
    capture_first_pressed_input_code,
    gamepad_is_connected,
    input_code_name,
    player_gamepad_index,
)
from ...movement_controls import MovementControlType
from ...ui.checkbox import UiCheckbox, ui_checkbox_draw, ui_checkbox_update
from ...ui.dropdown import UiListWidget, ui_list_widget_draw, ui_list_widget_update
from ...ui.menu_panel import draw_ui_panel
from ...ui.perk_menu import UiButtonState, UiMenuItem, button_draw, button_update, ui_menu_item_update
from ..assets import require_runtime_resources
from .base import PanelMenuView
from .controls_labels import (
    RebindRowSpec,
    RebindTarget,
    controls_aim_method_dropdown_ids,
    controls_rebind_plan,
    input_configure_for_label,
    input_scheme_label,
)

# Port-only "Reset" button, beside the direction-arrow checkbox on the left panel.
CONTROLS_RESET_BUTTON_OFFSET = Vec2(388.0, 166.0)
CONTROLS_DIRECTION_ARROW_OFFSET = Vec2(213.0, 174.0)
# `controls_menu_update`: list origins off the left panel (`left_base + (10, 104)` etc.).
CONTROLS_MOVE_METHOD_LIST_OFFSET = Vec2(214.0, 144.0)
CONTROLS_AIM_METHOD_LIST_OFFSET = Vec2(214.0, 102.0)
CONTROLS_PLAYER_LIST_OFFSET = Vec2(340.0, 56.0)
# `controls_rebind_items`: one menu item per rebind row.
CONTROLS_REBIND_ITEM_COUNT = 15
# Native configures two players; the port configures four.
CONTROLS_PLAYER_ITEMS = ("Player 1", "Player 2", "Player 3", "Player 4")

# `ui_menu_item_update`: idle rebind value tint (rgb 70,180,240 @ alpha 0.6).
CONTROLS_REBIND_VALUE_COLOR = rl.Color(70, 180, 240, 153)
CONTROLS_REBIND_HOVER_COLOR = rl.Color(200, 230, 250, 230)
CONTROLS_REBIND_ACTIVE_COLOR = rl.Color(255, 228, 170, 255)


def _row_binding_code(row: RebindRowSpec, *, player_index: int, controls) -> int:
    player_controls = controls.player(player_index)
    match row.target:
        case RebindTarget.PLAYER_MOVE_CODES:
            assert row.target_index is not None
            return int(player_controls.move_codes[row.target_index])
        case RebindTarget.PLAYER_FIRE_CODE:
            return int(player_controls.fire_code)
        case RebindTarget.PLAYER_KEYBOARD_AIM_CODES:
            assert row.target_index is not None
            return int(player_controls.keyboard_aim_codes[row.target_index])
        case RebindTarget.PLAYER_AIM_AXIS_CODES:
            assert row.target_index is not None
            return int(player_controls.aim_axis_codes[row.target_index])
        case RebindTarget.PLAYER_MOVE_AXIS_CODES:
            assert row.target_index is not None
            return int(player_controls.move_axis_codes[row.target_index])
        case RebindTarget.GLOBAL_PICK_PERK_CODE:
            return int(controls.pick_perk_code)
        case RebindTarget.GLOBAL_RELOAD_CODE:
            return int(controls.reload_code)


def _set_row_binding_code(row: RebindRowSpec, value: int, *, player_index: int, controls) -> None:
    player_controls = controls.player(player_index)
    code = int(value)
    match row.target:
        case RebindTarget.PLAYER_MOVE_CODES:
            assert row.target_index is not None
            values = list(player_controls.move_codes)
            values[row.target_index] = code
            player_controls.move_codes = tuple(values)
        case RebindTarget.PLAYER_FIRE_CODE:
            player_controls.fire_code = code
        case RebindTarget.PLAYER_KEYBOARD_AIM_CODES:
            assert row.target_index is not None
            values = list(player_controls.keyboard_aim_codes)
            values[row.target_index] = code
            player_controls.keyboard_aim_codes = tuple(values)
        case RebindTarget.PLAYER_AIM_AXIS_CODES:
            assert row.target_index is not None
            values = list(player_controls.aim_axis_codes)
            values[row.target_index] = code
            player_controls.aim_axis_codes = tuple(values)
        case RebindTarget.PLAYER_MOVE_AXIS_CODES:
            assert row.target_index is not None
            values = list(player_controls.move_axis_codes)
            values[row.target_index] = code
            player_controls.move_axis_codes = tuple(values)
        case RebindTarget.GLOBAL_PICK_PERK_CODE:
            controls.pick_perk_code = code
        case RebindTarget.GLOBAL_RELOAD_CODE:
            controls.reload_code = code


def _default_row_binding_code(player_index: int, row: RebindRowSpec) -> int:
    controls = default_crimson_cfg().controls
    return _row_binding_code(row, player_index=player_index, controls=controls)


class _RebindRowLayout(msgspec.Struct, frozen=True):
    row: RebindRowSpec
    row_y: float
    value_pos: Vec2
    value_rect: Rect


class RebindCapture(msgspec.Struct):
    row: RebindRowSpec
    player_index: int
    skip_frames: int = 1


class ControlsMenuView(PanelMenuView):
    def __init__(self, state: GameState) -> None:
        super().__init__(
            state,
            game_state=GameStateId.CONTROLS_MENU,
            panel_element=14,
            back_element=18,
            title="Controls",
            back_action=Route.BACK,
        )
        self._config_player = 1
        self.move_method_list = UiListWidget()
        self.aim_method_list = UiListWidget()
        self.player_list = UiListWidget()
        self._capture: RebindCapture | None = None
        self._reset_button = UiButtonState("Reset")
        self._direction_arrow_checkbox = UiCheckbox("Show direction arrow")
        self._rebind_items = tuple(UiMenuItem() for _ in range(CONTROLS_REBIND_ITEM_COUNT))

    def open(self) -> None:
        super().open()
        self._config_player = max(1, min(4, int(self._config_player)))
        self._close_lists()
        self._dirty = False
        self._capture = None
        self._reset_button = UiButtonState("Reset")

    def close(self) -> None:
        self.state.focus.input_locked = False
        super().close()

    def update(self, dt: float) -> None:
        if not self._update_panel(dt):
            return
        entry = self._entry
        if entry is None or not self._entry_enabled():
            return
        left_top_left = self._left_panel_top_left()
        right_top_left = self._right_panel_top_left()
        resources = require_runtime_resources(self.state)
        font = resources.small_font
        capturing = self._capture is not None
        dropdown_was_open = self._list_open()
        # Escape closes an open list before it goes back.
        closing_list = dropdown_was_open and self.state.focus.escape
        if closing_list:
            self._close_lists()

        # `controls_menu_update` focus order: the direction-arrow checkbox (the port's Reset beside it), the rebind
        # rows, then the move, aim and player lists. Every widget registers every frame, capture or not.
        click_consumed = capturing or dropdown_was_open
        if self._update_direction_arrow_checkbox(left_top_left, resources):
            self._dirty = True
            click_consumed = True
        if self._update_reset_button(dt, left_top_left=left_top_left, enabled=not click_consumed):
            click_consumed = True
        if self._update_rebind_rows(right_top_left=right_top_left, font=font, enabled=not click_consumed):
            click_consumed = True
        elif capturing:
            self._update_rebind_capture()
        if self._update_method_lists(left_top_left=left_top_left, resources=resources):
            click_consumed = True
        self._update_back_button(dt, enabled=not click_consumed and not closing_list and self._capture is None)
        # Native `ui_focus_input_locked`: Tab and checkbox Enter stay out of the way while a rebind waits.
        self.state.focus.input_locked = self._capture is not None

    def _current_player_index(self) -> int:
        return max(0, min(3, int(self._config_player) - 1))

    def _start_rebind_capture(self, *, row: RebindRowSpec, player_index: int) -> None:
        self._capture = RebindCapture(row, player_index)
        self._close_lists()

    @staticmethod
    def _capture_prompt_for_binding(row: RebindRowSpec) -> str:
        if row.axis:
            return "<press axis>"
        return "<press input>"

    def _binding_default_code(self, *, player_index: int, row: RebindRowSpec) -> int:
        return _default_row_binding_code(player_index, row)

    def _binding_code(self, *, player_index: int, row: RebindRowSpec) -> int:
        return _row_binding_code(row, player_index=player_index, controls=self.state.config.controls)

    def _set_binding_code(self, *, player_index: int, row: RebindRowSpec, code: int) -> None:
        _set_row_binding_code(row, int(code), player_index=player_index, controls=self.state.config.controls)

    def _left_panel_top_left(self) -> Vec2:
        return self._panel_rect(self._panel_element).top_left

    def _right_panel_top_left(self) -> Vec2:
        # `controls_menu_update` lays the bindings out on `ui_element_slot_40`.
        return self._panel_rect(40).top_left

    def _direction_arrow_enabled(self) -> bool:
        return self.state.config.controls.player(self._current_player_index()).show_direction_arrow

    def _set_direction_arrow_enabled(self, enabled: bool) -> None:
        self.state.config.controls.player(self._current_player_index()).show_direction_arrow = bool(enabled)

    def _lists(self) -> tuple[UiListWidget, ...]:
        return (self.move_method_list, self.aim_method_list, self.player_list)

    def _list_open(self) -> bool:
        return any(widget.open for widget in self._lists())

    def _close_lists(self) -> None:
        for widget in self._lists():
            widget.open = False

    def _checkbox_enabled(self) -> bool:
        # `controls_menu_update`: an open method list disables the direction-arrow checkbox.
        return self._capture is None and not (self.move_method_list.open or self.aim_method_list.open)

    def _update_direction_arrow_checkbox(self, left_top_left: Vec2, resources: RuntimeResources) -> bool:
        checkbox = self._direction_arrow_checkbox
        checkbox.checked = self._direction_arrow_enabled()
        checkbox.disabled = not self._checkbox_enabled()
        if not ui_checkbox_update(
            resources,
            checkbox,
            left_top_left + CONTROLS_DIRECTION_ARROW_OFFSET,
            focus=self.state.focus,
            mouse=Vec2.from_xy(canvas.mouse_position()),
            click=rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT),
        ):
            return False
        self._set_direction_arrow_enabled(checkbox.checked)
        return True

    def _update_reset_button(self, dt: float, *, left_top_left: Vec2, enabled: bool) -> bool:
        button = self._reset_button
        button.enabled = enabled and self._checkbox_enabled() and not self._list_open()
        if not button_update(
            require_runtime_resources(self.state),
            button,
            focus=self.state.focus,
            pos=left_top_left + CONTROLS_RESET_BUTTON_OFFSET,
            dt_ms=min(dt, 0.1) * 1000.0,
            mouse=canvas.mouse_position(),
            click=rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT),
        ):
            return False
        self._reset_current_player()
        return True

    def _reset_current_player(self) -> None:
        player_idx = self._current_player_index()
        gamepad = player_gamepad_index(player_idx)
        pad_connected = gamepad_is_connected(gamepad)
        reset_player_controls(self.state.config.controls, player_idx, pad_connected=pad_connected)
        log = self.state.console.log
        if pad_connected:
            log.log(f"controls: player {player_idx + 1} reset to gamepad defaults (pad {gamepad}: {rl.get_gamepad_name(gamepad)})")
        else:
            log.log(f"controls: player {player_idx + 1} reset to defaults")
        try:
            self.state.config.save()
        except (OSError, ValueError) as exc:
            log.log(f"config: save failed: {exc}")
            self._dirty = True
        else:
            self._dirty = False

    def _rebind_sections(
        self,
        *,
        player_index: int,
        aim_scheme: AimScheme,
        move_mode: MovementControlType,
    ) -> tuple[tuple[str, tuple[RebindRowSpec, ...]], ...]:
        aim_rows, move_rows, misc_rows = controls_rebind_plan(
            aim_scheme=aim_scheme,
            move_mode=move_mode,
            player_index=player_index,
        )
        sections: list[tuple[str, tuple[RebindRowSpec, ...]]] = [("Aiming", aim_rows), ("Moving", move_rows)]
        if misc_rows:
            sections.append(("Misc", misc_rows))
        return tuple(sections)

    def _collect_rebind_rows(
        self,
        *,
        right_top_left: Vec2,
        player_index: int,
        sections: tuple[tuple[str, tuple[RebindRowSpec, ...]], ...],
        font: SmallFontData,
    ) -> tuple[_RebindRowLayout, ...]:
        rows: list[_RebindRowLayout] = []
        y = right_top_left.y + 64.0
        for _section_title, section_rows in sections:
            row_y = y + 18.0
            for row in section_rows:
                key_code = int(self._binding_code(player_index=player_index, row=row))
                value_text = input_code_name(key_code)
                value_pos = Vec2(right_top_left.x + 180.0, row_y)
                value_w = max(60.0, measure_small_text_width(font, value_text))
                value_rect = Rect.from_top_left(
                    Vec2(value_pos.x - 2.0, row_y - 2.0),
                    value_w + 4.0,
                    14.0,
                )
                rows.append(
                    _RebindRowLayout(
                        row=row,
                        row_y=float(row_y),
                        value_pos=value_pos,
                        value_rect=value_rect,
                    ),
                )
                row_y += 16.0
            y = row_y + 8.0
        return tuple(rows)

    def _update_rebind_rows(self, *, right_top_left: Vec2, font: SmallFontData, enabled: bool) -> bool:
        """`controls_menu_update`'s rebind rows: menu items over the binding values; activating one arms a capture."""
        player_idx = self._current_player_index()
        player_controls = self.state.config.controls.player(player_idx)
        sections = self._rebind_sections(
            player_index=player_idx, aim_scheme=player_controls.aim_scheme, move_mode=player_controls.movement,
        )
        rows = self._collect_rebind_rows(
            right_top_left=right_top_left,
            player_index=player_idx,
            sections=sections,
            font=font,
        )
        mouse = Vec2.from_xy(canvas.mouse_position())
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        started = False
        for row, item in zip(rows, self._rebind_items, strict=False):
            item.enabled = enabled
            if ui_menu_item_update(item, focus=self.state.focus, hit=row.value_rect, mouse=mouse, click=click):
                if not started:
                    self._start_rebind_capture(row=row.row, player_index=player_idx)
                started = True
        return started

    def _update_rebind_capture(self) -> None:
        capture = self._capture
        assert capture is not None
        active_row = capture.row
        active_player = capture.player_index
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) or rl.is_mouse_button_pressed(
            rl.MouseButton.MOUSE_BUTTON_RIGHT,
        ):
            self._capture = None
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_BACKSPACE):
            self._set_binding_code(
                player_index=active_player,
                row=active_row,
                code=self._binding_default_code(player_index=active_player, row=active_row),
            )
            self._dirty = True
            self._capture = None
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_DELETE):
            self._set_binding_code(player_index=active_player, row=active_row, code=INPUT_CODE_UNBOUND)
            self._dirty = True
            self._capture = None
            return

        if capture.skip_frames > 0:
            capture.skip_frames -= 1
            return

        axis_only = active_row.axis
        captured = capture_first_pressed_input_code(
            player_index=active_player,
            include_keyboard=not axis_only,
            include_mouse=not axis_only,
            include_gamepad=not axis_only,
            include_axes=axis_only,
            axis_threshold=0.5,
        )
        if captured is not None:
            self._set_binding_code(player_index=active_player, row=active_row, code=int(captured))
            self._dirty = True
            self._capture = None

    def _set_player_move_mode(self, *, player_index: int, move_mode: MovementControlType) -> None:
        self.state.config.controls.player(player_index).movement = move_mode

    def _set_player_aim_scheme(self, *, player_index: int, aim_scheme: AimScheme) -> None:
        self.state.config.controls.player(player_index).aim_scheme = aim_scheme

    @staticmethod
    def _move_method_ids(*, move_mode: MovementControlType) -> tuple[MovementControlType, ...]:
        items = [
            MovementControlType.RELATIVE,
            MovementControlType.STATIC,
            MovementControlType.DUAL_ACTION_PAD,
        ]
        if move_mode is MovementControlType.MOUSE_POINT_CLICK:
            items.append(MovementControlType.MOUSE_POINT_CLICK)
        return tuple(items)

    def _sync_lists(self) -> tuple[tuple[MovementControlType, ...], tuple[AimScheme, ...]]:
        """`controls_menu_update`: refill the lists from the player's controls; an open list disables the others."""
        player_idx = self._current_player_index()
        player_controls = self.state.config.controls.player(player_idx)
        move_mode_ids = self._move_method_ids(move_mode=player_controls.movement)
        aim_item_ids = controls_aim_method_dropdown_ids(player_controls.aim_scheme)
        # A scheme the lists do not offer (a hand-edited config) shows as the first item.
        self.move_method_list.items = tuple(input_scheme_label(mode) for mode in move_mode_ids)
        self.move_method_list.selected_index = (
            move_mode_ids.index(player_controls.movement) if player_controls.movement in move_mode_ids else 0
        )
        self.aim_method_list.items = tuple(input_configure_for_label(scheme) for scheme in aim_item_ids)
        self.aim_method_list.selected_index = (
            aim_item_ids.index(player_controls.aim_scheme) if player_controls.aim_scheme in aim_item_ids else 0
        )
        self.player_list.items = CONTROLS_PLAYER_ITEMS
        self.player_list.selected_index = player_idx

        idle = self._capture is None
        self.move_method_list.enabled = idle and not (self.player_list.open or self.aim_method_list.open)
        self.aim_method_list.enabled = idle and not (self.move_method_list.open or self.player_list.open)
        self.player_list.enabled = idle and not (self.move_method_list.open or self.aim_method_list.open)
        return move_mode_ids, aim_item_ids

    def _activate_list(
        self, resources: RuntimeResources, widget: UiListWidget, pos: Vec2, *, mouse: Vec2, pressed: bool,
    ) -> int | None:
        """`activate_list`: a press on the header or an open list toggles it; returns the row taken, if any.

        `None` means the press was not the list's; -1 means the list took it without taking a row.
        """
        selected = ui_list_widget_update(
            resources,
            widget,
            pos,
            focus=self.state.focus,
            mouse=mouse,
            click=rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT),
            preserve_bugs=self.state.preserve_bugs,
        )
        if selected <= -2 or not pressed:
            return None
        widget.open = not widget.open
        return selected

    def _update_method_lists(self, *, left_top_left: Vec2, resources: RuntimeResources) -> bool:
        player_idx = self._current_player_index()
        move_mode_ids, aim_item_ids = self._sync_lists()
        mouse = Vec2.from_xy(canvas.mouse_position())
        # `input_primary_just_pressed() || grim_was_key_pressed(Enter)`.
        pressed = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT) or self.state.focus.enter

        move_selected = self._activate_list(
            resources, self.move_method_list, left_top_left + CONTROLS_MOVE_METHOD_LIST_OFFSET, mouse=mouse, pressed=pressed,
        )
        if move_selected is not None and move_selected >= 0:
            self._set_player_move_mode(player_index=player_idx, move_mode=move_mode_ids[move_selected])
            self._dirty = True
        aim_selected = self._activate_list(
            resources, self.aim_method_list, left_top_left + CONTROLS_AIM_METHOD_LIST_OFFSET, mouse=mouse, pressed=pressed,
        )
        if aim_selected is not None and aim_selected >= 0:
            self._set_player_aim_scheme(player_index=player_idx, aim_scheme=aim_item_ids[aim_selected])
            self._dirty = True
        player_selected = self._activate_list(
            resources, self.player_list, left_top_left + CONTROLS_PLAYER_LIST_OFFSET, mouse=mouse, pressed=pressed,
        )
        if player_selected is not None and player_selected >= 0:
            self._config_player = player_selected + 1
        return move_selected is not None or aim_selected is not None or player_selected is not None

    def _draw_panel(self) -> None:
        super()._draw_panel()
        draw_ui_panel(
            require_runtime_resources(self.state), 40, self._panel_rect(40),
            shadow=self.state.config.display.shadows_enabled,
        )

    def _draw_contents(self) -> None:
        # Positions are expressed relative to the panel top-left corners.

        left_top_left = self._left_panel_top_left()
        right_top_left = self._right_panel_top_left()

        resources = require_runtime_resources(self.state)
        font = resources.small_font

        text_color_full = rl.Color(255, 255, 255, 255)
        text_color_soft = rl.Color(255, 255, 255, 204)
        config = self.state.config
        player_idx = self._current_player_index()
        player_controls = config.controls.player(player_idx)
        aim_scheme = player_controls.aim_scheme
        move_mode = player_controls.movement

        # --- Left panel: "Configure for" + method selectors (state_3 in trace) ---
        text_controls = resources.texture(TextureId.UI_TEXT_CONTROLS)
        draw_ui_quad(
            texture=text_controls,
            src=rl.Rectangle(0.0, 0.0, float(text_controls.width), float(text_controls.height)),
            dst=rl.Rectangle(
                left_top_left.x + 206.0,
                left_top_left.y + 44.0,
                128.0,
                32.0,
            ),
            origin=rl.Vector2(0.0, 0.0),
            rotation_deg=0.0,
            tint=rl.WHITE,
        )

        draw_small_text(
            font,
            "Configure for:",
            Vec2(left_top_left.x + 339.0, left_top_left.y + 41.0),
            text_color_soft,
        )

        draw_small_text(
            font,
            "Aiming method:",
            Vec2(left_top_left.x + 213.0, left_top_left.y + 86.0),
            text_color_full,
        )

        draw_small_text(
            font,
            "Moving method:",
            Vec2(left_top_left.x + 213.0, left_top_left.y + 128.0),
            text_color_full,
        )

        focus = self.state.focus
        ui_checkbox_draw(
            resources, self._direction_arrow_checkbox, left_top_left + CONTROLS_DIRECTION_ARROW_OFFSET, focus=focus,
        )

        button_draw(resources, self._reset_button, focus=focus, pos=left_top_left + CONTROLS_RESET_BUTTON_OFFSET)

        # `controls_menu_update` draws the lists in update order, so an open list covers the ones below it.
        self._sync_lists()
        mouse = Vec2.from_xy(canvas.mouse_position())
        for widget, offset in (
            (self.move_method_list, CONTROLS_MOVE_METHOD_LIST_OFFSET),
            (self.aim_method_list, CONTROLS_AIM_METHOD_LIST_OFFSET),
            (self.player_list, CONTROLS_PLAYER_LIST_OFFSET),
        ):
            ui_list_widget_draw(resources, widget, left_top_left + offset, focus=focus, mouse=mouse)

        # --- Right panel: configured bindings list ---
        def _draw_section_heading(title: str, *, y: float) -> None:
            x_heading = right_top_left.x + 44.0
            draw_small_text(font, title, Vec2(x_heading, y), text_color_full)
            line = rl.Rectangle(
                x_heading,
                y + 13.0,
                228.0,
                1.0,
            )
            rl.draw_rectangle_lines_ex(line, 1.0, rl.Color(255, 255, 255, 178))

        draw_small_text(
            font,
            "Configured controls",
            Vec2(right_top_left.x + 120.0, right_top_left.y + 38.0),
            text_color_full,
        )
        header_w = measure_small_text_width(font, "Configured controls")
        header_line = rl.Rectangle(
            right_top_left.x + 120.0,
            right_top_left.y + 51.0,
            header_w,
            1.0,
        )
        rl.draw_rectangle_lines_ex(header_line, 1.0, rl.Color(255, 255, 255, 204))

        sections = self._rebind_sections(player_index=player_idx, aim_scheme=aim_scheme, move_mode=move_mode)
        rows = self._collect_rebind_rows(
            right_top_left=right_top_left,
            player_index=player_idx,
            sections=sections,
            font=font,
        )
        row_iter = iter(zip(rows, self._rebind_items, strict=False))
        dropdown_blocked = self._list_open()

        y = right_top_left.y + 64.0
        for section_title, section_rows in sections:
            _draw_section_heading(section_title, y=y)
            row_y = y + 18.0
            for _ in section_rows:
                row, item = next(row_iter)
                capture = self._capture
                active_row = capture is not None and capture.row == row.row and capture.player_index == player_idx
                hovered_row = (capture is None) and (not dropdown_blocked) and row.value_rect.contains(mouse)
                value_text = (
                    self._capture_prompt_for_binding(row.row)
                    if active_row
                    else input_code_name(self._binding_code(player_index=player_idx, row=row.row))
                )
                value_pos = row.value_pos
                if item.focused:
                    focus.draw(value_pos.offset(dx=-16.0))

                draw_small_text(
                    font,
                    row.row.label,
                    Vec2(right_top_left.x + 52.0, row_y),
                    rl.Color(255, 255, 255, 178),
                )
                value_color = CONTROLS_REBIND_VALUE_COLOR
                if hovered_row:
                    value_color = CONTROLS_REBIND_HOVER_COLOR
                if active_row:
                    value_color = CONTROLS_REBIND_ACTIVE_COLOR
                draw_small_text(font, value_text, value_pos, value_color)
                value_w = measure_small_text_width(font, value_text)
                underline_y = row.row_y + 13.0
                rl.draw_line(
                    int(value_pos.x),
                    int(underline_y),
                    int(value_pos.x + value_w),
                    int(underline_y),
                    value_color,
                )
                row_y += 16.0
            y = row_y + 8.0

        if self._capture is not None and self._capture.player_index == player_idx:
            hint_pos = Vec2(
                right_top_left.x + 48.0,
                right_top_left.y + (self._panel_rect(40).height - 26.0),
            )
            draw_small_text(
                font,
                "Esc/Right: cancel  Backspace: default  Delete: unbind",
                hint_pos,
                rl.Color(255, 226, 188, 220),
            )
