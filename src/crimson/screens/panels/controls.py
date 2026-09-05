from __future__ import annotations

import msgspec

from crimson.screens.actions import Route, ScreenAction
from grim.assets import RuntimeResources, TextureId
from grim.config import (
    default_crimson_cfg,
)
from grim.fonts.small import SmallFontData, draw_small_text, measure_small_text_width
from grim.geom import Rect, Vec2
from grim.raylib_api import rl

from ...aim_schemes import AimScheme
from ...game.types import GameState
from ...input_codes import INPUT_CODE_UNBOUND, capture_first_pressed_input_code, input_code_name
from ...movement_controls import MovementControlType
from ...ui.layout import DropdownLayoutBase
from ...ui.menu_panel import draw_classic_menu_panel
from ..assets import require_runtime_resources
from ..menu import (
    MENU_PANEL_HEIGHT,
    MENU_PANEL_WIDTH,
    MenuView,
)
from .base import PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS, PanelMenuView
from .controls_labels import (
    RebindRowSpec,
    RebindTarget,
    controls_aim_method_dropdown_ids,
    controls_rebind_plan,
    input_configure_for_label,
    input_scheme_label,
)
from .hit_test import mouse_inside_rect_with_padding

# Measured from ui_render_trace_oracle_1024x768.json (state_3:Configure for:, timeline=300).
CONTROLS_LEFT_PANEL_POS_X = -165.0
CONTROLS_LEFT_PANEL_POS_Y = 200.0
CONTROLS_RIGHT_PANEL_POS_X = 590.0
CONTROLS_RIGHT_PANEL_POS_Y = 110.0
CONTROLS_RIGHT_PANEL_HEIGHT = 378.0
CONTROLS_BACK_POS_X = -155.0
CONTROLS_BACK_POS_Y = 420.0

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


def _controls_left_panel_pos_x(screen_width: float) -> float:
    """
    Left controls panel X in panel-pos space.

    Native `ui_menu_layout_init` nudges the controls left panel 18px further left
    at 640-wide layouts.
    """

    if int(screen_width) <= 640:
        return CONTROLS_LEFT_PANEL_POS_X - 18.0
    return CONTROLS_LEFT_PANEL_POS_X


def _controls_right_panel_pos_x(screen_width: float) -> float:
    """
    Right controls panel X in panel-pos space.

    Native `ui_menu_layout_init` uses:
      slot40_pos_x = screen_width - 350  (+80 at <=640)

    Our panel-pos abstraction differs by a fixed -84 offset from that slot-space,
    so this becomes:
      x = screen_width - 434  (+80 at <=640).
    """

    w = int(screen_width)
    x = float(w - 434)
    if w <= 640:
        x += 80.0
    return x


def _controls_right_panel_pos_y(screen_width: float) -> float:
    """
    Right controls panel Y in panel-pos space.

    Native slot40 y moves from 200 to 186 at <=640. In panel-pos coordinates this
    is 110 -> 96.
    """

    if int(screen_width) <= 640:
        return CONTROLS_RIGHT_PANEL_POS_Y - 14.0
    return CONTROLS_RIGHT_PANEL_POS_Y


class _ControlsDropdownLayout(DropdownLayoutBase, frozen=True):
    arrow_pos: Vec2
    arrow_size: Vec2
    text_pos: Vec2
    text_scale: float


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
            title="Controls",
            back_action=Route.BACK,
            panel_pos=Vec2(CONTROLS_LEFT_PANEL_POS_X, CONTROLS_LEFT_PANEL_POS_Y),
            back_pos=Vec2(CONTROLS_BACK_POS_X, CONTROLS_BACK_POS_Y),
        )
        self._config_player = 1
        self._move_method_open = False
        self._aim_method_open = False
        self._player_profile_open = False
        self._dirty = False
        self._capture: RebindCapture | None = None

    def open(self) -> None:
        super().open()
        self._config_player = max(1, min(4, int(self._config_player)))
        self._move_method_open = False
        self._aim_method_open = False
        self._player_profile_open = False
        self._dirty = False
        self._clear_rebind_capture()

    def update(self, dt: float) -> None:
        if not self._update_panel(dt):
            return
        entry = self._entry
        if entry is None or not self._entry_enabled(entry):
            return
        panel_scale, _local_y_shift = self._menu_item_scale(0)
        left_top_left = self._left_panel_top_left(panel_scale)
        right_top_left = self._right_panel_top_left(panel_scale)
        resources = require_runtime_resources(self.state)
        font = resources.small_font
        if self._capture is not None:
            self._update_back_button(dt, enabled=False)
            self._update_rebind_capture(right_top_left=right_top_left, panel_scale=panel_scale, font=font)
            return
        click_consumed = self._update_method_dropdowns(
            left_top_left=left_top_left,
            panel_scale=panel_scale,
            font=font,
        )
        if not click_consumed:
            click_consumed = self._update_rebind_capture(
                right_top_left=right_top_left,
                panel_scale=panel_scale,
                font=font,
            )
        if (not click_consumed) and self._update_direction_arrow_checkbox(
            left_top_left=left_top_left,
            panel_scale=panel_scale,
            enabled=self._checkbox_enabled(),
            resources=resources,
            font=font,
        ):
            self._dirty = True
            click_consumed = True
        self._update_back_button(dt, enabled=not click_consumed and self._capture is None)

    def _begin_close_transition(self, action: ScreenAction) -> None:
        if self._dirty:
            try:
                self.state.config.save()
            except (OSError, ValueError) as exc:
                self.state.console.log.log(f"config: save failed: {exc}")
            else:
                self._dirty = False
        super()._begin_close_transition(action)

    def _current_player_index(self) -> int:
        return max(0, min(3, int(self._config_player) - 1))

    def _rebind_active(self) -> bool:
        return self._capture is not None

    def _clear_rebind_capture(self) -> None:
        self._capture = None

    def _start_rebind_capture(self, *, row: RebindRowSpec, player_index: int) -> None:
        self._capture = RebindCapture(row, player_index)
        self._move_method_open = False
        self._aim_method_open = False
        self._player_profile_open = False

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

    def _left_panel_top_left(self, panel_scale: float) -> Vec2:
        panel_w = MENU_PANEL_WIDTH * panel_scale
        _, slide_x = MenuView._ui_element_anim(
            self,
            index=1,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w,
        )
        return (
            Vec2(
                _controls_left_panel_pos_x(float(self.state.config.display.width)) + slide_x,
                self._panel_pos.y + self._widescreen_y_shift,
            )
            + self._panel_offset * panel_scale
        )

    def _right_panel_top_left(self, panel_scale: float) -> Vec2:
        panel_w = MENU_PANEL_WIDTH * panel_scale
        _, slide_x = MenuView._ui_element_anim(
            self,
            index=3,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w,
            direction_flag=1,
        )
        return (
            Vec2(
                _controls_right_panel_pos_x(float(self.state.config.display.width)) + slide_x,
                _controls_right_panel_pos_y(float(self.state.config.display.width)) + self._widescreen_y_shift,
            )
            + self._panel_offset * panel_scale
        )

    def _direction_arrow_enabled(self) -> bool:
        return self.state.config.controls.player(self._current_player_index()).show_direction_arrow

    def _set_direction_arrow_enabled(self, enabled: bool) -> None:
        self.state.config.controls.player(self._current_player_index()).show_direction_arrow = bool(enabled)

    def _checkbox_enabled(self) -> bool:
        return not (self._move_method_open or self._aim_method_open or self._rebind_active())

    def _checkbox_hovered(
        self,
        *,
        left_top_left: Vec2,
        panel_scale: float,
        enabled: bool,
        resources: RuntimeResources,
        font: SmallFontData,
    ) -> bool:
        if not enabled:
            return False
        check_on = resources.texture(TextureId.UI_CHECK_ON)
        text_scale = 1.0 * panel_scale
        label = "Show direction arrow"
        check_pos = Vec2(left_top_left.x + 213.0 * panel_scale, left_top_left.y + 174.0 * panel_scale)
        label_w = measure_small_text_width(font, label)
        rect_w = float(check_on.width) * panel_scale + 6.0 * panel_scale + label_w
        rect_h = max(float(check_on.height) * panel_scale, font.cell_size * text_scale)
        mouse_pos = Vec2.from_xy(rl.get_mouse_position())
        return Rect.from_top_left(check_pos, rect_w, rect_h).contains(mouse_pos)

    def _update_direction_arrow_checkbox(
        self,
        *,
        left_top_left: Vec2,
        panel_scale: float,
        enabled: bool,
        resources: RuntimeResources,
        font: SmallFontData,
    ) -> bool:
        if not enabled:
            return False
        hovered = self._checkbox_hovered(
            left_top_left=left_top_left,
            panel_scale=panel_scale,
            enabled=enabled,
            resources=resources,
            font=font,
        )
        if hovered and rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
            self._set_direction_arrow_enabled(not self._direction_arrow_enabled())
            return True
        return False

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
        panel_scale: float,
        player_index: int,
        sections: tuple[tuple[str, tuple[RebindRowSpec, ...]], ...],
        font: SmallFontData,
    ) -> tuple[_RebindRowLayout, ...]:
        rows: list[_RebindRowLayout] = []
        y = right_top_left.y + 64.0 * panel_scale
        for _section_title, section_rows in sections:
            row_y = y + 18.0 * panel_scale
            for row in section_rows:
                key_code = int(self._binding_code(player_index=player_index, row=row))
                value_text = input_code_name(key_code)
                value_pos = Vec2(right_top_left.x + 180.0 * panel_scale, row_y)
                value_w = max(60.0 * panel_scale, measure_small_text_width(font, value_text))
                value_rect = Rect.from_top_left(
                    Vec2(value_pos.x - 2.0 * panel_scale, row_y - 2.0 * panel_scale),
                    value_w + 4.0 * panel_scale,
                    14.0 * panel_scale,
                )
                rows.append(
                    _RebindRowLayout(
                        row=row,
                        row_y=float(row_y),
                        value_pos=value_pos,
                        value_rect=value_rect,
                    ),
                )
                row_y += 16.0 * panel_scale
            y = row_y + 8.0 * panel_scale
        return tuple(rows)

    def _update_rebind_capture(self, *, right_top_left: Vec2, panel_scale: float, font: SmallFontData) -> bool:
        player_idx = self._current_player_index()
        player_controls = self.state.config.controls.player(player_idx)
        aim_scheme = player_controls.aim_scheme
        move_mode = player_controls.movement
        sections = self._rebind_sections(player_index=player_idx, aim_scheme=aim_scheme, move_mode=move_mode)
        rows = self._collect_rebind_rows(
            right_top_left=right_top_left,
            panel_scale=panel_scale,
            player_index=player_idx,
            sections=sections,
            font=font,
        )

        capture = self._capture
        if capture is not None:
            active_row = capture.row
            active_player = capture.player_index
            if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) or rl.is_mouse_button_pressed(
                rl.MouseButton.MOUSE_BUTTON_RIGHT,
            ):
                self._clear_rebind_capture()
                return True

            if rl.is_key_pressed(rl.KeyboardKey.KEY_BACKSPACE):
                self._set_binding_code(
                    player_index=active_player,
                    row=active_row,
                    code=self._binding_default_code(player_index=active_player, row=active_row),
                )
                self._dirty = True
                self._clear_rebind_capture()
                return True

            if rl.is_key_pressed(rl.KeyboardKey.KEY_DELETE):
                self._set_binding_code(player_index=active_player, row=active_row, code=INPUT_CODE_UNBOUND)
                self._dirty = True
                self._clear_rebind_capture()
                return True

            if capture.skip_frames > 0:
                capture.skip_frames -= 1
                return True

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
                self._clear_rebind_capture()
            return True

        if self._move_method_open or self._aim_method_open or self._player_profile_open:
            return False

        if not rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
            return False
        mouse = Vec2.from_xy(rl.get_mouse_position())
        for row in rows:
            if row.value_rect.contains(mouse):
                self._start_rebind_capture(row=row.row, player_index=player_idx)
                return True
        return False

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

    def _dropdown_layout(
        self,
        *,
        pos: Vec2,
        items: tuple[str, ...],
        scale: float,
        font: SmallFontData,
    ) -> _ControlsDropdownLayout:
        text_scale = 1.0 * scale
        max_label_w = 0.0
        for label in items:
            max_label_w = max(max_label_w, measure_small_text_width(font, label))
        width = max_label_w + 48.0 * scale
        header_h = 16.0 * scale
        row_h = 16.0 * scale
        full_h = (float(len(items)) * 16.0 + 24.0) * scale
        arrow = 16.0 * scale
        return _ControlsDropdownLayout(
            pos=pos,
            width=width,
            header_h=header_h,
            row_h=row_h,
            rows_y0=pos.y + 17.0 * scale,
            full_h=full_h,
            arrow_pos=Vec2(pos.x + width - arrow - 1.0 * scale, pos.y),
            arrow_size=Vec2(arrow, arrow),
            text_pos=pos + Vec2(4.0 * scale, 1.0 * scale),
            text_scale=text_scale,
        )

    def _update_dropdown(
        self,
        *,
        layout: _ControlsDropdownLayout,
        item_count: int,
        is_open: bool,
        enabled: bool,
        scale: float,
    ) -> tuple[bool, int | None, bool]:
        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        hovered_header = bool(enabled) and mouse_inside_rect_with_padding(
            mouse,
            pos=layout.pos,
            width=layout.width,
            height=14.0 * scale,
        )
        if hovered_header and click:
            return (not is_open), None, True
        if not is_open:
            return is_open, None, False

        list_hovered = Rect.from_top_left(layout.pos, layout.width, layout.full_h).contains(Vec2.from_xy(mouse))
        if click and not list_hovered:
            return False, None, True

        for idx in range(item_count):
            item_y = layout.rows_y0 + layout.row_h * float(idx)
            hovered = bool(enabled) and mouse_inside_rect_with_padding(
                mouse,
                pos=Vec2(layout.pos.x, item_y),
                width=layout.width,
                height=14.0 * scale,
            )
            if hovered and click:
                return False, idx, True

        return is_open, None, False

    def _update_method_dropdowns(self, *, left_top_left: Vec2, panel_scale: float, font: SmallFontData) -> bool:
        config = self.state.config
        player_idx = self._current_player_index()
        player_controls = config.controls.player(player_idx)
        aim_scheme = player_controls.aim_scheme
        move_mode = player_controls.movement
        move_mode_ids = self._move_method_ids(move_mode=move_mode)
        move_items = tuple(input_scheme_label(mode) for mode in move_mode_ids)
        aim_item_ids = controls_aim_method_dropdown_ids(aim_scheme)
        aim_items = tuple(input_configure_for_label(scheme) for scheme in aim_item_ids)
        player_items = ("Player 1", "Player 2", "Player 3", "Player 4")

        move_layout = self._dropdown_layout(
            pos=Vec2(left_top_left.x + 214.0 * panel_scale, left_top_left.y + 144.0 * panel_scale),
            items=move_items,
            scale=panel_scale,
            font=font,
        )
        aim_layout = self._dropdown_layout(
            pos=Vec2(left_top_left.x + 214.0 * panel_scale, left_top_left.y + 102.0 * panel_scale),
            items=aim_items,
            scale=panel_scale,
            font=font,
        )
        player_layout = self._dropdown_layout(
            pos=Vec2(left_top_left.x + 340.0 * panel_scale, left_top_left.y + 56.0 * panel_scale),
            items=player_items,
            scale=panel_scale,
            font=font,
        )

        rebind_active = self._rebind_active()
        move_enabled = not (self._aim_method_open or self._player_profile_open or rebind_active)
        aim_enabled = not (self._move_method_open or self._player_profile_open or rebind_active)
        player_enabled = not (self._move_method_open or self._aim_method_open or rebind_active)

        self._move_method_open, move_selected, consumed = self._update_dropdown(
            layout=move_layout,
            item_count=len(move_items),
            is_open=self._move_method_open,
            enabled=move_enabled,
            scale=panel_scale,
        )
        if move_selected is not None:
            selected_idx = max(0, min(int(move_selected), len(move_mode_ids) - 1))
            self._set_player_move_mode(player_index=player_idx, move_mode=move_mode_ids[selected_idx])
            self._dirty = True
        if consumed:
            return True

        self._aim_method_open, aim_selected, consumed = self._update_dropdown(
            layout=aim_layout,
            item_count=len(aim_items),
            is_open=self._aim_method_open,
            enabled=aim_enabled,
            scale=panel_scale,
        )
        if aim_selected is not None:
            selected_idx = max(0, min(int(aim_selected), len(aim_item_ids) - 1))
            self._set_player_aim_scheme(player_index=player_idx, aim_scheme=aim_item_ids[selected_idx])
            self._dirty = True
        if consumed:
            return True

        self._player_profile_open, player_selected, consumed = self._update_dropdown(
            layout=player_layout,
            item_count=len(player_items),
            is_open=self._player_profile_open,
            enabled=player_enabled,
            scale=panel_scale,
        )
        if player_selected is not None:
            self._config_player = max(1, min(4, player_selected + 1))
        return bool(consumed)

    def _draw_panel(self) -> None:
        shadows_enabled = self.state.config.display.shadows_enabled
        panel_scale, _local_y_shift = self._menu_item_scale(0)
        panel_w = MENU_PANEL_WIDTH * panel_scale
        panel = require_runtime_resources(self.state).texture(TextureId.UI_MENU_PANEL)

        # Left (controls options) panel: standard 254px height => a single quad.
        left_top_left = self._left_panel_top_left(panel_scale)
        left_h = MENU_PANEL_HEIGHT * panel_scale
        draw_classic_menu_panel(
            panel,
            dst=rl.Rectangle(left_top_left.x, left_top_left.y, panel_w, left_h),
            tint=rl.WHITE,
            shadow=shadows_enabled,
        )

        # Right (configured bindings) panel: tall 378px panel rendered as 3 vertical slices.
        right_top_left = self._right_panel_top_left(panel_scale)
        right_h = float(CONTROLS_RIGHT_PANEL_HEIGHT) * panel_scale
        draw_classic_menu_panel(
            panel,
            dst=rl.Rectangle(right_top_left.x, right_top_left.y, panel_w, right_h),
            tint=rl.WHITE,
            shadow=shadows_enabled,
            # Original ui_element_slot_40 sets direction_flag=1, which mirrors panel UVs.
            flip_x=True,
        )

    def _draw_contents(self) -> None:
        # Positions are expressed relative to the panel top-left corners and scaled with the panel scale.
        panel_scale, _local_y_shift = self._menu_item_scale(0)

        left_top_left = self._left_panel_top_left(panel_scale)
        right_top_left = self._right_panel_top_left(panel_scale)

        resources = require_runtime_resources(self.state)
        font = resources.small_font

        text_color_full = rl.Color(255, 255, 255, 255)
        text_color_soft = rl.Color(255, 255, 255, 204)
        config = self.state.config
        player_idx = self._current_player_index()
        player_controls = config.controls.player(player_idx)
        aim_scheme = player_controls.aim_scheme
        move_mode = player_controls.movement
        move_mode_ids = self._move_method_ids(move_mode=move_mode)
        move_items = tuple(input_scheme_label(mode) for mode in move_mode_ids)
        aim_item_ids = controls_aim_method_dropdown_ids(aim_scheme)
        aim_items = tuple(input_configure_for_label(scheme) for scheme in aim_item_ids)
        player_items = ("Player 1", "Player 2", "Player 3", "Player 4")
        try:
            move_selected = move_mode_ids.index(move_mode)
        except ValueError:
            move_selected = 0
        try:
            aim_selected = aim_item_ids.index(aim_scheme)
        except ValueError:
            aim_selected = 0
        player_selected = max(0, min(len(player_items) - 1, player_idx))
        move_layout = self._dropdown_layout(
            pos=Vec2(left_top_left.x + 214.0 * panel_scale, left_top_left.y + 144.0 * panel_scale),
            items=move_items,
            scale=panel_scale,
            font=font,
        )
        aim_layout = self._dropdown_layout(
            pos=Vec2(left_top_left.x + 214.0 * panel_scale, left_top_left.y + 102.0 * panel_scale),
            items=aim_items,
            scale=panel_scale,
            font=font,
        )
        player_layout = self._dropdown_layout(
            pos=Vec2(left_top_left.x + 340.0 * panel_scale, left_top_left.y + 56.0 * panel_scale),
            items=player_items,
            scale=panel_scale,
            font=font,
        )

        # --- Left panel: "Configure for" + method selectors (state_3 in trace) ---
        text_controls = resources.texture(TextureId.UI_TEXT_CONTROLS)
        MenuView._draw_ui_quad(
            texture=text_controls,
            src=rl.Rectangle(0.0, 0.0, float(text_controls.width), float(text_controls.height)),
            dst=rl.Rectangle(
                left_top_left.x + 206.0 * panel_scale,
                left_top_left.y + 44.0 * panel_scale,
                128.0 * panel_scale,
                32.0 * panel_scale,
            ),
            origin=rl.Vector2(0.0, 0.0),
            rotation_deg=0.0,
            tint=rl.WHITE,
        )

        draw_small_text(
            font,
            "Configure for:",
            Vec2(left_top_left.x + 339.0 * panel_scale, left_top_left.y + 41.0 * panel_scale),
            text_color_soft,
        )

        draw_small_text(
            font,
            "Aiming method:",
            Vec2(left_top_left.x + 213.0 * panel_scale, left_top_left.y + 86.0 * panel_scale),
            text_color_full,
        )

        draw_small_text(
            font,
            "Moving method:",
            Vec2(left_top_left.x + 213.0 * panel_scale, left_top_left.y + 128.0 * panel_scale),
            text_color_full,
        )

        check_tex = (
            resources.texture(TextureId.UI_CHECK_ON)
            if self._direction_arrow_enabled()
            else resources.texture(TextureId.UI_CHECK_OFF)
        )
        MenuView._draw_ui_quad(
            texture=check_tex,
            src=rl.Rectangle(0.0, 0.0, float(check_tex.width), float(check_tex.height)),
            dst=rl.Rectangle(
                left_top_left.x + 213.0 * panel_scale,
                left_top_left.y + 174.0 * panel_scale,
                16.0 * panel_scale,
                16.0 * panel_scale,
            ),
            origin=rl.Vector2(0.0, 0.0),
            rotation_deg=0.0,
            tint=rl.WHITE,
        )
        checkbox_hovered = self._checkbox_hovered(
            left_top_left=left_top_left,
            panel_scale=panel_scale,
            enabled=self._checkbox_enabled(),
            resources=resources,
            font=font,
        )
        checkbox_alpha = 255 if checkbox_hovered else 178
        draw_small_text(
            font,
            "Show direction arrow",
            Vec2(left_top_left.x + 235.0 * panel_scale, left_top_left.y + 175.0 * panel_scale),
            rl.Color(255, 255, 255, checkbox_alpha),
        )

        dropdowns: tuple[tuple[bool, _ControlsDropdownLayout, tuple[str, ...], int, bool], ...] = (
            (
                self._player_profile_open,
                player_layout,
                player_items,
                player_selected,
                not (self._move_method_open or self._aim_method_open or self._rebind_active()),
            ),
            (
                self._aim_method_open,
                aim_layout,
                aim_items,
                aim_selected,
                not (self._move_method_open or self._player_profile_open or self._rebind_active()),
            ),
            (
                self._move_method_open,
                move_layout,
                move_items,
                move_selected,
                not (self._aim_method_open or self._player_profile_open or self._rebind_active()),
            ),
        )
        # Active list must render last so overlapping widgets don't occlude open options.
        for is_open, layout, items, selected_index, enabled in dropdowns:
            if is_open:
                continue
            self._draw_dropdown(
                layout=layout,
                items=items,
                selected_index=selected_index,
                is_open=is_open,
                enabled=enabled,
                scale=panel_scale,
                resources=resources,
                font=font,
            )
        for is_open, layout, items, selected_index, enabled in dropdowns:
            if not is_open:
                continue
            self._draw_dropdown(
                layout=layout,
                items=items,
                selected_index=selected_index,
                is_open=is_open,
                enabled=enabled,
                scale=panel_scale,
                resources=resources,
                font=font,
            )

        # --- Right panel: configured bindings list ---
        def _draw_section_heading(title: str, *, y: float) -> None:
            x_heading = right_top_left.x + 44.0 * panel_scale
            draw_small_text(font, title, Vec2(x_heading, y), text_color_full)
            line = rl.Rectangle(
                x_heading,
                y + 13.0 * panel_scale,
                228.0 * panel_scale,
                max(1.0, panel_scale),
            )
            rl.draw_rectangle_lines_ex(line, max(1.0, panel_scale), rl.Color(255, 255, 255, 178))

        draw_small_text(
            font,
            "Configured controls",
            Vec2(right_top_left.x + 120.0 * panel_scale, right_top_left.y + 38.0 * panel_scale),
            text_color_full,
        )
        header_w = measure_small_text_width(font, "Configured controls")
        header_line = rl.Rectangle(
            right_top_left.x + 120.0 * panel_scale,
            right_top_left.y + 51.0 * panel_scale,
            header_w,
            max(1.0, panel_scale),
        )
        rl.draw_rectangle_lines_ex(header_line, max(1.0, panel_scale), rl.Color(255, 255, 255, 204))

        sections = self._rebind_sections(player_index=player_idx, aim_scheme=aim_scheme, move_mode=move_mode)
        rows = self._collect_rebind_rows(
            right_top_left=right_top_left,
            panel_scale=panel_scale,
            player_index=player_idx,
            sections=sections,
            font=font,
        )
        row_iter = iter(rows)
        mouse = Vec2.from_xy(rl.get_mouse_position())
        dropdown_blocked = self._move_method_open or self._aim_method_open or self._player_profile_open
        rebind_active = self._rebind_active()

        y = right_top_left.y + 64.0 * panel_scale
        for section_title, section_rows in sections:
            _draw_section_heading(section_title, y=y)
            row_y = y + 18.0 * panel_scale
            for _ in section_rows:
                row = next(row_iter)
                capture = self._capture
                active_row = capture is not None and capture.row == row.row and capture.player_index == player_idx
                hovered_row = (not rebind_active) and (not dropdown_blocked) and row.value_rect.contains(mouse)
                value_text = (
                    self._capture_prompt_for_binding(row.row)
                    if active_row
                    else input_code_name(self._binding_code(player_index=player_idx, row=row.row))
                )
                value_pos = row.value_pos

                draw_small_text(
                    font,
                    row.row.label,
                    Vec2(right_top_left.x + 52.0 * panel_scale, row_y),
                    rl.Color(255, 255, 255, 178),
                )
                value_color = CONTROLS_REBIND_VALUE_COLOR
                if hovered_row:
                    value_color = CONTROLS_REBIND_HOVER_COLOR
                if active_row:
                    value_color = CONTROLS_REBIND_ACTIVE_COLOR
                draw_small_text(font, value_text, value_pos, value_color)
                value_w = measure_small_text_width(font, value_text)
                underline_y = row.row_y + 13.0 * panel_scale
                rl.draw_line(
                    int(value_pos.x),
                    int(underline_y),
                    int(value_pos.x + value_w),
                    int(underline_y),
                    value_color,
                )
                row_y += 16.0 * panel_scale
            y = row_y + 8.0 * panel_scale

        if self._capture is not None and self._capture.player_index == player_idx:
            hint_pos = Vec2(
                right_top_left.x + 48.0 * panel_scale,
                right_top_left.y + (CONTROLS_RIGHT_PANEL_HEIGHT - 26.0) * panel_scale,
            )
            draw_small_text(
                font, "Esc/Right: cancel  Backspace: default  Delete: unbind", hint_pos, rl.Color(255, 226, 188, 220),
            )

    def _draw_dropdown(
        self,
        *,
        layout: _ControlsDropdownLayout,
        items: tuple[str, ...],
        selected_index: int,
        is_open: bool,
        enabled: bool,
        scale: float,
        resources: RuntimeResources,
        font: SmallFontData,
    ) -> None:
        mouse = rl.get_mouse_position()
        hovered_header = bool(enabled) and mouse_inside_rect_with_padding(
            mouse,
            pos=layout.pos,
            width=layout.width,
            height=14.0 * scale,
        )
        widget_h = layout.full_h if is_open else layout.header_h
        rl.draw_rectangle(int(layout.pos.x), int(layout.pos.y), int(layout.width), int(widget_h), rl.WHITE)
        inner_w = max(0, int(layout.width) - 2)
        inner_h = max(0, int(widget_h) - 2)
        rl.draw_rectangle(int(layout.pos.x) + 1, int(layout.pos.y) + 1, inner_w, inner_h, rl.BLACK)

        if (is_open or hovered_header) and enabled:
            line_h = max(1, int(1.0 * scale))
            rl.draw_rectangle(
                int(layout.pos.x),
                int(layout.pos.y + 15.0 * scale),
                int(layout.width),
                line_h,
                rl.Color(255, 255, 255, 128),
            )
        arrow_tex = (
            resources.texture(TextureId.UI_DROP_ON)
            if ((is_open or hovered_header) and enabled)
            else resources.texture(TextureId.UI_DROP_OFF)
        )
        rl.draw_texture_pro(
            arrow_tex,
            rl.Rectangle(0.0, 0.0, float(arrow_tex.width), float(arrow_tex.height)),
            rl.Rectangle(layout.arrow_pos.x, layout.arrow_pos.y, layout.arrow_size.x, layout.arrow_size.y),
            rl.Vector2(0.0, 0.0),
            0.0,
            rl.WHITE,
        )

        idx = max(0, min(len(items) - 1, int(selected_index))) if items else 0
        header_alpha = 242 if ((is_open or hovered_header) and enabled) else 191
        if items:
            draw_small_text(font, items[idx], layout.text_pos, rl.Color(255, 255, 255, header_alpha))

        if not is_open:
            return

        for idx, item in enumerate(items):
            item_y = layout.rows_y0 + layout.row_h * float(idx)
            hovered = bool(enabled) and mouse_inside_rect_with_padding(
                mouse,
                pos=Vec2(layout.pos.x, item_y),
                width=layout.width,
                height=14.0 * scale,
            )
            alpha = 153
            if hovered:
                alpha = 242
            if idx == selected_index:
                alpha = max(alpha, 245)
            draw_small_text(font, item, Vec2(layout.text_pos.x, item_y), rl.Color(255, 255, 255, alpha))
