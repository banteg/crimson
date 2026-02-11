from __future__ import annotations
from dataclasses import dataclass
import struct

from grim.geom import Rect, Vec2
from grim.config import (
    KEYBIND_UNBOUND_CODE,
    default_player_keybind_block,
    hud_indicator_enabled_for_player,
    player_keybind_value,
    set_hud_indicator_for_player,
    set_player_keybind_value,
)

import pyray as rl

from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width

from ..menu import (
    MENU_PANEL_HEIGHT,
    MENU_PANEL_WIDTH,
    MenuView,
)
from ...ui.menu_panel import draw_classic_menu_panel
from .base import PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS, PanelMenuView
from ...movement_controls import MovementControlType, movement_control_type_from_value
from .controls_labels import (
    PICK_PERK_BIND_SLOT,
    RELOAD_BIND_SLOT,
    controls_aim_method_dropdown_ids,
    controls_method_values,
    controls_rebind_slot_plan,
    input_configure_for_label,
    input_scheme_label,
)
from ...input_codes import INPUT_CODE_UNBOUND, capture_first_pressed_input_code, input_code_name
from .hit_test import mouse_inside_rect_with_padding
from ..types import GameState


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

_AXIS_REBIND_SLOTS = frozenset((9, 10, 11, 12))


@dataclass(frozen=True, slots=True)
class _DropdownLayout:
    pos: Vec2
    width: float
    header_h: float
    row_h: float
    rows_y0: float
    full_h: float
    arrow_pos: Vec2
    arrow_size: Vec2
    text_pos: Vec2
    text_scale: float


@dataclass(frozen=True, slots=True)
class _RebindRowLayout:
    label: str
    slot: int
    row_y: float
    value_pos: Vec2
    value_rect: Rect


class ControlsMenuView(PanelMenuView):
    def __init__(self, state: GameState) -> None:
        super().__init__(
            state,
            title="Controls",
            back_action="open_options",
            panel_pos=Vec2(CONTROLS_LEFT_PANEL_POS_X, CONTROLS_LEFT_PANEL_POS_Y),
            back_pos=Vec2(CONTROLS_BACK_POS_X, CONTROLS_BACK_POS_Y),
        )
        self._small_font: SmallFontData | None = None
        self._text_controls: rl.Texture | None = None
        self._drop_on: rl.Texture | None = None
        self._drop_off: rl.Texture | None = None
        self._check_on: rl.Texture | None = None
        self._check_off: rl.Texture | None = None

        self._config_player = 1
        self._move_method_open = False
        self._aim_method_open = False
        self._player_profile_open = False
        self._dirty = False
        self._rebind_slot: int | None = None
        self._rebind_player_index: int | None = None
        self._rebind_skip_frames = 0

    def open(self) -> None:
        super().open()
        cache = self._ensure_cache()
        # UI elements used by the classic controls screen.
        self._text_controls = cache.get_or_load("ui_textControls", "ui/ui_textControls.jaz").texture
        self._drop_on = cache.get_or_load("ui_dropOn", "ui/ui_dropDownOn.jaz").texture
        self._drop_off = cache.get_or_load("ui_dropOff", "ui/ui_dropDownOff.jaz").texture
        self._check_on = cache.get_or_load("ui_checkOn", "ui/ui_checkOn.jaz").texture
        self._check_off = cache.get_or_load("ui_checkOff", "ui/ui_checkOff.jaz").texture
        self._config_player = max(1, min(4, int(self._config_player)))
        self._move_method_open = False
        self._aim_method_open = False
        self._player_profile_open = False
        self._dirty = False
        self._clear_rebind_capture()

    def update(self, dt: float) -> None:
        super().update(dt)
        if self._closing:
            return
        entry = self._entry
        if entry is None or not self._entry_enabled(entry):
            return
        panel_scale, _local_y_shift = self._menu_item_scale(0)
        left_top_left = self._left_panel_top_left(panel_scale)
        right_top_left = self._right_panel_top_left(panel_scale)
        click_consumed = self._update_method_dropdowns(left_top_left=left_top_left, panel_scale=panel_scale)
        if not click_consumed:
            click_consumed = self._update_rebind_capture(right_top_left=right_top_left, panel_scale=panel_scale)
        if (not click_consumed) and self._update_direction_arrow_checkbox(
            left_top_left=left_top_left,
            panel_scale=panel_scale,
            enabled=self._checkbox_enabled(),
        ):
            self._dirty = True

    def _begin_close_transition(self, action: str) -> None:
        if self._dirty:
            try:
                self._state.config.save()
            except Exception:
                pass
            self._dirty = False
        super()._begin_close_transition(action)

    def _ensure_small_font(self) -> SmallFontData:
        if self._small_font is not None:
            return self._small_font
        missing_assets: list[str] = []
        self._small_font = load_small_font(self._state.assets_dir, missing_assets)
        return self._small_font

    def _current_player_index(self) -> int:
        return max(0, min(3, int(self._config_player) - 1))

    def _rebind_active(self) -> bool:
        return self._rebind_slot is not None and self._rebind_player_index is not None

    def _clear_rebind_capture(self) -> None:
        self._rebind_slot = None
        self._rebind_player_index = None
        self._rebind_skip_frames = 0

    def _start_rebind_capture(self, *, slot: int, player_index: int) -> None:
        self._rebind_slot = int(slot)
        self._rebind_player_index = max(0, min(3, int(player_index)))
        self._move_method_open = False
        self._aim_method_open = False
        self._player_profile_open = False
        # Ignore the click that opened capture so Mouse1 is not rebound accidentally.
        self._rebind_skip_frames = 1

    @staticmethod
    def _slot_is_axis(slot: int) -> bool:
        return int(slot) in _AXIS_REBIND_SLOTS

    @staticmethod
    def _capture_prompt_for_slot(slot: int) -> str:
        if ControlsMenuView._slot_is_axis(int(slot)):
            return "<press axis>"
        return "<press input>"

    def _slot_default_key(self, *, player_index: int, slot: int) -> int:
        slot_idx = int(slot)
        if slot_idx == PICK_PERK_BIND_SLOT:
            return 0x101
        if slot_idx == RELOAD_BIND_SLOT:
            return 0x102
        defaults = default_player_keybind_block(int(player_index))
        if 0 <= slot_idx < len(defaults):
            return int(defaults[slot_idx])
        return int(KEYBIND_UNBOUND_CODE)

    def _slot_key(self, *, player_index: int, slot: int) -> int:
        slot_idx = int(slot)
        if slot_idx == PICK_PERK_BIND_SLOT:
            return int(self._state.config.data.get("keybind_pick_perk", 0x101) or 0x101)
        if slot_idx == RELOAD_BIND_SLOT:
            return int(self._state.config.data.get("keybind_reload", 0x102) or 0x102)
        return int(player_keybind_value(self._state.config.data, player_index=int(player_index), slot_index=slot_idx))

    def _set_slot_key(self, *, player_index: int, slot: int, code: int) -> None:
        slot_idx = int(slot)
        value = int(code)
        if slot_idx == PICK_PERK_BIND_SLOT:
            self._state.config.data["keybind_pick_perk"] = value
            return
        if slot_idx == RELOAD_BIND_SLOT:
            self._state.config.data["keybind_reload"] = value
            return
        set_player_keybind_value(
            self._state.config.data,
            player_index=int(player_index),
            slot_index=slot_idx,
            value=value,
        )

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
                self._panel_pos.x + slide_x,
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
                CONTROLS_RIGHT_PANEL_POS_X + slide_x,
                CONTROLS_RIGHT_PANEL_POS_Y + self._widescreen_y_shift,
            )
            + self._panel_offset * panel_scale
        )

    def _direction_arrow_enabled(self) -> bool:
        return bool(
            hud_indicator_enabled_for_player(self._state.config.data, player_index=int(self._current_player_index()))
        )

    def _set_direction_arrow_enabled(self, enabled: bool) -> None:
        set_hud_indicator_for_player(
            self._state.config.data,
            player_index=int(self._current_player_index()),
            enabled=bool(enabled),
        )

    def _checkbox_enabled(self) -> bool:
        return not (self._move_method_open or self._aim_method_open or self._rebind_active())

    def _checkbox_hovered(self, *, left_top_left: Vec2, panel_scale: float, enabled: bool) -> bool:
        if not enabled:
            return False
        check_on = self._check_on
        check_off = self._check_off
        if check_on is None or check_off is None:
            return False
        font = self._ensure_small_font()
        text_scale = 1.0 * panel_scale
        label = "Show direction arrow"
        check_pos = Vec2(left_top_left.x + 213.0 * panel_scale, left_top_left.y + 174.0 * panel_scale)
        label_w = measure_small_text_width(font, label, text_scale)
        rect_w = float(check_on.width) * panel_scale + 6.0 * panel_scale + label_w
        rect_h = max(float(check_on.height) * panel_scale, font.cell_size * text_scale)
        mouse_pos = Vec2.from_xy(rl.get_mouse_position())
        return Rect.from_top_left(check_pos, rect_w, rect_h).contains(mouse_pos)

    def _update_direction_arrow_checkbox(self, *, left_top_left: Vec2, panel_scale: float, enabled: bool) -> bool:
        if not enabled:
            return False
        check_on = self._check_on
        check_off = self._check_off
        if check_on is None or check_off is None:
            return False

        hovered = self._checkbox_hovered(left_top_left=left_top_left, panel_scale=panel_scale, enabled=enabled)
        if hovered and rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
            self._set_direction_arrow_enabled(not self._direction_arrow_enabled())
            return True
        return False

    def _rebind_sections(
        self,
        *,
        player_index: int,
        aim_scheme: int,
        move_mode: int | MovementControlType,
    ) -> tuple[tuple[str, tuple[tuple[str, int], ...]], ...]:
        aim_rows, move_rows, misc_rows = controls_rebind_slot_plan(
            aim_scheme=aim_scheme,
            move_mode=move_mode,
            player_index=player_index,
        )
        sections: list[tuple[str, tuple[tuple[str, int], ...]]] = [("Aiming", aim_rows), ("Moving", move_rows)]
        if misc_rows:
            sections.append(("Misc", misc_rows))
        return tuple(sections)

    def _collect_rebind_rows(
        self,
        *,
        right_top_left: Vec2,
        panel_scale: float,
        player_index: int,
        sections: tuple[tuple[str, tuple[tuple[str, int], ...]], ...],
    ) -> tuple[_RebindRowLayout, ...]:
        font = self._ensure_small_font()
        text_scale = 1.0 * panel_scale
        rows: list[_RebindRowLayout] = []
        y = right_top_left.y + 64.0 * panel_scale
        for _section_title, section_rows in sections:
            row_y = y + 18.0 * panel_scale
            for label, slot in section_rows:
                key_code = int(self._slot_key(player_index=player_index, slot=slot))
                value_text = input_code_name(key_code)
                value_pos = Vec2(right_top_left.x + 180.0 * panel_scale, row_y)
                value_w = max(60.0 * panel_scale, measure_small_text_width(font, value_text, text_scale))
                value_rect = Rect.from_top_left(
                    Vec2(value_pos.x - 2.0 * panel_scale, row_y - 2.0 * panel_scale),
                    value_w + 4.0 * panel_scale,
                    14.0 * panel_scale,
                )
                rows.append(
                    _RebindRowLayout(
                        label=str(label),
                        slot=int(slot),
                        row_y=float(row_y),
                        value_pos=value_pos,
                        value_rect=value_rect,
                    )
                )
                row_y += 16.0 * panel_scale
            y = row_y + 8.0 * panel_scale
        return tuple(rows)

    def _update_rebind_capture(self, *, right_top_left: Vec2, panel_scale: float) -> bool:
        player_idx = self._current_player_index()
        aim_scheme, move_mode = controls_method_values(self._state.config.data, player_index=player_idx)
        sections = self._rebind_sections(player_index=player_idx, aim_scheme=aim_scheme, move_mode=move_mode)
        rows = self._collect_rebind_rows(
            right_top_left=right_top_left,
            panel_scale=panel_scale,
            player_index=player_idx,
            sections=sections,
        )

        if self._rebind_active():
            active_slot = int(self._rebind_slot or 0)
            active_player = int(self._rebind_player_index or 0)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) or rl.is_mouse_button_pressed(
                rl.MouseButton.MOUSE_BUTTON_RIGHT
            ):
                self._clear_rebind_capture()
                return True

            if rl.is_key_pressed(rl.KeyboardKey.KEY_BACKSPACE):
                self._set_slot_key(
                    player_index=active_player,
                    slot=active_slot,
                    code=self._slot_default_key(player_index=active_player, slot=active_slot),
                )
                self._dirty = True
                self._clear_rebind_capture()
                return True

            if rl.is_key_pressed(rl.KeyboardKey.KEY_DELETE):
                self._set_slot_key(player_index=active_player, slot=active_slot, code=INPUT_CODE_UNBOUND)
                self._dirty = True
                self._clear_rebind_capture()
                return True

            if self._rebind_skip_frames > 0:
                self._rebind_skip_frames = max(0, int(self._rebind_skip_frames) - 1)
                return True

            axis_only = self._slot_is_axis(active_slot)
            captured = capture_first_pressed_input_code(
                player_index=active_player,
                include_keyboard=not axis_only,
                include_mouse=not axis_only,
                include_gamepad=not axis_only,
                include_axes=axis_only,
                axis_threshold=0.5,
            )
            if captured is not None:
                self._set_slot_key(player_index=active_player, slot=active_slot, code=int(captured))
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
                self._start_rebind_capture(slot=row.slot, player_index=player_idx)
                return True
        return False

    @staticmethod
    def _coerce_blob(raw: object, size: int) -> bytearray:
        values = bytearray(raw) if isinstance(raw, (bytes, bytearray)) else bytearray()
        if len(values) < size:
            values.extend(b"\x00" * (size - len(values)))
        if len(values) > size:
            del values[size:]
        return values

    def _set_player_move_mode(self, *, player_index: int, move_mode: int) -> None:
        config = self._state.config
        raw = self._coerce_blob(config.data.get("unknown_1c"), 0x28)
        idx = max(0, min(3, int(player_index)))
        struct.pack_into("<I", raw, idx * 4, int(move_mode))
        config.data["unknown_1c"] = bytes(raw)

    def _set_player_aim_scheme(self, *, player_index: int, aim_scheme: int) -> None:
        config = self._state.config
        idx = max(0, min(3, int(player_index)))
        scheme = int(aim_scheme)
        if idx == 0:
            config.data["unknown_44"] = scheme
            return
        if idx == 1:
            config.data["unknown_48"] = scheme
            return
        raw = self._coerce_blob(config.data.get("unknown_4c"), 0x20)
        struct.pack_into("<I", raw, (idx - 2) * 4, scheme)
        config.data["unknown_4c"] = bytes(raw)

    @staticmethod
    def _move_method_ids(*, move_mode: int | MovementControlType) -> tuple[MovementControlType, ...]:
        items = [
            MovementControlType.RELATIVE,
            MovementControlType.STATIC,
            MovementControlType.DUAL_ACTION_PAD,
        ]
        if movement_control_type_from_value(move_mode) is MovementControlType.MOUSE_POINT_CLICK:
            items.append(MovementControlType.MOUSE_POINT_CLICK)
        return tuple(items)

    def _dropdown_layout(self, *, pos: Vec2, items: tuple[str, ...], scale: float) -> _DropdownLayout:
        font = self._ensure_small_font()
        text_scale = 1.0 * scale
        max_label_w = 0.0
        for label in items:
            max_label_w = max(max_label_w, measure_small_text_width(font, label, text_scale))
        width = max_label_w + 48.0 * scale
        header_h = 16.0 * scale
        row_h = 16.0 * scale
        full_h = (float(len(items)) * 16.0 + 24.0) * scale
        arrow = 16.0 * scale
        return _DropdownLayout(
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
        layout: _DropdownLayout,
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

    def _update_method_dropdowns(self, *, left_top_left: Vec2, panel_scale: float) -> bool:
        config = self._state.config
        player_idx = self._current_player_index()
        aim_scheme, move_mode = controls_method_values(config.data, player_index=player_idx)
        move_mode_ids = self._move_method_ids(move_mode=move_mode)
        move_items = tuple(input_scheme_label(mode) for mode in move_mode_ids)
        aim_item_ids = controls_aim_method_dropdown_ids(int(aim_scheme))
        aim_items = tuple(input_configure_for_label(i) for i in aim_item_ids)
        player_items = ("Player 1", "Player 2", "Player 3", "Player 4")

        move_layout = self._dropdown_layout(
            pos=Vec2(left_top_left.x + 214.0 * panel_scale, left_top_left.y + 144.0 * panel_scale),
            items=move_items,
            scale=panel_scale,
        )
        aim_layout = self._dropdown_layout(
            pos=Vec2(left_top_left.x + 214.0 * panel_scale, left_top_left.y + 102.0 * panel_scale),
            items=aim_items,
            scale=panel_scale,
        )
        player_layout = self._dropdown_layout(
            pos=Vec2(left_top_left.x + 340.0 * panel_scale, left_top_left.y + 56.0 * panel_scale),
            items=player_items,
            scale=panel_scale,
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
            self._set_player_move_mode(player_index=player_idx, move_mode=int(move_mode_ids[selected_idx]))
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
        if consumed:
            return True

        return False

    def _draw_panel(self) -> None:
        assets = self._assets
        if assets is None or assets.panel is None:
            return
        panel = assets.panel

        fx_detail = bool(self._state.config.data.get("fx_detail_0", 0))
        panel_scale, _local_y_shift = self._menu_item_scale(0)
        panel_w = MENU_PANEL_WIDTH * panel_scale

        # Left (controls options) panel: standard 254px height => a single quad.
        left_top_left = self._left_panel_top_left(panel_scale)
        left_h = MENU_PANEL_HEIGHT * panel_scale
        draw_classic_menu_panel(
            panel,
            dst=rl.Rectangle(left_top_left.x, left_top_left.y, panel_w, left_h),
            tint=rl.WHITE,
            shadow=fx_detail,
        )

        # Right (configured bindings) panel: tall 378px panel rendered as 3 vertical slices.
        right_top_left = self._right_panel_top_left(panel_scale)
        right_h = float(CONTROLS_RIGHT_PANEL_HEIGHT) * panel_scale
        draw_classic_menu_panel(
            panel,
            dst=rl.Rectangle(right_top_left.x, right_top_left.y, panel_w, right_h),
            tint=rl.WHITE,
            shadow=fx_detail,
            # Original ui_element_slot_40 sets direction_flag=1, which mirrors panel UVs.
            flip_x=True,
        )

    def _draw_contents(self) -> None:
        # Positions are expressed relative to the panel top-left corners and scaled with the panel scale.
        panel_scale, _local_y_shift = self._menu_item_scale(0)

        left_top_left = self._left_panel_top_left(panel_scale)
        right_top_left = self._right_panel_top_left(panel_scale)

        font = self._ensure_small_font()
        text_color_full = rl.Color(255, 255, 255, 255)
        text_color_soft = rl.Color(255, 255, 255, 204)
        config = self._state.config
        player_idx = self._current_player_index()
        aim_scheme, move_mode = controls_method_values(config.data, player_index=player_idx)
        move_mode_ids = self._move_method_ids(move_mode=move_mode)
        move_items = tuple(input_scheme_label(mode) for mode in move_mode_ids)
        aim_item_ids = controls_aim_method_dropdown_ids(int(aim_scheme))
        aim_items = tuple(input_configure_for_label(i) for i in aim_item_ids)
        player_items = ("Player 1", "Player 2", "Player 3", "Player 4")
        move_mode_type = movement_control_type_from_value(move_mode)
        try:
            move_selected = move_mode_ids.index(move_mode_type) if move_mode_type is not None else 0
        except ValueError:
            move_selected = 0
        try:
            aim_selected = aim_item_ids.index(int(aim_scheme))
        except ValueError:
            aim_selected = max(0, min(len(aim_items) - 1, int(aim_scheme)))
        player_selected = max(0, min(len(player_items) - 1, player_idx))
        move_layout = self._dropdown_layout(
            pos=Vec2(left_top_left.x + 214.0 * panel_scale, left_top_left.y + 144.0 * panel_scale),
            items=move_items,
            scale=panel_scale,
        )
        aim_layout = self._dropdown_layout(
            pos=Vec2(left_top_left.x + 214.0 * panel_scale, left_top_left.y + 102.0 * panel_scale),
            items=aim_items,
            scale=panel_scale,
        )
        player_layout = self._dropdown_layout(
            pos=Vec2(left_top_left.x + 340.0 * panel_scale, left_top_left.y + 56.0 * panel_scale),
            items=player_items,
            scale=panel_scale,
        )

        # --- Left panel: "Configure for" + method selectors (state_3 in trace) ---
        if self._text_controls is not None:
            MenuView._draw_ui_quad(
                texture=self._text_controls,
                src=rl.Rectangle(0.0, 0.0, float(self._text_controls.width), float(self._text_controls.height)),
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
            1.0 * panel_scale,
            text_color_soft,
        )

        draw_small_text(
            font,
            "Aiming method:",
            Vec2(left_top_left.x + 213.0 * panel_scale, left_top_left.y + 86.0 * panel_scale),
            1.0 * panel_scale,
            text_color_full,
        )

        draw_small_text(
            font,
            "Moving method:",
            Vec2(left_top_left.x + 213.0 * panel_scale, left_top_left.y + 128.0 * panel_scale),
            1.0 * panel_scale,
            text_color_full,
        )

        check_tex = self._check_on if self._direction_arrow_enabled() else self._check_off
        if check_tex is not None:
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
        )
        checkbox_alpha = 255 if checkbox_hovered else 178
        draw_small_text(
            font,
            "Show direction arrow",
            Vec2(left_top_left.x + 235.0 * panel_scale, left_top_left.y + 175.0 * panel_scale),
            1.0 * panel_scale,
            rl.Color(255, 255, 255, checkbox_alpha),
        )

        self._draw_dropdown(
            layout=player_layout,
            items=player_items,
            selected_index=player_selected,
            is_open=self._player_profile_open,
            enabled=not (self._move_method_open or self._aim_method_open or self._rebind_active()),
            scale=panel_scale,
        )
        self._draw_dropdown(
            layout=aim_layout,
            items=aim_items,
            selected_index=aim_selected,
            is_open=self._aim_method_open,
            enabled=not (self._move_method_open or self._player_profile_open or self._rebind_active()),
            scale=panel_scale,
        )
        self._draw_dropdown(
            layout=move_layout,
            items=move_items,
            selected_index=move_selected,
            is_open=self._move_method_open,
            enabled=not (self._aim_method_open or self._player_profile_open or self._rebind_active()),
            scale=panel_scale,
        )

        # --- Right panel: configured bindings list ---
        def _draw_section_heading(title: str, *, y: float) -> None:
            x_heading = right_top_left.x + 44.0 * panel_scale
            draw_small_text(
                font,
                title,
                Vec2(x_heading, y),
                1.0 * panel_scale,
                text_color_full,
            )
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
            1.0 * panel_scale,
            text_color_full,
        )
        header_w = measure_small_text_width(font, "Configured controls", 1.0 * panel_scale)
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
                label = row.label
                slot = int(row.slot)
                active_row = rebind_active and int(self._rebind_slot or -1) == slot and int(
                    self._rebind_player_index or -1
                ) == player_idx
                hovered_row = (not rebind_active) and (not dropdown_blocked) and row.value_rect.contains(mouse)
                value_text = (
                    self._capture_prompt_for_slot(slot)
                    if active_row
                    else input_code_name(self._slot_key(player_index=player_idx, slot=slot))
                )
                value_pos = row.value_pos

                draw_small_text(
                    font,
                    label,
                    Vec2(right_top_left.x + 52.0 * panel_scale, row_y),
                    1.0 * panel_scale,
                    rl.Color(255, 255, 255, 178),
                )
                value_color = CONTROLS_REBIND_VALUE_COLOR
                if hovered_row:
                    value_color = CONTROLS_REBIND_HOVER_COLOR
                if active_row:
                    value_color = CONTROLS_REBIND_ACTIVE_COLOR
                draw_small_text(
                    font,
                    value_text,
                    value_pos,
                    1.0 * panel_scale,
                    value_color,
                )
                value_w = measure_small_text_width(font, value_text, 1.0 * panel_scale)
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

        if rebind_active and int(self._rebind_player_index or -1) == player_idx:
            hint_pos = Vec2(
                right_top_left.x + 48.0 * panel_scale,
                right_top_left.y + (CONTROLS_RIGHT_PANEL_HEIGHT - 26.0) * panel_scale,
            )
            draw_small_text(
                font,
                "Esc/Right: cancel  Backspace: default  Delete: unbind",
                hint_pos,
                0.85 * panel_scale,
                rl.Color(255, 226, 188, 220),
            )

    def _draw_dropdown(
        self,
        *,
        layout: _DropdownLayout,
        items: tuple[str, ...],
        selected_index: int,
        is_open: bool,
        enabled: bool,
        scale: float,
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

        arrow_tex = self._drop_on if ((is_open or hovered_header) and enabled) else self._drop_off
        if arrow_tex is None:
            arrow_tex = self._drop_off
        if arrow_tex is not None:
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
            draw_small_text(
                self._ensure_small_font(),
                items[idx],
                layout.text_pos,
                layout.text_scale,
                rl.Color(255, 255, 255, header_alpha),
            )

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
            draw_small_text(
                self._ensure_small_font(),
                item,
                Vec2(layout.text_pos.x, item_y),
                layout.text_scale,
                rl.Color(255, 255, 255, alpha),
            )
