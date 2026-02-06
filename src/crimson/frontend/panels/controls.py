from __future__ import annotations
from grim.geom import Rect, Vec2

import pyray as rl

from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width

from ..menu import (
    MENU_PANEL_HEIGHT,
    MENU_PANEL_WIDTH,
    MenuView,
)
from ...ui.menu_panel import draw_classic_menu_panel
from .base import PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS, PanelMenuView
from ...input_codes import config_keybinds, input_code_name, player_move_fire_binds
from ..types import GameState


# Measured from ui_render_trace_oracle_1024x768.json (state_3:Configure for:, timeline=300).
CONTROLS_LEFT_PANEL_POS_X = -165.0
CONTROLS_LEFT_PANEL_POS_Y = 200.0
CONTROLS_RIGHT_PANEL_POS_X = 590.0
CONTROLS_RIGHT_PANEL_POS_Y = 110.0
CONTROLS_RIGHT_PANEL_HEIGHT = 378.0
CONTROLS_BACK_POS_X = -155.0
CONTROLS_BACK_POS_Y = 420.0


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
        self._text_controls: rl.Texture2D | None = None
        self._drop_off: rl.Texture2D | None = None
        self._check_on: rl.Texture2D | None = None
        self._check_off: rl.Texture2D | None = None

        self._config_player = 1
        self._dirty = False

    def open(self) -> None:
        super().open()
        cache = self._ensure_cache()
        # UI elements used by the classic controls screen.
        self._text_controls = cache.get_or_load("ui_textControls", "ui/ui_textControls.jaz").texture
        self._drop_off = cache.get_or_load("ui_dropOff", "ui/ui_dropDownOff.jaz").texture
        self._check_on = cache.get_or_load("ui_checkOn", "ui/ui_checkOn.jaz").texture
        self._check_off = cache.get_or_load("ui_checkOff", "ui/ui_checkOff.jaz").texture
        self._dirty = False

    def update(self, dt: float) -> None:
        super().update(dt)
        if self._closing:
            return
        entry = self._entry
        if entry is None or not self._entry_enabled(entry):
            return
        if self._update_direction_arrow_checkbox():
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

    def _direction_arrow_enabled(self) -> bool:
        raw = self._state.config.data.get("hud_indicators", b"\x01\x01")
        if not isinstance(raw, (bytes, bytearray)):
            return True
        player_idx = max(0, min(1, int(self._config_player) - 1))
        if player_idx >= len(raw):
            return True
        return bool(raw[player_idx])

    def _set_direction_arrow_enabled(self, enabled: bool) -> None:
        raw = self._state.config.data.get("hud_indicators", b"\x01\x01")
        values = bytearray(raw) if isinstance(raw, (bytes, bytearray)) else bytearray(b"\x01\x01")
        if len(values) < 2:
            values.extend(b"\x01" * (2 - len(values)))
        player_idx = max(0, min(1, int(self._config_player) - 1))
        values[player_idx] = 1 if enabled else 0
        self._state.config.data["hud_indicators"] = bytes(values[:2])

    def _update_direction_arrow_checkbox(self) -> bool:
        check_on = self._check_on
        check_off = self._check_off
        if check_on is None or check_off is None:
            return False

        panel_scale, _local_y_shift = self._menu_item_scale(0)
        left_top_left = (
            Vec2(self._panel_pos.x, self._panel_pos.y + self._widescreen_y_shift) + self._panel_offset * panel_scale
        )

        font = self._ensure_small_font()
        text_scale = 1.0 * panel_scale
        label = "Show direction arrow"
        check_pos = Vec2(left_top_left.x + 213.0 * panel_scale, left_top_left.y + 174.0 * panel_scale)
        label_w = measure_small_text_width(font, label, text_scale)
        rect_w = float(check_on.width) * panel_scale + 6.0 * panel_scale + label_w
        rect_h = max(float(check_on.height) * panel_scale, font.cell_size * text_scale)
        mouse_pos = Vec2.from_xy(rl.get_mouse_position())
        hovered = Rect.from_top_left(check_pos, rect_w, rect_h).contains(mouse_pos)
        if hovered and rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
            self._set_direction_arrow_enabled(not self._direction_arrow_enabled())
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
        _angle_rad, slide_x = MenuView._ui_element_anim(
            self,
            index=1,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w,
        )
        left_top_left = (
            Vec2(
                self._panel_pos.x + slide_x,
                self._panel_pos.y + self._widescreen_y_shift,
            )
            + self._panel_offset * panel_scale
        )
        left_h = MENU_PANEL_HEIGHT * panel_scale
        draw_classic_menu_panel(
            panel,
            dst=rl.Rectangle(left_top_left.x, left_top_left.y, panel_w, left_h),
            tint=rl.WHITE,
            shadow=fx_detail,
        )

        # Right (configured bindings) panel: tall 378px panel rendered as 3 vertical slices.
        _angle_rad, slide_x = MenuView._ui_element_anim(
            self,
            index=3,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w,
            direction_flag=1,
        )
        right_top_left = (
            Vec2(
                CONTROLS_RIGHT_PANEL_POS_X + slide_x,
                CONTROLS_RIGHT_PANEL_POS_Y + self._widescreen_y_shift,
            )
            + self._panel_offset * panel_scale
        )
        right_h = float(CONTROLS_RIGHT_PANEL_HEIGHT) * panel_scale
        draw_classic_menu_panel(
            panel,
            dst=rl.Rectangle(right_top_left.x, right_top_left.y, panel_w, right_h),
            tint=rl.WHITE,
            shadow=fx_detail,
        )

    def _draw_contents(self) -> None:
        # Positions are expressed relative to the panel top-left corners and scaled with the panel scale.
        panel_scale, _local_y_shift = self._menu_item_scale(0)

        left_top_left = (
            Vec2(self._panel_pos.x, self._panel_pos.y + self._widescreen_y_shift) + self._panel_offset * panel_scale
        )
        right_top_left = (
            Vec2(
                CONTROLS_RIGHT_PANEL_POS_X,
                CONTROLS_RIGHT_PANEL_POS_Y + self._widescreen_y_shift,
            )
            + self._panel_offset * panel_scale
        )

        font = self._ensure_small_font()
        text_color = rl.Color(255, 255, 255, 255)

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
            text_color,
        )
        draw_small_text(
            font,
            f"Player {int(self._config_player)}",
            Vec2(left_top_left.x + 344.0 * panel_scale, left_top_left.y + 57.0 * panel_scale),
            1.0 * panel_scale,
            text_color,
        )

        draw_small_text(
            font,
            "Aiming method:",
            Vec2(left_top_left.x + 213.0 * panel_scale, left_top_left.y + 86.0 * panel_scale),
            1.0 * panel_scale,
            text_color,
        )
        draw_small_text(
            font,
            "Mouse",
            Vec2(left_top_left.x + 218.0 * panel_scale, left_top_left.y + 103.0 * panel_scale),
            1.0 * panel_scale,
            text_color,
        )

        draw_small_text(
            font,
            "Moving method:",
            Vec2(left_top_left.x + 213.0 * panel_scale, left_top_left.y + 128.0 * panel_scale),
            1.0 * panel_scale,
            text_color,
        )
        draw_small_text(
            font,
            "Static",
            Vec2(left_top_left.x + 218.0 * panel_scale, left_top_left.y + 145.0 * panel_scale),
            1.0 * panel_scale,
            text_color,
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
        draw_small_text(
            font,
            "Show direction arrow",
            Vec2(left_top_left.x + 235.0 * panel_scale, left_top_left.y + 175.0 * panel_scale),
            1.0 * panel_scale,
            text_color,
        )

        drop_tex = self._drop_off
        if drop_tex is not None:
            for ox, oy in (
                (418.0, 56.0),  # player dropdown
                (336.0, 102.0),  # aiming dropdown
                (336.0, 144.0),  # moving dropdown
            ):
                MenuView._draw_ui_quad(
                    texture=drop_tex,
                    src=rl.Rectangle(0.0, 0.0, float(drop_tex.width), float(drop_tex.height)),
                    dst=rl.Rectangle(
                        left_top_left.x + ox * panel_scale,
                        left_top_left.y + oy * panel_scale,
                        16.0 * panel_scale,
                        16.0 * panel_scale,
                    ),
                    origin=rl.Vector2(0.0, 0.0),
                    rotation_deg=0.0,
                    tint=rl.WHITE,
                )

        # --- Right panel: configured bindings list ---
        config = self._state.config
        pick_perk_key = int(config.data.get("keybind_pick_perk", 0x101) or 0x101)
        reload_key = int(config.data.get("keybind_reload", 0x102) or 0x102)

        keybinds = config_keybinds(config)
        if not keybinds:
            keybinds = (0x11, 0x1F, 0x1E, 0x20, 0x100) + (0x17E,) * 11 + (0xC8, 0xD0, 0xCB, 0xCD, 0x9D)

        p1_up, p1_down, p1_left, p1_right, p1_fire = player_move_fire_binds(keybinds, 0)

        draw_small_text(
            font,
            "Configured controls",
            Vec2(right_top_left.x + 120.0 * panel_scale, right_top_left.y + 38.0 * panel_scale),
            1.0 * panel_scale,
            text_color,
        )

        draw_small_text(
            font,
            "Aiming",
            Vec2(right_top_left.x + 44.0 * panel_scale, right_top_left.y + 64.0 * panel_scale),
            1.0 * panel_scale,
            text_color,
        )
        draw_small_text(
            font,
            "Fire:",
            Vec2(right_top_left.x + 52.0 * panel_scale, right_top_left.y + 82.0 * panel_scale),
            1.0 * panel_scale,
            text_color,
        )
        draw_small_text(
            font,
            input_code_name(p1_fire),
            Vec2(right_top_left.x + 180.0 * panel_scale, right_top_left.y + 82.0 * panel_scale),
            1.0 * panel_scale,
            text_color,
        )

        draw_small_text(
            font,
            "Moving",
            Vec2(right_top_left.x + 44.0 * panel_scale, right_top_left.y + 106.0 * panel_scale),
            1.0 * panel_scale,
            text_color,
        )
        draw_small_text(
            font,
            "Move Up:",
            Vec2(right_top_left.x + 52.0 * panel_scale, right_top_left.y + 124.0 * panel_scale),
            1.0 * panel_scale,
            text_color,
        )
        draw_small_text(
            font,
            input_code_name(p1_up),
            Vec2(right_top_left.x + 180.0 * panel_scale, right_top_left.y + 124.0 * panel_scale),
            1.0 * panel_scale,
            text_color,
        )
        draw_small_text(
            font,
            "Move Down:",
            Vec2(right_top_left.x + 52.0 * panel_scale, right_top_left.y + 140.0 * panel_scale),
            1.0 * panel_scale,
            text_color,
        )
        draw_small_text(
            font,
            input_code_name(p1_down),
            Vec2(right_top_left.x + 180.0 * panel_scale, right_top_left.y + 140.0 * panel_scale),
            1.0 * panel_scale,
            text_color,
        )
        draw_small_text(
            font,
            "Move Left:",
            Vec2(right_top_left.x + 52.0 * panel_scale, right_top_left.y + 156.0 * panel_scale),
            1.0 * panel_scale,
            text_color,
        )
        draw_small_text(
            font,
            input_code_name(p1_left),
            Vec2(right_top_left.x + 180.0 * panel_scale, right_top_left.y + 156.0 * panel_scale),
            1.0 * panel_scale,
            text_color,
        )
        draw_small_text(
            font,
            "Move Right:",
            Vec2(right_top_left.x + 52.0 * panel_scale, right_top_left.y + 172.0 * panel_scale),
            1.0 * panel_scale,
            text_color,
        )
        draw_small_text(
            font,
            input_code_name(p1_right),
            Vec2(right_top_left.x + 180.0 * panel_scale, right_top_left.y + 172.0 * panel_scale),
            1.0 * panel_scale,
            text_color,
        )

        draw_small_text(
            font,
            "Misc",
            Vec2(right_top_left.x + 44.0 * panel_scale, right_top_left.y + 196.0 * panel_scale),
            1.0 * panel_scale,
            text_color,
        )
        draw_small_text(
            font,
            "Level Up:",
            Vec2(right_top_left.x + 52.0 * panel_scale, right_top_left.y + 214.0 * panel_scale),
            1.0 * panel_scale,
            text_color,
        )
        draw_small_text(
            font,
            input_code_name(pick_perk_key),
            Vec2(right_top_left.x + 180.0 * panel_scale, right_top_left.y + 214.0 * panel_scale),
            1.0 * panel_scale,
            text_color,
        )
        draw_small_text(
            font,
            "Reload:",
            Vec2(right_top_left.x + 52.0 * panel_scale, right_top_left.y + 230.0 * panel_scale),
            1.0 * panel_scale,
            text_color,
        )
        draw_small_text(
            font,
            input_code_name(reload_key),
            Vec2(right_top_left.x + 180.0 * panel_scale, right_top_left.y + 230.0 * panel_scale),
            1.0 * panel_scale,
            text_color,
        )
