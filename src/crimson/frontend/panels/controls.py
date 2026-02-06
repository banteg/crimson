from __future__ import annotations
from grim.geom import Vec2

import pyray as rl

from grim.fonts.small import SmallFontData, draw_small_text, load_small_font

from ..menu import (
    MENU_PANEL_OFFSET_X,
    MENU_PANEL_OFFSET_Y,
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
            panel_pos_x=CONTROLS_LEFT_PANEL_POS_X,
            panel_pos_y=CONTROLS_LEFT_PANEL_POS_Y,
            back_pos_x=CONTROLS_BACK_POS_X,
            back_pos_y=CONTROLS_BACK_POS_Y,
        )
        self._small_font: SmallFontData | None = None
        self._text_controls: rl.Texture2D | None = None
        self._drop_off: rl.Texture2D | None = None
        self._check_on: rl.Texture2D | None = None
        self._check_off: rl.Texture2D | None = None

        self._config_player = 1

    def open(self) -> None:
        super().open()
        cache = self._ensure_cache()
        # UI elements used by the classic controls screen.
        self._text_controls = cache.get_or_load("ui_textControls", "ui/ui_textControls.jaz").texture
        self._drop_off = cache.get_or_load("ui_dropOff", "ui/ui_dropDownOff.jaz").texture
        self._check_on = cache.get_or_load("ui_checkOn", "ui/ui_checkOn.jaz").texture
        self._check_off = cache.get_or_load("ui_checkOff", "ui/ui_checkOff.jaz").texture

    def _ensure_small_font(self) -> SmallFontData:
        if self._small_font is not None:
            return self._small_font
        missing_assets: list[str] = []
        self._small_font = load_small_font(self._state.assets_dir, missing_assets)
        return self._small_font

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
        left_x0 = self._panel_pos_x + slide_x + MENU_PANEL_OFFSET_X * panel_scale
        left_y0 = self._panel_pos_y + self._widescreen_y_shift + MENU_PANEL_OFFSET_Y * panel_scale
        left_h = MENU_PANEL_HEIGHT * panel_scale
        draw_classic_menu_panel(panel, dst=rl.Rectangle(left_x0, left_y0, panel_w, left_h), tint=rl.WHITE, shadow=fx_detail)

        # Right (configured bindings) panel: tall 378px panel rendered as 3 vertical slices.
        _angle_rad, slide_x = MenuView._ui_element_anim(
            self,
            index=3,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w,
            direction_flag=1,
        )
        right_x0 = CONTROLS_RIGHT_PANEL_POS_X + slide_x + MENU_PANEL_OFFSET_X * panel_scale
        right_y0 = CONTROLS_RIGHT_PANEL_POS_Y + self._widescreen_y_shift + MENU_PANEL_OFFSET_Y * panel_scale
        right_h = float(CONTROLS_RIGHT_PANEL_HEIGHT) * panel_scale
        draw_classic_menu_panel(panel, dst=rl.Rectangle(right_x0, right_y0, panel_w, right_h), tint=rl.WHITE, shadow=fx_detail)

    def _draw_contents(self) -> None:
        # Positions are expressed relative to the panel top-left corners and scaled with the panel scale.
        panel_scale, _local_y_shift = self._menu_item_scale(0)

        left_x0 = self._panel_pos_x + MENU_PANEL_OFFSET_X * panel_scale
        left_y0 = self._panel_pos_y + self._widescreen_y_shift + MENU_PANEL_OFFSET_Y * panel_scale
        right_x0 = CONTROLS_RIGHT_PANEL_POS_X + MENU_PANEL_OFFSET_X * panel_scale
        right_y0 = CONTROLS_RIGHT_PANEL_POS_Y + self._widescreen_y_shift + MENU_PANEL_OFFSET_Y * panel_scale

        font = self._ensure_small_font()
        text_color = rl.Color(255, 255, 255, 255)

        # --- Left panel: "Configure for" + method selectors (state_3 in trace) ---
        if self._text_controls is not None:
            MenuView._draw_ui_quad(
                texture=self._text_controls,
                src=rl.Rectangle(0.0, 0.0, float(self._text_controls.width), float(self._text_controls.height)),
                dst=rl.Rectangle(left_x0 + 206.0 * panel_scale, left_y0 + 44.0 * panel_scale, 128.0 * panel_scale, 32.0 * panel_scale),
                origin=rl.Vector2(0.0, 0.0),
                rotation_deg=0.0,
                tint=rl.WHITE,
            )

        draw_small_text(font, "Configure for:", Vec2(left_x0 + 339.0 * panel_scale, left_y0 + 41.0 * panel_scale), 1.0 * panel_scale, text_color)
        draw_small_text(font, f"Player {int(self._config_player)}", Vec2(left_x0 + 344.0 * panel_scale, left_y0 + 57.0 * panel_scale), 1.0 * panel_scale, text_color)

        draw_small_text(font, "Aiming method:", Vec2(left_x0 + 213.0 * panel_scale, left_y0 + 86.0 * panel_scale), 1.0 * panel_scale, text_color)
        draw_small_text(font, "Mouse", Vec2(left_x0 + 218.0 * panel_scale, left_y0 + 103.0 * panel_scale), 1.0 * panel_scale, text_color)

        draw_small_text(font, "Moving method:", Vec2(left_x0 + 213.0 * panel_scale, left_y0 + 128.0 * panel_scale), 1.0 * panel_scale, text_color)
        draw_small_text(font, "Static", Vec2(left_x0 + 218.0 * panel_scale, left_y0 + 145.0 * panel_scale), 1.0 * panel_scale, text_color)

        check_tex = self._check_on
        if check_tex is not None:
            MenuView._draw_ui_quad(
                texture=check_tex,
                src=rl.Rectangle(0.0, 0.0, float(check_tex.width), float(check_tex.height)),
                dst=rl.Rectangle(left_x0 + 213.0 * panel_scale, left_y0 + 174.0 * panel_scale, 16.0 * panel_scale, 16.0 * panel_scale),
                origin=rl.Vector2(0.0, 0.0),
                rotation_deg=0.0,
                tint=rl.WHITE,
            )
        draw_small_text(
            font,
            "Show direction arrow",
            Vec2(left_x0 + 235.0 * panel_scale, left_y0 + 175.0 * panel_scale), 1.0 * panel_scale,
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
                    dst=rl.Rectangle(left_x0 + ox * panel_scale, left_y0 + oy * panel_scale, 16.0 * panel_scale, 16.0 * panel_scale),
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

        draw_small_text(font, "Configured controls", Vec2(right_x0 + 120.0 * panel_scale, right_y0 + 38.0 * panel_scale), 1.0 * panel_scale, text_color)

        draw_small_text(font, "Aiming", Vec2(right_x0 + 44.0 * panel_scale, right_y0 + 64.0 * panel_scale), 1.0 * panel_scale, text_color)
        draw_small_text(font, "Fire:", Vec2(right_x0 + 52.0 * panel_scale, right_y0 + 82.0 * panel_scale), 1.0 * panel_scale, text_color)
        draw_small_text(font, input_code_name(p1_fire), Vec2(right_x0 + 180.0 * panel_scale, right_y0 + 82.0 * panel_scale), 1.0 * panel_scale, text_color)

        draw_small_text(font, "Moving", Vec2(right_x0 + 44.0 * panel_scale, right_y0 + 106.0 * panel_scale), 1.0 * panel_scale, text_color)
        draw_small_text(font, "Move Up:", Vec2(right_x0 + 52.0 * panel_scale, right_y0 + 124.0 * panel_scale), 1.0 * panel_scale, text_color)
        draw_small_text(font, input_code_name(p1_up), Vec2(right_x0 + 180.0 * panel_scale, right_y0 + 124.0 * panel_scale), 1.0 * panel_scale, text_color)
        draw_small_text(font, "Move Down:", Vec2(right_x0 + 52.0 * panel_scale, right_y0 + 140.0 * panel_scale), 1.0 * panel_scale, text_color)
        draw_small_text(font, input_code_name(p1_down), Vec2(right_x0 + 180.0 * panel_scale, right_y0 + 140.0 * panel_scale), 1.0 * panel_scale, text_color)
        draw_small_text(font, "Move Left:", Vec2(right_x0 + 52.0 * panel_scale, right_y0 + 156.0 * panel_scale), 1.0 * panel_scale, text_color)
        draw_small_text(font, input_code_name(p1_left), Vec2(right_x0 + 180.0 * panel_scale, right_y0 + 156.0 * panel_scale), 1.0 * panel_scale, text_color)
        draw_small_text(font, "Move Right:", Vec2(right_x0 + 52.0 * panel_scale, right_y0 + 172.0 * panel_scale), 1.0 * panel_scale, text_color)
        draw_small_text(font, input_code_name(p1_right), Vec2(right_x0 + 180.0 * panel_scale, right_y0 + 172.0 * panel_scale), 1.0 * panel_scale, text_color)

        draw_small_text(font, "Misc", Vec2(right_x0 + 44.0 * panel_scale, right_y0 + 196.0 * panel_scale), 1.0 * panel_scale, text_color)
        draw_small_text(font, "Level Up:", Vec2(right_x0 + 52.0 * panel_scale, right_y0 + 214.0 * panel_scale), 1.0 * panel_scale, text_color)
        draw_small_text(font, input_code_name(pick_perk_key), Vec2(right_x0 + 180.0 * panel_scale, right_y0 + 214.0 * panel_scale), 1.0 * panel_scale, text_color)
        draw_small_text(font, "Reload:", Vec2(right_x0 + 52.0 * panel_scale, right_y0 + 230.0 * panel_scale), 1.0 * panel_scale, text_color)
        draw_small_text(font, input_code_name(reload_key), Vec2(right_x0 + 180.0 * panel_scale, right_y0 + 230.0 * panel_scale), 1.0 * panel_scale, text_color)
