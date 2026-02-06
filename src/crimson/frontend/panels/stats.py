from __future__ import annotations

import pyray as rl

from grim.audio import play_music, play_sfx, stop_music, update_audio
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font
from grim.geom import Vec2
from grim.terrain_render import GroundRenderer

from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import UiButtonState, UiButtonTextureSet, button_draw, button_update, button_width
from ..assets import MenuAssets, _ensure_texture_cache, load_menu_assets
from ..menu import (
    MENU_LABEL_ROW_HEIGHT,
    MENU_LABEL_ROW_STATISTICS,
    MENU_PANEL_OFFSET_X,
    MENU_PANEL_OFFSET_Y,
    MENU_PANEL_WIDTH,
    MENU_SCALE_SMALL_THRESHOLD,
    MENU_SIGN_HEIGHT,
    MENU_SIGN_OFFSET_X,
    MENU_SIGN_OFFSET_Y,
    MENU_SIGN_POS_X_PAD,
    MENU_SIGN_POS_Y,
    MENU_SIGN_POS_Y_SMALL,
    MENU_SIGN_WIDTH,
    UI_SHADOW_OFFSET,
    MenuView,
    _draw_menu_cursor,
    ensure_menu_ground,
)
from ..transitions import _draw_screen_fade
from ..types import GameState


# Measured from ui_render_trace_oracle_1024x768.json (state_4:played for # hours # minutes, timeline=300).
STATISTICS_PANEL_POS_X = -89.0
STATISTICS_PANEL_POS_Y = 185.0
STATISTICS_PANEL_HEIGHT = 378.0

# Child layout inside the panel (relative to panel top-left).
_TITLE_X = 290.0
_TITLE_Y = 52.0
_TITLE_W = 128.0
_TITLE_H = 32.0

_BUTTON_X = 270.0
_BUTTON_Y0 = 104.0
_BUTTON_STEP_Y = 34.0

_BACK_BUTTON_X = 394.0
_BACK_BUTTON_Y = 290.0

_PLAYTIME_X = 204.0
_PLAYTIME_Y = 334.0


class StatisticsMenuView:
    """
    Classic "Statistics" menu (state_id=4).

    This is a small hub panel with buttons for:
      - High scores
      - Weapons / Perks databases
      - Credits
    """

    def __init__(self, state: GameState) -> None:
        self._state = state
        self._assets: MenuAssets | None = None
        self._ground: GroundRenderer | None = None
        self._small_font: SmallFontData | None = None
        self._button_textures: UiButtonTextureSet | None = None

        self._cursor_pulse_time = 0.0
        self._widescreen_y_shift = 0.0

        self._action: str | None = None

        self._btn_high_scores = UiButtonState("High scores", force_wide=True)
        self._btn_weapons = UiButtonState("Weapons", force_wide=True)
        self._btn_perks = UiButtonState("Perks", force_wide=True)
        self._btn_credits = UiButtonState("Credits", force_wide=True)
        self._btn_back = UiButtonState("Back", force_wide=False)

    def open(self) -> None:
        layout_w = float(self._state.config.screen_width)
        self._widescreen_y_shift = MenuView._menu_widescreen_y_shift(layout_w)
        self._assets = load_menu_assets(self._state)
        self._ground = None if self._state.pause_background is not None else ensure_menu_ground(self._state)
        self._small_font = None
        self._cursor_pulse_time = 0.0
        self._action = None

        cache = _ensure_texture_cache(self._state)
        button_md = cache.get_or_load("ui_buttonMd", "ui/ui_button_128x32.jaz").texture
        button_sm = cache.get_or_load("ui_buttonSm", "ui/ui_button_64x32.jaz").texture
        self._button_textures = UiButtonTextureSet(button_sm=button_sm, button_md=button_md)

        self._btn_high_scores = UiButtonState("High scores", force_wide=True)
        self._btn_weapons = UiButtonState("Weapons", force_wide=True)
        self._btn_perks = UiButtonState("Perks", force_wide=True)
        self._btn_credits = UiButtonState("Credits", force_wide=True)
        self._btn_back = UiButtonState("Back", force_wide=False)

        if self._state.audio is not None:
            if self._state.audio.music.active_track != "shortie_monk":
                stop_music(self._state.audio)
            play_music(self._state.audio, "shortie_monk")
            play_sfx(self._state.audio, "sfx_ui_panelclick", rng=self._state.rng)

    def close(self) -> None:
        if self._small_font is not None:
            rl.unload_texture(self._small_font.texture)
            self._small_font = None
        self._button_textures = None
        self._assets = None
        self._ground = None
        self._action = None

    def take_action(self) -> str | None:
        action = self._action
        self._action = None
        return action

    def _ensure_small_font(self) -> SmallFontData:
        if self._small_font is not None:
            return self._small_font
        missing_assets: list[str] = []
        self._small_font = load_small_font(self._state.assets_dir, missing_assets)
        return self._small_font

    def _panel_top_left(self, *, scale: float) -> Vec2:
        return Vec2(
            STATISTICS_PANEL_POS_X + MENU_PANEL_OFFSET_X * scale,
            STATISTICS_PANEL_POS_Y + self._widescreen_y_shift + MENU_PANEL_OFFSET_Y * scale,
        )

    def update(self, dt: float) -> None:
        if self._state.audio is not None:
            update_audio(self._state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        self._cursor_pulse_time += min(float(dt), 0.1) * 1.1

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            if self._state.audio is not None:
                play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
            self._action = "back_to_menu"
            return

        textures = self._button_textures
        if textures is None or (textures.button_md is None and textures.button_sm is None):
            return

        scale = 0.9 if float(self._state.config.screen_width) < 641.0 else 1.0
        panel_top_left = self._panel_top_left(scale=scale)

        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT)
        dt_ms = min(float(dt), 0.1) * 1000.0

        def _update_button(btn: UiButtonState, *, pos: Vec2) -> bool:
            w = button_width(None, btn.label, scale=scale, force_wide=btn.force_wide)
            return button_update(btn, pos=Vec2(pos.x, pos.y), width=w, dt_ms=dt_ms, mouse=mouse, click=click)

        button_base = panel_top_left + Vec2(_BUTTON_X * scale, _BUTTON_Y0 * scale)
        if _update_button(self._btn_high_scores, pos=button_base.offset(dy=_BUTTON_STEP_Y * 0.0 * scale)):
            if self._state.audio is not None:
                play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
            self._action = "open_high_scores"
            return
        if _update_button(self._btn_weapons, pos=button_base.offset(dy=_BUTTON_STEP_Y * 1.0 * scale)):
            if self._state.audio is not None:
                play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
            self._action = "open_weapon_database"
            return
        if _update_button(self._btn_perks, pos=button_base.offset(dy=_BUTTON_STEP_Y * 2.0 * scale)):
            if self._state.audio is not None:
                play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
            self._action = "open_perk_database"
            return
        if _update_button(self._btn_credits, pos=button_base.offset(dy=_BUTTON_STEP_Y * 3.0 * scale)):
            if self._state.audio is not None:
                play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
            self._action = "open_credits"
            return

        if _update_button(self._btn_back, pos=panel_top_left + Vec2(_BACK_BUTTON_X * scale, _BACK_BUTTON_Y * scale)):
            if self._state.audio is not None:
                play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
            self._action = "back_to_menu"
            return

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        pause_background = self._state.pause_background
        if pause_background is not None:
            pause_background.draw_pause_background()
        elif self._ground is not None:
            self._ground.draw(Vec2())
        _draw_screen_fade(self._state)

        assets = self._assets
        if assets is None or assets.panel is None:
            return

        scale = 0.9 if float(self._state.config.screen_width) < 641.0 else 1.0
        panel_top_left = self._panel_top_left(scale=scale)
        dst = rl.Rectangle(
            panel_top_left.x, panel_top_left.y, MENU_PANEL_WIDTH * scale, STATISTICS_PANEL_HEIGHT * scale
        )
        fx_detail = bool(self._state.config.data.get("fx_detail_0", 0))
        draw_classic_menu_panel(assets.panel, dst=dst, tint=rl.WHITE, shadow=fx_detail)

        # Title: full-size row from ui_itemTexts.jaz (128x32).
        if assets.labels is not None:
            label_tex = assets.labels
            row_h = float(MENU_LABEL_ROW_HEIGHT)
            src = rl.Rectangle(0.0, float(MENU_LABEL_ROW_STATISTICS) * row_h, float(label_tex.width), row_h)
            MenuView._draw_ui_quad(
                texture=label_tex,
                src=src,
                dst=rl.Rectangle(
                    panel_top_left.x + _TITLE_X * scale,
                    panel_top_left.y + _TITLE_Y * scale,
                    _TITLE_W * scale,
                    _TITLE_H * scale,
                ),
                origin=rl.Vector2(0.0, 0.0),
                rotation_deg=0.0,
                tint=rl.WHITE,
            )

        # "played for # hours # minutes"
        font = self._ensure_small_font()
        playtime_text = "played for 0 hours 0 minutes"
        try:
            # The classic menu shows a coarse playtime summary; our persisted value is ms.
            ms = max(0, int(self._state.status.game_sequence_id))
            minutes = (ms // 1000) // 60
            hours = minutes // 60
            minutes %= 60
            playtime_text = f"played for {hours} hours {minutes} minutes"
        except Exception:
            playtime_text = "played for ? hours ? minutes"

        draw_small_text(
            font,
            playtime_text,
            panel_top_left + Vec2(_PLAYTIME_X * scale, _PLAYTIME_Y * scale),
            1.0 * scale,
            rl.Color(255, 255, 255, int(255 * 0.8)),
        )

        # Buttons.
        textures = self._button_textures
        if textures is not None and (textures.button_md is not None or textures.button_sm is not None):
            button_base = panel_top_left + Vec2(_BUTTON_X * scale, _BUTTON_Y0 * scale)
            for i, btn in enumerate((self._btn_high_scores, self._btn_weapons, self._btn_perks, self._btn_credits)):
                w = button_width(None, btn.label, scale=scale, force_wide=btn.force_wide)
                button_draw(
                    textures,
                    font,
                    btn,
                    pos=button_base.offset(dy=_BUTTON_STEP_Y * float(i) * scale),
                    width=w,
                    scale=scale,
                )

            back_w = button_width(None, self._btn_back.label, scale=scale, force_wide=self._btn_back.force_wide)
            button_draw(
                textures,
                font,
                self._btn_back,
                pos=panel_top_left + Vec2(_BACK_BUTTON_X * scale, _BACK_BUTTON_Y * scale),
                width=back_w,
                scale=scale,
            )

        self._draw_sign(scale=scale)
        _draw_menu_cursor(self._state, pulse_time=self._cursor_pulse_time)

    def _draw_sign(self, *, scale: float) -> None:
        assets = self._assets
        if assets is None or assets.sign is None:
            return
        sign = assets.sign
        screen_w = float(self._state.config.screen_width)
        sign_scale, shift_x = MenuView._sign_layout_scale(int(screen_w))
        sign_pos = Vec2(
            screen_w + MENU_SIGN_POS_X_PAD,
            MENU_SIGN_POS_Y if screen_w > MENU_SCALE_SMALL_THRESHOLD else MENU_SIGN_POS_Y_SMALL,
        )
        sign_w = MENU_SIGN_WIDTH * sign_scale
        sign_h = MENU_SIGN_HEIGHT * sign_scale
        offset_x = MENU_SIGN_OFFSET_X * sign_scale + shift_x
        offset_y = MENU_SIGN_OFFSET_Y * sign_scale
        rotation_deg = 0.0
        fx_detail = bool(self._state.config.data.get("fx_detail_0", 0))
        if fx_detail:
            MenuView._draw_ui_quad_shadow(
                texture=sign,
                src=rl.Rectangle(0.0, 0.0, float(sign.width), float(sign.height)),
                dst=rl.Rectangle(sign_pos.x + UI_SHADOW_OFFSET, sign_pos.y + UI_SHADOW_OFFSET, sign_w, sign_h),
                origin=rl.Vector2(-offset_x, -offset_y),
                rotation_deg=rotation_deg,
            )
        MenuView._draw_ui_quad(
            texture=sign,
            src=rl.Rectangle(0.0, 0.0, float(sign.width), float(sign.height)),
            dst=rl.Rectangle(sign_pos.x, sign_pos.y, sign_w, sign_h),
            origin=rl.Vector2(-offset_x, -offset_y),
            rotation_deg=rotation_deg,
            tint=rl.WHITE,
        )
