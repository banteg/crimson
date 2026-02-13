from __future__ import annotations

from dataclasses import dataclass

import pyray as rl

from grim.audio import play_sfx, update_audio
from grim.fonts.small import (
    SmallFontData,
    draw_small_text,
    load_small_font,
    measure_small_text_width,
)
from grim.geom import Vec2
from grim.terrain_render import GroundRenderer

from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import UiButtonState, UiButtonTextureSet, button_draw, button_update, button_width
from ...debug import debug_enabled
from ..assets import MenuAssets, _ensure_texture_cache, load_menu_assets
from ..menu import (
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
    menu_ground_camera,
)
from ..transitions import _draw_screen_fade
from ..types import GameState
from .base import PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS


# Measured from ui_render_trace_oracle_1024x768.json (state_17:credits, timeline=300).
CREDITS_PANEL_POS_X = -119.0
CREDITS_PANEL_POS_Y = 185.0
CREDITS_PANEL_HEIGHT = 378.0

# Child layout inside the panel (relative to panel top-left).
_TITLE_X = 202.0
_TITLE_Y = 46.0

_TEXT_ANCHOR_X = 198.0
_TEXT_CENTER_OFFSET_X = 140.0
_TEXT_BASE_Y = 60.0
_TEXT_LINE_HEIGHT = 16.0
_TEXT_FADE_PX = 24.0
_TEXT_RECT_H = 16.0

_BACK_BUTTON_X = 298.0
_BACK_BUTTON_Y = 310.0
_SECRET_BUTTON_X = 392.0
_SECRET_BUTTON_Y = 310.0

_FLAG_HEADING = 0x1
_FLAG_CLICKED = 0x4

_CREDITS_TABLE_SIZE = 0x100
_CREDITS_SECRET_LINE_COUNT = 10

_CREDITS_SECRET_LINES = (
    "Inside Dead Let Mighty Blood",
    "Do Firepower See Mark Of",
    "The Sacrifice Old Center",
    "Yourself Ground First For",
    "Triangle Cube Last Not Flee",
    "0001001110000010101110011",
    "0101001011100010010101100",
    "011111001000111",
    "(4 bits for index) <- OOOPS I meant FIVE!",
    "(4 bits for index)",
)
assert len(_CREDITS_SECRET_LINES) == _CREDITS_SECRET_LINE_COUNT


@dataclass(slots=True)
class _CreditsLine:
    text: str = ""
    flags: int = 0


def _credits_build_lines() -> tuple[list[_CreditsLine], int, int]:
    lines = [_CreditsLine() for _ in range(_CREDITS_TABLE_SIZE)]
    line_max_index = 0

    def _line_set(index: int, text: str, flags: int) -> None:
        nonlocal line_max_index
        lines[index] = _CreditsLine(text=text, flags=flags)
        line_max_index = index

    _line_set(0x00, "2026 Remake:", _FLAG_HEADING)
    _line_set(0x01, "banteg", 0)
    _line_set(0x02, "", 0)
    _line_set(0x03, "Crimsonland", _FLAG_HEADING)
    _line_set(0x04, "Game Design:", _FLAG_HEADING)
    _line_set(0x05, "Tero Alatalo", 0)
    _line_set(0x06, "", 0)
    _line_set(0x07, "Programming:", _FLAG_HEADING)
    _line_set(0x08, "Tero Alatalo", 0)
    _line_set(0x09, "", 0)
    _line_set(0x0A, "Producer:", _FLAG_HEADING)
    _line_set(0x0B, "Zach Young", 0)
    _line_set(0x0C, "", 0)
    _line_set(0x0D, "2D Art:", _FLAG_HEADING)
    _line_set(0x0E, "Tero Alatalo", 0)
    _line_set(0x0F, "", 0)
    _line_set(0x10, "3D Modelling:", _FLAG_HEADING)
    _line_set(0x11, "Tero Alatalo", 0)
    _line_set(0x12, "Timo Palonen", 0)
    _line_set(0x13, "", 0)
    _line_set(0x14, "Music:", _FLAG_HEADING)
    _line_set(0x15, "Valtteri Pihlajam", 0)
    _line_set(0x16, "Ville Eriksson", 0)
    _line_set(0x17, "", 0)
    _line_set(0x18, "Sound Effects:", _FLAG_HEADING)
    _line_set(0x19, "Ion Hardie", 0)
    _line_set(0x1A, "Tero Alatalo", 0)
    _line_set(0x1B, "Valtteri Pihlajam", 0)
    _line_set(0x1C, "Ville Eriksson", 0)
    _line_set(0x1D, "", 0)
    _line_set(0x1E, "Manual:", _FLAG_HEADING)
    _line_set(0x1F, "Miikka Kulmala", 0)
    _line_set(0x20, "Zach Young", 0)
    _line_set(0x21, "", 0)
    _line_set(0x22, "Special thanks to:", _FLAG_HEADING)
    _line_set(0x23, "Petri J", 0)
    _line_set(0x24, "Peter Hajba / Remedy", 0)
    _line_set(0x25, "", 0)
    _line_set(0x26, "Play testers:", _FLAG_HEADING)
    _line_set(0x27, "Avraham Petrosyan", 0)
    _line_set(0x28, "Bryce Baker", 0)
    _line_set(0x29, "Dan Ruskin", 0)
    _line_set(0x2A, "Dirk Bunk", 0)
    _line_set(0x2B, "Eric Dallaire", 0)
    _line_set(0x2C, "Erik Van Pelt", 0)
    _line_set(0x2D, "Ernie Ramirez", 0)
    _line_set(0x2E, "Ion Hardie", 0)
    _line_set(0x2F, "James C. Smith", 0)
    _line_set(0x30, "Jarkko Forsbacka", 0)
    _line_set(0x31, "Jeff McAteer", 0)
    _line_set(0x32, "Juha Alatalo", 0)
    _line_set(0x33, "Kalle Hahl", 0)
    _line_set(0x34, "Lars Brubaker", 0)
    _line_set(0x35, "Lee Cooper", 0)
    _line_set(0x36, "Markus Lassila", 0)
    _line_set(0x37, "Matti Alanen", 0)
    _line_set(0x38, "Miikka Kulmala", 0)
    _line_set(0x39, "Mika Alatalo", 0)
    _line_set(0x3A, "Mike Colonnese", 0)
    _line_set(0x3B, "Simon Hallam", 0)
    _line_set(0x3C, "Toni Nurminen", 0)
    _line_set(0x3D, "Valtteri Pihlajam", 0)
    _line_set(0x3E, "Ville Eriksson", 0)
    _line_set(0x3F, "Ville M", 0)
    _line_set(0x40, "Zach Young", 0)
    _line_set(0x41, "", 0)

    # This repeated index sequence is present in the decompile.
    _line_set(0x42, "Greeting to:", 0)
    _line_set(0x42, "Chaos^", 0)
    _line_set(0x42, "Matricks", 0)
    _line_set(0x42, "Muzzy", 0)
    _line_set(0x42, "", 0)

    _line_set(0x43, "", 0)
    _line_set(0x44, "2003 (c) 10tons entertainment", 0)
    _line_set(0x45, "10tons logo by", 0)
    _line_set(0x46, "Pasi Heinonen", 0)
    _line_set(0x47, "", 0)
    _line_set(0x48, "", 0)
    _line_set(0x49, "", 0)
    _line_set(0x4A, "Uses Vorbis Audio Decompression", 0)
    _line_set(0x4B, "2003 (c) Xiph.Org Foundation", 0)
    _line_set(0x4C, "(see vorbis.txt)", 0)

    for index in range(0x4D, 0x54):
        _line_set(index, "", 0)

    secret_line_base_index = 0x54
    _line_set(0x54, "", 0)
    _line_set(0x55, "", 0)
    _line_set(0x56, "", 0)
    _line_set(0x57, "You can stop watching now.", 0)

    for index in range(0x58, 0x77):
        _line_set(index, "", 0)

    _line_set(0x77, "Click the ones with the round ones!", 0)
    _line_set(0x78, "(and be patient!)", 0)

    for index in range(0x79, 0x7E):
        _line_set(index, "", 0)

    return lines, line_max_index, secret_line_base_index


def _credits_line_clear_flag(lines: list[_CreditsLine], index: int) -> bool:
    while index >= 0:
        if lines[index].flags & _FLAG_CLICKED:
            lines[index].flags &= ~_FLAG_CLICKED
            return True
        index -= 1
    return False


def _credits_all_round_lines_flagged(lines: list[_CreditsLine]) -> bool:
    for line in lines:
        if line.text and ("o" in line.text) and ((line.flags & _FLAG_CLICKED) == 0):
            return False
    return True


def _credits_unlock_secret_lines(lines: list[_CreditsLine], base_index: int) -> None:
    for offset, text in enumerate(_CREDITS_SECRET_LINES):
        line = lines[base_index + offset]
        line.flags |= _FLAG_CLICKED
        line.text = text


class CreditsView:
    def __init__(self, state: GameState) -> None:
        self.state = state
        self._is_open = False
        self._assets: MenuAssets | None = None
        self._ground: GroundRenderer | None = None
        self._small_font: SmallFontData | None = None
        self._button_textures: UiButtonTextureSet | None = None

        self._cursor_pulse_time = 0.0
        self._widescreen_y_shift = 0.0
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._closing = False
        self._close_action: str | None = None
        self._pending_action: str | None = None
        self._action: str | None = None

        self._lines: list[_CreditsLine] = []
        self._line_max_index = 0
        self._secret_line_base_index = 0x54
        self._secret_unlock = False
        self._scroll_time_s = 0.0
        self._scroll_line_start_index = 0
        self._scroll_line_end_index = 0

        self._back_button = UiButtonState("Back", force_wide=False)
        self._secret_button = UiButtonState("Secret", force_wide=False)

    def open(self) -> None:
        layout_w = float(self.state.config.screen_width)
        self._widescreen_y_shift = MenuView._menu_widescreen_y_shift(layout_w)
        self._assets = load_menu_assets(self.state)
        self._ground = None if self.state.pause_background is not None else ensure_menu_ground(self.state)
        self._small_font = None
        self._cursor_pulse_time = 0.0
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._closing = False
        self._close_action = None
        self._pending_action = None
        self._action = None

        self._lines, self._line_max_index, self._secret_line_base_index = _credits_build_lines()
        self._secret_unlock = False
        self._scroll_time_s = 0.0
        self._scroll_line_start_index = 0
        self._scroll_line_end_index = 0

        cache = _ensure_texture_cache(self.state)
        button_md = cache.get_or_load("ui_buttonMd", "ui/ui_button_128x32.jaz").texture
        button_sm = cache.get_or_load("ui_buttonSm", "ui/ui_button_64x32.jaz").texture
        self._button_textures = UiButtonTextureSet(button_sm=button_sm, button_md=button_md)
        self._back_button = UiButtonState("Back", force_wide=False)
        self._secret_button = UiButtonState("Secret", force_wide=False)

        if self.state.audio is not None:
            play_sfx(self.state.audio, "sfx_ui_panelclick", rng=self.state.rng)
        self._is_open = True

    def close(self) -> None:
        self._is_open = False
        if self._small_font is not None:
            rl.unload_texture(self._small_font.texture)
            self._small_font = None
        self._button_textures = None
        self._assets = None
        self._ground = None
        self._closing = False
        self._close_action = None
        self._pending_action = None
        self._action = None

    def take_action(self) -> str | None:
        self._assert_open()
        if self._pending_action is not None:
            action = self._pending_action
            self._pending_action = None
            self._closing = False
            self._close_action = None
            self._timeline_ms = self._timeline_max_ms
            return action
        action = self._action
        self._action = None
        return action

    def _assert_open(self) -> None:
        assert self._is_open, "CreditsView must be opened before use"

    def _begin_close_transition(self, action: str) -> None:
        if self._closing:
            return
        self._closing = True
        self._close_action = action

    def _ensure_small_font(self) -> SmallFontData:
        if self._small_font is not None:
            return self._small_font
        missing_assets: list[str] = []
        self._small_font = load_small_font(self.state.assets_dir, missing_assets)
        return self._small_font

    def _panel_top_left(self, *, scale: float) -> Vec2:
        return Vec2(
            CREDITS_PANEL_POS_X + MENU_PANEL_OFFSET_X * scale,
            CREDITS_PANEL_POS_Y + self._widescreen_y_shift + MENU_PANEL_OFFSET_Y * scale,
        )

    @staticmethod
    def _scroll_fraction_px(scroll_time_s: float, *, scale: float) -> float:
        frac = scroll_time_s * (_TEXT_LINE_HEIGHT * scale)
        line_h = _TEXT_LINE_HEIGHT * scale
        while frac > line_h:
            frac -= line_h
        return frac

    def _update_scroll_window(self) -> None:
        if (self._line_max_index + 2) < self._scroll_line_start_index:
            self._scroll_time_s = 0.0
            self._scroll_line_start_index = 0

        whole_scroll = int(self._scroll_time_s)
        self._scroll_line_start_index = whole_scroll - 0x0F
        self._scroll_line_end_index = whole_scroll + 1
        if self._line_max_index < self._scroll_line_end_index:
            self._scroll_line_end_index = self._line_max_index

    def _panel_slide_x(self, *, scale: float) -> float:
        panel_w = MENU_PANEL_WIDTH * scale
        _angle_rad, slide_x = MenuView._ui_element_anim(
            self,
            index=1,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w,
            direction_flag=0,
        )
        return float(slide_x)

    @staticmethod
    def _mouse_inside_rect(mouse: rl.Vector2, *, x: float, y: float, w: float, h: float) -> bool:
        return (x <= mouse.x <= (x + w)) and (y <= mouse.y <= (y + h))

    @staticmethod
    def _line_color(flags: int, *, alpha: float) -> rl.Color:
        if (flags & _FLAG_CLICKED) == 0:
            if (flags & _FLAG_HEADING) == 0:
                r, g, b = 0.4, 0.5, 0.7
            else:
                r, g, b = 1.0, 1.0, 1.0
        else:
            if (flags & _FLAG_HEADING) == 0:
                r, g, b = 0.4, 0.7, 0.7
            else:
                r, g, b = 0.9, 1.0, 0.9
        return rl.Color(
            int(r * 255.0 + 0.5),
            int(g * 255.0 + 0.5),
            int(b * 255.0 + 0.5),
            int(max(0.0, min(1.0, alpha)) * 255.0 + 0.5),
        )

    def _line_alpha(
        self,
        *,
        y: float,
        base_y: float,
        visible_count: int,
        scale: float,
    ) -> float:
        fade_px = _TEXT_FADE_PX * scale
        top = base_y + (8.0 * scale)
        alpha = 1.0
        if y < top:
            alpha = 1.0 - ((top - y) / fade_px)
        else:
            bottom = base_y + (float(visible_count - 1) * (_TEXT_LINE_HEIGHT * scale)) - fade_px
            if y > bottom:
                alpha = ((bottom - y) / fade_px) + 1.0
        if alpha < 0.0:
            return 0.0
        if alpha > 1.0:
            return 1.0
        return alpha

    def _update_line_clicks(
        self,
        *,
        panel_top_left: Vec2,
        scale: float,
        font: SmallFontData,
        mouse: rl.Vector2,
        click: bool,
    ) -> None:
        visible_count = self._scroll_line_end_index - self._scroll_line_start_index
        if visible_count <= 0 or not click:
            return

        base_y = panel_top_left.y + (_TEXT_BASE_Y * scale)
        frac_px = self._scroll_fraction_px(self._scroll_time_s, scale=scale)
        center_x = panel_top_left.x + ((_TEXT_ANCHOR_X + _TEXT_CENTER_OFFSET_X) * scale)

        for row in range(visible_count):
            index = self._scroll_line_start_index + row
            if index < 0 or index >= len(self._lines):
                continue
            line = self._lines[index]
            text_w = measure_small_text_width(font, line.text, 1.0 * scale)
            x = center_x - (text_w * 0.5)
            y = base_y + (float(row) * (_TEXT_LINE_HEIGHT * scale)) - frac_px
            if not self._mouse_inside_rect(
                mouse,
                x=x,
                y=y,
                w=text_w,
                h=_TEXT_RECT_H * scale,
            ):
                continue

            if "o" in line.text:
                if (line.flags & _FLAG_CLICKED) == 0 and self.state.audio is not None:
                    play_sfx(self.state.audio, "sfx_ui_bonus", rng=self.state.rng)
                line.flags |= _FLAG_CLICKED
            else:
                if _credits_line_clear_flag(self._lines, index) and self.state.audio is not None:
                    play_sfx(self.state.audio, "sfx_trooper_inpain_01", rng=self.state.rng)
            return

    def _update_secret_unlock(self) -> None:
        if self._secret_unlock:
            return
        if not _credits_all_round_lines_flagged(self._lines):
            return
        self._secret_unlock = True
        _credits_unlock_secret_lines(self._lines, self._secret_line_base_index)

    def _secret_button_visible(self) -> bool:
        return self._secret_unlock or debug_enabled()

    def update(self, dt: float) -> None:
        self._assert_open()
        if self.state.audio is not None:
            update_audio(self.state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        dt_clamped = min(float(dt), 0.1)
        dt_ms = int(dt_clamped * 1000.0)
        self._cursor_pulse_time += dt_clamped * 1.1

        if self._closing:
            if dt_ms > 0 and self._pending_action is None:
                self._timeline_ms -= dt_ms
                if self._timeline_ms < 0 and self._close_action is not None:
                    self._pending_action = self._close_action
                    self._close_action = None
            return

        if dt_ms > 0:
            self._timeline_ms = min(self._timeline_max_ms, int(self._timeline_ms + dt_ms))
        self._scroll_time_s += dt_clamped
        self._update_scroll_window()

        interactive = self._timeline_ms >= self._timeline_max_ms
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) and interactive:
            if self.state.audio is not None:
                play_sfx(self.state.audio, "sfx_ui_buttonclick", rng=self.state.rng)
            self._begin_close_transition("back_to_previous")
            return

        if not interactive:
            return

        scale = 0.9 if float(self.state.config.screen_width) < 641.0 else 1.0
        slide_x = self._panel_slide_x(scale=scale)
        panel_top_left = self._panel_top_left(scale=scale).offset(dx=slide_x)
        font = self._ensure_small_font()
        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)

        self._update_line_clicks(
            panel_top_left=panel_top_left,
            scale=scale,
            font=font,
            mouse=mouse,
            click=click,
        )
        self._update_secret_unlock()

        textures = self._button_textures
        if textures is None or (textures.button_md is None and textures.button_sm is None):
            return

        dt_ms_f = dt_clamped * 1000.0

        back_w = button_width(font, self._back_button.label, scale=scale, force_wide=self._back_button.force_wide)
        if button_update(
            self._back_button,
            pos=panel_top_left + Vec2(_BACK_BUTTON_X * scale, _BACK_BUTTON_Y * scale),
            width=back_w,
            dt_ms=dt_ms_f,
            mouse=mouse,
            click=click,
        ):
            if self.state.audio is not None:
                play_sfx(self.state.audio, "sfx_ui_buttonclick", rng=self.state.rng)
            self._begin_close_transition("back_to_previous")
            return

        if self._secret_button_visible():
            secret_w = button_width(
                font,
                self._secret_button.label,
                scale=scale,
                force_wide=self._secret_button.force_wide,
            )
            if button_update(
                self._secret_button,
                pos=panel_top_left + Vec2(_SECRET_BUTTON_X * scale, _SECRET_BUTTON_Y * scale),
                width=secret_w,
                dt_ms=dt_ms_f,
                mouse=mouse,
                click=click,
            ):
                if self.state.audio is not None:
                    play_sfx(self.state.audio, "sfx_ui_buttonclick", rng=self.state.rng)
                self._begin_close_transition("open_alien_zookeeper")
                return

    def draw(self) -> None:
        self._assert_open()
        rl.clear_background(rl.BLACK)
        pause_background = self.state.pause_background
        if pause_background is not None:
            pause_background.draw_pause_background()
        elif self._ground is not None:
            self._ground.draw(menu_ground_camera(self.state))
        _draw_screen_fade(self.state)

        assets = self._assets
        assert assets is not None, "CreditsView assets must be loaded before draw()"

        scale = 0.9 if float(self.state.config.screen_width) < 641.0 else 1.0
        slide_x = self._panel_slide_x(scale=scale)
        panel_top_left = self._panel_top_left(scale=scale).offset(dx=slide_x)

        dst = rl.Rectangle(
            panel_top_left.x,
            panel_top_left.y,
            MENU_PANEL_WIDTH * scale,
            CREDITS_PANEL_HEIGHT * scale,
        )
        fx_detail = self.state.config.fx_detail(level=0, default=False)
        draw_classic_menu_panel(assets.panel, dst=dst, tint=rl.WHITE, shadow=fx_detail)

        font = self._ensure_small_font()
        draw_small_text(
            font,
            "credits",
            panel_top_left + Vec2(_TITLE_X * scale, _TITLE_Y * scale),
            1.0 * scale,
            rl.Color(255, 255, 255, 255),
        )

        visible_count = self._scroll_line_end_index - self._scroll_line_start_index
        if visible_count > 0:
            base_y = panel_top_left.y + (_TEXT_BASE_Y * scale)
            frac_px = self._scroll_fraction_px(self._scroll_time_s, scale=scale)
            center_x = panel_top_left.x + ((_TEXT_ANCHOR_X + _TEXT_CENTER_OFFSET_X) * scale)

            for row in range(visible_count):
                index = self._scroll_line_start_index + row
                if index < 0 or index >= len(self._lines):
                    continue
                line = self._lines[index]
                y = base_y + (float(row) * (_TEXT_LINE_HEIGHT * scale)) - frac_px
                alpha = self._line_alpha(y=y, base_y=base_y, visible_count=visible_count, scale=scale)
                color = self._line_color(line.flags, alpha=alpha)
                text_w = measure_small_text_width(font, line.text, 1.0 * scale)
                draw_small_text(
                    font,
                    line.text,
                    Vec2(center_x - (text_w * 0.5), y),
                    1.0 * scale,
                    color,
                )

        textures = self._button_textures
        if textures is not None and (textures.button_md is not None or textures.button_sm is not None):
            back_w = button_width(font, self._back_button.label, scale=scale, force_wide=self._back_button.force_wide)
            button_draw(
                textures,
                font,
                self._back_button,
                pos=panel_top_left + Vec2(_BACK_BUTTON_X * scale, _BACK_BUTTON_Y * scale),
                width=back_w,
                scale=scale,
            )

            if self._secret_button_visible():
                secret_w = button_width(
                    font,
                    self._secret_button.label,
                    scale=scale,
                    force_wide=self._secret_button.force_wide,
                )
                button_draw(
                    textures,
                    font,
                    self._secret_button,
                    pos=panel_top_left + Vec2(_SECRET_BUTTON_X * scale, _SECRET_BUTTON_Y * scale),
                    width=secret_w,
                    scale=scale,
                )

        self._draw_sign()
        _draw_menu_cursor(self.state, pulse_time=self._cursor_pulse_time)

    def _draw_sign(self) -> None:
        assets = self._assets
        assert assets is not None, "CreditsView assets must be loaded before drawing sign"
        sign = assets.sign
        screen_w = float(self.state.config.screen_width)
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
        fx_detail = self.state.config.fx_detail(level=0, default=False)
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
