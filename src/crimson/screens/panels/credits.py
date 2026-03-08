from __future__ import annotations

import msgspec

from grim.assets import TextureId
from grim.audio import play_sfx
from grim.fonts.small import SmallFontData, draw_small_text, measure_small_text_width
from grim.geom import Vec2
from grim.raylib_api import rl

from ...debug import debug_enabled
from ...game.types import GameState
from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import UiButtonState, button_draw, button_update, button_width
from ..assets import require_runtime_resources
from ..chrome import ActionDispatchPolicy, BackdropPolicy, ChromeSpec, SignPolicy
from .base import _ChromePanelView

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


class _CreditsLine(msgspec.Struct):
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


class CreditsView(_ChromePanelView):
    def __init__(self, state: GameState) -> None:
        super().__init__(
            state,
            chrome_spec=ChromeSpec(
                backdrop=BackdropPolicy(),
                sign=SignPolicy(),
                dispatch=ActionDispatchPolicy(mode="pending_rearm"),
                open_sfx="sfx_ui_panelclick",
                open_sfx_mode="on_open",
                close_sfx="sfx_ui_buttonclick",
            ),
        )
        self._lines: list[_CreditsLine] = []
        self._line_max_index = 0
        self._secret_line_base_index = 0x54
        self._secret_unlock = False
        self._scroll_time_s = 0.0
        self._scroll_line_start_index = 0
        self._scroll_line_end_index = 0
        self._back_button = UiButtonState("Back", force_wide=False)
        self._secret_button = UiButtonState("Secret", force_wide=False)

    def _reset_view_state(self) -> None:
        self._lines, self._line_max_index, self._secret_line_base_index = _credits_build_lines()
        self._secret_unlock = False
        self._scroll_time_s = 0.0
        self._scroll_line_start_index = 0
        self._scroll_line_end_index = 0
        self._back_button = UiButtonState("Back", force_wide=False)
        self._secret_button = UiButtonState("Secret", force_wide=False)

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
            text_w = measure_small_text_width(font, line.text)
            x = center_x - (text_w * 0.5)
            y = base_y + (float(row) * (_TEXT_LINE_HEIGHT * scale)) - frac_px
            if not self._mouse_inside_rect(mouse, x=x, y=y, w=text_w, h=_TEXT_RECT_H * scale):
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
        tick = self._chrome.update(dt)
        if self._chrome.chrome.closing:
            return

        dt_clamped = min(float(dt), 0.1)
        self._scroll_time_s += dt_clamped
        self._update_scroll_window()

        if tick.interactive and rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._begin_close_transition("back_to_previous")
            return
        if not tick.interactive:
            return

        frame = self._panel_frame(
            panel_pos=Vec2(CREDITS_PANEL_POS_X, CREDITS_PANEL_POS_Y),
            panel_height=CREDITS_PANEL_HEIGHT,
        )
        resources = require_runtime_resources(self.state)
        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)

        self._update_line_clicks(
            panel_top_left=frame.panel_top_left,
            scale=frame.scale,
            font=resources.small_font,
            mouse=mouse,
            click=bool(click),
        )
        self._update_secret_unlock()

        dt_ms = dt_clamped * 1000.0
        back_w = button_width(resources, self._back_button.label, scale=frame.scale, force_wide=self._back_button.force_wide)
        if button_update(
            self._back_button,
            pos=frame.panel_top_left + Vec2(_BACK_BUTTON_X * frame.scale, _BACK_BUTTON_Y * frame.scale),
            width=back_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=bool(click),
        ):
            self._begin_close_transition("back_to_previous")
            return

        if self._secret_button_visible():
            secret_w = button_width(
                resources,
                self._secret_button.label,
                scale=frame.scale,
                force_wide=self._secret_button.force_wide,
            )
            if button_update(
                self._secret_button,
                pos=frame.panel_top_left + Vec2(_SECRET_BUTTON_X * frame.scale, _SECRET_BUTTON_Y * frame.scale),
                width=secret_w,
                dt_ms=dt_ms,
                mouse=mouse,
                click=bool(click),
            ):
                self._begin_close_transition("open_alien_zookeeper")

    def draw(self) -> None:
        self._assert_open()
        self._draw_background()
        self._chrome.draw_fade()
        resources = require_runtime_resources(self.state)
        frame = self._panel_frame(
            panel_pos=Vec2(CREDITS_PANEL_POS_X, CREDITS_PANEL_POS_Y),
            panel_height=CREDITS_PANEL_HEIGHT,
        )

        dst = rl.Rectangle(
            frame.panel_top_left.x,
            frame.panel_top_left.y,
            frame.panel_width,
            frame.panel_height,
        )
        fx_detail = self.state.config.fx_detail(level=0, default=False)
        draw_classic_menu_panel(resources.texture(TextureId.UI_MENU_PANEL), dst=dst, tint=rl.WHITE, shadow=fx_detail)

        font = resources.small_font
        draw_small_text(font, "credits", frame.panel_top_left + Vec2(_TITLE_X * frame.scale, _TITLE_Y * frame.scale), rl.Color(255, 255, 255, 255))

        visible_count = self._scroll_line_end_index - self._scroll_line_start_index
        if visible_count > 0:
            base_y = frame.panel_top_left.y + (_TEXT_BASE_Y * frame.scale)
            frac_px = self._scroll_fraction_px(self._scroll_time_s, scale=frame.scale)
            center_x = frame.panel_top_left.x + ((_TEXT_ANCHOR_X + _TEXT_CENTER_OFFSET_X) * frame.scale)

            for row in range(visible_count):
                index = self._scroll_line_start_index + row
                if index < 0 or index >= len(self._lines):
                    continue
                line = self._lines[index]
                y = base_y + (float(row) * (_TEXT_LINE_HEIGHT * frame.scale)) - frac_px
                alpha = self._line_alpha(
                    y=y,
                    base_y=base_y,
                    visible_count=visible_count,
                    scale=frame.scale,
                )
                color = self._line_color(line.flags, alpha=alpha)
                text_w = measure_small_text_width(font, line.text)
                draw_small_text(font, line.text, Vec2(center_x - (text_w * 0.5), y), color)

        back_w = button_width(resources, self._back_button.label, scale=frame.scale, force_wide=self._back_button.force_wide)
        button_draw(
            resources,
            self._back_button,
            pos=frame.panel_top_left + Vec2(_BACK_BUTTON_X * frame.scale, _BACK_BUTTON_Y * frame.scale),
            width=back_w,
            scale=frame.scale,
        )

        if self._secret_button_visible():
            secret_w = button_width(
                resources,
                self._secret_button.label,
                scale=frame.scale,
                force_wide=self._secret_button.force_wide,
            )
            button_draw(
                resources,
                self._secret_button,
                pos=frame.panel_top_left + Vec2(_SECRET_BUTTON_X * frame.scale, _SECRET_BUTTON_Y * frame.scale),
                width=secret_w,
                scale=frame.scale,
            )

        self._draw_sign()
        self._draw_cursor()
