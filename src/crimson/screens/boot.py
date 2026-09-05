from __future__ import annotations

import os

from grim.assets import RuntimeResources, TextureId
from grim.audio import play_music, stop_music, update_audio
from grim.raylib_api import rl

from ..game.types import GameState
from .actions import Route

SPLASH_ALPHA_SCALE = 2.0
LOGO_TIME_SCALE = 1.1
LOGO_TIME_OFFSET = 2.0
LOGO_SKIP_ACCEL = 4.0
LOGO_SKIP_JUMP = 16.0
LOGO_THEME_TRIGGER = 14.0
LOGO_10_IN_START = 1.0
LOGO_10_IN_END = 2.0
LOGO_10_HOLD_END = 4.0
LOGO_10_OUT_END = 5.0
LOGO_REF_IN_START = 7.0
LOGO_REF_IN_END = 8.0
LOGO_REF_HOLD_END = 10.0
LOGO_REF_OUT_END = 11.0
DEBUG_LOADING_HOLD_ENV = "CRIMSON_DEBUG_LOADING_HOLD_SECONDS"


def _debug_loading_hold_seconds() -> float:
    raw = os.getenv(DEBUG_LOADING_HOLD_ENV, "").strip()
    if not raw:
        return 0.0
    try:
        return max(0.0, float(raw))
    except ValueError:
        return 0.0


class BootView:
    def __init__(self, state: GameState) -> None:
        self.state = state
        self._boot_time = 0.5
        self._fade_out_ready = False
        self._fade_out_done = False
        self._logo_delay_ticks = 0
        self._logo_skip = False
        self._logo_active = False
        self._intro_started = False
        self._theme_started = False
        self._loading_hold_remaining = _debug_loading_hold_seconds()

    def open(self) -> None:
        self._boot_time = 0.5
        self._fade_out_ready = True
        self._fade_out_done = False
        self._logo_delay_ticks = 0
        self._logo_skip = False
        self._logo_active = False
        self._intro_started = False
        self._theme_started = False
        self._loading_hold_remaining = _debug_loading_hold_seconds()

    def update(self, dt: float) -> None:
        frame_dt = min(dt, 0.1)
        if self.state.audio is not None:
            update_audio(self.state.audio, frame_dt)
        if self._theme_started:
            return

        if self._fade_out_ready and not self._fade_out_done:
            if self._loading_hold_remaining > 0.0:
                self._loading_hold_remaining = max(0.0, self._loading_hold_remaining - frame_dt)
                return
            self._boot_time -= frame_dt
            if self._boot_time <= 0.0:
                self._boot_time = 0.0
                self._fade_out_done = True
            return

        if self.state.skip_intro:
            self._start_theme()
            return

        if self._logo_delay_ticks < 5:
            self._logo_delay_ticks += 1
            return

        self._logo_active = True
        if self._boot_time > LOGO_THEME_TRIGGER:
            self._start_theme()
            return
        if (not self._intro_started) and self.state.audio is not None:
            play_music(self.state.audio, "intro")
            self._intro_started = True
        if not self._logo_skip and self._skip_triggered():
            self._logo_skip = True
        self._boot_time += frame_dt * LOGO_TIME_SCALE
        t = self._boot_time - LOGO_TIME_OFFSET
        if self._logo_skip:
            if t < LOGO_10_IN_START or (LOGO_10_OUT_END <= t and (t < LOGO_REF_IN_START or LOGO_REF_OUT_END <= t)):
                t = LOGO_SKIP_JUMP
            else:
                t += frame_dt * LOGO_SKIP_ACCEL
            self._boot_time = t + LOGO_TIME_OFFSET

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        resources = self.state.resources
        if resources is None:
            return
        if not self._fade_out_done:
            self._draw_splash(resources, self._splash_alpha())
            return
        if self._logo_active and not self._theme_started:
            self._draw_company_logo_sequence()

    def close(self) -> None:
        pass

    def take_action(self) -> Route | None:
        if not self._theme_started:
            return None
        return Route.DEMO if self.state.demo_enabled else Route.MENU

    def _start_theme(self) -> None:
        if self._theme_started:
            return
        if self.state.audio is not None:
            stop_music(self.state.audio)
            theme = "crimsonquest" if self.state.demo_enabled else "crimson_theme"
            play_music(self.state.audio, theme)
        self._theme_started = True

    def is_theme_started(self) -> bool:
        return self._theme_started

    def _skip_triggered(self) -> bool:
        if rl.get_key_pressed() != 0:
            return True
        if rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
            return True
        return bool(rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_RIGHT))

    def _logo_state(self, t: float) -> tuple[TextureId, float] | None:
        if LOGO_10_IN_START <= t < LOGO_10_OUT_END:
            if t < LOGO_10_IN_END:
                alpha = t - LOGO_10_IN_START
            elif t < LOGO_10_HOLD_END:
                alpha = 1.0
            else:
                alpha = 1.0 - (t - LOGO_10_HOLD_END)
            return TextureId.SPLASH_10TONS, self._clamp01(alpha)
        if LOGO_REF_IN_START <= t < LOGO_REF_OUT_END:
            if t < LOGO_REF_IN_END:
                alpha = t - LOGO_REF_IN_START
            elif t < LOGO_REF_HOLD_END:
                alpha = 1.0
            else:
                alpha = 1.0 - (t - LOGO_REF_HOLD_END)
            return TextureId.SPLASH_REFLEXIVE, self._clamp01(alpha)
        return None

    def _draw_company_logo_sequence(self) -> None:
        resources = self.state.resources
        if resources is None:
            return
        t = self._boot_time - LOGO_TIME_OFFSET
        state = self._logo_state(t)
        if state is None:
            return
        texture_id, alpha = state
        tex = resources.texture(texture_id)
        tex_w = float(tex.width)
        tex_h = float(tex.height)
        x = (rl.get_screen_width() - tex_w) * 0.5
        y = (rl.get_screen_height() - tex_h) * 0.5
        tint = rl.Color(255, 255, 255, int(round(alpha * 255.0)))
        rl.draw_texture_v(tex, rl.Vector2(x, y), tint)

    def _splash_alpha(self) -> float:
        return self._clamp01(self._boot_time * SPLASH_ALPHA_SCALE)

    @staticmethod
    def _clamp01(value: float) -> float:
        if value < 0.0:
            return 0.0
        if value > 1.0:
            return 1.0
        return value

    def _draw_splash(self, resources: RuntimeResources, alpha: float) -> None:
        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        if alpha <= 0.0:
            return

        logo = resources.texture(TextureId.CL_LOGO)
        logo_h = float(logo.height)
        band_height = logo_h * 2.0
        band_top = (screen_h - band_height) * 0.5 - 4.0
        band_bottom = band_top + band_height
        band_left = -4.0
        band_right = screen_w + 4.0

        line_alpha = self._clamp01(alpha * 0.7)
        line_color = rl.Color(149, 175, 198, int(round(line_alpha * 255.0)))
        rl.draw_rectangle(
            int(round(band_left)),
            int(round(band_top)),
            int(round(band_right - band_left)),
            1,
            line_color,
        )
        rl.draw_rectangle(
            int(round(band_left)),
            int(round(band_bottom)),
            int(round(band_right - band_left)),
            1,
            line_color,
        )
        rl.draw_rectangle(
            int(round(band_left)),
            int(round(band_top)),
            1,
            int(round(band_height)),
            line_color,
        )
        rl.draw_rectangle(
            int(round(band_right)),
            int(round(band_top)),
            1,
            int(round(band_height)),
            line_color,
        )

        tint = rl.Color(255, 255, 255, int(round(alpha * 255.0)))

        logo_w = float(logo.width)
        logo_h = float(logo.height)
        logo_x = (screen_w - logo_w) * 0.5
        logo_y = (screen_h - logo_h) * 0.5
        rl.draw_texture_v(logo, rl.Vector2(logo_x, logo_y), tint)
        loading = resources.texture(TextureId.LOADING)
        loading_x = screen_w * 0.5 + 128.0
        loading_y = screen_h * 0.5 + 16.0
        rl.draw_texture_v(loading, rl.Vector2(loading_x, loading_y), tint)

        esrb = resources.texture(TextureId.LOGO_ESRB)
        esrb_w = float(esrb.width)
        esrb_h = float(esrb.height)
        esrb_x = screen_w - esrb_w - 1.0
        esrb_y = screen_h - esrb_h - 1.0
        rl.draw_texture_v(esrb, rl.Vector2(esrb_x, esrb_y), tint)
