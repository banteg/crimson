from __future__ import annotations

from typing import TYPE_CHECKING
import os

import pyray as rl

from grim.audio import init_audio_state, play_music, stop_music, update_audio, shutdown_audio
from grim.assets import LogoAssets, PaqTextureCache, load_logo_assets

from .assets import _load_resource_entries

if TYPE_CHECKING:
    from ..game import GameState


TEXTURE_LOAD_STAGES: dict[int, tuple[tuple[str, str], ...]] = {
    0: (
        ("GRIM_Font2", "load/smallWhite.tga"),
        ("trooper", "game/trooper.jaz"),
        ("zombie", "game/zombie.jaz"),
        ("spider_sp1", "game/spider_sp1.jaz"),
        ("spider_sp2", "game/spider_sp2.jaz"),
        ("alien", "game/alien.jaz"),
        ("lizard", "game/lizard.jaz"),
    ),
    1: (
        ("arrow", "load/arrow.tga"),
        ("bullet_i", "load/bullet16.tga"),
        ("bulletTrail", "load/bulletTrail.tga"),
        ("bodyset", "game/bodyset.jaz"),
        ("projs", "game/projs.jaz"),
    ),
    2: (
        ("ui_iconAim", "ui/ui_iconAim.jaz"),
        ("ui_buttonSm", "ui/ui_button_64x32.jaz"),
        ("ui_buttonMd", "ui/ui_button_128x32.jaz"),
        ("ui_checkOn", "ui/ui_checkOn.jaz"),
        ("ui_checkOff", "ui/ui_checkOff.jaz"),
        ("ui_rectOff", "ui/ui_rectOff.jaz"),
        ("ui_rectOn", "ui/ui_rectOn.jaz"),
        ("bonuses", "game/bonuses.jaz"),
    ),
    3: (
        ("ui_indBullet", "ui/ui_indBullet.jaz"),
        ("ui_indRocket", "ui/ui_indRocket.jaz"),
        ("ui_indElectric", "ui/ui_indElectric.jaz"),
        ("ui_indFire", "ui/ui_indFire.jaz"),
        ("particles", "game/particles.jaz"),
    ),
    4: (
        ("ui_indLife", "ui/ui_indLife.jaz"),
        ("ui_indPanel", "ui/ui_indPanel.jaz"),
        ("ui_arrow", "ui/ui_arrow.jaz"),
        ("ui_cursor", "ui/ui_cursor.jaz"),
        ("ui_aim", "ui/ui_aim.jaz"),
    ),
    5: (
        ("ter_q1_base", "ter/ter_q1_base.jaz"),
        ("ter_q1_tex1", "ter/ter_q1_tex1.jaz"),
        ("ter_q2_base", "ter/ter_q2_base.jaz"),
        ("ter_q2_tex1", "ter/ter_q2_tex1.jaz"),
        ("ter_q3_base", "ter/ter_q3_base.jaz"),
        ("ter_q3_tex1", "ter/ter_q3_tex1.jaz"),
        ("ter_q4_base", "ter/ter_q4_base.jaz"),
        ("ter_q4_tex1", "ter/ter_q4_tex1.jaz"),
    ),
    6: (
        ("ui_textLevComp", "ui/ui_textLevComp.jaz"),
        ("ui_textQuest", "ui/ui_textQuest.jaz"),
        ("ui_num1", "ui/ui_num1.jaz"),
        ("ui_num2", "ui/ui_num2.jaz"),
        ("ui_num3", "ui/ui_num3.jaz"),
        ("ui_num4", "ui/ui_num4.jaz"),
        ("ui_num5", "ui/ui_num5.jaz"),
    ),
    7: (
        ("ui_wicons", "ui/ui_wicons.jaz"),
        ("iGameUI", "ui/ui_gameTop.jaz"),
        ("iHeart", "ui/ui_lifeHeart.jaz"),
        ("ui_clockTable", "ui/ui_clockTable.jaz"),
        ("ui_clockPointer", "ui/ui_clockPointer.jaz"),
    ),
    8: (
        ("game\\muzzleFlash.jaz", "game/muzzleFlash.jaz"),
        ("ui_dropOn", "ui/ui_dropDownOn.jaz"),
        ("ui_dropOff", "ui/ui_dropDownOff.jaz"),
    ),
    9: (),
}

COMPANY_LOGOS: dict[str, str] = {
    "splash10tons": "load/splash10tons.jaz",
    "splashReflexive": "load/splashReflexive.jpg",
}
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

MENU_PREP_TEXTURES: tuple[tuple[str, str], ...] = (
    ("ui_signCrimson", "ui/ui_signCrimson.jaz"),
    ("ui_menuItem", "ui/ui_menuItem.jaz"),
    ("ui_menuPanel", "ui/ui_menuPanel.jaz"),
    ("ui_itemTexts", "ui/ui_itemTexts.jaz"),
    ("ui_checkOn", "ui/ui_checkOn.jaz"),
    ("ui_checkOff", "ui/ui_checkOff.jaz"),
    ("ui_rectOff", "ui/ui_rectOff.jaz"),
    ("ui_rectOn", "ui/ui_rectOn.jaz"),
    ("ui_button_md", "ui/ui_button_145x32.jaz"),
)


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
        self._state = state
        self._texture_stage = 0
        self._textures_done = False
        self._boot_time = 0.0
        self._fade_out_ready = False
        self._fade_out_done = False
        self._logo_delay_ticks = 0
        self._logo_skip = False
        self._logo_active = False
        self._intro_started = False
        self._theme_started = False
        self._company_logos_loaded = False
        self._menu_prepped = False
        self._loading_hold_remaining = _debug_loading_hold_seconds()

    def _load_texture_stage(self, stage: int) -> None:
        cache = self._state.texture_cache
        if cache is None:
            return
        stage_defs = TEXTURE_LOAD_STAGES.get(stage)
        if not stage_defs:
            return
        for name, rel_path in stage_defs:
            cache.get_or_load(name, rel_path)

    def _load_company_logos(self) -> None:
        if self._company_logos_loaded:
            return
        cache = self._state.texture_cache
        if cache is None:
            return
        for name, rel_path in COMPANY_LOGOS.items():
            cache.get_or_load(name, rel_path)
        loaded = sum(1 for name in COMPANY_LOGOS if cache.get(name) and cache.get(name).texture is not None)
        if COMPANY_LOGOS:
            self._state.console.log.log(f"company logos loaded: {loaded}/{len(COMPANY_LOGOS)}")
            self._state.console.log.flush()
        self._company_logos_loaded = True

    def _prepare_menu_assets(self) -> None:
        if self._menu_prepped:
            return
        cache = self._state.texture_cache
        if cache is None:
            return
        for name, rel_path in MENU_PREP_TEXTURES:
            cache.get_or_load(name, rel_path)
        loaded = sum(1 for name, _rel in MENU_PREP_TEXTURES if cache.get(name) and cache.get(name).texture is not None)
        if MENU_PREP_TEXTURES:
            self._state.console.log.log(f"menu textures loaded: {loaded}/{len(MENU_PREP_TEXTURES)}")
            self._state.console.log.flush()
        self._menu_prepped = True

    def open(self) -> None:
        if self._state.logos is None:
            entries = _load_resource_entries(self._state)
            logos = load_logo_assets(self._state.assets_dir, entries=entries)
            self._state.console.log.log(f"logo assets: {logos.loaded_count()}/{len(logos.all())} loaded")
            self._state.console.log.flush()
            self._state.logos = logos
            self._state.texture_cache = PaqTextureCache(entries=entries, textures={})
        if self._state.audio is None:
            self._state.audio = init_audio_state(self._state.config, self._state.assets_dir, self._state.console)
            self._state.console.exec_line("exec music/game_tunes.txt")

    def update(self, dt: float) -> None:
        frame_dt = min(dt, 0.1)
        if self._state.audio is not None:
            update_audio(self._state.audio, frame_dt)
        if self._theme_started:
            return
        if not self._textures_done:
            self._boot_time += frame_dt
            if self._texture_stage in TEXTURE_LOAD_STAGES:
                self._load_texture_stage(self._texture_stage)
                self._texture_stage += 1
                if self._texture_stage >= len(TEXTURE_LOAD_STAGES):
                    self._textures_done = True
                    if self._state.texture_cache is not None:
                        loaded = self._state.texture_cache.loaded_count()
                        total = len(self._state.texture_cache.textures)
                        self._state.console.log.log(f"boot textures loaded: {loaded}/{total}")
                        self._state.console.log.flush()
                    self._load_company_logos()
                    self._prepare_menu_assets()
                    self._fade_out_ready = True
                    self._loading_hold_remaining = _debug_loading_hold_seconds()
                    if self._boot_time > 0.5:
                        self._boot_time = 0.5
            return

        if self._fade_out_ready and not self._fade_out_done:
            if self._loading_hold_remaining > 0.0:
                if self._boot_time < 0.5:
                    self._boot_time = min(0.5, self._boot_time + frame_dt)
                    return
                self._loading_hold_remaining = max(0.0, self._loading_hold_remaining - frame_dt)
                return
            self._boot_time -= frame_dt
            if self._boot_time <= 0.0:
                self._boot_time = 0.0
                self._fade_out_done = True
            return

        if not self._fade_out_done:
            self._boot_time += frame_dt
            return

        if self._logo_delay_ticks < 5:
            self._logo_delay_ticks += 1
            return

        self._logo_active = True
        if self._boot_time > LOGO_THEME_TRIGGER:
            self._start_theme()
            return
        if not self._intro_started and self._state.audio is not None:
            play_music(self._state.audio, "intro")
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
        if not self._fade_out_ready or not self._fade_out_done:
            logos = self._state.logos
            if logos is not None:
                self._draw_splash(logos, self._splash_alpha())
            return
        if self._logo_active and not self._theme_started:
            self._draw_company_logo_sequence()

    def close(self) -> None:
        if self._state.logos is not None:
            self._state.logos.unload()
        if self._state.texture_cache is not None:
            self._state.texture_cache.unload()
        if self._state.audio is not None:
            shutdown_audio(self._state.audio)

    def _start_theme(self) -> None:
        if self._theme_started:
            return
        if self._state.audio is not None:
            stop_music(self._state.audio)
            theme = "crimsonquest" if self._state.demo_enabled else "crimson_theme"
            play_music(self._state.audio, theme)
        self._theme_started = True

    def is_theme_started(self) -> bool:
        return self._theme_started

    def _skip_triggered(self) -> bool:
        if rl.get_key_pressed() != 0:
            return True
        if rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT):
            return True
        if rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_RIGHT):
            return True
        return False

    def _logo_state(self, t: float) -> tuple[str, float] | None:
        if LOGO_10_IN_START <= t < LOGO_10_OUT_END:
            if t < LOGO_10_IN_END:
                alpha = t - LOGO_10_IN_START
            elif t < LOGO_10_HOLD_END:
                alpha = 1.0
            else:
                alpha = 1.0 - (t - LOGO_10_HOLD_END)
            return ("splash10tons", self._clamp01(alpha))
        if LOGO_REF_IN_START <= t < LOGO_REF_OUT_END:
            if t < LOGO_REF_IN_END:
                alpha = t - LOGO_REF_IN_START
            elif t < LOGO_REF_HOLD_END:
                alpha = 1.0
            else:
                alpha = 1.0 - (t - LOGO_REF_HOLD_END)
            return ("splashReflexive", self._clamp01(alpha))
        return None

    def _draw_company_logo_sequence(self) -> None:
        cache = self._state.texture_cache
        if cache is None:
            return
        t = self._boot_time - LOGO_TIME_OFFSET
        state = self._logo_state(t)
        if state is None:
            return
        name, alpha = state
        rel_path = COMPANY_LOGOS.get(name)
        if rel_path is None:
            return
        asset = cache.get_or_load(name, rel_path)
        if asset.texture is None:
            return
        tex = asset.texture
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

    def _draw_splash(self, logos: LogoAssets, alpha: float) -> None:
        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        if alpha <= 0.0:
            return

        logo = logos.cl_logo.texture
        logo_h = float(logo.height) if logo is not None else 64.0
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

        if logo is not None:
            logo_w = float(logo.width)
            logo_h = float(logo.height)
            logo_x = (screen_w - logo_w) * 0.5
            logo_y = (screen_h - logo_h) * 0.5
            rl.draw_texture_v(logo, rl.Vector2(logo_x, logo_y), tint)
            loading = logos.loading.texture
            if loading is not None:
                loading_x = screen_w * 0.5 + 128.0
                loading_y = screen_h * 0.5 + 16.0
                rl.draw_texture_v(loading, rl.Vector2(loading_x, loading_y), tint)

        esrb = logos.logo_esrb.texture
        if esrb is not None:
            esrb_w = float(esrb.width)
            esrb_h = float(esrb.height)
            esrb_x = screen_w - esrb_w - 1.0
            esrb_y = screen_h - esrb_h - 1.0
            rl.draw_texture_v(esrb, rl.Vector2(esrb_x, esrb_y), tint)
