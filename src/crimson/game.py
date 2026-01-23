from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import datetime as dt
import faulthandler
import math
import random
import shutil
import traceback

import pyray as rl

from .audio import (
    AudioState,
    init_audio_state,
    play_music,
    stop_music,
    update_audio,
    shutdown_audio,
)
from .assets import LogoAssets, PaqTextureCache, load_logo_assets, load_paq_entries
from .config import CrimsonConfig, ensure_crimson_cfg
from .console import (
    ConsoleState,
    create_console,
    register_boot_commands,
    register_core_cvars,
)
from .demo import DemoView
from .entrypoint import DEFAULT_BASE_DIR
from .raylib_app import run_view
from .terrain_render import GroundRenderer
from .views.types import View


@dataclass(frozen=True, slots=True)
class GameConfig:
    base_dir: Path = DEFAULT_BASE_DIR
    assets_dir: Path | None = None
    width: int | None = None
    height: int | None = None
    fps: int = 60
    seed: int | None = None


@dataclass(slots=True)
class GameState:
    base_dir: Path
    assets_dir: Path
    rng: random.Random
    config: CrimsonConfig
    console: ConsoleState
    demo_enabled: bool
    logos: LogoAssets | None
    texture_cache: PaqTextureCache | None
    audio: AudioState | None


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
DEMO_MODE_ENV = "CRIMSON_IS_DEMO"
CRIMSON_PAQ_NAME = "crimson.paq"
MUSIC_PAQ_NAME = "music.paq"
SFX_PAQ_NAME = "sfx.paq"


def _debug_loading_hold_seconds() -> float:
    raw = os.getenv(DEBUG_LOADING_HOLD_ENV, "").strip()
    if not raw:
        return 0.0
    try:
        return max(0.0, float(raw))
    except ValueError:
        return 0.0


def _demo_mode_enabled() -> bool:
    raw = os.getenv(DEMO_MODE_ENV, "").strip().lower()
    return raw in {"1", "true", "yes", "on"}

MENU_PREP_TEXTURES: tuple[tuple[str, str], ...] = (
    ("ui_signCrimson", "ui/ui_signCrimson.jaz"),
    ("ui_menuItem", "ui/ui_menuItem.jaz"),
    ("ui_menuPanel", "ui/ui_menuPanel.jaz"),
    ("ui_itemTexts", "ui/ui_itemTexts.jaz"),
)

MENU_LABEL_WIDTH = 124.0
MENU_LABEL_HEIGHT = 30.0
MENU_LABEL_ROW_HEIGHT = 32.0
MENU_LABEL_BASE_X = -60.0
MENU_LABEL_BASE_Y = 210.0
MENU_LABEL_OFFSET_X = 270.0
MENU_LABEL_OFFSET_Y = -38.0
MENU_LABEL_STEP = 60.0
MENU_ITEM_OFFSET_X = -72.0
MENU_ITEM_OFFSET_Y = -60.0
MENU_PANEL_WIDTH = 512.0
MENU_PANEL_HEIGHT = 256.0
MENU_PANEL_OFFSET_X = 20.0
MENU_PANEL_OFFSET_Y = -82.0
MENU_PANEL_BASE_X = -45.0
MENU_PANEL_BASE_Y = 210.0
MENU_SCALE_SMALL_THRESHOLD = 640
MENU_SCALE_LARGE_MIN = 801
MENU_SCALE_LARGE_MAX = 1024
MENU_SCALE_SMALL = 0.8
MENU_SCALE_LARGE = 1.2
MENU_SCALE_SHIFT = 10.0

MENU_SIGN_WIDTH = 573.44
MENU_SIGN_HEIGHT = 143.36
MENU_SIGN_OFFSET_X = -577.44
MENU_SIGN_OFFSET_Y = -62.0
MENU_SIGN_POS_Y = 70.0
MENU_SIGN_POS_Y_SMALL = 60.0
MENU_SIGN_POS_X_PAD = 4.0


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
        loaded = sum(
            1
            for name in COMPANY_LOGOS
            if cache.get(name) and cache.get(name).texture is not None
        )
        if COMPANY_LOGOS:
            self._state.console.log.log(
                f"company logos loaded: {loaded}/{len(COMPANY_LOGOS)}"
            )
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
        loaded = sum(
            1
            for name, _rel in MENU_PREP_TEXTURES
            if cache.get(name) and cache.get(name).texture is not None
        )
        if MENU_PREP_TEXTURES:
            self._state.console.log.log(
                f"menu textures loaded: {loaded}/{len(MENU_PREP_TEXTURES)}"
            )
            self._state.console.log.flush()
        self._menu_prepped = True

    def open(self) -> None:
        if self._state.logos is None:
            entries = load_paq_entries(self._state.assets_dir)
            logos = load_logo_assets(self._state.assets_dir, entries=entries)
            self._state.console.log.log(
                f"logo assets: {logos.loaded_count()}/{len(logos.all())} loaded"
            )
            self._state.console.log.flush()
            self._state.logos = logos
            self._state.texture_cache = PaqTextureCache(entries=entries, textures={})
        if self._state.audio is None:
            self._state.audio = init_audio_state(
                self._state.config, self._state.assets_dir, self._state.console
            )

    def update(self, dt: float) -> None:
        frame_dt = min(dt, 0.1)
        if self._state.audio is not None:
            update_audio(self._state.audio)
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
                        self._state.console.log.log(
                            f"boot textures loaded: {loaded}/{total}"
                        )
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
                self._loading_hold_remaining = max(
                    0.0, self._loading_hold_remaining - frame_dt
                )
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
            if t < LOGO_10_IN_START or (
                LOGO_10_OUT_END <= t
                and (t < LOGO_REF_IN_START or LOGO_REF_OUT_END <= t)
            ):
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


@dataclass(slots=True)
class MenuAssets:
    sign: rl.Texture2D | None
    item: rl.Texture2D | None
    panel: rl.Texture2D | None
    labels: rl.Texture2D | None


@dataclass(slots=True)
class MenuEntry:
    slot: int
    row: int
    y: float
    hover_amount: int = 0
    ready_timer_ms: int = 0x100


class MenuView:
    def __init__(self, state: GameState) -> None:
        self._state = state
        self._assets: MenuAssets | None = None
        self._ground: GroundRenderer | None = None
        self._menu_entries: list[MenuEntry] = []
        self._selected_index = 0
        self._focus_timer_ms = 0
        self._hovered_index: int | None = None
        self._full_version = False
        self._timeline_ms = 0
        self._timeline_max_ms = 0
        self._widescreen_y_shift = 0.0
        self._menu_screen_width = 0

    def open(self) -> None:
        layout_w = float(self._state.config.screen_width)
        self._menu_screen_width = int(layout_w)
        self._widescreen_y_shift = self._menu_widescreen_y_shift(layout_w)
        cache = self._ensure_cache()
        sign = cache.get_or_load("ui_signCrimson", "ui/ui_signCrimson.jaz").texture
        item = cache.get_or_load("ui_menuItem", "ui/ui_menuItem.jaz").texture
        panel = cache.get_or_load("ui_menuPanel", "ui/ui_menuPanel.jaz").texture
        labels = cache.get_or_load("ui_itemTexts", "ui/ui_itemTexts.jaz").texture
        self._assets = MenuAssets(sign=sign, item=item, panel=panel, labels=labels)
        self._full_version = bool(self._state.config.data.get("full_version_flag", 0))
        self._menu_entries = self._menu_entries_for_flags(
            full_version=self._full_version,
            mods_available=self._mods_available(),
            other_games=self._other_games_enabled(),
        )
        self._selected_index = 0 if self._menu_entries else -1
        self._focus_timer_ms = 0
        self._hovered_index = None
        self._timeline_ms = 0
        self._timeline_max_ms = self._menu_max_timeline_ms(
            full_version=self._full_version,
            mods_available=self._mods_available(),
            other_games=self._other_games_enabled(),
        )
        self._init_ground()

    def close(self) -> None:
        if self._ground is not None and self._ground.render_target is not None:
            rl.unload_render_texture(self._ground.render_target)
        self._ground = None

    def update(self, dt: float) -> None:
        if self._state.audio is not None:
            update_audio(self._state.audio)
        if self._ground is not None:
            self._ground.process_pending()
        dt_ms = int(min(dt, 0.1) * 1000.0)
        if dt_ms > 0:
            self._timeline_ms = min(self._timeline_max_ms, self._timeline_ms + dt_ms)
            self._focus_timer_ms = max(0, self._focus_timer_ms - dt_ms)
        if not self._menu_entries:
            return

        self._hovered_index = self._hovered_entry_index()

        if rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            reverse = rl.is_key_down(rl.KeyboardKey.KEY_LEFT_SHIFT) or rl.is_key_down(
                rl.KeyboardKey.KEY_RIGHT_SHIFT
            )
            delta = -1 if reverse else 1
            self._selected_index = (self._selected_index + delta) % len(self._menu_entries)
            self._focus_timer_ms = 1000

        if (
            rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER)
            and 0 <= self._selected_index < len(self._menu_entries)
        ):
            entry = self._menu_entries[self._selected_index]
            if self._menu_entry_enabled(entry):
                self._state.console.log.log(
                    f"menu select: {self._selected_index} (row {entry.row})"
                )
                self._state.console.log.flush()
        self._update_ready_timers(dt_ms)
        self._update_hover_amounts(dt_ms)

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        if self._ground is not None:
            self._ground.draw(0.0, 0.0)
        assets = self._assets
        if assets is None:
            return
        self._draw_menu_items()
        self._draw_menu_sign()

    def _ensure_cache(self) -> PaqTextureCache:
        cache = self._state.texture_cache
        if cache is None:
            entries = load_paq_entries(self._state.assets_dir)
            cache = PaqTextureCache(entries=entries, textures={})
            self._state.texture_cache = cache
        return cache

    def _init_ground(self) -> None:
        cache = self._state.texture_cache
        if cache is None:
            return
        base = cache.texture("ter_q1_base")
        if base is None:
            return
        overlay = cache.texture("ter_q1_tex1")
        detail = overlay or base
        self._ground = GroundRenderer(
            texture=base,
            overlay=overlay,
            overlay_detail=detail,
            width=1024,
            height=1024,
            texture_scale=self._state.config.texture_scale,
            screen_width=float(self._state.config.screen_width),
            screen_height=float(self._state.config.screen_height),
        )
        self._ground.schedule_generate(seed=self._state.rng.randrange(0, 10_000), layers=3)

    def _menu_entries_for_flags(
        self,
        full_version: bool,
        mods_available: bool,
        other_games: bool,
    ) -> list[MenuEntry]:
        rows = self._menu_label_rows(full_version, other_games)
        slot_ys = self._menu_slot_ys(other_games, self._widescreen_y_shift)
        active = self._menu_slot_active(full_version, mods_available, other_games)
        entries: list[MenuEntry] = []
        for slot, (row, y, enabled) in enumerate(
            zip(rows, slot_ys, active, strict=False)
        ):
            if not enabled:
                continue
            entries.append(MenuEntry(slot=slot, row=row, y=y))
        return entries

    @staticmethod
    def _menu_label_rows(_full_version: bool, other_games: bool) -> list[int]:
        # Label atlas rows in ui_itemTexts.jaz:
        #   0 BUY NOW (unused in rewrite), 1 PLAY GAME, 2 OPTIONS, 3 STATISTICS, 4 MODS,
        #   5 OTHER GAMES, 6 QUIT, 7 BACK
        top = 4
        slot4 = 5 if other_games else 7
        return [top, 1, 2, 3, slot4, 6]

    @staticmethod
    def _menu_slot_ys(other_games: bool, y_shift: float) -> list[float]:
        ys = [
            MENU_LABEL_BASE_Y,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP * 2.0,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP * 3.0,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP * 4.0,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP * (5.0 if other_games else 4.0),
        ]
        return [y + y_shift for y in ys]

    @staticmethod
    def _menu_slot_active(
        _full_version: bool,
        mods_available: bool,
        other_games: bool,
    ) -> list[bool]:
        show_top = mods_available
        return [
            show_top,
            True,
            True,
            True,
            other_games,
            True,
        ]

    def _draw_menu_items(self) -> None:
        assets = self._assets
        if assets is None or assets.labels is None or not self._menu_entries:
            return
        item = assets.item
        if item is None:
            return
        label_tex = assets.labels
        item_w = float(item.width)
        item_h = float(item.height)
        fx_detail = bool(self._state.config.data.get("fx_detail_0", 0))
        for idx, entry in enumerate(self._menu_entries):
            pos_x = self._menu_slot_pos_x(entry.slot)
            pos_y = entry.y
            angle_rad, slide_x = self._ui_element_anim(
                index=entry.slot + 2,
                start_ms=self._menu_slot_start_ms(entry.slot),
                end_ms=self._menu_slot_end_ms(entry.slot),
                width=item_w,
            )
            _ = slide_x  # slide is ignored for render_mode==0 (transform) elements
            item_scale, local_y_shift = self._menu_item_scale(entry.slot)
            offset_x = MENU_ITEM_OFFSET_X * item_scale
            offset_y = MENU_ITEM_OFFSET_Y * item_scale - local_y_shift
            dst = rl.Rectangle(
                pos_x,
                pos_y,
                item_w * item_scale,
                item_h * item_scale,
            )
            origin = rl.Vector2(-offset_x, -offset_y)
            rotation_deg = math.degrees(angle_rad)
            if fx_detail:
                self._draw_ui_quad(
                    texture=item,
                    src=rl.Rectangle(0.0, 0.0, item_w, item_h),
                    dst=rl.Rectangle(dst.x + 7.0, dst.y + 7.0, dst.width, dst.height),
                    origin=origin,
                    rotation_deg=rotation_deg,
                    tint=rl.Color(0x44, 0x44, 0x44, 0x44),
                )
            self._draw_ui_quad(
                texture=item,
                src=rl.Rectangle(0.0, 0.0, item_w, item_h),
                dst=dst,
                origin=origin,
                rotation_deg=rotation_deg,
                tint=rl.WHITE,
            )
            counter_value = entry.hover_amount
            if idx == self._selected_index and self._focus_timer_ms > 0:
                counter_value = self._focus_timer_ms
            alpha = self._label_alpha(counter_value)
            tint = rl.Color(255, 255, 255, alpha)
            src = rl.Rectangle(
                0.0,
                float(entry.row) * MENU_LABEL_ROW_HEIGHT,
                MENU_LABEL_WIDTH,
                MENU_LABEL_ROW_HEIGHT,
            )
            label_offset_x = MENU_LABEL_OFFSET_X * item_scale
            label_offset_y = MENU_LABEL_OFFSET_Y * item_scale - local_y_shift
            label_dst = rl.Rectangle(
                pos_x,
                pos_y,
                MENU_LABEL_WIDTH * item_scale,
                MENU_LABEL_HEIGHT * item_scale,
            )
            label_origin = rl.Vector2(-label_offset_x, -label_offset_y)
            self._draw_ui_quad(
                texture=label_tex,
                src=src,
                dst=label_dst,
                origin=label_origin,
                rotation_deg=rotation_deg,
                tint=tint,
            )
            if self._menu_entry_enabled(entry):
                glow_alpha = alpha
                if 0 <= entry.ready_timer_ms < 0x100:
                    glow_alpha = 0xFF - (entry.ready_timer_ms // 2)
                rl.begin_blend_mode(rl.BLEND_ADDITIVE)
                self._draw_ui_quad(
                    texture=label_tex,
                    src=src,
                    dst=label_dst,
                    origin=label_origin,
                    rotation_deg=rotation_deg,
                    tint=rl.Color(255, 255, 255, glow_alpha),
                )
                rl.end_blend_mode()

    def _mods_available(self) -> bool:
        mods_dir = self._state.base_dir / "mods"
        if not mods_dir.exists():
            return False
        return any(mods_dir.glob("*.dll"))

    def _other_games_enabled(self) -> bool:
        # Original game checks a config string via grim_get_config_var(100).
        # Our config-var system is not implemented yet; allow a simple env opt-in.
        return os.getenv("CRIMSON_GRIM_CONFIG_VAR_100", "").strip() != ""

    def _hovered_entry_index(self) -> int | None:
        if not self._menu_entries:
            return None
        mouse = rl.get_mouse_position()
        mouse_x = float(mouse.x)
        mouse_y = float(mouse.y)
        for idx, entry in enumerate(self._menu_entries):
            if not self._menu_entry_enabled(entry):
                continue
            left, top, right, bottom = self._menu_item_bounds(entry)
            if left <= mouse_x <= right and top <= mouse_y <= bottom:
                return idx
        return None

    def _update_ready_timers(self, dt_ms: int) -> None:
        for entry in self._menu_entries:
            if entry.ready_timer_ms < 0x100:
                entry.ready_timer_ms = min(0x100, entry.ready_timer_ms + dt_ms)

    def _update_hover_amounts(self, dt_ms: int) -> None:
        hovered_index = self._hovered_index
        for idx, entry in enumerate(self._menu_entries):
            hover = hovered_index is not None and idx == hovered_index
            if hover:
                entry.hover_amount += dt_ms * 6
            else:
                entry.hover_amount -= dt_ms * 2
            entry.hover_amount = max(0, min(1000, entry.hover_amount))

    @staticmethod
    def _label_alpha(counter_value: int) -> int:
        # ui_element_render: alpha = 100 + floor(counter_value * 155 / 1000)
        return 100 + (counter_value * 155) // 1000

    def _menu_entry_enabled(self, entry: MenuEntry) -> bool:
        return self._timeline_ms >= self._menu_slot_start_ms(entry.slot)

    @staticmethod
    def _menu_widescreen_y_shift(screen_w: float) -> float:
        # ((screen_width / 640.0) * 150.0) - 150.0
        return (screen_w * 0.0015625 * 150.0) - 150.0

    def _menu_item_scale(self, slot: int) -> tuple[float, float]:
        if self._menu_screen_width < 641:
            return 0.9, float(slot) * 11.0
        return 1.0, 0.0

    def _menu_item_bounds(self, entry: MenuEntry) -> tuple[float, float, float, float]:
        # FUN_0044fb50: inset bounds derived from quad0 v0/v2 and pos_x/pos_y.
        assets = self._assets
        if assets is None or assets.item is None:
            return (0.0, 0.0, 0.0, 0.0)
        item_w = float(assets.item.width)
        item_h = float(assets.item.height)
        item_scale, local_y_shift = self._menu_item_scale(entry.slot)
        x0 = MENU_ITEM_OFFSET_X * item_scale
        y0 = MENU_ITEM_OFFSET_Y * item_scale - local_y_shift
        x2 = (MENU_ITEM_OFFSET_X + item_w) * item_scale
        y2 = (MENU_ITEM_OFFSET_Y + item_h) * item_scale - local_y_shift
        w = x2 - x0
        h = y2 - y0
        pos_x = self._menu_slot_pos_x(entry.slot)
        pos_y = entry.y
        left = pos_x + x0 + w * 0.54
        top = pos_y + y0 + h * 0.28
        right = pos_x + x2 - w * 0.05
        bottom = pos_y + y2 - h * 0.10
        return left, top, right, bottom

    @staticmethod
    def _menu_slot_pos_x(slot: int) -> float:
        # ui_menu_layout_init: subtract 20, 40, ... from later menu items
        return MENU_LABEL_BASE_X - float(slot * 20)

    @staticmethod
    def _menu_slot_start_ms(slot: int) -> int:
        # ui_menu_layout_init: start_time_ms is the fully-visible time.
        return (slot + 2) * 100 + 300

    @classmethod
    def _menu_slot_end_ms(cls, slot: int) -> int:
        # ui_menu_layout_init: end_time_ms is the fully-hidden time.
        return (slot + 2) * 100

    @staticmethod
    def _menu_max_timeline_ms(
        full_version: bool, mods_available: bool, other_games: bool
    ) -> int:
        del full_version
        max_ms = 300  # sign element at index 0
        show_top = mods_available
        slot_active = [show_top, True, True, True, other_games, True]
        for slot, active in enumerate(slot_active):
            if not active:
                continue
            max_ms = max(max_ms, (slot + 2) * 100 + 300)
        return max_ms

    def _ui_element_anim(
        self,
        *,
        index: int,
        start_ms: int,
        end_ms: int,
        width: float,
    ) -> tuple[float, float]:
        # Matches ui_element_update: angle lerps pi/2 -> 0 over [end_ms, start_ms].
        # Direction flag (element+0x314) appears to be 0 for main menu elements.
        if start_ms <= end_ms or width <= 0.0:
            return 0.0, 0.0
        t = self._timeline_ms
        if t < end_ms:
            angle = 1.5707964
            offset_x = -abs(width)
        elif t < start_ms:
            elapsed = t - end_ms
            span = float(start_ms - end_ms)
            p = float(elapsed) / span
            angle = 1.5707964 * (1.0 - p)
            offset_x = -((1.0 - p) * abs(width))
        else:
            angle = 0.0
            offset_x = 0.0
        if index == 0:
            angle = -abs(angle)
        return angle, offset_x

    @staticmethod
    def _draw_ui_quad(
        *,
        texture: rl.Texture2D,
        src: rl.Rectangle,
        dst: rl.Rectangle,
        origin: rl.Vector2,
        rotation_deg: float,
        tint: rl.Color,
    ) -> None:
        rl.draw_texture_pro(texture, src, dst, origin, rotation_deg, tint)

    def _draw_menu_sign(self) -> None:
        assets = self._assets
        if assets is None or assets.sign is None:
            return
        screen_w = float(self._state.config.screen_width)
        scale, shift_x = self._sign_layout_scale(int(screen_w))
        pos_x = screen_w + MENU_SIGN_POS_X_PAD
        pos_y = (
            MENU_SIGN_POS_Y
            if screen_w > MENU_SCALE_SMALL_THRESHOLD
            else MENU_SIGN_POS_Y_SMALL
        )
        sign_w = MENU_SIGN_WIDTH * scale
        sign_h = MENU_SIGN_HEIGHT * scale
        offset_x = MENU_SIGN_OFFSET_X * scale + shift_x
        offset_y = MENU_SIGN_OFFSET_Y * scale
        angle_rad, slide_x = self._ui_element_anim(
            index=0,
            start_ms=300,
            end_ms=0,
            width=sign_w,
        )
        _ = slide_x  # slide is ignored for render_mode==0 (transform) elements
        sign = assets.sign
        self._draw_ui_quad(
            texture=sign,
            src=rl.Rectangle(0.0, 0.0, float(sign.width), float(sign.height)),
            dst=rl.Rectangle(pos_x, pos_y, sign_w, sign_h),
            origin=rl.Vector2(-offset_x, -offset_y),
            rotation_deg=math.degrees(angle_rad),
            tint=rl.WHITE,
        )

    @staticmethod
    def _sign_layout_scale(width: int) -> tuple[float, float]:
        if width <= MENU_SCALE_SMALL_THRESHOLD:
            return MENU_SCALE_SMALL, MENU_SCALE_SHIFT
        if MENU_SCALE_LARGE_MIN <= width <= MENU_SCALE_LARGE_MAX:
            return MENU_SCALE_LARGE, MENU_SCALE_SHIFT
        return 1.0, 0.0


class GameLoopView:
    def __init__(self, state: GameState) -> None:
        self._state = state
        self._boot = BootView(state)
        self._demo = DemoView(state)
        self._menu = MenuView(state)
        self._active: View = self._boot
        self._demo_active = False
        self._menu_active = False

    def open(self) -> None:
        self._boot.open()

    def update(self, dt: float) -> None:
        self._active.update(dt)
        if (
            (not self._demo_active)
            and (not self._menu_active)
            and self._state.demo_enabled
            and self._boot.is_theme_started()
        ):
            self._demo.open()
            self._active = self._demo
            self._demo_active = True
            return
        if self._demo_active and not self._menu_active and self._demo.is_finished():
            self._demo.close()
            self._demo_active = False
            self._menu.open()
            self._active = self._menu
            self._menu_active = True
            return
        if (not self._demo_active) and (not self._menu_active) and self._boot.is_theme_started():
            self._menu.open()
            self._active = self._menu
            self._menu_active = True

    def draw(self) -> None:
        self._active.draw()

    def close(self) -> None:
        if self._menu_active:
            self._menu.close()
        if self._demo_active:
            self._demo.close()
        self._boot.close()


def _score_assets_dir(path: Path) -> tuple[int, str]:
    score = 0
    if (path / CRIMSON_PAQ_NAME).is_file():
        score += 10
    if (path / MUSIC_PAQ_NAME).is_file():
        score += 5
    if (path / SFX_PAQ_NAME).is_file():
        score += 1
    return score, path.name


def _auto_detect_game_assets_dir() -> Path | None:
    try:
        repo_root = Path(__file__).resolve().parents[2]
    except Exception:
        repo_root = Path.cwd()

    root = repo_root / "game_bins" / "crimsonland"
    if not root.is_dir():
        return None

    best: Path | None = None
    best_key: tuple[int, str] | None = None
    for candidate in root.iterdir():
        if not candidate.is_dir():
            continue
        key = _score_assets_dir(candidate)
        if key[0] == 0:
            continue
        if best is None or (best_key is not None and key > best_key):
            best = candidate
            best_key = key
    return best


def _copy_missing_assets(assets_dir: Path, console: ConsoleState) -> None:
    assets_dir.mkdir(parents=True, exist_ok=True)

    wanted = (CRIMSON_PAQ_NAME, MUSIC_PAQ_NAME, SFX_PAQ_NAME)
    missing = [name for name in wanted if not (assets_dir / name).is_file()]
    if not missing:
        return

    source_dir = _auto_detect_game_assets_dir()
    if source_dir is None:
        console.log.log(f"assets: missing {', '.join(missing)}")
        console.log.log("assets: no game_bins source found for auto-copy")
        raise FileNotFoundError(
            f"Missing assets: {', '.join(missing)} (no game_bins source found)"
        )

    still_missing: list[str] = []
    for name in missing:
        src = source_dir / name
        dst = assets_dir / name
        if dst.is_file():
            continue
        if not src.is_file():
            console.log.log(f"assets: missing {name} (source missing)")
            still_missing.append(name)
            continue
        try:
            if src.resolve() == dst.resolve():
                continue
        except Exception:
            pass
        try:
            shutil.copy2(src, dst)
        except Exception as exc:
            console.log.log(f"assets: failed to copy {name}: {exc}")
            still_missing.append(name)
            continue
        console.log.log(f"assets: copied {name} from {source_dir}")
    if still_missing:
        raise FileNotFoundError(
            f"Missing assets after copy: {', '.join(still_missing)}"
        )


def _resolve_assets_dir(config: GameConfig) -> Path:
    if config.assets_dir is not None:
        return config.assets_dir
    return config.base_dir


def run_game(config: GameConfig) -> None:
    base_dir = config.base_dir
    base_dir.mkdir(parents=True, exist_ok=True)
    crash_path = base_dir / "crash.log"
    crash_file = crash_path.open("a", encoding="utf-8", buffering=1)
    faulthandler.enable(crash_file)
    crash_file.write(f"\n[{dt.datetime.now().isoformat()}] run_game start\n")
    cfg = ensure_crimson_cfg(base_dir)
    width = cfg.screen_width if config.width is None else config.width
    height = cfg.screen_height if config.height is None else config.height
    rng = random.Random(config.seed)
    console = create_console(base_dir)
    assets_dir = _resolve_assets_dir(config)
    try:
        register_boot_commands(console)
        register_core_cvars(console, width, height)
        console.log.log("crimson: boot start")
        console.log.log(
            f"config: {cfg.screen_width}x{cfg.screen_height} windowed={cfg.windowed_flag}"
        )
        console.log.log(f"assets: {assets_dir}")
        _copy_missing_assets(assets_dir, console)
        if not (assets_dir / CRIMSON_PAQ_NAME).is_file():
            console.log.log(f"assets: missing {CRIMSON_PAQ_NAME} (textures will not load)")
        if not (assets_dir / MUSIC_PAQ_NAME).is_file():
            console.log.log(f"assets: missing {MUSIC_PAQ_NAME}")
        console.log.log(f"commands: {len(console.commands)} registered")
        console.log.log(f"cvars: {len(console.cvars)} registered")
        console.exec_line("exec autoexec.txt")
        console.log.flush()
        state = GameState(
            base_dir=base_dir,
            assets_dir=assets_dir,
            rng=rng,
            config=cfg,
            console=console,
            demo_enabled=_demo_mode_enabled(),
            logos=None,
            texture_cache=None,
            audio=None,
        )
        config_flags = 0
        if cfg.windowed_flag == 0:
            config_flags |= rl.ConfigFlags.FLAG_FULLSCREEN_MODE
        view: View = GameLoopView(state)
        run_view(
            view,
            width=width,
            height=height,
            title="Crimsonland",
            fps=config.fps,
            config_flags=config_flags,
        )
    except Exception:
        crash_file.write("python exception:\n")
        crash_file.write(traceback.format_exc())
        crash_file.write("\n")
        crash_file.flush()
        raise
    finally:
        faulthandler.disable()
        crash_file.close()
