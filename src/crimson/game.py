from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import datetime as dt
import faulthandler
import random
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
        ("game_muzzleFlash", "game/muzzleFlash.jaz"),
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


def _debug_loading_hold_seconds() -> float:
    raw = os.getenv(DEBUG_LOADING_HOLD_ENV, "").strip()
    if not raw:
        return 0.0
    try:
        return max(0.0, float(raw))
    except ValueError:
        return 0.0

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
            play_music(self._state.audio, "crimson_theme")
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
    row: int
    y: float


class MenuView:
    def __init__(self, state: GameState) -> None:
        self._state = state
        self._assets: MenuAssets | None = None
        self._ground: GroundRenderer | None = None
        self._menu_entries: list[MenuEntry] = []
        self._selected_index = 0
        self._full_version = False

    def open(self) -> None:
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
        self._init_ground()

    def close(self) -> None:
        if self._ground is not None and self._ground.render_target is not None:
            rl.unload_render_texture(self._ground.render_target)
        self._ground = None

    def update(self, dt: float) -> None:
        if self._state.audio is not None:
            update_audio(self._state.audio)
        if not self._menu_entries:
            return
        if rl.is_key_pressed(rl.KeyboardKey.KEY_UP):
            self._selected_index = (self._selected_index - 1) % len(self._menu_entries)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_DOWN):
            self._selected_index = (self._selected_index + 1) % len(self._menu_entries)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER):
            entry = self._menu_entries[self._selected_index]
            self._state.console.log.log(
                f"menu select: {self._selected_index} (row {entry.row})"
            )
            self._state.console.log.flush()

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        if self._ground is not None:
            self._ground.draw(0.0, 0.0)
        assets = self._assets
        if assets is None:
            return
        ui_scale, ui_shift = self._menu_layout_scale()
        screen_w = float(self._state.config.screen_width)
        sign = assets.sign
        if sign is not None:
            sign_w = MENU_SIGN_WIDTH
            sign_h = MENU_SIGN_HEIGHT
            sign_pos_y = (
                MENU_SIGN_POS_Y
                if screen_w > MENU_SCALE_SMALL_THRESHOLD
                else MENU_SIGN_POS_Y_SMALL
            )
            sign_x = screen_w + MENU_SIGN_POS_X_PAD + MENU_SIGN_OFFSET_X
            sign_y = sign_pos_y + MENU_SIGN_OFFSET_Y
            src = rl.Rectangle(0.0, 0.0, float(sign.width), float(sign.height))
            dst = rl.Rectangle(sign_x, sign_y, sign_w, sign_h)
            rl.draw_texture_pro(sign, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)
        self._draw_menu_panel(ui_scale, ui_shift)
        self._draw_menu_items(ui_scale, ui_shift)

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
        self._ground.generate(seed=self._state.rng.randrange(0, 10_000))

    def _menu_layout_scale(self) -> tuple[float, float]:
        width = int(self._state.config.screen_width)
        if width <= MENU_SCALE_SMALL_THRESHOLD:
            return MENU_SCALE_SMALL, MENU_SCALE_SHIFT
        if MENU_SCALE_LARGE_MIN <= width <= MENU_SCALE_LARGE_MAX:
            return MENU_SCALE_LARGE, MENU_SCALE_SHIFT
        return 1.0, 0.0

    def _menu_entries_for_flags(
        self,
        full_version: bool,
        mods_available: bool,
        other_games: bool,
    ) -> list[MenuEntry]:
        rows = self._menu_label_rows(full_version, other_games)
        slot_ys = self._menu_slot_ys(other_games)
        active = self._menu_slot_active(full_version, mods_available, other_games)
        entries: list[MenuEntry] = []
        for row, y, enabled in zip(rows, slot_ys, active, strict=False):
            if not enabled:
                continue
            entries.append(MenuEntry(row=row, y=y))
        return entries

    @staticmethod
    def _menu_label_rows(full_version: bool, other_games: bool) -> list[int]:
        rows: list[int] = []
        row = 0
        for slot in range(6):
            if slot == 0 and full_version:
                row = 4
            if not other_games and slot == 4:
                row = 6
            rows.append(row)
            if slot == 0 and full_version:
                row = 0
            row += 1
            if row == 4:
                row += 1
        return rows

    @staticmethod
    def _menu_slot_ys(other_games: bool) -> list[float]:
        ys = [
            MENU_LABEL_BASE_Y,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP * 2.0,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP * 3.0,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP * 4.0,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP * (5.0 if other_games else 4.0),
        ]
        return ys

    @staticmethod
    def _menu_slot_active(
        full_version: bool,
        mods_available: bool,
        other_games: bool,
    ) -> list[bool]:
        show_top = (not full_version) or mods_available
        return [
            show_top,
            True,
            True,
            True,
            other_games,
            True,
        ]

    def _draw_menu_items(self, ui_scale: float, ui_shift: float) -> None:
        assets = self._assets
        if assets is None or assets.labels is None or not self._menu_entries:
            return
        label_tex = assets.labels
        label_w = MENU_LABEL_WIDTH * ui_scale
        label_h = MENU_LABEL_HEIGHT * ui_scale
        for entry in self._menu_entries:
            row_base_y = entry.y
            label_x = MENU_LABEL_BASE_X + MENU_LABEL_OFFSET_X * ui_scale + ui_shift
            label_y = row_base_y + MENU_LABEL_OFFSET_Y * ui_scale + ui_shift
            if assets.item is not None:
                item_x = MENU_LABEL_BASE_X + MENU_ITEM_OFFSET_X * ui_scale + ui_shift
                item_y = row_base_y + MENU_ITEM_OFFSET_Y * ui_scale + ui_shift
                self._draw_menu_item_bg(assets.item, item_x, item_y, ui_scale)
            src = rl.Rectangle(
                0.0,
                float(entry.row) * MENU_LABEL_ROW_HEIGHT,
                float(label_tex.width),
                MENU_LABEL_ROW_HEIGHT,
            )
            dst = rl.Rectangle(label_x, label_y, label_w, label_h)
            rl.draw_texture_pro(label_tex, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

    @staticmethod
    def _draw_menu_item_bg(
        texture: rl.Texture2D,
        x: float,
        y: float,
        ui_scale: float,
    ) -> None:
        bg_w = float(texture.width) * ui_scale
        bg_h = float(texture.height) * ui_scale
        src = rl.Rectangle(0.0, 0.0, float(texture.width), float(texture.height))
        dst = rl.Rectangle(x, y, bg_w, bg_h)
        rl.draw_texture_pro(texture, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

    def _draw_menu_panel(self, ui_scale: float, ui_shift: float) -> None:
        assets = self._assets
        if assets is None or assets.panel is None:
            return
        panel = assets.panel
        panel_w = MENU_PANEL_WIDTH * ui_scale
        panel_h = MENU_PANEL_HEIGHT * ui_scale
        panel_x = MENU_PANEL_BASE_X + MENU_PANEL_OFFSET_X * ui_scale + ui_shift
        panel_y = MENU_PANEL_BASE_Y + MENU_PANEL_OFFSET_Y * ui_scale + ui_shift
        src = rl.Rectangle(0.0, 0.0, float(panel.width), float(panel.height))
        dst = rl.Rectangle(panel_x, panel_y, panel_w, panel_h)
        rl.draw_texture_pro(panel, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

    def _mods_available(self) -> bool:
        mods_dir = self._state.base_dir / "mods"
        if not mods_dir.exists():
            return False
        return any(mods_dir.glob("*.dll"))

    def _other_games_enabled(self) -> bool:
        # Original game checks a config string via grim_get_config_var(100).
        return True


class GameLoopView:
    def __init__(self, state: GameState) -> None:
        self._state = state
        self._boot = BootView(state)
        self._menu = MenuView(state)
        self._active: View = self._boot
        self._menu_active = False

    def open(self) -> None:
        self._boot.open()

    def update(self, dt: float) -> None:
        self._active.update(dt)
        if not self._menu_active and self._boot.is_theme_started():
            self._menu.open()
            self._active = self._menu
            self._menu_active = True

    def draw(self) -> None:
        self._active.draw()

    def close(self) -> None:
        if self._menu_active:
            self._menu.close()
        self._boot.close()


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
    assets_dir = config.assets_dir if config.assets_dir is not None else base_dir
    try:
        register_boot_commands(console)
        register_core_cvars(console, width, height)
        console.log.log("crimson: boot start")
        console.log.log(
            f"config: {cfg.screen_width}x{cfg.screen_height} windowed={cfg.windowed_flag}"
        )
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
