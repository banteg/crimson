from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import datetime as dt
import faulthandler
import math
import random
import shutil
import time
import traceback
import webbrowser
from typing import Protocol

import pyray as rl

from grim.audio import (
    AudioState,
    play_music,
    stop_music,
    update_audio,
    set_music_volume,
    set_sfx_volume,
)
from grim.assets import (
    LogoAssets,
    PaqTextureCache,
    load_paq_entries_from_path,
)
from grim.config import CrimsonConfig, apply_detail_preset, ensure_crimson_cfg
from grim.console import (
    CommandHandler,
    ConsoleState,
    create_console,
    register_boot_commands,
    register_core_cvars,
)
from grim.app import run_view
from grim.terrain_render import GroundRenderer
from grim.view import View, ViewContext
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width
from grim import music

from .demo import DemoView
from .frontend.boot import BootView
from .frontend.assets import _ensure_texture_cache
from .ui.cursor import draw_menu_cursor
from .persistence.save_status import MODE_COUNT_ORDER, GameStatus, ensure_game_status
from .weapons import WEAPON_BY_ID

DEFAULT_BASE_DIR = Path("artifacts") / "runtime"


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
    status: GameStatus
    console: ConsoleState
    demo_enabled: bool
    logos: LogoAssets | None
    texture_cache: PaqTextureCache | None
    audio: AudioState | None
    resource_paq: Path
    session_start: float
    gamma_ramp: float = 1.0
    snd_freq_adjustment_enabled: bool = False
    menu_ground: GroundRenderer | None = None
    menu_sign_locked: bool = False
    pending_quest_level: str | None = None
    quit_requested: bool = False
    screen_fade_alpha: float = 0.0
    screen_fade_ramp: bool = False


def ensure_menu_ground(state: GameState, *, regenerate: bool = False) -> GroundRenderer | None:
    cache = state.texture_cache
    if cache is None:
        return None
    base = cache.texture("ter_q1_base")
    if base is None:
        return None
    overlay = cache.texture("ter_q1_tex1")
    detail = overlay or base
    ground = state.menu_ground
    screen_width = float(state.config.screen_width)
    screen_height = float(state.config.screen_height)
    texture_scale = float(state.config.texture_scale)
    if ground is None:
        ground = GroundRenderer(
            texture=base,
            overlay=overlay,
            overlay_detail=detail,
            width=1024,
            height=1024,
            texture_scale=texture_scale,
            screen_width=screen_width,
            screen_height=screen_height,
        )
        state.menu_ground = ground
        regenerate = True
    else:
        scale_changed = abs(float(ground.texture_scale) - texture_scale) > 1e-6
        ground.texture = base
        ground.overlay = overlay
        ground.overlay_detail = detail
        ground.texture_scale = texture_scale
        ground.screen_width = screen_width
        ground.screen_height = screen_height
        if scale_changed:
            regenerate = True
    if regenerate:
        ground.schedule_generate(seed=state.rng.randrange(0, 10_000), layers=3)
    return ground


SCREEN_FADE_OUT_RATE = 2.0
SCREEN_FADE_IN_RATE = 10.0


def _update_screen_fade(state: GameState, dt: float) -> None:
    if state.screen_fade_ramp:
        state.screen_fade_alpha += float(dt) * SCREEN_FADE_IN_RATE
    else:
        state.screen_fade_alpha -= float(dt) * SCREEN_FADE_OUT_RATE
    if state.screen_fade_alpha < 0.0:
        state.screen_fade_alpha = 0.0
    elif state.screen_fade_alpha > 1.0:
        state.screen_fade_alpha = 1.0


def _draw_screen_fade(state: GameState) -> None:
    alpha = float(state.screen_fade_alpha)
    if alpha <= 0.0:
        return
    shade = int(max(0.0, min(1.0, alpha)) * 255.0)
    rl.draw_rectangle(0, 0, int(rl.get_screen_width()), int(rl.get_screen_height()), rl.Color(0, 0, 0, shade))


DEMO_MODE_ENV = "CRIMSON_IS_DEMO"
CRIMSON_PAQ_NAME = "crimson.paq"
MUSIC_PAQ_NAME = "music.paq"
SFX_PAQ_NAME = "sfx.paq"
AUTOEXEC_NAME = "autoexec.txt"

def _demo_mode_enabled() -> bool:
    raw = os.getenv(DEMO_MODE_ENV, "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _draw_menu_cursor(state: GameState, *, pulse_time: float) -> None:
    cache = _ensure_texture_cache(state)
    particles = cache.get_or_load("particles", "game/particles.jaz").texture
    cursor_tex = cache.get_or_load("ui_cursor", "ui/ui_cursor.jaz").texture

    mouse = rl.get_mouse_position()
    mouse_x = float(mouse.x)
    mouse_y = float(mouse.y)
    draw_menu_cursor(particles, cursor_tex, x=mouse_x, y=mouse_y, pulse_time=float(pulse_time))


MENU_LABEL_WIDTH = 124.0
MENU_LABEL_HEIGHT = 30.0
MENU_LABEL_ROW_HEIGHT = 32.0
MENU_LABEL_ROW_PLAY_GAME = 1
MENU_LABEL_ROW_OPTIONS = 2
MENU_LABEL_ROW_STATISTICS = 3
MENU_LABEL_ROW_MODS = 4
MENU_LABEL_ROW_OTHER_GAMES = 5
MENU_LABEL_ROW_QUIT = 6
MENU_LABEL_ROW_BACK = 7
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

# ui_element_render (0x446c40): shadow pass uses offset (7, 7), tint 0x44444444, and
# blend factors (src=ZERO, dst=ONE_MINUS_SRC_ALPHA).
UI_SHADOW_OFFSET = 7.0
UI_SHADOW_TINT = rl.Color(0x44, 0x44, 0x44, 0x44)

MENU_SIGN_WIDTH = 573.44
MENU_SIGN_HEIGHT = 143.36
MENU_SIGN_OFFSET_X = -577.44
MENU_SIGN_OFFSET_Y = -62.0
MENU_SIGN_POS_Y = 70.0
MENU_SIGN_POS_Y_SMALL = 60.0
MENU_SIGN_POS_X_PAD = 4.0

# TODO: confirm the exact idle threshold from the original demo build.
MENU_DEMO_IDLE_START_MS = 30_000

PANEL_POS_X = -45.0
PANEL_POS_Y = 210.0
PANEL_BACK_POS_X = -55.0
PANEL_BACK_POS_Y = 430.0
PANEL_TIMELINE_START_MS = 300
PANEL_TIMELINE_END_MS = 0


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


@dataclass(slots=True)
class SliderState:
    value: int
    min_value: int
    max_value: int


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
        self._idle_ms = 0
        self._last_mouse_x = 0.0
        self._last_mouse_y = 0.0
        self._cursor_pulse_time = 0.0
        self._widescreen_y_shift = 0.0
        self._menu_screen_width = 0
        self._closing = False
        self._close_action: str | None = None
        self._pending_action: str | None = None

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
        self._idle_ms = 0
        self._cursor_pulse_time = 0.0
        mouse = rl.get_mouse_position()
        self._last_mouse_x = float(mouse.x)
        self._last_mouse_y = float(mouse.y)
        self._closing = False
        self._close_action = None
        self._pending_action = None
        self._timeline_max_ms = self._menu_max_timeline_ms(
            full_version=self._full_version,
            mods_available=self._mods_available(),
            other_games=self._other_games_enabled(),
        )
        self._init_ground()
        if self._state.audio is not None:
            theme = "crimsonquest" if self._state.demo_enabled else "crimson_theme"
            if self._state.audio.music.active_track != theme:
                stop_music(self._state.audio)
            play_music(self._state.audio, theme)

    def close(self) -> None:
        self._ground = None

    def update(self, dt: float) -> None:
        if self._state.audio is not None:
            update_audio(self._state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        self._cursor_pulse_time += min(dt, 0.1) * 1.1
        dt_ms = int(min(dt, 0.1) * 1000.0)
        if self._closing:
            if dt_ms > 0 and self._pending_action is None:
                self._timeline_ms -= dt_ms
                self._focus_timer_ms = max(0, self._focus_timer_ms - dt_ms)
                if self._timeline_ms < 0 and self._close_action is not None:
                    self._pending_action = self._close_action
                    self._close_action = None
            return

        if dt_ms > 0:
            mouse = rl.get_mouse_position()
            mouse_x = float(mouse.x)
            mouse_y = float(mouse.y)
            mouse_moved = (mouse_x != self._last_mouse_x) or (mouse_y != self._last_mouse_y)
            if mouse_moved:
                self._last_mouse_x = mouse_x
                self._last_mouse_y = mouse_y

            any_key = rl.get_key_pressed() != 0
            any_click = (
                rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT)
                or rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_RIGHT)
                or rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_MIDDLE)
            )

            if any_key or any_click or mouse_moved:
                self._idle_ms = 0
            else:
                self._idle_ms += dt_ms

        if dt_ms > 0:
            self._timeline_ms = min(self._timeline_max_ms, self._timeline_ms + dt_ms)
            self._focus_timer_ms = max(0, self._focus_timer_ms - dt_ms)
            if self._timeline_ms >= self._timeline_max_ms:
                self._state.menu_sign_locked = True
        if not self._menu_entries:
            return

        self._hovered_index = self._hovered_entry_index()

        if rl.is_key_pressed(rl.KeyboardKey.KEY_TAB):
            reverse = rl.is_key_down(rl.KeyboardKey.KEY_LEFT_SHIFT) or rl.is_key_down(rl.KeyboardKey.KEY_RIGHT_SHIFT)
            delta = -1 if reverse else 1
            self._selected_index = (self._selected_index + delta) % len(self._menu_entries)
            self._focus_timer_ms = 1000

        activated_index: int | None = None
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER) and 0 <= self._selected_index < len(self._menu_entries):
            entry = self._menu_entries[self._selected_index]
            if self._menu_entry_enabled(entry):
                activated_index = self._selected_index

        if activated_index is None and self._hovered_index is not None:
            if rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT):
                hovered = self._hovered_index
                entry = self._menu_entries[hovered]
                if self._menu_entry_enabled(entry):
                    self._selected_index = hovered
                    self._focus_timer_ms = 1000
                    activated_index = hovered

        if activated_index is not None:
            self._activate_menu_entry(activated_index)
        if (
            (not self._closing)
            and self._pending_action is None
            and self._state.demo_enabled
            and self._timeline_ms >= self._timeline_max_ms
            and self._idle_ms >= MENU_DEMO_IDLE_START_MS
        ):
            self._begin_close_transition("start_demo")
        self._update_ready_timers(dt_ms)
        self._update_hover_amounts(dt_ms)

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        if self._ground is not None:
            self._ground.draw(0.0, 0.0)
        _draw_screen_fade(self._state)
        assets = self._assets
        if assets is None:
            return
        self._draw_menu_items()
        self._draw_menu_sign()
        _draw_menu_cursor(self._state, pulse_time=self._cursor_pulse_time)

    def take_action(self) -> str | None:
        action = self._pending_action
        self._pending_action = None
        return action

    def _activate_menu_entry(self, index: int) -> None:
        if not (0 <= index < len(self._menu_entries)):
            return
        entry = self._menu_entries[index]
        self._state.console.log.log(f"menu select: {index} (row {entry.row})")
        self._state.console.log.flush()
        if entry.row == MENU_LABEL_ROW_QUIT:
            self._begin_quit_transition()
        elif entry.row == MENU_LABEL_ROW_PLAY_GAME:
            self._begin_close_transition("open_play_game")
        elif entry.row == MENU_LABEL_ROW_OPTIONS:
            self._begin_close_transition("open_options")
        elif entry.row == MENU_LABEL_ROW_STATISTICS:
            self._begin_close_transition("open_statistics")
        elif entry.row == MENU_LABEL_ROW_MODS:
            self._begin_close_transition("open_mods")
        elif entry.row == MENU_LABEL_ROW_OTHER_GAMES:
            self._begin_close_transition("open_other_games")

    def _begin_close_transition(self, action: str) -> None:
        if self._closing:
            return
        self._closing = True
        self._close_action = action

    def _begin_quit_transition(self) -> None:
        self._state.menu_sign_locked = False
        self._begin_close_transition("quit_after_demo" if self._state.demo_enabled else "quit_app")

    def _ensure_cache(self) -> PaqTextureCache:
        return _ensure_texture_cache(self._state)

    def _init_ground(self) -> None:
        self._ground = ensure_menu_ground(self._state)

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
        for slot, (row, y, enabled) in enumerate(zip(rows, slot_ys, active, strict=False)):
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
        if other_games:
            return [top, 1, 2, 3, 5, 6]
        # ui_menu_layout_init swaps table idx 6/7 depending on config var 100:
        # when empty, QUIT becomes idx 6 and the idx 7 element is inactive.
        return [top, 1, 2, 3, 6, 7]

    @staticmethod
    def _menu_slot_ys(_other_games: bool, y_shift: float) -> list[float]:
        ys = [
            MENU_LABEL_BASE_Y,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP * 2.0,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP * 3.0,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP * 4.0,
            MENU_LABEL_BASE_Y + MENU_LABEL_STEP * 5.0,
        ]
        return [y + y_shift for y in ys]

    @staticmethod
    def _menu_slot_active(
        _full_version: bool,
        mods_available: bool,
        other_games: bool,
    ) -> list[bool]:
        show_top = mods_available
        if other_games:
            return [show_top, True, True, True, True, True]
        return [show_top, True, True, True, True, False]

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
        # Matches ui_elements_update_and_render reverse table iteration:
        # later entries draw first, earlier entries draw last (on top).
        for idx in range(len(self._menu_entries) - 1, -1, -1):
            entry = self._menu_entries[idx]
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
                self._draw_ui_quad_shadow(
                    texture=item,
                    src=rl.Rectangle(0.0, 0.0, item_w, item_h),
                    dst=rl.Rectangle(dst.x + UI_SHADOW_OFFSET, dst.y + UI_SHADOW_OFFSET, dst.width, dst.height),
                    origin=origin,
                    rotation_deg=rotation_deg,
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
    def _menu_max_timeline_ms(full_version: bool, mods_available: bool, other_games: bool) -> int:
        del full_version
        max_ms = 300  # sign element at index 0
        show_top = mods_available
        slot_active = [show_top, True, True, True, True, other_games]
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

    @staticmethod
    def _draw_ui_quad_shadow(
        *,
        texture: rl.Texture2D,
        src: rl.Rectangle,
        dst: rl.Rectangle,
        origin: rl.Vector2,
        rotation_deg: float,
    ) -> None:
        # NOTE: raylib/rlgl tracks custom blend factors as state; some backends
        # only apply them when switching the blend mode.
        rl.rl_set_blend_factors_separate(
            rl.RL_ZERO,
            rl.RL_ONE_MINUS_SRC_ALPHA,
            rl.RL_ZERO,
            rl.RL_ONE,
            rl.RL_FUNC_ADD,
            rl.RL_FUNC_ADD,
        )
        rl.begin_blend_mode(rl.BLEND_CUSTOM_SEPARATE)
        rl.rl_set_blend_factors_separate(
            rl.RL_ZERO,
            rl.RL_ONE_MINUS_SRC_ALPHA,
            rl.RL_ZERO,
            rl.RL_ONE,
            rl.RL_FUNC_ADD,
            rl.RL_FUNC_ADD,
        )
        rl.draw_texture_pro(texture, src, dst, origin, rotation_deg, UI_SHADOW_TINT)
        rl.end_blend_mode()

    def _draw_menu_sign(self) -> None:
        assets = self._assets
        if assets is None or assets.sign is None:
            return
        screen_w = float(self._state.config.screen_width)
        scale, shift_x = self._sign_layout_scale(int(screen_w))
        pos_x = screen_w + MENU_SIGN_POS_X_PAD
        pos_y = MENU_SIGN_POS_Y if screen_w > MENU_SCALE_SMALL_THRESHOLD else MENU_SIGN_POS_Y_SMALL
        sign_w = MENU_SIGN_WIDTH * scale
        sign_h = MENU_SIGN_HEIGHT * scale
        offset_x = MENU_SIGN_OFFSET_X * scale + shift_x
        offset_y = MENU_SIGN_OFFSET_Y * scale
        rotation_deg = 0.0
        if not self._state.menu_sign_locked:
            angle_rad, slide_x = self._ui_element_anim(
                index=0,
                start_ms=300,
                end_ms=0,
                width=sign_w,
            )
            _ = slide_x  # slide is ignored for render_mode==0 (transform) elements
            rotation_deg = math.degrees(angle_rad)
        sign = assets.sign
        fx_detail = bool(self._state.config.data.get("fx_detail_0", 0))
        if fx_detail:
            self._draw_ui_quad_shadow(
                texture=sign,
                src=rl.Rectangle(0.0, 0.0, float(sign.width), float(sign.height)),
                dst=rl.Rectangle(pos_x + UI_SHADOW_OFFSET, pos_y + UI_SHADOW_OFFSET, sign_w, sign_h),
                origin=rl.Vector2(-offset_x, -offset_y),
                rotation_deg=rotation_deg,
            )
        self._draw_ui_quad(
            texture=sign,
            src=rl.Rectangle(0.0, 0.0, float(sign.width), float(sign.height)),
            dst=rl.Rectangle(pos_x, pos_y, sign_w, sign_h),
            origin=rl.Vector2(-offset_x, -offset_y),
            rotation_deg=rotation_deg,
            tint=rl.WHITE,
        )

    @staticmethod
    def _sign_layout_scale(width: int) -> tuple[float, float]:
        if width <= MENU_SCALE_SMALL_THRESHOLD:
            return MENU_SCALE_SMALL, MENU_SCALE_SHIFT
        if MENU_SCALE_LARGE_MIN <= width <= MENU_SCALE_LARGE_MAX:
            return MENU_SCALE_LARGE, MENU_SCALE_SHIFT
        return 1.0, 0.0


class PanelMenuView:
    def __init__(
        self,
        state: GameState,
        *,
        title: str,
        body: str | None = None,
        panel_pos_x: float = PANEL_POS_X,
        panel_pos_y: float = PANEL_POS_Y,
        back_pos_x: float = PANEL_BACK_POS_X,
        back_pos_y: float = PANEL_BACK_POS_Y,
        back_action: str = "back_to_menu",
    ) -> None:
        self._state = state
        self._title = title
        self._body_lines = (body or "").splitlines()
        self._panel_pos_x = panel_pos_x
        self._panel_pos_y = panel_pos_y
        self._back_pos_x = back_pos_x
        self._back_pos_y = back_pos_y
        self._back_action = back_action
        self._assets: MenuAssets | None = None
        self._ground: GroundRenderer | None = None
        self._entry: MenuEntry | None = None
        self._hovered = False
        self._menu_screen_width = 0
        self._widescreen_y_shift = 0.0
        self._timeline_ms = 0
        self._timeline_max_ms = 0
        self._cursor_pulse_time = 0.0
        self._closing = False
        self._close_action: str | None = None
        self._pending_action: str | None = None

    def open(self) -> None:
        layout_w = float(self._state.config.screen_width)
        self._menu_screen_width = int(layout_w)
        self._widescreen_y_shift = MenuView._menu_widescreen_y_shift(layout_w)
        cache = self._ensure_cache()
        sign = cache.get_or_load("ui_signCrimson", "ui/ui_signCrimson.jaz").texture
        item = cache.get_or_load("ui_menuItem", "ui/ui_menuItem.jaz").texture
        panel = cache.get_or_load("ui_menuPanel", "ui/ui_menuPanel.jaz").texture
        labels = cache.get_or_load("ui_itemTexts", "ui/ui_itemTexts.jaz").texture
        self._assets = MenuAssets(sign=sign, item=item, panel=panel, labels=labels)
        self._entry = MenuEntry(slot=0, row=MENU_LABEL_ROW_BACK, y=self._back_pos_y)
        self._hovered = False
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._cursor_pulse_time = 0.0
        self._closing = False
        self._close_action = None
        self._pending_action = None
        self._init_ground()

    def close(self) -> None:
        self._ground = None

    def update(self, dt: float) -> None:
        if self._state.audio is not None:
            update_audio(self._state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        self._cursor_pulse_time += min(dt, 0.1) * 1.1
        dt_ms = int(min(dt, 0.1) * 1000.0)
        if self._closing:
            if dt_ms > 0 and self._pending_action is None:
                self._timeline_ms -= dt_ms
                if self._timeline_ms < 0 and self._close_action is not None:
                    self._pending_action = self._close_action
                    self._close_action = None
            return

        if dt_ms > 0:
            self._timeline_ms = min(self._timeline_max_ms, self._timeline_ms + dt_ms)
            if self._timeline_ms >= self._timeline_max_ms:
                self._state.menu_sign_locked = True

        entry = self._entry
        if entry is None:
            return

        enabled = self._entry_enabled(entry)
        hovered = enabled and self._hovered_entry(entry)
        self._hovered = hovered

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) and enabled:
            self._begin_close_transition(self._back_action)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER) and enabled:
            self._begin_close_transition(self._back_action)
        if enabled and hovered and rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT):
            self._begin_close_transition(self._back_action)

        if hovered:
            entry.hover_amount += dt_ms * 6
        else:
            entry.hover_amount -= dt_ms * 2
        entry.hover_amount = max(0, min(1000, entry.hover_amount))

        if entry.ready_timer_ms < 0x100:
            entry.ready_timer_ms = min(0x100, entry.ready_timer_ms + dt_ms)

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        if self._ground is not None:
            self._ground.draw(0.0, 0.0)
        _draw_screen_fade(self._state)
        assets = self._assets
        entry = self._entry
        if assets is None or entry is None:
            return
        self._draw_panel()
        self._draw_entry(entry)
        self._draw_sign()
        self._draw_title_text()
        _draw_menu_cursor(self._state, pulse_time=self._cursor_pulse_time)

    def take_action(self) -> str | None:
        action = self._pending_action
        self._pending_action = None
        return action

    def _draw_title_text(self) -> None:
        x = 32
        y = 140
        rl.draw_text(self._title, x, y, 28, rl.Color(235, 235, 235, 255))
        y += 34
        for line in self._body_lines:
            rl.draw_text(line, x, y, 18, rl.Color(190, 190, 200, 255))
            y += 22

    def _begin_close_transition(self, action: str) -> None:
        if self._closing:
            return
        self._closing = True
        self._close_action = action

    def _ensure_cache(self) -> PaqTextureCache:
        return _ensure_texture_cache(self._state)

    def _init_ground(self) -> None:
        self._ground = ensure_menu_ground(self._state)

    def _draw_panel(self) -> None:
        assets = self._assets
        if assets is None or assets.panel is None:
            return
        panel = assets.panel
        panel_w = MENU_PANEL_WIDTH
        panel_h = MENU_PANEL_HEIGHT
        _angle_rad, slide_x = MenuView._ui_element_anim(
            self,
            index=1,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w * self._menu_item_scale(0)[0],
        )
        item_scale, _local_y_shift = self._menu_item_scale(0)
        dst = rl.Rectangle(
            self._panel_pos_x + slide_x,
            self._panel_pos_y + self._widescreen_y_shift,
            panel_w * item_scale,
            panel_h * item_scale,
        )
        origin = rl.Vector2(-(MENU_PANEL_OFFSET_X * item_scale), -(MENU_PANEL_OFFSET_Y * item_scale))
        fx_detail = bool(self._state.config.data.get("fx_detail_0", 0))
        if fx_detail:
            MenuView._draw_ui_quad_shadow(
                texture=panel,
                src=rl.Rectangle(0.0, 0.0, float(panel.width), float(panel.height)),
                dst=rl.Rectangle(dst.x + UI_SHADOW_OFFSET, dst.y + UI_SHADOW_OFFSET, dst.width, dst.height),
                origin=origin,
                rotation_deg=0.0,
            )
        MenuView._draw_ui_quad(
            texture=panel,
            src=rl.Rectangle(0.0, 0.0, float(panel.width), float(panel.height)),
            dst=dst,
            origin=origin,
            rotation_deg=0.0,
            tint=rl.WHITE,
        )

    def _draw_entry(self, entry: MenuEntry) -> None:
        assets = self._assets
        if assets is None or assets.labels is None:
            return
        item = assets.item
        if item is None:
            return
        label_tex = assets.labels
        item_w = float(item.width)
        item_h = float(item.height)
        pos_x = self._back_pos_x
        pos_y = entry.y + self._widescreen_y_shift
        _angle_rad, slide_x = MenuView._ui_element_anim(
            self,
            index=2,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=item_w * self._menu_item_scale(entry.slot)[0],
        )
        pos_x += slide_x
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
        fx_detail = bool(self._state.config.data.get("fx_detail_0", 0))
        if fx_detail:
            MenuView._draw_ui_quad_shadow(
                texture=item,
                src=rl.Rectangle(0.0, 0.0, item_w, item_h),
                dst=rl.Rectangle(dst.x + UI_SHADOW_OFFSET, dst.y + UI_SHADOW_OFFSET, dst.width, dst.height),
                origin=origin,
                rotation_deg=0.0,
            )
        MenuView._draw_ui_quad(
            texture=item,
            src=rl.Rectangle(0.0, 0.0, item_w, item_h),
            dst=dst,
            origin=origin,
            rotation_deg=0.0,
            tint=rl.WHITE,
        )
        alpha = MenuView._label_alpha(entry.hover_amount)
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
        MenuView._draw_ui_quad(
            texture=label_tex,
            src=src,
            dst=label_dst,
            origin=label_origin,
            rotation_deg=0.0,
            tint=tint,
        )
        if self._entry_enabled(entry):
            rl.begin_blend_mode(rl.BLEND_ADDITIVE)
            MenuView._draw_ui_quad(
                texture=label_tex,
                src=src,
                dst=label_dst,
                origin=label_origin,
                rotation_deg=0.0,
                tint=rl.Color(255, 255, 255, alpha),
            )
            rl.end_blend_mode()

    def _draw_sign(self) -> None:
        assets = self._assets
        if assets is None or assets.sign is None:
            return
        screen_w = float(self._state.config.screen_width)
        scale, shift_x = MenuView._sign_layout_scale(int(screen_w))
        pos_x = screen_w + MENU_SIGN_POS_X_PAD
        pos_y = MENU_SIGN_POS_Y if screen_w > MENU_SCALE_SMALL_THRESHOLD else MENU_SIGN_POS_Y_SMALL
        sign_w = MENU_SIGN_WIDTH * scale
        sign_h = MENU_SIGN_HEIGHT * scale
        offset_x = MENU_SIGN_OFFSET_X * scale + shift_x
        offset_y = MENU_SIGN_OFFSET_Y * scale
        # Quest screen is only reachable after the Play Game panel is fully visible,
        # so the sign is already locked in place. Keep it static here.
        rotation_deg = 0.0
        sign = assets.sign
        fx_detail = bool(self._state.config.data.get("fx_detail_0", 0))
        if fx_detail:
            MenuView._draw_ui_quad_shadow(
                texture=sign,
                src=rl.Rectangle(0.0, 0.0, float(sign.width), float(sign.height)),
                dst=rl.Rectangle(pos_x + UI_SHADOW_OFFSET, pos_y + UI_SHADOW_OFFSET, sign_w, sign_h),
                origin=rl.Vector2(-offset_x, -offset_y),
                rotation_deg=rotation_deg,
            )
        MenuView._draw_ui_quad(
            texture=sign,
            src=rl.Rectangle(0.0, 0.0, float(sign.width), float(sign.height)),
            dst=rl.Rectangle(pos_x, pos_y, sign_w, sign_h),
            origin=rl.Vector2(-offset_x, -offset_y),
            rotation_deg=rotation_deg,
            tint=rl.WHITE,
        )

    def _entry_enabled(self, entry: MenuEntry) -> bool:
        return self._timeline_ms >= PANEL_TIMELINE_START_MS

    def _hovered_entry(self, entry: MenuEntry) -> bool:
        left, top, right, bottom = self._menu_item_bounds(entry)
        mouse = rl.get_mouse_position()
        mouse_x = float(mouse.x)
        mouse_y = float(mouse.y)
        return left <= mouse_x <= right and top <= mouse_y <= bottom

    def _menu_item_scale(self, slot: int) -> tuple[float, float]:
        if self._menu_screen_width < 641:
            return 0.9, float(slot) * 11.0
        return 1.0, 0.0

    def _menu_item_bounds(self, entry: MenuEntry) -> tuple[float, float, float, float]:
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
        _angle_rad, slide_x = MenuView._ui_element_anim(
            self,
            index=2,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=item_w * item_scale,
        )
        pos_x = self._back_pos_x + slide_x
        pos_y = entry.y + self._widescreen_y_shift
        left = pos_x + x0 + w * 0.54
        top = pos_y + y0 + h * 0.28
        right = pos_x + x2 - w * 0.05
        bottom = pos_y + y2 - h * 0.10
        return left, top, right, bottom


@dataclass(slots=True)
class _PlayGameModeEntry:
    key: str
    label: str
    tooltip: str
    action: str
    game_mode: int | None = None
    show_count: bool = False


class PlayGameMenuView(PanelMenuView):
    """Play Game mode select panel.

    Layout and gating are based on `sub_44ed80` (crimsonland.exe).
    """

    _PLAYER_COUNT_LABELS = ("1 player", "2 players", "3 players", "4 players")

    def __init__(self, state: GameState) -> None:
        super().__init__(
            state,
            title="Play Game",
            back_pos_y=462.0,
        )
        self._small_font: SmallFontData | None = None
        self._button_sm: rl.Texture2D | None = None
        self._button_md: rl.Texture2D | None = None
        self._drop_on: rl.Texture2D | None = None
        self._drop_off: rl.Texture2D | None = None

        self._player_list_open = False
        self._dirty = False

        # Hover fade timers for tooltips (0..1000ms-ish; original uses ~0.0009 alpha scale).
        self._tooltip_ms: dict[str, int] = {}

    def open(self) -> None:
        super().open()
        cache = self._ensure_cache()
        self._button_sm = cache.get_or_load("ui_buttonSm", "ui/ui_button_64x32.jaz").texture
        self._button_md = cache.get_or_load("ui_buttonMd", "ui/ui_button_128x32.jaz").texture
        self._drop_on = cache.get_or_load("ui_dropOn", "ui/ui_dropDownOn.jaz").texture
        self._drop_off = cache.get_or_load("ui_dropOff", "ui/ui_dropDownOff.jaz").texture
        self._player_list_open = False
        self._dirty = False
        self._tooltip_ms.clear()

    def update(self, dt: float) -> None:
        if self._state.audio is not None:
            update_audio(self._state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        self._cursor_pulse_time += min(dt, 0.1) * 1.1
        dt_ms = int(min(dt, 0.1) * 1000.0)

        # Close transition (matches PanelMenuView).
        if self._closing:
            if dt_ms > 0 and self._pending_action is None:
                self._timeline_ms -= dt_ms
                if self._timeline_ms < 0 and self._close_action is not None:
                    self._pending_action = self._close_action
                    self._close_action = None
            return

        if dt_ms > 0:
            self._timeline_ms = min(self._timeline_max_ms, self._timeline_ms + dt_ms)
            if self._timeline_ms >= self._timeline_max_ms:
                self._state.menu_sign_locked = True

        entry = self._entry
        if entry is None:
            return

        enabled = self._entry_enabled(entry)
        hovered_back = enabled and self._hovered_entry(entry)
        self._hovered = hovered_back

        # ESC always goes back; Enter should not auto-back on this screen.
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) and enabled:
            self._begin_close_transition(self._back_action)
        if enabled and hovered_back and rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT):
            self._begin_close_transition(self._back_action)

        if hovered_back:
            entry.hover_amount += dt_ms * 6
        else:
            entry.hover_amount -= dt_ms * 2
        entry.hover_amount = max(0, min(1000, entry.hover_amount))

        if entry.ready_timer_ms < 0x100:
            entry.ready_timer_ms = min(0x100, entry.ready_timer_ms + dt_ms)

        if not enabled:
            return

        layout = self._content_layout()
        scale = layout["scale"]
        base_x = layout["base_x"]
        base_y = layout["base_y"]
        drop_x = layout["drop_x"]
        drop_y = layout["drop_y"]

        consumed_click = self._update_player_count(drop_x, drop_y, scale)
        if consumed_click:
            return

        # Mode buttons (disabled while the player dropdown is open).
        if self._player_list_open:
            return
        y = base_y
        entries, y_step, y_start, y_end = self._mode_entries()
        y += y_start * scale
        for mode in entries:
            clicked, hovered = self._update_mode_button(mode, base_x, y, scale)
            self._update_tooltip_timer(mode.key, hovered, dt_ms)
            if clicked:
                self._activate_mode(mode)
                return
            y += y_step * scale

        # Decay timers for modes that aren't visible right now.
        visible = {m.key for m in entries}
        for key in list(self._tooltip_ms):
            if key in visible:
                continue
            self._tooltip_ms[key] = max(0, self._tooltip_ms[key] - dt_ms * 2)

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        if self._ground is not None:
            self._ground.draw(0.0, 0.0)
        assets = self._assets
        entry = self._entry
        if assets is None or entry is None:
            return

        self._draw_panel()
        self._draw_entry(entry)
        self._draw_sign()
        self._draw_contents()
        _draw_menu_cursor(self._state, pulse_time=self._cursor_pulse_time)

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

    def _content_layout(self) -> dict[str, float]:
        panel_scale, _local_shift = self._menu_item_scale(0)
        panel_w = MENU_PANEL_WIDTH * panel_scale
        _angle_rad, slide_x = MenuView._ui_element_anim(
            self,
            index=1,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w,
        )
        panel_x = self._panel_pos_x + slide_x
        panel_y = self._panel_pos_y + self._widescreen_y_shift
        origin_x = -(MENU_PANEL_OFFSET_X * panel_scale)
        origin_y = -(MENU_PANEL_OFFSET_Y * panel_scale)
        panel_left = panel_x - origin_x
        panel_top = panel_y - origin_y

        # `sub_44ed80`:
        #   xy = panel_offset_x + panel_x + 330 - 64  (+ animated X offset)
        #   var_1c = panel_offset_y + panel_y + 50
        base_x = panel_left + 266.0 * panel_scale
        base_y = panel_top + 50.0 * panel_scale

        drop_x = base_x + 80.0 * panel_scale
        drop_y = base_y + 1.0 * panel_scale

        return {
            "panel_left": panel_left,
            "panel_top": panel_top,
            "scale": panel_scale,
            "base_x": base_x,
            "base_y": base_y,
            "drop_x": drop_x,
            "drop_y": drop_y,
        }

    def _quests_total_played(self) -> int:
        counts = self._state.status.data.get("quest_play_counts", [])
        if not isinstance(counts, list) or not counts:
            return 0
        # `sub_44ed80` sums 40 ints from game_status_blob+0x104..0x1a4.
        # Our `quest_play_counts` array starts at blob+0xd8, so this is indices 11..50.
        return int(sum(int(v) for v in counts[11:51]))

    def _mode_entries(self) -> tuple[list[_PlayGameModeEntry], float, float, float]:
        config = self._state.config
        status = self._state.status

        player_count = int(config.data.get("player_count", 1))
        quest_unlock = int(status.quest_unlock_index)
        full_version = bool(config.data.get("full_version_flag", 0))

        quests_total = self._quests_total_played()
        rush_total = int(status.mode_play_count("rush"))
        survival_total = int(status.mode_play_count("survival"))
        # Matches the tutorial placement gating in `sub_44ed80` (excludes Typ-o).
        main_total = quests_total + rush_total + survival_total

        # `sub_44ed80` uses tighter spacing when quest_unlock>=40 and player_count==1.
        tight_spacing = not (quest_unlock < 0x28 or player_count > 1)
        y_step = 28.0 if tight_spacing else 32.0
        y_start = 26.0 if tight_spacing else 32.0

        has_typo = tight_spacing and full_version and player_count == 1
        show_tutorial = player_count == 1

        entries: list[_PlayGameModeEntry] = []
        if show_tutorial and main_total <= 0:
            entries.append(
                _PlayGameModeEntry(
                    key="tutorial",
                    label="Tutorial",
                    tooltip="Learn how to play Crimsonland.",
                    action="start_tutorial",
                    game_mode=8,
                )
            )

        entries.extend(
            [
                _PlayGameModeEntry(
                    key="quests",
                    label=" Quests ",
                    tooltip="Unlock new weapons and perks in Quest mode.",
                    action="open_quests",
                    show_count=True,
                ),
                _PlayGameModeEntry(
                    key="rush",
                    label="  Rush  ",
                    tooltip="Face a rush of aliens in Rush mode.",
                    action="start_rush",
                    game_mode=2,
                    show_count=True,
                ),
                _PlayGameModeEntry(
                    key="survival",
                    label="Survival",
                    tooltip="Gain perks and weapons and fight back.",
                    action="start_survival",
                    game_mode=1,
                    show_count=True,
                ),
            ]
        )

        if has_typo:
            entries.append(
                _PlayGameModeEntry(
                    key="typo",
                    label="Typ'o'Shooter",
                    tooltip="Use your typing skills as the weapon to lay\nthem down.",
                    action="start_typo",
                    game_mode=4,
                    show_count=True,
                )
            )

        if show_tutorial and main_total > 0:
            entries.append(
                _PlayGameModeEntry(
                    key="tutorial",
                    label="Tutorial",
                    tooltip="Learn how to play Crimsonland.",
                    action="start_tutorial",
                    game_mode=8,
                )
            )

        # The y after the last row is used as a tooltip anchor in `sub_44ed80`.
        y_end = y_start + y_step * float(len(entries))
        return entries, y_step, y_start, y_end

    def _button_tex_for_label(self, label: str, scale: float) -> rl.Texture2D | None:
        md = self._button_md
        sm = self._button_sm
        if md is None:
            return sm
        if sm is None:
            return md

        # `ui_button_update` picks between button sizes based on rendered label width.
        font = self._ensure_small_font()
        label_w = measure_small_text_width(font, label, 1.0 * scale)
        return sm if label_w < 40.0 * scale else md

    def _mode_button_rect(self, label: str, x: float, y: float, scale: float) -> rl.Rectangle:
        tex = self._button_tex_for_label(label, scale)
        if tex is None:
            return rl.Rectangle(x, y, 145.0 * scale, 32.0 * scale)
        return rl.Rectangle(x, y, float(tex.width) * scale, float(tex.height) * scale)

    def _update_mode_button(self, mode: _PlayGameModeEntry, x: float, y: float, scale: float) -> tuple[bool, bool]:
        rect = self._mode_button_rect(mode.label, x, y, scale)
        mouse = rl.get_mouse_position()
        hovered = rect.x <= mouse.x <= rect.x + rect.width and rect.y <= mouse.y <= rect.y + rect.height
        clicked = hovered and rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT)
        return clicked, hovered

    def _activate_mode(self, mode: _PlayGameModeEntry) -> None:
        if mode.game_mode is not None:
            self._state.config.data["game_mode"] = int(mode.game_mode)
            self._dirty = True
        self._begin_close_transition(mode.action)

    def _update_tooltip_timer(self, key: str, hovered: bool, dt_ms: int) -> None:
        value = int(self._tooltip_ms.get(key, 0))
        if hovered:
            value += dt_ms * 6
        else:
            value -= dt_ms * 2
        self._tooltip_ms[key] = max(0, min(1000, value))

    def _player_count_widget_layout(self, x: float, y: float, scale: float) -> dict[str, float]:
        """Return Play Game player-count dropdown metrics.

        `ui_list_widget_update` (0x43efc0):
          - width = max(label_w) + 0x30
          - header height = 16
          - open height = (count * 16) + 0x18
          - arrow icon = 16x16 at (x + width - 16 - 1, y)
          - selected label at (x + 4, y + 1)
          - list rows start at y + 17, step 16
        """
        font = self._ensure_small_font()
        text_scale = 1.0 * scale
        max_label_w = 0.0
        for label in self._PLAYER_COUNT_LABELS:
            max_label_w = max(max_label_w, measure_small_text_width(font, label, text_scale))
        width = max_label_w + 48.0 * scale
        header_h = 16.0 * scale
        row_h = 16.0 * scale
        full_h = (float(len(self._PLAYER_COUNT_LABELS)) * 16.0 + 24.0) * scale
        arrow = 16.0 * scale
        return {
            "x": x,
            "y": y,
            "w": width,
            "header_h": header_h,
            "row_h": row_h,
            "rows_y0": y + 17.0 * scale,
            "full_h": full_h,
            "arrow_x": x + width - arrow - 1.0 * scale,
            "arrow_y": y,
            "arrow_w": arrow,
            "arrow_h": arrow,
            "text_x": x + 4.0 * scale,
            "text_y": y + 1.0 * scale,
            "text_scale": text_scale,
        }

    def _update_player_count(self, x: float, y: float, scale: float) -> bool:
        config = self._state.config
        layout = self._player_count_widget_layout(x, y, scale)
        w = layout["w"]
        header_h = layout["header_h"]
        row_h = layout["row_h"]
        rows_y0 = layout["rows_y0"]
        full_h = layout["full_h"]

        mouse = rl.get_mouse_position()
        hovered_header = x <= mouse.x <= x + w and y <= mouse.y <= y + header_h
        if hovered_header and rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT):
            self._player_list_open = not self._player_list_open
            return True

        if not self._player_list_open:
            return False

        # Close if we click outside the dropdown + list.
        list_hovered = x <= mouse.x <= x + w and y <= mouse.y <= y + full_h
        if rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT) and not list_hovered:
            self._player_list_open = False
            return True

        for idx, label in enumerate(self._PLAYER_COUNT_LABELS):
            del label
            item_y = rows_y0 + row_h * float(idx)
            item_hovered = x <= mouse.x <= x + w and item_y <= mouse.y <= item_y + row_h
            if item_hovered and rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT):
                config.data["player_count"] = idx + 1
                self._dirty = True
                self._player_list_open = False
                return True
        return False

    def _draw_contents(self) -> None:
        assets = self._assets
        if assets is None:
            return
        labels_tex = assets.labels
        layout = self._content_layout()
        panel_left = layout["panel_left"]
        panel_top = layout["panel_top"]
        base_x = layout["base_x"]
        base_y = layout["base_y"]
        drop_x = layout["drop_x"]
        drop_y = layout["drop_y"]
        scale = layout["scale"]

        font = self._ensure_small_font()
        text_scale = 1.0 * scale
        text_color = rl.Color(255, 255, 255, int(255 * 0.8))

        # Panel title label from ui_itemTexts (same as OptionsMenuView).
        if labels_tex is not None:
            src = rl.Rectangle(
                0.0,
                float(MENU_LABEL_ROW_PLAY_GAME) * MENU_LABEL_ROW_HEIGHT,
                MENU_LABEL_WIDTH,
                MENU_LABEL_ROW_HEIGHT,
            )
            dst = rl.Rectangle(
                panel_left + 212.0 * scale,
                panel_top + 32.0 * scale,
                MENU_LABEL_WIDTH * scale,
                MENU_LABEL_ROW_HEIGHT * scale,
            )
            MenuView._draw_ui_quad(
                texture=labels_tex,
                src=src,
                dst=dst,
                origin=rl.Vector2(0.0, 0.0),
                rotation_deg=0.0,
                tint=rl.WHITE,
            )
        else:
            rl.draw_text(self._title, int(panel_left + 212.0 * scale), int(panel_top + 32.0 * scale), int(24 * scale), rl.WHITE)

        self._draw_player_count(drop_x, drop_y, scale)

        entries, y_step, y_start, y_end = self._mode_entries()
        y = base_y + y_start * scale
        show_counts = rl.is_key_down(rl.KeyboardKey.KEY_F1)

        if show_counts:
            draw_small_text(font, "times played:", base_x + 132.0 * scale, base_y + 16.0 * scale, text_scale, text_color)

        for mode in entries:
            self._draw_mode_button(mode, base_x, y, scale)
            if show_counts and mode.show_count:
                self._draw_mode_count(mode.key, base_x + 158.0 * scale, y + 8.0 * scale, text_scale, text_color)
            y += y_step * scale

        self._draw_tooltips(entries, base_x, base_y, y_end, scale)

    def _draw_player_count(self, x: float, y: float, scale: float) -> None:
        drop_on = self._drop_on
        drop_off = self._drop_off
        font = self._ensure_small_font()
        layout = self._player_count_widget_layout(x, y, scale)
        w = layout["w"]
        header_h = layout["header_h"]
        row_h = layout["row_h"]
        rows_y0 = layout["rows_y0"]
        full_h = layout["full_h"]
        arrow_x = layout["arrow_x"]
        arrow_y = layout["arrow_y"]
        arrow_w = layout["arrow_w"]
        arrow_h = layout["arrow_h"]
        text_x = layout["text_x"]
        text_y = layout["text_y"]
        text_scale = layout["text_scale"]

        # `ui_list_widget_update` draws a single bordered black rect for the widget.
        widget_h = full_h if self._player_list_open else header_h
        rl.draw_rectangle(int(x), int(y), int(w), int(widget_h), rl.BLACK)
        rl.draw_rectangle_lines(int(x), int(y), int(w), int(widget_h), rl.WHITE)

        # Arrow icon (the ui_drop* assets are 16x16 icons, not the background).
        mouse = rl.get_mouse_position()
        hovered_header = x <= mouse.x <= x + w and y <= mouse.y <= y + header_h
        arrow_tex = drop_on if (self._player_list_open or hovered_header) else drop_off
        if arrow_tex is not None:
            rl.draw_texture_pro(
                arrow_tex,
                rl.Rectangle(0.0, 0.0, float(arrow_tex.width), float(arrow_tex.height)),
                rl.Rectangle(arrow_x, arrow_y, arrow_w, arrow_h),
                rl.Vector2(0.0, 0.0),
                0.0,
                rl.WHITE,
            )

        player_count = int(self._state.config.data.get("player_count", 1))
        if player_count < 1:
            player_count = 1
        if player_count > len(self._PLAYER_COUNT_LABELS):
            player_count = len(self._PLAYER_COUNT_LABELS)
        label = self._PLAYER_COUNT_LABELS[player_count - 1]
        header_alpha = 191 if self._player_list_open else 242  # 0x3f400000 / 0x3f733333
        draw_small_text(font, label, text_x, text_y, text_scale, rl.Color(255, 255, 255, header_alpha))

        if not self._player_list_open:
            return

        for idx, item in enumerate(self._PLAYER_COUNT_LABELS):
            item_y = rows_y0 + row_h * float(idx)
            hovered = x <= mouse.x <= x + w and item_y <= mouse.y <= item_y + row_h
            alpha = 179  # 0x3f333333
            if hovered:
                alpha = 242  # 0x3f733333
            if idx == (player_count - 1):
                alpha = max(alpha, 245)  # 0x3f75c28f
            draw_small_text(font, item, text_x, item_y, text_scale, rl.Color(255, 255, 255, alpha))

    def _draw_mode_button(self, mode: _PlayGameModeEntry, x: float, y: float, scale: float) -> None:
        tex = self._button_tex_for_label(mode.label, scale)
        font = self._ensure_small_font()
        rect = self._mode_button_rect(mode.label, x, y, scale)

        mouse = rl.get_mouse_position()
        hovered = rect.x <= mouse.x <= rect.x + rect.width and rect.y <= mouse.y <= rect.y + rect.height
        alpha = 255

        if tex is not None:
            rl.draw_texture_pro(
                tex,
                rl.Rectangle(0.0, 0.0, float(tex.width), float(tex.height)),
                rect,
                rl.Vector2(0.0, 0.0),
                0.0,
                rl.Color(255, 255, 255, alpha),
            )
        else:
            rl.draw_rectangle_lines(int(rect.x), int(rect.y), int(rect.width), int(rect.height), rl.Color(255, 255, 255, alpha))

        label_w = measure_small_text_width(font, mode.label, 1.0 * scale)
        # `ui_button_update` uses x centered (+1) and y = y + 10 (not fully centered).
        text_x = rect.x + (rect.width - label_w) * 0.5 + 1.0 * scale
        text_y = rect.y + 10.0 * scale
        text_alpha = 255 if hovered else 179  # 0x3f800000 / 0x3f333333
        draw_small_text(font, mode.label, text_x, text_y, 1.0 * scale, rl.Color(255, 255, 255, text_alpha))

    def _draw_mode_count(self, key: str, x: float, y: float, scale: float, color: rl.Color) -> None:
        status = self._state.status
        if key == "quests":
            count = self._quests_total_played()
        elif key == "rush":
            count = int(status.mode_play_count("rush"))
        elif key == "survival":
            count = int(status.mode_play_count("survival"))
        elif key == "typo":
            count = int(status.mode_play_count("typo"))
        else:
            return
        draw_small_text(self._ensure_small_font(), f"{count}", x, y, scale, color)

    def _draw_tooltips(self, entries: list[_PlayGameModeEntry], base_x: float, base_y: float, y_end: float, scale: float) -> None:
        # `sub_44ed80` draws these below the mode list based on per-button hover timers.
        font = self._ensure_small_font()
        tooltip_x = base_x - 55.0 * scale
        tooltip_y = base_y + (y_end + 16.0) * scale

        offsets = {
            "quests": (-8.0, 0.0),
            "rush": (32.0, 0.0),
            "survival": (20.0, 0.0),
            "typo": (0.0, -12.0),
            "tutorial": (38.0, 0.0),
        }

        for mode in entries:
            ms = int(self._tooltip_ms.get(mode.key, 0))
            if ms <= 0:
                continue
            alpha_f = min(1.0, float(ms) * 0.0009)
            alpha = int(255 * alpha_f)
            off_x, off_y = offsets.get(mode.key, (0.0, 0.0))
            x = tooltip_x + off_x * scale
            y = tooltip_y + off_y * scale
            for line in mode.tooltip.splitlines():
                draw_small_text(font, line, x, y, 1.0 * scale, rl.Color(255, 255, 255, alpha))
                y += font.cell_size * 1.0 * scale


QUEST_MENU_BASE_X = -5.0
QUEST_MENU_BASE_Y = 185.0

QUEST_TITLE_X_OFFSET = 219.0  # 300 + 64 - 145
QUEST_TITLE_Y_OFFSET = 44.0  # 40 + 4
QUEST_TITLE_W = 64.0
QUEST_TITLE_H = 32.0

QUEST_STAGE_ICON_X_OFFSET = 80.0  # 64 + 16
QUEST_STAGE_ICON_Y_OFFSET = 3.0
QUEST_STAGE_ICON_SIZE = 32.0
QUEST_STAGE_ICON_STEP = 36.0
QUEST_STAGE_ICON_SCALE_UNSELECTED = 0.8

QUEST_LIST_Y_OFFSET = 50.0
QUEST_LIST_ROW_STEP = 20.0
QUEST_LIST_NAME_X_OFFSET = 32.0
QUEST_LIST_HOVER_LEFT_PAD = 10.0
QUEST_LIST_HOVER_RIGHT_PAD = 210.0
QUEST_LIST_HOVER_TOP_PAD = 2.0
QUEST_LIST_HOVER_BOTTOM_PAD = 18.0

QUEST_HARDCORE_UNLOCK_INDEX = 40
QUEST_HARDCORE_CHECKBOX_X_OFFSET = 132.0
QUEST_HARDCORE_CHECKBOX_Y_OFFSET = -12.0
QUEST_HARDCORE_LIST_Y_SHIFT = 10.0

QUEST_BACK_BUTTON_X_OFFSET = 148.0
QUEST_BACK_BUTTON_Y_OFFSET = 212.0


class QuestsMenuView:
    """Quest selection menu.

    Layout and gating are based on `sub_447d40` (crimsonland.exe).

    The classic game treats this as a distinct UI state (transition target `0x0b`),
    entered from the Play Game panel.
    """

    def __init__(self, state: GameState) -> None:
        self._state = state
        self._assets: MenuAssets | None = None
        self._ground: GroundRenderer | None = None
        self._panel_tex: rl.Texture2D | None = None

        self._small_font: SmallFontData | None = None
        self._text_quest: rl.Texture2D | None = None
        self._stage_icons: dict[int, rl.Texture2D | None] = {}
        self._check_on: rl.Texture2D | None = None
        self._check_off: rl.Texture2D | None = None
        self._button_sm: rl.Texture2D | None = None
        self._button_md: rl.Texture2D | None = None

        self._menu_screen_width = 0
        self._widescreen_y_shift = 0.0

        self._stage = 1
        self._action: str | None = None
        self._dirty = False
        self._cursor_pulse_time = 0.0

    def open(self) -> None:
        layout_w = float(self._state.config.screen_width)
        self._menu_screen_width = int(layout_w)
        self._widescreen_y_shift = MenuView._menu_widescreen_y_shift(layout_w)
        cache = _ensure_texture_cache(self._state)

        # Sign and ground match the main menu/panels.
        sign = cache.get_or_load("ui_signCrimson", "ui/ui_signCrimson.jaz").texture
        self._panel_tex = cache.get_or_load("ui_menuPanel", "ui/ui_menuPanel.jaz").texture
        self._assets = MenuAssets(sign=sign, item=None, panel=self._panel_tex, labels=None)
        self._init_ground()

        self._text_quest = cache.get_or_load("ui_textQuest", "ui/ui_textQuest.jaz").texture
        self._stage_icons = {
            1: cache.get_or_load("ui_num1", "ui/ui_num1.jaz").texture,
            2: cache.get_or_load("ui_num2", "ui/ui_num2.jaz").texture,
            3: cache.get_or_load("ui_num3", "ui/ui_num3.jaz").texture,
            4: cache.get_or_load("ui_num4", "ui/ui_num4.jaz").texture,
            5: cache.get_or_load("ui_num5", "ui/ui_num5.jaz").texture,
        }
        self._check_on = cache.get_or_load("ui_checkOn", "ui/ui_checkOn.jaz").texture
        self._check_off = cache.get_or_load("ui_checkOff", "ui/ui_checkOff.jaz").texture
        self._button_sm = cache.get_or_load("ui_buttonSm", "ui/ui_button_64x32.jaz").texture
        self._button_md = cache.get_or_load("ui_buttonMd", "ui/ui_button_128x32.jaz").texture

        self._action = None
        self._dirty = False
        self._stage = max(1, min(5, int(self._stage)))
        self._cursor_pulse_time = 0.0

        # Ensure the quest registry is populated so titles render.
        # (The package import registers all tier builders.)
        try:
            from . import quests as _quests

            _ = _quests
        except Exception:
            pass

    def close(self) -> None:
        if self._dirty:
            try:
                self._state.config.save()
            except Exception:
                pass
            self._dirty = False
        self._ground = None

    def update(self, dt: float) -> None:
        if self._state.audio is not None:
            update_audio(self._state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        self._cursor_pulse_time += min(dt, 0.1) * 1.1

        config = self._state.config

        # The original forcibly clears hardcore in the demo build.
        if not bool(config.data.get("full_version_flag", 0)):
            if int(config.data.get("hardcore_flag", 0) or 0) != 0:
                config.data["hardcore_flag"] = 0
                self._dirty = True

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._action = "open_play_game"
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT):
            self._stage = max(1, self._stage - 1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT):
            self._stage = min(5, self._stage + 1)

        layout = self._layout()

        # Stage icons: hover is tracked, but stage selection requires a click.
        hovered_stage = self._hovered_stage(layout)
        if hovered_stage is not None and rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT):
            self._stage = hovered_stage
            return

        if self._hardcore_checkbox_clicked(layout):
            return

        if self._back_button_clicked(layout):
            self._action = "open_play_game"
            return

        # Quick-select row numbers 1..0 (10).
        row_from_key = self._digit_row_pressed()
        if row_from_key is not None:
            self._try_start_quest(self._stage, row_from_key)
            return

        hovered_row = self._hovered_row(layout)
        if hovered_row is not None and rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT):
            self._try_start_quest(self._stage, hovered_row)
            return

        if hovered_row is not None and rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER):
            self._try_start_quest(self._stage, hovered_row)
            return

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        if self._ground is not None:
            self._ground.draw(0.0, 0.0)

        self._draw_panel()
        self._draw_sign()
        self._draw_contents()
        _draw_menu_cursor(self._state, pulse_time=self._cursor_pulse_time)

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

    def _init_ground(self) -> None:
        self._ground = ensure_menu_ground(self._state)

    def _layout(self) -> dict[str, float]:
        # `sub_447d40` base sums:
        #   x_sum = <ui_element_x> + (-5)
        #   y_sum = <ui_element_y> + 185 (+ widescreen shift via ui_menu_layout_init)
        x_sum = QUEST_MENU_BASE_X
        y_sum = QUEST_MENU_BASE_Y + self._widescreen_y_shift

        title_x = x_sum + QUEST_TITLE_X_OFFSET
        title_y = y_sum + QUEST_TITLE_Y_OFFSET
        icons_x0 = title_x + QUEST_STAGE_ICON_X_OFFSET
        icons_y = title_y + QUEST_STAGE_ICON_Y_OFFSET
        last_icon_x = icons_x0 + QUEST_STAGE_ICON_STEP * 4.0
        list_x = last_icon_x - 208.0 + 16.0
        list_y0 = title_y + QUEST_LIST_Y_OFFSET
        return {
            "title_x": title_x,
            "title_y": title_y,
            "icons_x0": icons_x0,
            "icons_y": icons_y,
            "list_x": list_x,
            "list_y0": list_y0,
        }

    def _hovered_stage(self, layout: dict[str, float]) -> int | None:
        title_y = layout["title_y"]
        x0 = layout["icons_x0"]
        mouse = rl.get_mouse_position()
        for stage in range(1, 6):
            x = x0 + float(stage - 1) * QUEST_STAGE_ICON_STEP
            # Hover bounds are fixed 32x32, anchored at (x, title_y) (not icons_y).
            if (x <= mouse.x <= x + QUEST_STAGE_ICON_SIZE) and (title_y <= mouse.y <= title_y + QUEST_STAGE_ICON_SIZE):
                return stage
        return None

    def _hardcore_checkbox_clicked(self, layout: dict[str, float]) -> bool:
        status = self._state.status
        if int(status.quest_unlock_index) < QUEST_HARDCORE_UNLOCK_INDEX:
            return False
        check_on = self._check_on
        check_off = self._check_off
        if check_on is None or check_off is None:
            return False
        config = self._state.config
        hardcore = bool(int(config.data.get("hardcore_flag", 0) or 0))

        font = self._ensure_small_font()
        text_scale = 1.0
        label = "Hardcore"
        label_w = measure_small_text_width(font, label, text_scale)

        x = layout["list_x"] + QUEST_HARDCORE_CHECKBOX_X_OFFSET
        y = layout["list_y0"] + QUEST_HARDCORE_CHECKBOX_Y_OFFSET
        rect_w = float(check_on.width) + 6.0 + label_w
        rect_h = max(float(check_on.height), font.cell_size * text_scale)

        mouse = rl.get_mouse_position()
        hovered = x <= mouse.x <= x + rect_w and y <= mouse.y <= y + rect_h
        if hovered and rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT):
            config.data["hardcore_flag"] = 0 if hardcore else 1
            self._dirty = True
            if not bool(config.data.get("full_version_flag", 0)):
                config.data["hardcore_flag"] = 0
            return True
        return False

    def _back_button_clicked(self, layout: dict[str, float]) -> bool:
        tex = self._button_sm
        if tex is None:
            tex = self._button_md
        if tex is None:
            return False
        x = layout["list_x"] + QUEST_BACK_BUTTON_X_OFFSET
        y = self._rows_y0(layout) + QUEST_BACK_BUTTON_Y_OFFSET
        w = float(tex.width)
        h = float(tex.height)
        mouse = rl.get_mouse_position()
        hovered = x <= mouse.x <= x + w and y <= mouse.y <= y + h
        return hovered and rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT)

    @staticmethod
    def _digit_row_pressed() -> int | None:
        keys = [
            (rl.KeyboardKey.KEY_ONE, 0),
            (rl.KeyboardKey.KEY_TWO, 1),
            (rl.KeyboardKey.KEY_THREE, 2),
            (rl.KeyboardKey.KEY_FOUR, 3),
            (rl.KeyboardKey.KEY_FIVE, 4),
            (rl.KeyboardKey.KEY_SIX, 5),
            (rl.KeyboardKey.KEY_SEVEN, 6),
            (rl.KeyboardKey.KEY_EIGHT, 7),
            (rl.KeyboardKey.KEY_NINE, 8),
            (rl.KeyboardKey.KEY_ZERO, 9),
        ]
        for key, row in keys:
            if rl.is_key_pressed(key):
                return row
        return None

    def _rows_y0(self, layout: dict[str, float]) -> float:
        # `sub_447d40` adds +10 to the list Y after rendering the Hardcore checkbox.
        status = self._state.status
        y0 = layout["list_y0"]
        if int(status.quest_unlock_index) >= QUEST_HARDCORE_UNLOCK_INDEX:
            y0 += QUEST_HARDCORE_LIST_Y_SHIFT
        return y0

    def _hovered_row(self, layout: dict[str, float]) -> int | None:
        list_x = layout["list_x"]
        y0 = self._rows_y0(layout)
        mouse = rl.get_mouse_position()
        for row in range(10):
            y = y0 + float(row) * QUEST_LIST_ROW_STEP
            left = list_x - QUEST_LIST_HOVER_LEFT_PAD
            top = y - QUEST_LIST_HOVER_TOP_PAD
            right = list_x + QUEST_LIST_HOVER_RIGHT_PAD
            bottom = y + QUEST_LIST_HOVER_BOTTOM_PAD
            if left <= mouse.x <= right and top <= mouse.y <= bottom:
                return row
        return None

    def _quest_unlocked(self, stage: int, row: int) -> bool:
        status = self._state.status
        config = self._state.config
        unlock = int(status.quest_unlock_index)
        if bool(int(config.data.get("hardcore_flag", 0) or 0)):
            unlock = int(status.quest_unlock_index_full)
        global_index = (int(stage) - 1) * 10 + int(row)
        return unlock >= global_index

    def _try_start_quest(self, stage: int, row: int) -> None:
        if not self._quest_unlocked(stage, row):
            return
        level = f"{int(stage)}.{int(row) + 1}"
        self._state.pending_quest_level = level
        self._state.config.data["game_mode"] = 3
        self._dirty = True
        self._action = "start_quest"

    def _quest_title(self, stage: int, row: int) -> str:
        level = f"{int(stage)}.{int(row) + 1}"
        try:
            from .quests import quest_by_level

            quest = quest_by_level(level)
        except Exception:
            quest = None
        if quest is None:
            return "???"
        return quest.title

    @staticmethod
    def _quest_row_colors(*, hardcore: bool) -> tuple[rl.Color, rl.Color]:
        # `sub_447d40` uses different RGB when hardcore is toggled.
        if hardcore:
            # (0.980392, 0.274509, 0.235294, alpha)
            r, g, b = 250, 70, 60
        else:
            # (0.274509, 0.707..., 0.941..., alpha)
            r, g, b = 70, 180, 240
        return (rl.Color(r, g, b, 153), rl.Color(r, g, b, 255))

    def _quest_counts(self, *, stage: int, row: int) -> tuple[int, int] | None:
        # In `sub_447d40`, counts are indexed by (row + stage*10) and split across two
        # arrays at offsets 0xDC (games) and 0x17C (completed) within game.cfg.
        #
        # We only model the stable subset (stages 1..4 -> 40 quests). The stage 5
        # indices overlap unrelated fields in the saved blob in the original build.
        global_index = (int(stage) - 1) * 10 + int(row)
        if not (0 <= global_index < 40):
            return None
        count_index = global_index + 10

        status = self._state.status
        games_idx = 1 + count_index
        completed_idx = 41 + count_index
        try:
            games = int(status.quest_play_count(games_idx))
            completed = int(status.quest_play_count(completed_idx))
        except Exception:
            return None
        return completed, games

    def _draw_contents(self) -> None:
        layout = self._layout()
        title_x = layout["title_x"]
        title_y = layout["title_y"]
        icons_x0 = layout["icons_x0"]
        icons_y = layout["icons_y"]
        list_x = layout["list_x"]

        stage = int(self._stage)
        if stage < 1:
            stage = 1
        if stage > 5:
            stage = 5

        hovered_stage = self._hovered_stage(layout)
        hovered_row = self._hovered_row(layout)
        show_counts = rl.is_key_down(rl.KeyboardKey.KEY_F1)

        # Title texture is tinted by (0.7, 0.7, 0.7, 0.7).
        title_tex = self._text_quest
        if title_tex is not None:
            rl.draw_texture_pro(
                title_tex,
                rl.Rectangle(0.0, 0.0, float(title_tex.width), float(title_tex.height)),
                rl.Rectangle(title_x, title_y, QUEST_TITLE_W, QUEST_TITLE_H),
                rl.Vector2(0.0, 0.0),
                0.0,
                rl.Color(179, 179, 179, 179),
            )

        # Stage icons (1..5).
        hover_tint = rl.Color(255, 255, 255, 204)  # 0.8 alpha
        base_tint = rl.Color(179, 179, 179, 179)  # 0.7 RGBA
        selected_tint = rl.WHITE
        for idx in range(1, 6):
            icon = self._stage_icons.get(idx)
            if icon is None:
                continue
            x = icons_x0 + float(idx - 1) * QUEST_STAGE_ICON_STEP
            local_scale = 1.0 if idx == stage else QUEST_STAGE_ICON_SCALE_UNSELECTED
            size = QUEST_STAGE_ICON_SIZE * local_scale
            tint = base_tint
            if hovered_stage == idx:
                tint = hover_tint
            if idx == stage:
                tint = selected_tint
            rl.draw_texture_pro(
                icon,
                rl.Rectangle(0.0, 0.0, float(icon.width), float(icon.height)),
                rl.Rectangle(x, icons_y, size, size),
                rl.Vector2(0.0, 0.0),
                0.0,
                tint,
            )

        config = self._state.config
        status = self._state.status
        hardcore_flag = bool(int(config.data.get("hardcore_flag", 0) or 0))
        base_color, hover_color = self._quest_row_colors(hardcore=hardcore_flag)

        font = self._ensure_small_font()

        y0 = self._rows_y0(layout)
        # Hardcore checkbox (only drawn once tier5 is reachable in normal mode).
        if int(status.quest_unlock_index) >= QUEST_HARDCORE_UNLOCK_INDEX:
            check_on = self._check_on
            check_off = self._check_off
            if check_on is not None and check_off is not None:
                check_tex = check_on if hardcore_flag else check_off
                x = list_x + QUEST_HARDCORE_CHECKBOX_X_OFFSET
                y = layout["list_y0"] + QUEST_HARDCORE_CHECKBOX_Y_OFFSET
                rl.draw_texture_pro(
                    check_tex,
                    rl.Rectangle(0.0, 0.0, float(check_tex.width), float(check_tex.height)),
                    rl.Rectangle(x, y, float(check_tex.width), float(check_tex.height)),
                    rl.Vector2(0.0, 0.0),
                    0.0,
                    rl.WHITE,
                )
                draw_small_text(font, "Hardcore", x + float(check_tex.width) + 6.0, y + 1.0, 1.0, base_color)

        # Quest list (10 rows).
        for row in range(10):
            y = y0 + float(row) * QUEST_LIST_ROW_STEP
            unlocked = self._quest_unlocked(stage, row)
            color = hover_color if hovered_row == row else base_color

            draw_small_text(font, f"{stage}.{row + 1}", list_x, y, 1.0, color)

            if unlocked:
                title = self._quest_title(stage, row)
            else:
                title = "???"
            draw_small_text(font, title, list_x + QUEST_LIST_NAME_X_OFFSET, y, 1.0, color)

            if show_counts and unlocked:
                counts = self._quest_counts(stage=stage, row=row)
                if counts is not None:
                    completed, games = counts
                    title_w = measure_small_text_width(font, title, 1.0)
                    counts_x = list_x + QUEST_LIST_NAME_X_OFFSET + title_w + 12.0
                    draw_small_text(font, f"({completed}/{games})", counts_x, y, 1.0, color)

        if show_counts:
            # Header is drawn below the list, aligned with the count column.
            header_x = list_x + 96.0
            header_y = y0 + QUEST_LIST_ROW_STEP * 10.0 - 2.0
            draw_small_text(font, "(completed/games)", header_x, header_y, 1.0, base_color)

        # Back button.
        button = self._button_sm or self._button_md
        if button is not None:
            back_x = list_x + QUEST_BACK_BUTTON_X_OFFSET
            back_y = y0 + QUEST_BACK_BUTTON_Y_OFFSET
            back_w = float(button.width)
            back_h = float(button.height)
            mouse = rl.get_mouse_position()
            hovered = back_x <= mouse.x <= back_x + back_w and back_y <= mouse.y <= back_y + back_h
            rl.draw_texture_pro(
                button,
                rl.Rectangle(0.0, 0.0, float(button.width), float(button.height)),
                rl.Rectangle(back_x, back_y, back_w, back_h),
                rl.Vector2(0.0, 0.0),
                0.0,
                rl.WHITE,
            )
            label = "Back"
            label_w = measure_small_text_width(font, label, 1.0)
            text_x = back_x + (back_w - label_w) * 0.5 + 1.0
            text_y = back_y + 10.0
            text_alpha = 255 if hovered else 179
            draw_small_text(font, label, text_x, text_y, 1.0, rl.Color(255, 255, 255, text_alpha))

    def _draw_sign(self) -> None:
        assets = self._assets
        if assets is None or assets.sign is None:
            return
        screen_w = float(self._state.config.screen_width)
        scale, shift_x = MenuView._sign_layout_scale(int(screen_w))
        pos_x = screen_w + MENU_SIGN_POS_X_PAD
        pos_y = MENU_SIGN_POS_Y if screen_w > MENU_SCALE_SMALL_THRESHOLD else MENU_SIGN_POS_Y_SMALL
        sign_w = MENU_SIGN_WIDTH * scale
        sign_h = MENU_SIGN_HEIGHT * scale
        offset_x = MENU_SIGN_OFFSET_X * scale + shift_x
        offset_y = MENU_SIGN_OFFSET_Y * scale
        rotation_deg = 0.0
        if not self._state.menu_sign_locked:
            angle_rad, slide_x = MenuView._ui_element_anim(
                self,
                index=0,
                start_ms=300,
                end_ms=0,
                width=sign_w,
            )
            _ = slide_x
            rotation_deg = math.degrees(angle_rad)
        sign = assets.sign
        fx_detail = bool(self._state.config.data.get("fx_detail_0", 0))
        if fx_detail:
            MenuView._draw_ui_quad_shadow(
                texture=sign,
                src=rl.Rectangle(0.0, 0.0, float(sign.width), float(sign.height)),
                dst=rl.Rectangle(pos_x + UI_SHADOW_OFFSET, pos_y + UI_SHADOW_OFFSET, sign_w, sign_h),
                origin=rl.Vector2(-offset_x, -offset_y),
                rotation_deg=rotation_deg,
            )
        MenuView._draw_ui_quad(
            texture=sign,
            src=rl.Rectangle(0.0, 0.0, float(sign.width), float(sign.height)),
            dst=rl.Rectangle(pos_x, pos_y, sign_w, sign_h),
            origin=rl.Vector2(-offset_x, -offset_y),
            rotation_deg=rotation_deg,
            tint=rl.WHITE,
        )

    def _draw_panel(self) -> None:
        panel = self._panel_tex
        if panel is None:
            return
        panel_scale = 0.9 if self._menu_screen_width < 641 else 1.0
        dst = rl.Rectangle(
            QUEST_MENU_BASE_X,
            QUEST_MENU_BASE_Y + self._widescreen_y_shift,
            MENU_PANEL_WIDTH * panel_scale,
            MENU_PANEL_HEIGHT * panel_scale,
        )
        origin = rl.Vector2(-(MENU_PANEL_OFFSET_X * panel_scale), -(MENU_PANEL_OFFSET_Y * panel_scale))
        fx_detail = bool(self._state.config.data.get("fx_detail_0", 0))
        if fx_detail:
            MenuView._draw_ui_quad_shadow(
                texture=panel,
                src=rl.Rectangle(0.0, 0.0, float(panel.width), float(panel.height)),
                dst=rl.Rectangle(dst.x + UI_SHADOW_OFFSET, dst.y + UI_SHADOW_OFFSET, dst.width, dst.height),
                origin=origin,
                rotation_deg=0.0,
            )
        MenuView._draw_ui_quad(
            texture=panel,
            src=rl.Rectangle(0.0, 0.0, float(panel.width), float(panel.height)),
            dst=dst,
            origin=origin,
            rotation_deg=0.0,
            tint=rl.WHITE,
        )


class QuestStartView(PanelMenuView):
    def __init__(self, state: GameState) -> None:
        super().__init__(
            state,
            title="Quest",
            body="Quest gameplay is not implemented yet.",
            back_action="open_quests",
        )

    def open(self) -> None:
        level = self._state.pending_quest_level or "unknown"
        self._title = f"Quest {level}"
        self._body_lines = [
            f"Selected quest: {level}",
            "",
            "Quest gameplay is not implemented yet.",
        ]
        super().open()


class OptionsMenuView(PanelMenuView):
    _LABELS = (
        "Sound volume:",
        "Music volume:",
        "Graphics detail:",
        "Mouse sensitivity:",
    )

    def __init__(self, state: GameState) -> None:
        super().__init__(state, title="Options")
        self._small_font: SmallFontData | None = None
        self._rect_on: rl.Texture2D | None = None
        self._rect_off: rl.Texture2D | None = None
        self._check_on: rl.Texture2D | None = None
        self._check_off: rl.Texture2D | None = None
        self._button_tex: rl.Texture2D | None = None
        self._slider_sfx = SliderState(10, 0, 10)
        self._slider_music = SliderState(10, 0, 10)
        self._slider_detail = SliderState(5, 1, 5)
        self._slider_mouse = SliderState(10, 1, 10)
        self._ui_info_texts = True
        self._active_slider: str | None = None
        self._dirty = False

    def open(self) -> None:
        super().open()
        cache = self._ensure_cache()
        self._rect_on = cache.get_or_load("ui_rectOn", "ui/ui_rectOn.jaz").texture
        self._rect_off = cache.get_or_load("ui_rectOff", "ui/ui_rectOff.jaz").texture
        self._check_on = cache.get_or_load("ui_checkOn", "ui/ui_checkOn.jaz").texture
        self._check_off = cache.get_or_load("ui_checkOff", "ui/ui_checkOff.jaz").texture
        self._button_tex = cache.get_or_load("ui_button_md", "ui/ui_button_145x32.jaz").texture
        self._active_slider = None
        self._dirty = False
        self._sync_from_config()

    def update(self, dt: float) -> None:
        super().update(dt)
        if self._closing:
            return
        entry = self._entry
        if entry is None or not self._entry_enabled(entry):
            return

        config = self._state.config
        layout = self._content_layout()
        label_x = layout["label_x"]
        base_y = layout["base_y"]
        scale = layout["scale"]
        slider_x = layout["slider_x"]

        rect_on = self._rect_on
        rect_off = self._rect_off
        if rect_on is None or rect_off is None:
            return

        if self._update_slider("sfx", self._slider_sfx, slider_x, base_y + 47.0 * scale, rect_on, rect_off, scale):
            config.data["sfx_volume"] = float(self._slider_sfx.value) * 0.1
            set_sfx_volume(self._state.audio, float(config.data["sfx_volume"]))
            self._dirty = True

        if self._update_slider("music", self._slider_music, slider_x, base_y + 67.0 * scale, rect_on, rect_off, scale):
            config.data["music_volume"] = float(self._slider_music.value) * 0.1
            set_music_volume(self._state.audio, float(config.data["music_volume"]))
            self._dirty = True

        if self._update_slider("detail", self._slider_detail, slider_x, base_y + 87.0 * scale, rect_on, rect_off, scale):
            preset = apply_detail_preset(config, self._slider_detail.value)
            self._slider_detail.value = preset
            self._dirty = True

        if self._update_slider("mouse", self._slider_mouse, slider_x, base_y + 107.0 * scale, rect_on, rect_off, scale):
            sensitivity = float(self._slider_mouse.value) * 0.1
            if sensitivity < 0.1:
                sensitivity = 0.1
            if sensitivity > 1.0:
                sensitivity = 1.0
            config.data["mouse_sensitivity"] = sensitivity
            self._dirty = True

        if self._update_checkbox(label_x, base_y + 135.0 * scale, scale):
            value = 1 if self._ui_info_texts else 0
            config.data["hud_indicators"] = bytes((value, value))
            self._dirty = True

        if self._update_controls_button(label_x - 8.0 * scale, base_y + 155.0 * scale, scale):
            self._begin_close_transition("open_controls")

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        if self._ground is not None:
            self._ground.draw(0.0, 0.0)
        assets = self._assets
        entry = self._entry
        if assets is None or entry is None:
            return
        self._draw_panel()
        self._draw_entry(entry)
        self._draw_sign()
        self._draw_options_contents()
        _draw_menu_cursor(self._state, pulse_time=self._cursor_pulse_time)

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

    def _sync_from_config(self) -> None:
        config = self._state.config
        hud = config.data.get("hud_indicators", b"\x00\x00")
        self._ui_info_texts = bool(hud[0]) if isinstance(hud, (bytes, bytearray)) and hud else False

        sfx_volume = float(config.data.get("sfx_volume", 1.0))
        music_volume = float(config.data.get("music_volume", 1.0))
        detail_preset = int(config.data.get("detail_preset", 5))
        mouse_sensitivity = float(config.data.get("mouse_sensitivity", 1.0))

        self._slider_sfx.value = max(self._slider_sfx.min_value, min(self._slider_sfx.max_value, int(sfx_volume * 10.0)))
        self._slider_music.value = max(
            self._slider_music.min_value, min(self._slider_music.max_value, int(music_volume * 10.0))
        )
        if detail_preset < self._slider_detail.min_value:
            detail_preset = self._slider_detail.min_value
        if detail_preset > self._slider_detail.max_value:
            detail_preset = self._slider_detail.max_value
        self._slider_detail.value = detail_preset
        self._slider_mouse.value = max(
            self._slider_mouse.min_value,
            min(self._slider_mouse.max_value, int(mouse_sensitivity * 10.0 + 0.5)),
        )

    def _content_layout(self) -> dict[str, float]:
        panel_scale, _local_shift = self._menu_item_scale(0)
        panel_w = MENU_PANEL_WIDTH * panel_scale
        _angle_rad, slide_x = MenuView._ui_element_anim(
            self,
            index=1,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w,
        )
        panel_x = self._panel_pos_x + slide_x
        panel_y = self._panel_pos_y + self._widescreen_y_shift
        origin_x = -(MENU_PANEL_OFFSET_X * panel_scale)
        origin_y = -(MENU_PANEL_OFFSET_Y * panel_scale)
        panel_left = panel_x - origin_x
        panel_top = panel_y - origin_y
        base_x = panel_left + 212.0 * panel_scale
        base_y = panel_top + 32.0 * panel_scale
        label_x = base_x + 8.0 * panel_scale
        slider_x = label_x + 130.0 * panel_scale
        return {
            "panel_left": panel_left,
            "panel_top": panel_top,
            "base_x": base_x,
            "base_y": base_y,
            "label_x": label_x,
            "slider_x": slider_x,
            "scale": panel_scale,
        }

    def _update_slider(
        self,
        slider_id: str,
        slider: SliderState,
        x: float,
        y: float,
        rect_on: rl.Texture2D,
        rect_off: rl.Texture2D,
        scale: float,
    ) -> bool:
        rect_w = float(rect_on.width) * scale
        rect_h = float(rect_on.height) * scale
        if rect_w <= 0.0 or rect_h <= 0.0:
            return False
        bar_w = rect_w * float(slider.max_value)
        bar_h = rect_h
        mouse = rl.get_mouse_position()
        hovered = x <= mouse.x <= x + bar_w and y <= mouse.y <= y + bar_h

        changed = False
        if hovered:
            if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT):
                slider.value = max(slider.min_value, slider.value - 1)
                changed = True
            if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT):
                slider.value = min(slider.max_value, slider.value + 1)
                changed = True

        mouse_down = rl.is_mouse_button_down(rl.MOUSE_BUTTON_LEFT)
        if hovered and rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT):
            self._active_slider = slider_id
        if self._active_slider == slider_id and mouse_down:
            relative = float(mouse.x) - x
            idx = int(relative // rect_w) + 1
            if idx < slider.min_value:
                idx = slider.min_value
            if idx > slider.max_value:
                idx = slider.max_value
            if slider.value != idx:
                slider.value = idx
                changed = True
        if self._active_slider == slider_id and not mouse_down:
            self._active_slider = None

        return changed

    def _update_checkbox(self, x: float, y: float, scale: float) -> bool:
        check_on = self._check_on
        check_off = self._check_off
        if check_on is None or check_off is None:
            return False
        font = self._ensure_small_font()
        text_scale = 1.0 * scale
        label = "UI Info texts"
        label_w = measure_small_text_width(font, label, text_scale)
        rect_w = float(check_on.width) * scale + 6.0 * scale + label_w
        rect_h = max(float(check_on.height) * scale, font.cell_size * text_scale)
        mouse = rl.get_mouse_position()
        hovered = x <= mouse.x <= x + rect_w and y <= mouse.y <= y + rect_h
        if hovered and rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT):
            self._ui_info_texts = not self._ui_info_texts
            return True
        return False

    def _update_controls_button(self, x: float, y: float, scale: float) -> bool:
        tex = self._button_tex
        if tex is None:
            return False
        w = float(tex.width) * scale
        h = float(tex.height) * scale
        mouse = rl.get_mouse_position()
        hovered = x <= mouse.x <= x + w and y <= mouse.y <= y + h
        if hovered and rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT):
            return True
        return False

    def _draw_options_contents(self) -> None:
        assets = self._assets
        if assets is None:
            return
        labels_tex = assets.labels
        layout = self._content_layout()
        base_x = layout["base_x"]
        base_y = layout["base_y"]
        label_x = layout["label_x"]
        slider_x = layout["slider_x"]
        scale = layout["scale"]

        font = self._ensure_small_font()
        text_scale = 1.0 * scale
        text_color = rl.Color(255, 255, 255, int(255 * 0.8))

        if labels_tex is not None:
            src = rl.Rectangle(
                0.0,
                float(MENU_LABEL_ROW_OPTIONS) * MENU_LABEL_ROW_HEIGHT,
                MENU_LABEL_WIDTH,
                MENU_LABEL_ROW_HEIGHT,
            )
            dst = rl.Rectangle(
                base_x,
                base_y,
                MENU_LABEL_WIDTH * scale,
                MENU_LABEL_ROW_HEIGHT * scale,
            )
            MenuView._draw_ui_quad(
                texture=labels_tex,
                src=src,
                dst=dst,
                origin=rl.Vector2(0.0, 0.0),
                rotation_deg=0.0,
                tint=rl.WHITE,
            )
        else:
            rl.draw_text(self._title, int(base_x), int(base_y), int(24 * scale), rl.WHITE)

        y_offsets = (47.0, 67.0, 87.0, 107.0)
        for label, offset in zip(self._LABELS, y_offsets, strict=False):
            draw_small_text(font, label, label_x, base_y + offset * scale, text_scale, text_color)

        rect_on = self._rect_on
        rect_off = self._rect_off
        if rect_on is None or rect_off is None:
            return
        rect_w = float(rect_on.width) * scale
        rect_h = float(rect_on.height) * scale

        self._draw_slider(self._slider_sfx, slider_x, base_y + 47.0 * scale, rect_on, rect_off, rect_w, rect_h)
        self._draw_slider(self._slider_music, slider_x, base_y + 67.0 * scale, rect_on, rect_off, rect_w, rect_h)
        self._draw_slider(self._slider_detail, slider_x, base_y + 87.0 * scale, rect_on, rect_off, rect_w, rect_h)
        self._draw_slider(self._slider_mouse, slider_x, base_y + 107.0 * scale, rect_on, rect_off, rect_w, rect_h)

        check_on = self._check_on
        check_off = self._check_off
        if check_on is not None and check_off is not None:
            check_tex = check_on if self._ui_info_texts else check_off
            check_w = float(check_tex.width) * scale
            check_h = float(check_tex.height) * scale
            check_x = label_x
            check_y = base_y + 135.0 * scale
            rl.draw_texture_pro(
                check_tex,
                rl.Rectangle(0.0, 0.0, float(check_tex.width), float(check_tex.height)),
                rl.Rectangle(check_x, check_y, check_w, check_h),
                rl.Vector2(0.0, 0.0),
                0.0,
                rl.WHITE,
            )
            draw_small_text(
                font,
                "UI Info texts",
                check_x + check_w + 6.0 * scale,
                check_y + 1.0 * scale,
                text_scale,
                text_color,
            )

        button = self._button_tex
        if button is not None:
            button_x = label_x - 8.0 * scale
            button_y = base_y + 155.0 * scale
            button_w = float(button.width) * scale
            button_h = float(button.height) * scale
            mouse = rl.get_mouse_position()
            hovered = button_x <= mouse.x <= button_x + button_w and button_y <= mouse.y <= button_y + button_h
            alpha = 255 if hovered else 220
            rl.draw_texture_pro(
                button,
                rl.Rectangle(0.0, 0.0, float(button.width), float(button.height)),
                rl.Rectangle(button_x, button_y, button_w, button_h),
                rl.Vector2(0.0, 0.0),
                0.0,
                rl.Color(255, 255, 255, alpha),
            )
            label = "Controls"
            label_w = measure_small_text_width(font, label, text_scale)
            text_x = button_x + (button_w - label_w) * 0.5
            text_y = button_y + (button_h - font.cell_size * text_scale) * 0.5
            draw_small_text(font, label, text_x, text_y, text_scale, rl.Color(20, 20, 20, 255))

    def _draw_slider(
        self,
        slider: SliderState,
        x: float,
        y: float,
        rect_on: rl.Texture2D,
        rect_off: rl.Texture2D,
        rect_w: float,
        rect_h: float,
    ) -> None:
        for idx in range(slider.max_value):
            tex = rect_on if idx < slider.value else rect_off
            dst = rl.Rectangle(x + float(idx) * rect_w, y, rect_w, rect_h)
            tint = rl.WHITE if idx < slider.value else rl.Color(255, 255, 255, int(255 * 0.5))
            rl.draw_texture_pro(
                tex,
                rl.Rectangle(0.0, 0.0, float(tex.width), float(tex.height)),
                dst,
                rl.Vector2(0.0, 0.0),
                0.0,
                tint,
            )


class StatisticsMenuView(PanelMenuView):
    def __init__(self, state: GameState) -> None:
        super().__init__(state, title="Statistics")
        self._small_font: SmallFontData | None = None
        self._stats_lines: list[str] = []

    def open(self) -> None:
        super().open()
        self._stats_lines = self._build_stats_lines()

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        if self._ground is not None:
            self._ground.draw(0.0, 0.0)
        assets = self._assets
        entry = self._entry
        if assets is None or entry is None:
            return
        self._draw_panel()
        self._draw_entry(entry)
        self._draw_sign()
        self._draw_stats_contents()
        _draw_menu_cursor(self._state, pulse_time=self._cursor_pulse_time)

    def _ensure_small_font(self) -> SmallFontData:
        if self._small_font is not None:
            return self._small_font
        missing_assets: list[str] = []
        self._small_font = load_small_font(self._state.assets_dir, missing_assets)
        return self._small_font

    def _content_layout(self) -> dict[str, float]:
        panel_scale, _local_shift = self._menu_item_scale(0)
        panel_w = MENU_PANEL_WIDTH * panel_scale
        _angle_rad, slide_x = MenuView._ui_element_anim(
            self,
            index=1,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w,
        )
        panel_x = self._panel_pos_x + slide_x
        panel_y = self._panel_pos_y + self._widescreen_y_shift
        origin_x = -(MENU_PANEL_OFFSET_X * panel_scale)
        origin_y = -(MENU_PANEL_OFFSET_Y * panel_scale)
        panel_left = panel_x - origin_x
        panel_top = panel_y - origin_y
        base_x = panel_left + 212.0 * panel_scale
        base_y = panel_top + 32.0 * panel_scale
        label_x = base_x + 8.0 * panel_scale
        return {
            "panel_left": panel_left,
            "panel_top": panel_top,
            "base_x": base_x,
            "base_y": base_y,
            "label_x": label_x,
            "scale": panel_scale,
        }

    def _build_stats_lines(self) -> list[str]:
        status = self._state.status
        mode_counts = {name: status.mode_play_count(name) for name, _offset in MODE_COUNT_ORDER}
        quest_counts = status.data.get("quest_play_counts", [])
        if isinstance(quest_counts, list):
            quest_total = int(sum(int(v) for v in quest_counts[:40]))
        else:
            quest_total = 0

        checksum_text = "unknown"
        try:
            from .persistence.save_status import load_status

            blob = load_status(status.path)
            ok = "ok" if blob.checksum_valid else "BAD"
            checksum_text = f"0x{blob.checksum:08x} ({ok})"
        except Exception as exc:
            checksum_text = f"error: {type(exc).__name__}"

        lines = [
            f"Quest unlock: {status.quest_unlock_index} (full {status.quest_unlock_index_full})",
            f"Quest plays (1-40): {quest_total}",
            f"Mode plays: surv {mode_counts['survival']}  rush {mode_counts['rush']}",
            f"            typo {mode_counts['typo']}  other {mode_counts['other']}",
            f"Sequence id: {status.game_sequence_id}",
            f"Checksum: {checksum_text}",
        ]

        usage = status.data.get("weapon_usage_counts", [])
        top_weapons: list[tuple[int, int]] = []
        if isinstance(usage, list):
            for idx, count in enumerate(usage):
                count = int(count)
                if count > 0:
                    top_weapons.append((idx, count))
        top_weapons.sort(key=lambda item: (-item[1], item[0]))
        top_weapons = top_weapons[:4]

        if top_weapons:
            lines.append("Top weapons:")
            for idx, count in top_weapons:
                weapon = WEAPON_BY_ID.get(idx)
                name = weapon.name if weapon is not None and weapon.name else f"weapon_{idx}"
                lines.append(f"  {name}: {count}")
        else:
            lines.append("Top weapons: none")

        return lines

    def _draw_stats_contents(self) -> None:
        assets = self._assets
        if assets is None:
            return
        labels_tex = assets.labels
        layout = self._content_layout()
        base_x = layout["base_x"]
        base_y = layout["base_y"]
        label_x = layout["label_x"]
        scale = layout["scale"]

        font = self._ensure_small_font()
        text_scale = 1.0 * scale
        text_color = rl.Color(255, 255, 255, int(255 * 0.8))

        if labels_tex is not None:
            src = rl.Rectangle(
                0.0,
                float(MENU_LABEL_ROW_STATISTICS) * MENU_LABEL_ROW_HEIGHT,
                MENU_LABEL_WIDTH,
                MENU_LABEL_ROW_HEIGHT,
            )
            dst = rl.Rectangle(
                base_x,
                base_y,
                MENU_LABEL_WIDTH * scale,
                MENU_LABEL_ROW_HEIGHT * scale,
            )
            MenuView._draw_ui_quad(
                texture=labels_tex,
                src=src,
                dst=dst,
                origin=rl.Vector2(0.0, 0.0),
                rotation_deg=0.0,
                tint=rl.WHITE,
            )
        else:
            rl.draw_text(self._title, int(base_x), int(base_y), int(24 * scale), rl.WHITE)

        line_y = base_y + 44.0 * scale
        line_step = (font.cell_size + 4.0) * scale
        for line in self._stats_lines:
            draw_small_text(font, line, label_x, line_y, text_scale, text_color)
            line_y += line_step


class FrontView(Protocol):
    def open(self) -> None: ...

    def close(self) -> None: ...

    def update(self, dt: float) -> None: ...

    def draw(self) -> None: ...

    def take_action(self) -> str | None: ...


class SurvivalGameView:
    """Gameplay view wrapper that adapts SurvivalMode into `crimson game`."""

    def __init__(self, state: GameState) -> None:
        from .modes.survival_mode import SurvivalMode

        self._state = state
        self._mode = SurvivalMode(
            ViewContext(assets_dir=state.assets_dir),
            texture_cache=state.texture_cache,
            config=state.config,
            audio=state.audio,
            audio_rng=state.rng,
        )
        self._action: str | None = None

    def open(self) -> None:
        self._action = None
        self._state.screen_fade_ramp = False
        if self._state.audio is not None:
            # Original game: entering gameplay cuts the menu theme; in-game tunes
            # start later on the first creature hit.
            stop_music(self._state.audio)
        self._mode.bind_audio(self._state.audio, self._state.rng)
        self._mode.bind_screen_fade(self._state)
        self._mode.open()

    def close(self) -> None:
        if self._state.audio is not None:
            stop_music(self._state.audio)
        self._mode.close()

    def update(self, dt: float) -> None:
        self._mode.update(dt)
        if getattr(self._mode, "close_requested", False):
            self._action = "back_to_menu"
            self._mode.close_requested = False

    def draw(self) -> None:
        self._mode.draw()

    def take_action(self) -> str | None:
        action = self._action
        self._action = None
        return action


class GameLoopView:
    def __init__(self, state: GameState) -> None:
        self._state = state
        self._boot = BootView(state)
        self._demo = DemoView(state)
        self._menu = MenuView(state)
        self._front_views: dict[str, FrontView] = {
            "open_play_game": PlayGameMenuView(state),
            "open_quests": QuestsMenuView(state),
            "start_quest": QuestStartView(state),
            "start_survival": SurvivalGameView(state),
            "start_rush": PanelMenuView(
                state,
                title="Rush",
                body="Rush mode is not implemented yet.",
                back_action="open_play_game",
            ),
            "start_typo": PanelMenuView(
                state,
                title="Typ-o-Shooter",
                body="Typ-o-Shooter mode is not implemented yet.",
                back_action="open_play_game",
            ),
            "start_tutorial": PanelMenuView(
                state,
                title="Tutorial",
                body="Tutorial mode is not implemented yet.",
                back_action="open_play_game",
            ),
            "open_options": OptionsMenuView(state),
            "open_controls": PanelMenuView(
                state,
                title="Controls",
                body="Controls UI is not implemented yet.",
                back_action="open_options",
            ),
            "open_statistics": StatisticsMenuView(state),
            "open_mods": PanelMenuView(
                state,
                title="Mods",
                body="Mod loader is not implemented yet.",
            ),
            "open_other_games": PanelMenuView(
                state,
                title="Other games",
                body="This menu is out of scope for the rewrite.",
            ),
        }
        self._front_active: FrontView | None = None
        self._active: View = self._boot
        self._demo_active = False
        self._menu_active = False
        self._quit_after_demo = False
        self._screenshot_requested = False

    def open(self) -> None:
        rl.hide_cursor()
        self._boot.open()

    def should_close(self) -> bool:
        return self._state.quit_requested

    def update(self, dt: float) -> None:
        console = self._state.console
        console.handle_hotkey()
        console.update(dt)
        _update_screen_fade(self._state, dt)
        if (not console.open_flag) and rl.is_key_pressed(rl.KeyboardKey.KEY_P):
            self._screenshot_requested = True
        if console.open_flag:
            if console.quit_requested:
                self._state.quit_requested = True
                console.quit_requested = False
            return
        self._active.update(dt)
        if self._front_active is not None:
            action = self._front_active.take_action()
            if action == "back_to_menu":
                self._front_active.close()
                self._front_active = None
                self._menu.open()
                self._active = self._menu
                self._menu_active = True
                return
            if action in {"start_survival", "start_rush", "start_typo"}:
                # Temporary: bump the counter on mode start so the Play Game overlay (F1)
                # and Statistics screen reflect activity.
                mode_name = {
                    "start_survival": "survival",
                    "start_rush": "rush",
                    "start_typo": "typo",
                }.get(action)
                if mode_name is not None:
                    self._state.status.increment_mode_play_count(mode_name)
            if action is not None:
                view = self._front_views.get(action)
                if view is not None:
                    self._front_active.close()
                    view.open()
                    self._front_active = view
                    self._active = view
                    return
        if self._menu_active:
            action = self._menu.take_action()
            if action == "quit_app":
                self._state.quit_requested = True
                return
            if action == "start_demo":
                self._menu.close()
                self._menu_active = False
                self._demo.open()
                self._active = self._demo
                self._demo_active = True
                return
            if action == "quit_after_demo":
                self._menu.close()
                self._menu_active = False
                self._quit_after_demo = True
                self._demo.open()
                self._active = self._demo
                self._demo_active = True
                return
            if action is not None:
                view = self._front_views.get(action)
                if view is not None:
                    self._menu.close()
                    self._menu_active = False
                    view.open()
                    self._front_active = view
                    self._active = view
                    return
        if (
            (not self._demo_active)
            and (not self._menu_active)
            and self._front_active is None
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
            if self._quit_after_demo:
                self._quit_after_demo = False
                self._state.quit_requested = True
                return
            ensure_menu_ground(self._state, regenerate=True)
            self._menu.open()
            self._active = self._menu
            self._menu_active = True
            return
        if (not self._demo_active) and (not self._menu_active) and self._front_active is None and self._boot.is_theme_started():
            self._menu.open()
            self._active = self._menu
            self._menu_active = True
        if console.quit_requested:
            self._state.quit_requested = True
            console.quit_requested = False

    def consume_screenshot_request(self) -> bool:
        requested = self._screenshot_requested
        self._screenshot_requested = False
        return requested

    def draw(self) -> None:
        self._active.draw()
        self._state.console.draw()

    def close(self) -> None:
        if self._menu_active:
            self._menu.close()
        if self._front_active is not None:
            self._front_active.close()
        if self._demo_active:
            self._demo.close()
        if self._state.menu_ground is not None and self._state.menu_ground.render_target is not None:
            rl.unload_render_texture(self._state.menu_ground.render_target)
            self._state.menu_ground.render_target = None
        self._boot.close()
        self._state.console.close()
        rl.show_cursor()


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
        raise FileNotFoundError(f"Missing assets: {', '.join(missing)} (no game_bins source found)")

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
        raise FileNotFoundError(f"Missing assets after copy: {', '.join(still_missing)}")


def _ensure_autoexec_file(base_dir: Path, source_dir: Path | None, console: ConsoleState) -> None:
    dst = base_dir / AUTOEXEC_NAME
    if dst.is_file():
        return
    if source_dir is None:
        return
    src = source_dir / AUTOEXEC_NAME
    if not src.is_file():
        return
    try:
        shutil.copy2(src, dst)
    except Exception as exc:
        console.log.log(f"assets: failed to copy {AUTOEXEC_NAME}: {exc}")


def _parse_float_arg(value: str) -> float:
    try:
        return float(value)
    except ValueError:
        return 0.0


def _cvar_float(console: ConsoleState, name: str, default: float = 0.0) -> float:
    cvar = console.cvars.get(name)
    if cvar is None:
        return default
    return float(cvar.value_f)


def _resolve_resource_paq_path(state: GameState, raw: str) -> Path | None:
    candidate = Path(raw)
    if candidate.is_file():
        return candidate
    if not candidate.is_absolute():
        for base in (state.assets_dir, state.base_dir):
            path = base / candidate
            if path.is_file():
                return path
    return None


def _boot_command_handlers(state: GameState) -> dict[str, CommandHandler]:
    console = state.console

    def cmd_set_gamma_ramp(args: list[str]) -> None:
        if len(args) != 1:
            console.log.log("setGammaRamp <scalar > 0>")
            console.log.log(
                "Command adjusts gamma ramp linearly by multiplying with given scalar"
            )
            return
        value = _parse_float_arg(args[0])
        state.gamma_ramp = value
        console.log.log(f"Gamma ramp regenerated and multiplied with {value:.6f}")

    def cmd_snd_add_game_tune(args: list[str]) -> None:
        if len(args) != 1:
            console.log.log("snd_addGameTune <tuneName.ogg>")
            return
        audio = state.audio
        if audio is None:
            return
        rel_path = f"music/{args[0]}"
        result = music.load_music_track(audio.music, state.assets_dir, rel_path, console=console)
        if result is None:
            return
        track_key, _track_id = result
        music.queue_track(audio.music, track_key)

    def cmd_generate_terrain(_args: list[str]) -> None:
        ensure_menu_ground(state, regenerate=True)

    def cmd_tell_time_survived(_args: list[str]) -> None:
        seconds = int(max(0.0, time.monotonic() - state.session_start))
        console.log.log(f"Survived: {seconds} seconds.")

    def cmd_set_resource_paq(args: list[str]) -> None:
        if len(args) != 1:
            console.log.log("setresourcepaq <resourcepaq>")
            return
        raw = args[0]
        resolved = _resolve_resource_paq_path(state, raw)
        if resolved is None:
            console.log.log(f"File '{raw}' not found.")
            return
        entries = load_paq_entries_from_path(resolved)
        state.resource_paq = resolved
        if state.texture_cache is None:
            state.texture_cache = PaqTextureCache(entries=entries, textures={})
        else:
            state.texture_cache.entries = entries
        console.log.log(f"Set resource paq to '{raw}'")

    def cmd_load_texture(args: list[str]) -> None:
        if len(args) != 1:
            console.log.log("loadtexture <texturefileid>")
            return
        name = args[0]
        rel_path = name.replace("\\", "/")
        try:
            cache = _ensure_texture_cache(state)
        except FileNotFoundError:
            console.log.log(f"...loading texture '{name}' failed")
            return
        existing = cache.get(name)
        if existing is not None and existing.texture is not None:
            return
        try:
            asset = cache.get_or_load(name, rel_path)
        except FileNotFoundError:
            console.log.log(f"...loading texture '{name}' failed")
            return
        if asset.texture is None:
            console.log.log(f"...loading texture '{name}' failed")
            return
        if _cvar_float(console, "cv_silentloads", 0.0) == 0.0:
            console.log.log(f"...loading texture '{name}' ok")

    def cmd_open_url(args: list[str]) -> None:
        if len(args) != 1:
            console.log.log("openurl <url>")
            return
        url = args[0]
        ok = False
        try:
            ok = webbrowser.open(url)
        except Exception:
            ok = False
        if ok:
            console.log.log(f"Launching web browser ({url})..")
        else:
            console.log.log("Failed to launch web browser.")

    def cmd_snd_freq_adjustment(_args: list[str]) -> None:
        state.snd_freq_adjustment_enabled = not state.snd_freq_adjustment_enabled
        if state.snd_freq_adjustment_enabled:
            console.log.log("Sound frequency adjustment is now enabled.")
        else:
            console.log.log("Sound frequency adjustment is now disabled.")

    return {
        "setGammaRamp": cmd_set_gamma_ramp,
        "snd_addGameTune": cmd_snd_add_game_tune,
        "generateterrain": cmd_generate_terrain,
        "telltimesurvived": cmd_tell_time_survived,
        "setresourcepaq": cmd_set_resource_paq,
        "loadtexture": cmd_load_texture,
        "openurl": cmd_open_url,
        "sndfreqadjustment": cmd_snd_freq_adjustment,
    }


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
    assets_dir = _resolve_assets_dir(config)
    console = create_console(base_dir, assets_dir=assets_dir)
    source_assets_dir = _auto_detect_game_assets_dir()
    if source_assets_dir is not None:
        console.add_script_dir(source_assets_dir)
    status = ensure_game_status(base_dir)
    state: GameState | None = None
    try:
        state = GameState(
            base_dir=base_dir,
            assets_dir=assets_dir,
            rng=rng,
            config=cfg,
            status=status,
            console=console,
            demo_enabled=_demo_mode_enabled(),
            logos=None,
            texture_cache=None,
            audio=None,
            resource_paq=assets_dir / CRIMSON_PAQ_NAME,
            session_start=time.monotonic(),
        )
        register_boot_commands(console, _boot_command_handlers(state))
        register_core_cvars(console, width, height)
        console.log.log("crimson: boot start")
        console.log.log(f"config: {cfg.screen_width}x{cfg.screen_height} windowed={cfg.windowed_flag}")
        console.log.log(f"status: {status.path.name} loaded")
        console.log.log(f"assets: {assets_dir}")
        _copy_missing_assets(assets_dir, console)
        _ensure_autoexec_file(base_dir, source_assets_dir, console)
        if not (assets_dir / CRIMSON_PAQ_NAME).is_file():
            console.log.log(f"assets: missing {CRIMSON_PAQ_NAME} (textures will not load)")
        if not (assets_dir / MUSIC_PAQ_NAME).is_file():
            console.log.log(f"assets: missing {MUSIC_PAQ_NAME}")
        console.log.log(f"commands: {len(console.commands)} registered")
        console.log.log(f"cvars: {len(console.cvars)} registered")
        console.exec_line("exec autoexec.txt")
        console.log.flush()
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
        if state is not None:
            state.status.save_if_dirty()
    except Exception:
        crash_file.write("python exception:\n")
        crash_file.write(traceback.format_exc())
        crash_file.write("\n")
        crash_file.flush()
        raise
    finally:
        faulthandler.disable()
        crash_file.close()
