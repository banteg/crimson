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
)
from grim.assets import (
    LogoAssets,
    PaqTextureCache,
    load_paq_entries_from_path,
)
from grim.config import CrimsonConfig, ensure_crimson_cfg
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

from .debug import debug_enabled
from grim import music

from .demo import DemoView
from .frontend.boot import BootView
from .frontend.assets import MenuAssets, _ensure_texture_cache, load_menu_assets
from .frontend.menu import (
    MENU_PANEL_HEIGHT,
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
    UI_SHADOW_TINT,
    MenuView,
    _draw_menu_cursor,
    ensure_menu_ground,
)
from .frontend.panels.base import PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS, PanelMenuView
from .frontend.panels.options import OptionsMenuView
from .frontend.panels.play_game import PlayGameMenuView
from .frontend.panels.stats import StatisticsMenuView
from .frontend.transitions import _draw_screen_fade, _update_screen_fade
from .persistence.save_status import GameStatus, ensure_game_status

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


DEMO_MODE_ENV = "CRIMSON_IS_DEMO"
CRIMSON_PAQ_NAME = "crimson.paq"
MUSIC_PAQ_NAME = "music.paq"
SFX_PAQ_NAME = "sfx.paq"
AUTOEXEC_NAME = "autoexec.txt"

def _demo_mode_enabled() -> bool:
    raw = os.getenv(DEMO_MODE_ENV, "").strip().lower()
    return raw in {"1", "true", "yes", "on"}

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
        self._assets = load_menu_assets(self._state)
        self._panel_tex = self._assets.panel if self._assets is not None else None
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
        if self._state.demo_enabled:
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
            if self._state.demo_enabled:
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
        show_counts = debug_enabled() and rl.is_key_down(rl.KeyboardKey.KEY_F1)

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


class RushGameView:
    """Gameplay view wrapper that adapts RushMode into `crimson game`."""

    def __init__(self, state: GameState) -> None:
        from .modes.rush_mode import RushMode

        self._state = state
        self._mode = RushMode(
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


class QuestGameView:
    """Gameplay view wrapper that adapts QuestMode into `crimson game`."""

    def __init__(self, state: GameState) -> None:
        from .modes.quest_mode import QuestMode

        self._state = state
        self._mode = QuestMode(
            ViewContext(assets_dir=state.assets_dir),
            texture_cache=state.texture_cache,
            config=state.config,
            audio=state.audio,
            audio_rng=state.rng,
            demo_mode_active=state.demo_enabled,
        )
        self._action: str | None = None

    def open(self) -> None:
        self._action = None
        self._state.screen_fade_ramp = False
        if self._state.audio is not None:
            stop_music(self._state.audio)
        self._mode.bind_audio(self._state.audio, self._state.rng)
        self._mode.bind_screen_fade(self._state)
        self._mode.open()

        level = self._state.pending_quest_level
        if level is not None:
            self._mode.prepare_new_run(level, status=self._state.status)

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
            "start_quest": QuestGameView(state),
            "start_survival": SurvivalGameView(state),
            "start_rush": RushGameView(state),
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
