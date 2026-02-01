from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import datetime as dt
import faulthandler
import math
import random
import time
import traceback
import webbrowser
from typing import Protocol, TYPE_CHECKING

import pyray as rl

from grim.audio import (
    AudioState,
    play_music,
    play_sfx,
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
from .demo_trial import (
    DEMO_QUEST_GRACE_TIME_MS,
    DEMO_TOTAL_PLAY_TIME_MS,
    demo_trial_overlay_info,
    format_demo_trial_time,
    tick_demo_trial_timers,
)
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
from .frontend.panels.controls import ControlsMenuView
from .frontend.panels.mods import ModsMenuView
from .frontend.panels.options import OptionsMenuView
from .frontend.panels.play_game import PlayGameMenuView
from .frontend.panels.stats import StatisticsMenuView
from .frontend.pause_menu import PauseMenuView
from .frontend.transitions import _draw_screen_fade, _update_screen_fade
from .persistence.save_status import GameStatus, ensure_game_status
from .ui.demo_trial_overlay import DEMO_PURCHASE_URL, DemoTrialOverlayUi
from .ui.perk_menu import UiButtonState, UiButtonTextureSet, button_draw, button_update
from .paths import default_runtime_dir
from .assets_fetch import download_missing_paqs

if TYPE_CHECKING:
    from .modes.quest_mode import QuestRunOutcome

@dataclass(frozen=True, slots=True)
class GameConfig:
    base_dir: Path = field(default_factory=default_runtime_dir)
    assets_dir: Path | None = None
    width: int | None = None
    height: int | None = None
    fps: int = 60
    seed: int | None = None
    demo_enabled: bool = False
    no_intro: bool = False


@dataclass(slots=True)
class HighScoresRequest:
    game_mode_id: int
    quest_stage_major: int = 0
    quest_stage_minor: int = 0
    highlight_rank: int | None = None


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
    skip_intro: bool = False
    gamma_ramp: float = 1.0
    snd_freq_adjustment_enabled: bool = False
    menu_ground: GroundRenderer | None = None
    menu_sign_locked: bool = False
    pause_background: PauseBackground | None = None
    pending_quest_level: str | None = None
    pending_high_scores: HighScoresRequest | None = None
    quest_outcome: QuestRunOutcome | None = None
    quest_fail_retry_count: int = 0
    demo_trial_elapsed_ms: int = 0
    quit_requested: bool = False
    screen_fade_alpha: float = 0.0
    screen_fade_ramp: bool = False


CRIMSON_PAQ_NAME = "crimson.paq"
MUSIC_PAQ_NAME = "music.paq"
SFX_PAQ_NAME = "sfx.paq"
AUTOEXEC_NAME = "autoexec.txt"

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
        self._button_textures: UiButtonTextureSet | None = None
        self._back_button = UiButtonState("Back")

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
        self._button_textures = UiButtonTextureSet(button_sm=self._button_sm, button_md=self._button_md)

        self._action = None
        self._dirty = False
        self._stage = max(1, min(5, int(self._stage)))
        self._cursor_pulse_time = 0.0
        self._back_button = UiButtonState("Back")

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
        self._button_textures = None

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

        textures = self._button_textures
        if textures is not None and (textures.button_sm is not None or textures.button_md is not None):
            back_x = layout["list_x"] + QUEST_BACK_BUTTON_X_OFFSET
            back_y = self._rows_y0(layout) + QUEST_BACK_BUTTON_Y_OFFSET
            dt_ms = min(float(dt), 0.1) * 1000.0
            font = self._ensure_small_font()
            back_w = button_width(font, self._back_button.label, scale=1.0, force_wide=self._back_button.force_wide)
            mouse = rl.get_mouse_position()
            click = rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT)
            if button_update(
                self._back_button,
                x=float(back_x),
                y=float(back_y),
                width=float(back_w),
                dt_ms=float(dt_ms),
                mouse=mouse,
                click=bool(click),
            ):
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
        # Stage 5 does not fit cleanly in the saved blob:
        # - The "games" index range would overlap stage-1 completion counters.
        # - The "completed" index range reads into trailing fields (mode counters,
        #   game_sequence_id, and unknown tail bytes), and the last row would run past
        #   the decoded payload.
        #
        # We emulate this layout so the debug `F1` overlay matches the classic build.
        global_index = (int(stage) - 1) * 10 + int(row)
        if not (0 <= global_index < 50):
            return None
        count_index = global_index + 10

        status = self._state.status
        games_idx = 1 + count_index
        completed_idx = 41 + count_index
        try:
            games = int(status.quest_play_count(games_idx))
        except Exception:
            return None

        try:
            completed = int(status.quest_play_count(completed_idx))
        except Exception:
            # Stage-5 completed reads into trailing fields (and beyond).
            if int(stage) != 5:
                return None
            tail_slot = int(count_index) - 50
            if tail_slot == 0:
                completed = int(status.mode_play_count("survival"))
            elif tail_slot == 1:
                completed = int(status.mode_play_count("rush"))
            elif tail_slot == 2:
                completed = int(status.mode_play_count("typo"))
            elif tail_slot == 3:
                completed = int(status.mode_play_count("other"))
            elif tail_slot == 4:
                completed = int(status.game_sequence_id)
            elif 5 <= tail_slot <= 8:
                tail = status.unknown_tail()
                off = (tail_slot - 5) * 4
                if len(tail) < off + 4:
                    completed = 0
                else:
                    completed = int.from_bytes(tail[off : off + 4], "little") & 0xFFFFFFFF
            else:
                completed = 0
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
        textures = self._button_textures
        if textures is not None and (textures.button_sm is not None or textures.button_md is not None):
            back_x = list_x + QUEST_BACK_BUTTON_X_OFFSET
            back_y = y0 + QUEST_BACK_BUTTON_Y_OFFSET
            back_w = button_width(font, self._back_button.label, scale=1.0, force_wide=self._back_button.force_wide)
            button_draw(textures, font, self._back_button, x=float(back_x), y=float(back_y), width=float(back_w), scale=1.0)

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


class FrontView(Protocol):
    def open(self) -> None: ...

    def close(self) -> None: ...

    def update(self, dt: float) -> None: ...

    def draw(self) -> None: ...

    def take_action(self) -> str | None: ...


class PauseBackground(Protocol):
    def draw_pause_background(self) -> None: ...


class SurvivalGameView:
    """Gameplay view wrapper that adapts SurvivalMode into `crimson game`."""

    def __init__(self, state: GameState) -> None:
        from .modes.survival_mode import SurvivalMode

        self._state = state
        self._mode = SurvivalMode(
            ViewContext(assets_dir=state.assets_dir),
            texture_cache=state.texture_cache,
            config=state.config,
            console=state.console,
            audio=state.audio,
            audio_rng=state.rng,
        )
        self._action: str | None = None

    def open(self) -> None:
        self._action = None
        if self._state.screen_fade_ramp:
            self._state.screen_fade_alpha = 1.0
        self._state.screen_fade_ramp = False
        if self._state.audio is not None:
            # Original game: entering gameplay cuts the menu theme; in-game tunes
            # start later on the first creature hit.
            stop_music(self._state.audio)
        self._mode.bind_status(self._state.status)
        self._mode.bind_audio(self._state.audio, self._state.rng)
        self._mode.bind_screen_fade(self._state)
        self._mode.open()

    def close(self) -> None:
        if self._state.audio is not None:
            stop_music(self._state.audio)
        self._mode.close()

    def update(self, dt: float) -> None:
        self._mode.update(dt)
        mode_action = self._mode.take_action()
        if mode_action == "open_pause_menu":
            self._action = "open_pause_menu"
            return
        if mode_action == "open_high_scores":
            self._state.pending_high_scores = HighScoresRequest(game_mode_id=1)
            self._action = "open_high_scores"
            return
        if mode_action == "back_to_menu":
            self._action = "back_to_menu"
            self._mode.close_requested = False
            return
        if getattr(self._mode, "close_requested", False):
            self._action = "back_to_menu"
            self._mode.close_requested = False

    def draw(self) -> None:
        self._mode.draw()

    def draw_pause_background(self) -> None:
        self._mode.draw_pause_background()

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
            console=state.console,
            audio=state.audio,
            audio_rng=state.rng,
        )
        self._action: str | None = None

    def open(self) -> None:
        self._action = None
        if self._state.screen_fade_ramp:
            self._state.screen_fade_alpha = 1.0
        self._state.screen_fade_ramp = False
        if self._state.audio is not None:
            stop_music(self._state.audio)
        self._mode.bind_status(self._state.status)
        self._mode.bind_audio(self._state.audio, self._state.rng)
        self._mode.bind_screen_fade(self._state)
        self._mode.open()

    def close(self) -> None:
        if self._state.audio is not None:
            stop_music(self._state.audio)
        self._mode.close()

    def update(self, dt: float) -> None:
        self._mode.update(dt)
        mode_action = self._mode.take_action()
        if mode_action == "open_pause_menu":
            self._action = "open_pause_menu"
            return
        if mode_action == "open_high_scores":
            self._state.pending_high_scores = HighScoresRequest(game_mode_id=2)
            self._action = "open_high_scores"
            return
        if mode_action == "back_to_menu":
            self._action = "back_to_menu"
            self._mode.close_requested = False
            return
        if getattr(self._mode, "close_requested", False):
            self._action = "back_to_menu"
            self._mode.close_requested = False

    def draw(self) -> None:
        self._mode.draw()

    def draw_pause_background(self) -> None:
        self._mode.draw_pause_background()

    def take_action(self) -> str | None:
        action = self._action
        self._action = None
        return action


class TypoShooterGameView:
    """Gameplay view wrapper that adapts TypoShooterMode into `crimson game`."""

    def __init__(self, state: GameState) -> None:
        from .modes.typo_mode import TypoShooterMode

        self._state = state
        self._mode = TypoShooterMode(
            ViewContext(assets_dir=state.assets_dir),
            texture_cache=state.texture_cache,
            config=state.config,
            console=state.console,
            audio=state.audio,
            audio_rng=state.rng,
        )
        self._action: str | None = None

    def open(self) -> None:
        self._action = None
        if self._state.screen_fade_ramp:
            self._state.screen_fade_alpha = 1.0
        self._state.screen_fade_ramp = False
        if self._state.audio is not None:
            stop_music(self._state.audio)
        self._mode.bind_status(self._state.status)
        self._mode.bind_audio(self._state.audio, self._state.rng)
        self._mode.bind_screen_fade(self._state)
        self._mode.open()

    def close(self) -> None:
        if self._state.audio is not None:
            stop_music(self._state.audio)
        self._mode.close()

    def update(self, dt: float) -> None:
        self._mode.update(dt)
        mode_action = self._mode.take_action()
        if mode_action == "open_pause_menu":
            self._action = "open_pause_menu"
            return
        if mode_action == "open_high_scores":
            self._state.pending_high_scores = HighScoresRequest(game_mode_id=4)
            self._action = "open_high_scores"
            return
        if mode_action == "back_to_menu":
            self._action = "back_to_menu"
            self._mode.close_requested = False
            return
        if getattr(self._mode, "close_requested", False):
            self._action = "back_to_menu"
            self._mode.close_requested = False

    def draw(self) -> None:
        self._mode.draw()

    def draw_pause_background(self) -> None:
        self._mode.draw_pause_background()

    def take_action(self) -> str | None:
        action = self._action
        self._action = None
        return action


class TutorialGameView:
    """Gameplay view wrapper that adapts TutorialMode into `crimson game`."""

    def __init__(self, state: GameState) -> None:
        from .modes.tutorial_mode import TutorialMode

        self._state = state
        self._mode = TutorialMode(
            ViewContext(assets_dir=state.assets_dir),
            texture_cache=state.texture_cache,
            config=state.config,
            console=state.console,
            audio=state.audio,
            audio_rng=state.rng,
            demo_mode_active=state.demo_enabled,
        )
        self._action: str | None = None

    def open(self) -> None:
        self._action = None
        if self._state.screen_fade_ramp:
            self._state.screen_fade_alpha = 1.0
        self._state.screen_fade_ramp = False
        if self._state.audio is not None:
            stop_music(self._state.audio)
        self._mode.bind_status(self._state.status)
        self._mode.bind_audio(self._state.audio, self._state.rng)
        self._mode.bind_screen_fade(self._state)
        self._mode.open()

    def close(self) -> None:
        if self._state.audio is not None:
            stop_music(self._state.audio)
        self._mode.close()

    def update(self, dt: float) -> None:
        self._mode.update(dt)
        mode_action = self._mode.take_action()
        if mode_action == "open_pause_menu":
            self._action = "open_pause_menu"
            return
        if getattr(self._mode, "close_requested", False):
            self._action = "back_to_menu"
            self._mode.close_requested = False

    def draw(self) -> None:
        self._mode.draw()

    def draw_pause_background(self) -> None:
        self._mode.draw_pause_background()

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
            console=state.console,
            audio=state.audio,
            audio_rng=state.rng,
            demo_mode_active=state.demo_enabled,
        )
        self._action: str | None = None

    def open(self) -> None:
        self._action = None
        if self._state.screen_fade_ramp:
            self._state.screen_fade_alpha = 1.0
        self._state.screen_fade_ramp = False
        self._state.quest_outcome = None
        if self._state.audio is not None:
            stop_music(self._state.audio)
        self._mode.bind_status(self._state.status)
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
        mode_action = self._mode.take_action()
        if mode_action == "open_pause_menu":
            self._action = "open_pause_menu"
            return
        if getattr(self._mode, "close_requested", False):
            outcome = self._mode.consume_outcome()
            if outcome is not None:
                self._state.quest_outcome = outcome
                if outcome.kind == "completed":
                    self._action = "quest_results"
                elif outcome.kind == "failed":
                    self._action = "quest_failed"
                else:
                    self._action = "back_to_menu"
            else:
                self._action = "back_to_menu"
            self._mode.close_requested = False

    def draw(self) -> None:
        self._mode.draw()

    def draw_pause_background(self) -> None:
        self._mode.draw_pause_background()

    def take_action(self) -> str | None:
        action = self._action
        self._action = None
        return action


def _player_name_default(config: CrimsonConfig) -> str:
    raw = config.data.get("player_name")
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw).split(b"\x00", 1)[0].decode("latin-1", errors="ignore")
    if isinstance(raw, str):
        return raw
    return ""


def _next_quest_level(level: str) -> str | None:
    try:
        major_text, minor_text = level.split(".", 1)
        major = int(major_text)
        minor = int(minor_text)
    except Exception:
        return None

    from .quests import quest_by_level

    for _ in range(100):
        minor += 1
        if minor > 10:
            minor = 1
            major += 1
        candidate = f"{major}.{minor}"
        if quest_by_level(candidate) is not None:
            return candidate
    return None


class QuestResultsView:
    def __init__(self, state: GameState) -> None:
        self._state = state
        self._ground: GroundRenderer | None = None
        self._outcome: QuestRunOutcome | None = None
        self._quest_title: str = ""
        self._quest_stage_major = 0
        self._quest_stage_minor = 0
        self._unlock_weapon_name: str = ""
        self._unlock_perk_name: str = ""
        self._breakdown = None
        self._breakdown_anim = None
        self._record = None
        self._rank_index: int | None = None
        self._action: str | None = None
        self._cursor_pulse_time = 0.0
        self._small_font: SmallFontData | None = None
        self._button_tex: rl.Texture2D | None = None
        self._button_textures: UiButtonTextureSet | None = None
        self._retry_button = UiButtonState("Retry", force_wide=True)
        self._quest_list_button = UiButtonState("Quest list", force_wide=True)
        self._main_menu_button = UiButtonState("Main menu", force_wide=True)
        self._button_textures: UiButtonTextureSet | None = None
        self._play_again_button = UiButtonState("Play again", force_wide=True)
        self._play_next_button = UiButtonState("Play next", force_wide=True)
        self._high_scores_button = UiButtonState("High scores", force_wide=True)
        self._main_menu_button = UiButtonState("Main menu", force_wide=True)

    def open(self) -> None:
        from .quests.results import QuestResultsBreakdownAnim, compute_quest_final_time
        from .persistence.highscores import HighScoreRecord, scores_path_for_config, upsert_highscore_record

        self._action = None
        self._ground = ensure_menu_ground(self._state)
        self._cursor_pulse_time = 0.0
        self._outcome = self._state.quest_outcome
        self._state.quest_outcome = None
        outcome = self._outcome
        self._state.quest_fail_retry_count = 0
        self._quest_title = ""
        self._quest_stage_major = 0
        self._quest_stage_minor = 0
        self._unlock_weapon_name = ""
        self._unlock_perk_name = ""
        self._breakdown = None
        self._breakdown_anim = None
        self._record = None
        self._rank_index = None
        self._button_tex = None
        self._button_textures = None
        self._small_font = None
        self._play_again_button = UiButtonState("Play again", force_wide=True)
        self._play_next_button = UiButtonState("Play next", force_wide=True)
        self._high_scores_button = UiButtonState("High scores", force_wide=True)
        self._main_menu_button = UiButtonState("Main menu", force_wide=True)
        if outcome is None:
            return

        major, minor = 0, 0
        try:
            major_text, minor_text = outcome.level.split(".", 1)
            major = int(major_text)
            minor = int(minor_text)
        except Exception:
            major = 0
            minor = 0
        self._quest_stage_major = int(major)
        self._quest_stage_minor = int(minor)

        try:
            from .quests import quest_by_level

            quest = quest_by_level(outcome.level)
            self._quest_title = quest.title if quest is not None else ""
            if quest is not None:
                weapon_id_native = int(quest.unlock_weapon_id or 0)
                if weapon_id_native > 0:
                    from .weapons import WEAPON_BY_ID

                    weapon_entry = WEAPON_BY_ID.get(weapon_id_native)
                    self._unlock_weapon_name = weapon_entry.name if weapon_entry is not None and weapon_entry.name else f"weapon_{weapon_id_native}"

                from .perks import PERK_BY_ID, PerkId, perk_display_name

                perk_id = int(quest.unlock_perk_id or 0)
                if perk_id != int(PerkId.ANTIPERK):
                    perk_entry = PERK_BY_ID.get(perk_id)
                    if perk_entry is not None and perk_entry.name:
                        fx_toggle = int(self._state.config.data.get("fx_toggle", 0) or 0)
                        self._unlock_perk_name = perk_display_name(perk_id, fx_toggle=fx_toggle)
                    else:
                        self._unlock_perk_name = f"perk_{perk_id}"
        except Exception:
            self._quest_title = ""

        record = HighScoreRecord.blank()
        record.game_mode_id = 3
        record.quest_stage_major = major
        record.quest_stage_minor = minor
        record.score_xp = int(outcome.experience)
        record.creature_kill_count = int(outcome.kill_count)
        record.most_used_weapon_id = int(outcome.most_used_weapon_id)
        fired = max(0, int(outcome.shots_fired))
        hit = max(0, min(int(outcome.shots_hit), fired))
        record.shots_fired = fired
        record.shots_hit = hit

        breakdown = compute_quest_final_time(
            base_time_ms=int(outcome.base_time_ms),
            player_health=float(outcome.player_health),
            player2_health=(float(outcome.player2_health) if outcome.player2_health is not None else None),
            pending_perk_count=int(outcome.pending_perk_count),
        )
        record.survival_elapsed_ms = int(breakdown.final_time_ms)
        record.set_name(_player_name_default(self._state.config) or "Player")

        global_index = (int(major) - 1) * 10 + (int(minor) - 1)
        if 0 <= global_index < 40:
            try:
                # `sub_447d40` reads completed counts from indices 51..90.
                self._state.status.increment_quest_play_count(global_index + 51)
            except Exception:
                pass

        # Advance quest unlock progression when completing the currently-unlocked quest.
        if global_index >= 0:
            next_unlock = int(global_index + 1)
            hardcore = bool(int(self._state.config.data.get("hardcore_flag", 0) or 0))
            try:
                if hardcore:
                    if next_unlock > int(self._state.status.quest_unlock_index_full):
                        self._state.status.quest_unlock_index_full = next_unlock
                else:
                    if next_unlock > int(self._state.status.quest_unlock_index):
                        self._state.status.quest_unlock_index = next_unlock
            except Exception:
                pass

        try:
            self._state.status.save_if_dirty()
        except Exception:
            pass

        path = scores_path_for_config(self._state.base_dir, self._state.config, quest_stage_major=major, quest_stage_minor=minor)
        try:
            _table, rank_index = upsert_highscore_record(path, record)
            self._rank_index = int(rank_index)
        except Exception:
            self._rank_index = None

        cache = _ensure_texture_cache(self._state)
        self._button_tex = cache.get_or_load("ui_buttonMd", "ui/ui_button_128x32.jaz").texture
        button_sm = cache.get_or_load("ui_buttonSm", "ui/ui_button_64x32.jaz").texture
        self._button_textures = UiButtonTextureSet(button_sm=button_sm, button_md=self._button_tex)
        self._record = record
        self._breakdown = breakdown
        self._breakdown_anim = QuestResultsBreakdownAnim.start()

    def close(self) -> None:
        self._small_font = None
        self._button_tex = None
        self._button_textures = None
        self._record = None
        self._outcome = None
        self._breakdown = None
        self._breakdown_anim = None
        self._rank_index = None
        self._quest_stage_major = 0
        self._quest_stage_minor = 0
        self._unlock_weapon_name = ""
        self._unlock_perk_name = ""

    def update(self, dt: float) -> None:
        from .quests.results import tick_quest_results_breakdown_anim

        if self._state.audio is not None:
            update_audio(self._state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        self._cursor_pulse_time += min(dt, 0.1) * 1.1

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._action = "back_to_menu"
            return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_H):
            self._open_high_scores_list()
            return

        outcome = self._outcome
        record = self._record
        breakdown = self._breakdown
        if record is None or outcome is None or breakdown is None:
            return

        textures = self._button_textures
        if textures is None or (textures.button_sm is None and textures.button_md is None):
            return
        scale = 0.9 if float(self._state.config.screen_width) < 641.0 else 1.0
        button_w = button_width(None, self._play_again_button.label, scale=scale, force_wide=self._play_again_button.force_wide)
        button_h = 32.0 * scale
        gap_x = 18.0 * scale
        gap_y = 12.0 * scale
        x0 = 32.0
        y0 = float(rl.get_screen_height()) - (button_h * 2.0 + gap_y) - 52.0 * scale
        x1 = x0 + button_w + gap_x
        y1 = y0 + button_h + gap_y

        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT)
        dt_ms = min(float(dt), 0.1) * 1000.0

        anim = self._breakdown_anim
        if anim is not None and not anim.done:
            if rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE) or click:
                anim.set_final(breakdown)
                return

            clinks = tick_quest_results_breakdown_anim(
                anim,
                frame_dt_ms=int(dt_ms),
                target=breakdown,
            )
            if clinks > 0 and self._state.audio is not None:
                play_sfx(self._state.audio, "sfx_ui_clink_01", rng=self._state.rng)
            if not anim.done:
                # Keep hover/press animations alive even while the breakdown is running,
                # but don't allow activating buttons until the animation is complete.
                button_update(
                    self._play_again_button,
                    x=x0,
                    y=y0,
                    width=button_w,
                    dt_ms=dt_ms,
                    mouse=mouse,
                    click=False,
                )
                button_update(
                    self._play_next_button,
                    x=x1,
                    y=y0,
                    width=button_w,
                    dt_ms=dt_ms,
                    mouse=mouse,
                    click=False,
                )
                button_update(
                    self._high_scores_button,
                    x=x0,
                    y=y1,
                    width=button_w,
                    dt_ms=dt_ms,
                    mouse=mouse,
                    click=False,
                )
                button_update(
                    self._main_menu_button,
                    x=x1,
                    y=y1,
                    width=button_w,
                    dt_ms=dt_ms,
                    mouse=mouse,
                    click=False,
                )
                return

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER):
            self._state.pending_quest_level = outcome.level
            self._action = "start_quest"
            return
        if rl.is_key_pressed(rl.KeyboardKey.KEY_N):
            next_level = _next_quest_level(outcome.level)
            if next_level is not None:
                self._state.pending_quest_level = next_level
                self._action = "start_quest"
                return

        if button_update(
            self._play_again_button,
            x=x0,
            y=y0,
            width=button_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self._state.pending_quest_level = outcome.level
            self._action = "start_quest"
            return
        if button_update(
            self._play_next_button,
            x=x1,
            y=y0,
            width=button_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            next_level = _next_quest_level(outcome.level)
            if next_level is not None:
                self._state.pending_quest_level = next_level
                self._action = "start_quest"
                return
        if button_update(
            self._high_scores_button,
            x=x0,
            y=y1,
            width=button_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self._open_high_scores_list()
            return
        if button_update(
            self._main_menu_button,
            x=x1,
            y=y1,
            width=button_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self._action = "back_to_menu"
            return

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        if self._ground is not None:
            self._ground.draw(0.0, 0.0)
        _draw_screen_fade(self._state)

        record = self._record
        outcome = self._outcome
        breakdown = self._breakdown
        if record is None or outcome is None or breakdown is None:
            rl.draw_text("Quest results unavailable.", 32, 140, 28, rl.Color(235, 235, 235, 255))
            rl.draw_text("Press ESC to return to the menu.", 32, 180, 18, rl.Color(190, 190, 200, 255))
            return

        anim = self._breakdown_anim
        base_time_ms = int(breakdown.base_time_ms)
        life_bonus_ms = int(breakdown.life_bonus_ms)
        perk_bonus_ms = int(breakdown.unpicked_perk_bonus_ms)
        final_time_ms = int(breakdown.final_time_ms)
        step = 4
        highlight_alpha = 1.0
        if anim is not None and not anim.done:
            base_time_ms = int(anim.base_time_ms)
            life_bonus_ms = int(anim.life_bonus_ms)
            perk_bonus_ms = int(anim.unpicked_perk_bonus_s) * 1000
            final_time_ms = int(anim.final_time_ms)
            step = int(anim.step)
            highlight_alpha = float(anim.highlight_alpha())

        def _fmt_clock(ms: int) -> str:
            total_seconds = max(0, int(ms) // 1000)
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            return f"{minutes:02d}:{seconds:02d}"

        def _fmt_bonus(ms: int) -> str:
            return f"-{float(max(0, int(ms))) / 1000.0:.2f}s"

        def _breakdown_color(idx: int, *, final: bool = False) -> rl.Color:
            if anim is None or anim.done:
                if final:
                    return rl.Color(255, 255, 255, 255)
                return rl.Color(255, 255, 255, int(255 * 0.8))

            alpha = 0.2
            if idx < step:
                alpha = 0.4
            elif idx == step:
                alpha = 1.0
                if final:
                    alpha *= highlight_alpha
            rgb = (255, 255, 255)
            if idx == step:
                rgb = (25, 200, 25)
            return rl.Color(rgb[0], rgb[1], rgb[2], int(255 * max(0.0, min(1.0, alpha))))

        title = f"Quest {outcome.level} completed"
        subtitle = self._quest_title
        rl.draw_text(title, 32, 120, 28, rl.Color(235, 235, 235, 255))
        if subtitle:
            rl.draw_text(subtitle, 32, 154, 18, rl.Color(190, 190, 200, 255))

        font = self._ensure_small_font()
        text_color = rl.Color(255, 255, 255, int(255 * 0.8))
        y = 196.0
        draw_small_text(font, f"Base time: {_fmt_clock(base_time_ms)}", 32.0, y, 1.0, _breakdown_color(0))
        y += 18.0
        draw_small_text(font, f"Life bonus: {_fmt_bonus(life_bonus_ms)}", 32.0, y, 1.0, _breakdown_color(1))
        y += 18.0
        draw_small_text(font, f"Perk bonus: {_fmt_bonus(perk_bonus_ms)}", 32.0, y, 1.0, _breakdown_color(2))
        y += 18.0
        draw_small_text(font, f"Final time: {_fmt_clock(final_time_ms)}", 32.0, y, 1.0, _breakdown_color(3, final=True))
        y += 26.0
        draw_small_text(font, f"Kills: {int(record.creature_kill_count)}", 32.0, y, 1.0, rl.Color(255, 255, 255, int(255 * 0.8)))
        y += 18.0
        draw_small_text(font, f"XP: {int(record.score_xp)}", 32.0, y, 1.0, rl.Color(255, 255, 255, int(255 * 0.8)))
        if self._rank_index is not None and self._rank_index < 100:
            y += 18.0
            draw_small_text(font, f"Rank: {int(self._rank_index) + 1}", 32.0, y, 1.0, rl.Color(255, 255, 255, int(255 * 0.8)))

        if self._unlock_weapon_name:
            y += 26.0
            draw_small_text(font, "Weapon unlocked", 32.0, y, 1.0, rl.Color(255, 255, 255, int(255 * 0.7)))
            y += 16.0
            draw_small_text(font, self._unlock_weapon_name, 32.0, y, 1.0, rl.Color(255, 255, 255, int(255 * 0.9)))

        if self._unlock_perk_name:
            y += 20.0
            draw_small_text(font, "Perk unlocked", 32.0, y, 1.0, rl.Color(255, 255, 255, int(255 * 0.7)))
            y += 16.0
            draw_small_text(font, self._unlock_perk_name, 32.0, y, 1.0, rl.Color(255, 255, 255, int(255 * 0.9)))

        textures = self._button_textures
        if textures is not None and (textures.button_sm is not None or textures.button_md is not None):
            scale = 0.9 if float(self._state.config.screen_width) < 641.0 else 1.0
            button_w = button_width(None, self._play_again_button.label, scale=scale, force_wide=self._play_again_button.force_wide)
            button_h = 32.0 * scale
            gap_x = 18.0 * scale
            gap_y = 12.0 * scale
            x0 = 32.0
            y0 = float(rl.get_screen_height()) - (button_h * 2.0 + gap_y) - 52.0 * scale
            x1 = x0 + button_w + gap_x
            y1 = y0 + button_h + gap_y
            button_draw(textures, font, self._play_again_button, x=x0, y=y0, width=button_w, scale=scale)
            button_draw(textures, font, self._play_next_button, x=x1, y=y0, width=button_w, scale=scale)
            button_draw(textures, font, self._high_scores_button, x=x0, y=y1, width=button_w, scale=scale)
            button_draw(textures, font, self._main_menu_button, x=x1, y=y1, width=button_w, scale=scale)

        if anim is not None and not anim.done:
            draw_small_text(
                font,
                "SPACE / click: skip breakdown",
                32.0,
                float(rl.get_screen_height()) - 46.0,
                0.9,
                rl.Color(190, 190, 200, 255),
            )

        draw_small_text(
            font,
            "ENTER: Replay    N: Next    H: High scores    ESC: Menu",
            32.0,
            float(rl.get_screen_height()) - 28.0,
            1.0,
            rl.Color(190, 190, 200, 255),
        )
        _draw_menu_cursor(self._state, pulse_time=self._cursor_pulse_time)

    def take_action(self) -> str | None:
        action = self._action
        self._action = None
        return action

    def _open_high_scores_list(self) -> None:
        self._state.pending_high_scores = HighScoresRequest(
            game_mode_id=3,
            quest_stage_major=int(self._quest_stage_major),
            quest_stage_minor=int(self._quest_stage_minor),
            highlight_rank=self._rank_index,
        )
        self._action = "open_high_scores"

    def _ensure_small_font(self) -> SmallFontData:
        if self._small_font is not None:
            return self._small_font
        missing_assets: list[str] = []
        self._small_font = load_small_font(self._state.assets_dir, missing_assets)
        return self._small_font


class QuestFailedView:
    def __init__(self, state: GameState) -> None:
        self._state = state
        self._ground: GroundRenderer | None = None
        self._outcome: QuestRunOutcome | None = None
        self._quest_title: str = ""
        self._action: str | None = None
        self._cursor_pulse_time = 0.0
        self._small_font: SmallFontData | None = None
        self._button_tex: rl.Texture2D | None = None

    def open(self) -> None:
        self._action = None
        self._ground = ensure_menu_ground(self._state)
        self._cursor_pulse_time = 0.0
        self._outcome = self._state.quest_outcome
        self._state.quest_outcome = None
        self._quest_title = ""
        self._small_font = None
        self._button_tex = None
        self._button_textures = None
        self._retry_button = UiButtonState("Retry", force_wide=True)
        self._quest_list_button = UiButtonState("Quest list", force_wide=True)
        self._main_menu_button = UiButtonState("Main menu", force_wide=True)
        outcome = self._outcome
        if outcome is not None:
            try:
                from .quests import quest_by_level

                quest = quest_by_level(outcome.level)
                self._quest_title = quest.title if quest is not None else ""
            except Exception:
                self._quest_title = ""

        cache = _ensure_texture_cache(self._state)
        self._button_tex = cache.get_or_load("ui_buttonMd", "ui/ui_button_128x32.jaz").texture
        button_sm = cache.get_or_load("ui_buttonSm", "ui/ui_button_64x32.jaz").texture
        self._button_textures = UiButtonTextureSet(button_sm=button_sm, button_md=self._button_tex)

    def close(self) -> None:
        self._ground = None
        self._outcome = None
        self._quest_title = ""
        self._small_font = None
        self._button_tex = None
        self._button_textures = None

    def update(self, dt: float) -> None:
        if self._state.audio is not None:
            update_audio(self._state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        self._cursor_pulse_time += min(dt, 0.1) * 1.1

        outcome = self._outcome
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._state.quest_fail_retry_count = 0
            self._action = "back_to_menu"
            return
        if outcome is not None and rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER):
            self._state.quest_fail_retry_count = int(self._state.quest_fail_retry_count) + 1
            self._state.pending_quest_level = outcome.level
            self._action = "start_quest"
            return
        if rl.is_key_pressed(rl.KeyboardKey.KEY_Q):
            self._state.quest_fail_retry_count = 0
            self._action = "open_quests"
            return

        textures = self._button_textures
        if outcome is None or textures is None or (textures.button_sm is None and textures.button_md is None):
            return
        scale = 0.9 if float(self._state.config.screen_width) < 641.0 else 1.0
        button_w = button_width(None, self._retry_button.label, scale=scale, force_wide=self._retry_button.force_wide)
        button_h = 32.0 * scale
        gap_x = 18.0 * scale
        x0 = 32.0
        y0 = float(rl.get_screen_height()) - button_h - 56.0 * scale

        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT)
        dt_ms = min(float(dt), 0.1) * 1000.0

        if button_update(self._retry_button, x=x0, y=y0, width=button_w, dt_ms=dt_ms, mouse=mouse, click=click):
            self._state.quest_fail_retry_count = int(self._state.quest_fail_retry_count) + 1
            self._state.pending_quest_level = outcome.level
            self._action = "start_quest"
            return
        if button_update(
            self._quest_list_button,
            x=x0 + button_w + gap_x,
            y=y0,
            width=button_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self._state.quest_fail_retry_count = 0
            self._action = "open_quests"
            return
        if button_update(
            self._main_menu_button,
            x=x0 + (button_w + gap_x) * 2.0,
            y=y0,
            width=button_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self._state.quest_fail_retry_count = 0
            self._action = "back_to_menu"
            return

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        if self._ground is not None:
            self._ground.draw(0.0, 0.0)
        _draw_screen_fade(self._state)

        outcome = self._outcome
        level = outcome.level if outcome is not None else (self._state.pending_quest_level or "unknown")
        subtitle = self._quest_title
        rl.draw_text(f"Quest {level} failed", 32, 120, 28, rl.Color(235, 235, 235, 255))
        if subtitle:
            rl.draw_text(subtitle, 32, 154, 18, rl.Color(190, 190, 200, 255))

        font = self._ensure_small_font()
        text_color = rl.Color(255, 255, 255, int(255 * 0.8))
        retry_count = int(self._state.quest_fail_retry_count)
        message = "Quest failed, try again."
        if retry_count == 1:
            message = "You didn't make it, do try again."
        elif retry_count == 2:
            message = "Third time no good."
        elif retry_count == 3:
            message = "No luck this time, have another go?"
        elif retry_count == 4:
            message = "Persistence will be rewarded."
        elif retry_count == 5:
            message = "Try one more time?"

        y = 196.0
        draw_small_text(font, message, 32.0, y, 1.0, text_color)
        y += 22.0
        if outcome is not None:
            total_seconds = max(0, int(outcome.base_time_ms) // 1000)
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            time_text = f"{minutes:02d}:{seconds:02d}"
            draw_small_text(font, f"Time: {time_text}", 32.0, y, 1.0, text_color)
            y += 18.0
            draw_small_text(font, f"Kills: {int(outcome.kill_count)}", 32.0, y, 1.0, text_color)
            y += 18.0
            draw_small_text(font, f"XP: {int(outcome.experience)}", 32.0, y, 1.0, text_color)

        textures = self._button_textures
        if textures is not None and (textures.button_sm is not None or textures.button_md is not None):
            scale = 0.9 if float(self._state.config.screen_width) < 641.0 else 1.0
            button_w = button_width(None, self._retry_button.label, scale=scale, force_wide=self._retry_button.force_wide)
            button_h = 32.0 * scale
            gap_x = 18.0 * scale
            x0 = 32.0
            y0 = float(rl.get_screen_height()) - button_h - 56.0 * scale
            button_draw(textures, font, self._retry_button, x=x0, y=y0, width=button_w, scale=scale)
            button_draw(
                textures,
                font,
                self._quest_list_button,
                x=x0 + button_w + gap_x,
                y=y0,
                width=button_w,
                scale=scale,
            )
            button_draw(
                textures,
                font,
                self._main_menu_button,
                x=x0 + (button_w + gap_x) * 2.0,
                y=y0,
                width=button_w,
                scale=scale,
            )

        draw_small_text(
            font,
            "ENTER: Retry    Q: Quest list    ESC: Menu",
            32.0,
            float(rl.get_screen_height()) - 28.0,
            1.0,
            rl.Color(190, 190, 200, 255),
        )
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


class HighScoresView:
    def __init__(self, state: GameState) -> None:
        self._state = state
        self._ground: GroundRenderer | None = None
        self._action: str | None = None
        self._cursor_pulse_time = 0.0
        self._small_font: SmallFontData | None = None
        self._button_tex: rl.Texture2D | None = None
        self._button_textures: UiButtonTextureSet | None = None
        self._back_button = UiButtonState("Back", force_wide=True)
        self._main_menu_button = UiButtonState("Main menu", force_wide=True)

        self._request: HighScoresRequest | None = None
        self._records: list = []
        self._scroll_index = 0

    def open(self) -> None:
        from .persistence.highscores import read_highscore_table, scores_path_for_mode

        self._action = None
        self._ground = ensure_menu_ground(self._state)
        self._cursor_pulse_time = 0.0
        self._small_font = None
        self._scroll_index = 0
        self._button_textures = None
        self._back_button = UiButtonState("Back", force_wide=True)
        self._main_menu_button = UiButtonState("Main menu", force_wide=True)

        cache = _ensure_texture_cache(self._state)
        self._button_tex = cache.get_or_load("ui_buttonMd", "ui/ui_button_128x32.jaz").texture
        button_sm = cache.get_or_load("ui_buttonSm", "ui/ui_button_64x32.jaz").texture
        self._button_textures = UiButtonTextureSet(button_sm=button_sm, button_md=self._button_tex)

        request = self._state.pending_high_scores
        self._state.pending_high_scores = None
        if request is None:
            request = HighScoresRequest(game_mode_id=int(self._state.config.data.get("game_mode", 1) or 1))

        if int(request.game_mode_id) == 3 and (int(request.quest_stage_major) <= 0 or int(request.quest_stage_minor) <= 0):
            major, minor = self._parse_quest_level(self._state.pending_quest_level)
            if major <= 0 or minor <= 0:
                major, minor = self._parse_quest_level(self._state.config.data.get("quest_level"))
            if major <= 0 or minor <= 0:
                major = int(self._state.config.data.get("quest_stage_major", 0) or 0)
                minor = int(self._state.config.data.get("quest_stage_minor", 0) or 0)
            request.quest_stage_major = int(major)
            request.quest_stage_minor = int(minor)

        self._request = request
        path = scores_path_for_mode(
            self._state.base_dir,
            int(request.game_mode_id),
            hardcore=bool(int(self._state.config.data.get("hardcore_flag", 0) or 0)),
            quest_stage_major=int(request.quest_stage_major),
            quest_stage_minor=int(request.quest_stage_minor),
        )
        try:
            self._records = read_highscore_table(path, game_mode_id=int(request.game_mode_id))
        except Exception:
            self._records = []
        if self._state.audio is not None:
            play_sfx(self._state.audio, "sfx_ui_panelclick", rng=self._state.rng)

    def close(self) -> None:
        if self._small_font is not None:
            rl.unload_texture(self._small_font.texture)
            self._small_font = None
        self._button_tex = None
        self._button_textures = None
        self._request = None
        self._records = []
        self._scroll_index = 0

    def update(self, dt: float) -> None:
        if self._state.audio is not None:
            update_audio(self._state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        self._cursor_pulse_time += min(dt, 0.1) * 1.1

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            if self._state.audio is not None:
                play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
            self._action = "back_to_previous"
            return

        textures = self._button_textures
        if textures is not None and (textures.button_sm is not None or textures.button_md is not None):
            scale = 0.9 if float(self._state.config.screen_width) < 641.0 else 1.0
            button_w = button_width(None, self._back_button.label, scale=scale, force_wide=self._back_button.force_wide)
            button_h = 32.0 * scale
            gap_x = 18.0 * scale
            x0 = 32.0
            y0 = float(rl.get_screen_height()) - button_h - 52.0 * scale
            mouse = rl.get_mouse_position()
            click = rl.is_mouse_button_pressed(rl.MOUSE_BUTTON_LEFT)
            dt_ms = min(float(dt), 0.1) * 1000.0
            if button_update(self._back_button, x=x0, y=y0, width=button_w, dt_ms=dt_ms, mouse=mouse, click=click):
                if self._state.audio is not None:
                    play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
                self._action = "back_to_previous"
                return
            if button_update(
                self._main_menu_button,
                x=x0 + button_w + gap_x,
                y=y0,
                width=button_w,
                dt_ms=dt_ms,
                mouse=mouse,
                click=click,
            ):
                if self._state.audio is not None:
                    play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
                self._action = "back_to_menu"
                return

        font = self._ensure_small_font()
        rows = self._visible_rows(font)
        max_scroll = max(0, len(self._records) - rows)

        wheel = int(rl.get_mouse_wheel_move())
        if wheel:
            self._scroll_index = max(0, min(max_scroll, int(self._scroll_index) - wheel))

        if rl.is_key_pressed(rl.KeyboardKey.KEY_UP):
            self._scroll_index = max(0, int(self._scroll_index) - 1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_DOWN):
            self._scroll_index = min(max_scroll, int(self._scroll_index) + 1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_PAGE_UP):
            self._scroll_index = max(0, int(self._scroll_index) - rows)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_PAGE_DOWN):
            self._scroll_index = min(max_scroll, int(self._scroll_index) + rows)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_HOME):
            self._scroll_index = 0
        if rl.is_key_pressed(rl.KeyboardKey.KEY_END):
            self._scroll_index = max_scroll

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        if self._ground is not None:
            self._ground.draw(0.0, 0.0)
        _draw_screen_fade(self._state)

        font = self._ensure_small_font()
        request = self._request
        mode_id = int(request.game_mode_id) if request is not None else int(self._state.config.data.get("game_mode", 1) or 1)
        quest_major = int(request.quest_stage_major) if request is not None else 0
        quest_minor = int(request.quest_stage_minor) if request is not None else 0
        highlight_rank = request.highlight_rank if request is not None else None

        title = "High scores"
        subtitle = self._mode_label(mode_id, quest_major, quest_minor)
        draw_small_text(font, title, 32.0, 120.0, 1.2, rl.Color(235, 235, 235, 255))
        draw_small_text(font, subtitle, 32.0, 152.0, 1.0, rl.Color(190, 190, 200, 255))

        header_color = rl.Color(255, 255, 255, int(255 * 0.85))
        row_y0 = 188.0
        draw_small_text(font, "Rank", 32.0, row_y0, 1.0, header_color)
        draw_small_text(font, "Name", 96.0, row_y0, 1.0, header_color)
        score_label = "Score" if mode_id not in (2, 3) else "Time"
        draw_small_text(font, score_label, 320.0, row_y0, 1.0, header_color)

        row_step = float(font.cell_size)
        rows = self._visible_rows(font)
        start = max(0, int(self._scroll_index))
        end = min(len(self._records), start + rows)
        y = row_y0 + row_step

        if start >= end:
            draw_small_text(font, "No scores yet.", 32.0, y + 8.0, 1.0, rl.Color(190, 190, 200, 255))
        else:
            for idx in range(start, end):
                entry = self._records[idx]
                name = ""
                try:
                    name = str(entry.name())
                except Exception:
                    name = ""
                if not name:
                    name = "???"
                if len(name) > 16:
                    name = name[:16]

                value = ""
                if mode_id in (2, 3):
                    seconds = float(int(getattr(entry, "survival_elapsed_ms", 0))) * 0.001
                    value = f"{seconds:7.2f}s"
                else:
                    value = f"{int(getattr(entry, 'score_xp', 0)):7d}"

                color = rl.Color(255, 255, 255, int(255 * 0.7))
                if highlight_rank is not None and int(highlight_rank) == idx:
                    color = rl.Color(255, 255, 255, 255)

                draw_small_text(font, f"{idx + 1:>3}", 32.0, y, 1.0, color)
                draw_small_text(font, name, 96.0, y, 1.0, color)
                draw_small_text(font, value, 320.0, y, 1.0, color)
                y += row_step

        textures = self._button_textures
        if textures is not None and (textures.button_sm is not None or textures.button_md is not None):
            scale = 0.9 if float(self._state.config.screen_width) < 641.0 else 1.0
            button_w = button_width(None, self._back_button.label, scale=scale, force_wide=self._back_button.force_wide)
            button_h = 32.0 * scale
            gap_x = 18.0 * scale
            x0 = 32.0
            y0 = float(rl.get_screen_height()) - button_h - 52.0 * scale
            x1 = x0 + button_w + gap_x
            button_draw(textures, font, self._back_button, x=x0, y=y0, width=button_w, scale=scale)
            button_draw(textures, font, self._main_menu_button, x=x1, y=y0, width=button_w, scale=scale)

        draw_small_text(
            font,
            "UP/DOWN: Scroll    PGUP/PGDN: Page    ESC: Back",
            32.0,
            float(rl.get_screen_height()) - 28.0,
            1.0,
            rl.Color(190, 190, 200, 255),
        )
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

    def _visible_rows(self, font: SmallFontData) -> int:
        row_step = float(font.cell_size)
        table_top = 188.0 + row_step
        reserved_bottom = 96.0
        available = max(0.0, float(rl.get_screen_height()) - table_top - reserved_bottom)
        return max(1, int(available // row_step))

    @staticmethod
    def _parse_quest_level(level: str | None) -> tuple[int, int]:
        if not level:
            return (0, 0)
        try:
            major_text, minor_text = str(level).split(".", 1)
            return (int(major_text), int(minor_text))
        except Exception:
            return (0, 0)

    @staticmethod
    def _mode_label(mode_id: int, quest_major: int, quest_minor: int) -> str:
        if int(mode_id) == 1:
            return "Survival"
        if int(mode_id) == 2:
            return "Rush"
        if int(mode_id) == 4:
            return "Typ-o Shooter"
        if int(mode_id) == 3:
            if int(quest_major) > 0 and int(quest_minor) > 0:
                return f"Quest {int(quest_major)}.{int(quest_minor)}"
            return "Quests"
        return f"Mode {int(mode_id)}"


class GameLoopView:
    def __init__(self, state: GameState) -> None:
        self._state = state
        self._boot = BootView(state)
        self._demo = DemoView(state)
        self._menu = MenuView(state)
        self._front_views: dict[str, FrontView] = {
            "open_play_game": PlayGameMenuView(state),
            "open_quests": QuestsMenuView(state),
            "open_pause_menu": PauseMenuView(state),
            "start_quest": QuestGameView(state),
            "quest_results": QuestResultsView(state),
            "quest_failed": QuestFailedView(state),
            "open_high_scores": HighScoresView(state),
            "start_survival": SurvivalGameView(state),
            "start_rush": RushGameView(state),
            "start_typo": TypoShooterGameView(state),
            "start_tutorial": TutorialGameView(state),
            "open_options": OptionsMenuView(state),
            "open_controls": ControlsMenuView(state),
            "open_statistics": StatisticsMenuView(state),
            "open_mods": ModsMenuView(state),
            "open_other_games": PanelMenuView(
                state,
                title="Other games",
                body="This menu is out of scope for the rewrite.",
            ),
        }
        self._front_active: FrontView | None = None
        self._front_stack: list[FrontView] = []
        self._active: View = self._boot
        self._demo_trial_overlay = DemoTrialOverlayUi(state.assets_dir)
        self._demo_trial_info = None
        self._demo_active = False
        self._menu_active = False
        self._quit_after_demo = False
        self._screenshot_requested = False
        self._gameplay_views = frozenset(
            {
                self._front_views["start_survival"],
                self._front_views["start_rush"],
                self._front_views["start_typo"],
                self._front_views["start_tutorial"],
                self._front_views["start_quest"],
            }
        )

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
        if debug_enabled() and (not console.open_flag) and rl.is_key_pressed(rl.KeyboardKey.KEY_P):
            self._screenshot_requested = True
        if console.open_flag:
            if console.quit_requested:
                self._state.quit_requested = True
                console.quit_requested = False
            return

        self._demo_trial_info = None
        if self._front_active is not None and self._front_active in self._gameplay_views:
            if self._update_demo_trial_overlay(dt):
                return

        self._active.update(dt)
        if self._front_active is not None:
            action = self._front_active.take_action()
            if action == "back_to_menu":
                self._state.pause_background = None
                self._front_active.close()
                self._front_active = None
                while self._front_stack:
                    self._front_stack.pop().close()
                self._menu.open()
                self._active = self._menu
                self._menu_active = True
                return
            if action == "back_to_previous":
                if self._front_stack:
                    self._front_active.close()
                    self._front_active = self._front_stack.pop()
                    if self._front_active in self._gameplay_views:
                        self._state.pause_background = None
                    self._active = self._front_active
                    return
                self._front_active.close()
                self._front_active = None
                self._state.pause_background = None
                self._menu.open()
                self._active = self._menu
                self._menu_active = True
                return
            if action == "open_pause_menu":
                pause_view = self._front_views.get("open_pause_menu")
                if pause_view is None:
                    return
                if self._front_active in self._gameplay_views:
                    self._state.pause_background = self._front_active
                    self._front_stack.append(self._front_active)
                    pause_view.open()
                    self._front_active = pause_view
                    self._active = pause_view
                    return
                if self._state.pause_background is None:
                    # Options panel uses open_pause_menu as back_action; when no game is
                    # running, treat it like back_to_menu.
                    self._front_active.close()
                    self._front_active = None
                    while self._front_stack:
                        self._front_stack.pop().close()
                    self._menu.open()
                    self._active = self._menu
                    self._menu_active = True
                    return
                self._front_active.close()
                pause_view.open()
                self._front_active = pause_view
                self._active = pause_view
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
                    if action == "open_high_scores":
                        self._front_stack.append(self._front_active)
                    else:
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

    def _update_demo_trial_overlay(self, dt: float) -> bool:
        if not self._state.demo_enabled:
            return False

        mode_id = int(self._state.config.data.get("game_mode", 0) or 0)
        quest_major, quest_minor = 0, 0
        if mode_id == 3:
            level = self._state.pending_quest_level or ""
            try:
                major_text, minor_text = level.split(".", 1)
                quest_major = int(major_text)
                quest_minor = int(minor_text)
            except Exception:
                quest_major, quest_minor = 0, 0

        current = demo_trial_overlay_info(
            demo_build=True,
            game_mode_id=mode_id,
            global_playtime_ms=int(self._state.status.game_sequence_id),
            quest_grace_elapsed_ms=int(self._state.demo_trial_elapsed_ms),
            quest_stage_major=int(quest_major),
            quest_stage_minor=int(quest_minor),
        )

        frame_dt = min(float(dt), 0.1)
        dt_ms = int(frame_dt * 1000.0)
        used_ms, grace_ms = tick_demo_trial_timers(
            demo_build=True,
            game_mode_id=int(mode_id),
            overlay_visible=bool(current.visible),
            global_playtime_ms=int(self._state.status.game_sequence_id),
            quest_grace_elapsed_ms=int(self._state.demo_trial_elapsed_ms),
            dt_ms=int(dt_ms),
        )
        if used_ms != int(self._state.status.game_sequence_id):
            self._state.status.game_sequence_id = int(used_ms)
        self._state.demo_trial_elapsed_ms = int(grace_ms)

        info = demo_trial_overlay_info(
            demo_build=True,
            game_mode_id=mode_id,
            global_playtime_ms=int(self._state.status.game_sequence_id),
            quest_grace_elapsed_ms=int(self._state.demo_trial_elapsed_ms),
            quest_stage_major=int(quest_major),
            quest_stage_minor=int(quest_minor),
        )
        self._demo_trial_info = info
        if not info.visible:
            return False

        self._demo_trial_overlay.bind_cache(self._state.texture_cache)
        action = self._demo_trial_overlay.update(dt_ms)
        if action == "purchase":
            try:
                webbrowser.open(DEMO_PURCHASE_URL)
            except Exception:
                pass
            return True

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) or action == "maybe_later":
            if self._front_active is not None:
                self._front_active.close()
                self._front_active = None
            while self._front_stack:
                self._front_stack.pop().close()
            self._menu.open()
            self._active = self._menu
            self._menu_active = True
            return True

        return True

    def consume_screenshot_request(self) -> bool:
        requested = self._screenshot_requested
        self._screenshot_requested = False
        return requested

    def draw(self) -> None:
        self._active.draw()
        info = self._demo_trial_info
        if info is not None and getattr(info, "visible", False):
            self._demo_trial_overlay.bind_cache(self._state.texture_cache)
            self._demo_trial_overlay.draw(info)
        self._state.console.draw()

    def close(self) -> None:
        if self._menu_active:
            self._menu.close()
        if self._front_active is not None:
            self._front_active.close()
        while self._front_stack:
            self._front_stack.pop().close()
        if self._demo_active:
            self._demo.close()
        self._demo_trial_overlay.close()
        if self._state.menu_ground is not None and self._state.menu_ground.render_target is not None:
            rl.unload_render_texture(self._state.menu_ground.render_target)
            self._state.menu_ground.render_target = None
        self._boot.close()
        self._state.console.close()
        rl.show_cursor()


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

    def cmd_demo_trial_set_playtime(args: list[str]) -> None:
        if len(args) != 1:
            console.log.log("demoTrialSetPlaytime <ms>")
            return
        try:
            value = int(float(args[0]))
        except ValueError:
            value = 0
        state.status.game_sequence_id = max(0, value)
        state.status.save_if_dirty()
        console.log.log(f"demo trial: playtime={state.status.game_sequence_id}ms (total {DEMO_TOTAL_PLAY_TIME_MS}ms)")

    def cmd_demo_trial_set_grace(args: list[str]) -> None:
        if len(args) != 1:
            console.log.log("demoTrialSetGrace <ms>")
            return
        try:
            value = int(float(args[0]))
        except ValueError:
            value = 0
        state.demo_trial_elapsed_ms = max(0, value)
        console.log.log(
            f"demo trial: quest grace={state.demo_trial_elapsed_ms}ms (total {DEMO_QUEST_GRACE_TIME_MS}ms)"
        )

    def cmd_demo_trial_reset(_args: list[str]) -> None:
        state.status.game_sequence_id = 0
        state.status.save_if_dirty()
        state.demo_trial_elapsed_ms = 0
        console.log.log("demo trial: timers reset")

    def cmd_demo_trial_info(_args: list[str]) -> None:
        mode_id = int(state.config.data.get("game_mode", 0) or 0)
        quest_major = 0
        quest_minor = 0
        if mode_id == 3:
            level = state.pending_quest_level or ""
            try:
                major_text, minor_text = level.split(".", 1)
                quest_major = int(major_text)
                quest_minor = int(minor_text)
            except Exception:
                quest_major, quest_minor = 0, 0
        info = demo_trial_overlay_info(
            demo_build=bool(state.demo_enabled),
            game_mode_id=mode_id,
            global_playtime_ms=int(state.status.game_sequence_id),
            quest_grace_elapsed_ms=int(state.demo_trial_elapsed_ms),
            quest_stage_major=int(quest_major),
            quest_stage_minor=int(quest_minor),
        )
        remaining = format_demo_trial_time(info.remaining_ms)
        console.log.log(
            "demo trial: "
            f"demo={int(state.demo_enabled)} "
            f"mode={mode_id} "
            f"quest={quest_major}.{quest_minor} "
            f"playtime={int(state.status.game_sequence_id)}ms "
            f"grace={int(state.demo_trial_elapsed_ms)}ms "
            f"visible={int(info.visible)} "
            f"kind={info.kind} "
            f"remaining={remaining}"
        )

    return {
        "setGammaRamp": cmd_set_gamma_ramp,
        "snd_addGameTune": cmd_snd_add_game_tune,
        "generateterrain": cmd_generate_terrain,
        "telltimesurvived": cmd_tell_time_survived,
        "setresourcepaq": cmd_set_resource_paq,
        "loadtexture": cmd_load_texture,
        "openurl": cmd_open_url,
        "sndfreqadjustment": cmd_snd_freq_adjustment,
        "demoTrialSetPlaytime": cmd_demo_trial_set_playtime,
        "demoTrialSetGrace": cmd_demo_trial_set_grace,
        "demoTrialReset": cmd_demo_trial_reset,
        "demoTrialInfo": cmd_demo_trial_info,
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
            demo_enabled=bool(config.demo_enabled),
            skip_intro=bool(config.no_intro),
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
        download_missing_paqs(assets_dir, console)
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
            exit_key=rl.KeyboardKey.KEY_NULL,
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
