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
from typing import Protocol, TYPE_CHECKING, cast

import pyray as rl

from grim.audio import (
    AudioState,
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
from grim.geom import Rect, Vec2
from grim.app import run_view
from grim.terrain_render import GroundRenderer
from grim.view import View, ViewContext
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width

from .debug import debug_enabled, set_debug_enabled
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
from .frontend.high_scores_layout import (
    HS_BACK_BUTTON_X,
    HS_BACK_BUTTON_Y,
    HS_BUTTON_STEP_Y,
    HS_BUTTON_X,
    HS_BUTTON_Y0,
    HS_LOCAL_DATE_Y,
    HS_LOCAL_DATE_CENTER_X,
    HS_LOCAL_FRAGS_X,
    HS_LOCAL_FRAGS_Y,
    HS_LOCAL_HIT_X,
    HS_LOCAL_HIT_Y,
    HS_LOCAL_LABEL_X,
    HS_LOCAL_LABEL_Y,
    HS_LOCAL_NAME_X,
    HS_LOCAL_NAME_Y,
    HS_LOCAL_RANK_X,
    HS_LOCAL_RANK_Y,
    HS_LOCAL_SCORE_LABEL_X,
    HS_LOCAL_SCORE_LABEL_Y,
    HS_LOCAL_SCORE_VALUE_X,
    HS_LOCAL_SCORE_VALUE_Y,
    HS_LOCAL_CLOCK_X,
    HS_LOCAL_CLOCK_Y,
    HS_LOCAL_TIME_LABEL_X,
    HS_LOCAL_TIME_LABEL_Y,
    HS_LOCAL_TIME_VALUE_X,
    HS_LOCAL_TIME_VALUE_Y,
    HS_LOCAL_WEAPON_X,
    HS_LOCAL_WEAPON_Y,
    HS_LOCAL_WICON_X,
    HS_LOCAL_WICON_Y,
    HS_LEFT_PANEL_HEIGHT,
    HS_LEFT_PANEL_POS_X,
    HS_LEFT_PANEL_POS_Y,
    HS_QUEST_ARROW_X,
    HS_QUEST_ARROW_Y,
    HS_RIGHT_CHECK_X,
    HS_RIGHT_CHECK_Y,
    HS_RIGHT_PANEL_HEIGHT,
    HS_RIGHT_PANEL_POS_Y,
    HS_RIGHT_GAME_MODE_DROP_X,
    HS_RIGHT_GAME_MODE_DROP_Y,
    HS_RIGHT_GAME_MODE_VALUE_X,
    HS_RIGHT_GAME_MODE_VALUE_Y,
    HS_RIGHT_GAME_MODE_WIDGET_W,
    HS_RIGHT_GAME_MODE_WIDGET_X,
    HS_RIGHT_GAME_MODE_WIDGET_Y,
    HS_RIGHT_GAME_MODE_X,
    HS_RIGHT_GAME_MODE_Y,
    HS_RIGHT_NUMBER_PLAYERS_X,
    HS_RIGHT_NUMBER_PLAYERS_Y,
    HS_RIGHT_PLAYER_COUNT_DROP_X,
    HS_RIGHT_PLAYER_COUNT_DROP_Y,
    HS_RIGHT_PLAYER_COUNT_VALUE_X,
    HS_RIGHT_PLAYER_COUNT_VALUE_Y,
    HS_RIGHT_PLAYER_COUNT_WIDGET_W,
    HS_RIGHT_PLAYER_COUNT_WIDGET_X,
    HS_RIGHT_PLAYER_COUNT_WIDGET_Y,
    HS_RIGHT_SCORE_LIST_DROP_X,
    HS_RIGHT_SCORE_LIST_DROP_Y,
    HS_RIGHT_SCORE_LIST_VALUE_X,
    HS_RIGHT_SCORE_LIST_VALUE_Y,
    HS_RIGHT_SCORE_LIST_WIDGET_W,
    HS_RIGHT_SCORE_LIST_WIDGET_X,
    HS_RIGHT_SCORE_LIST_WIDGET_Y,
    HS_RIGHT_SCORE_LIST_X,
    HS_RIGHT_SCORE_LIST_Y,
    HS_RIGHT_SHOW_INTERNET_X,
    HS_RIGHT_SHOW_INTERNET_Y,
    HS_RIGHT_SHOW_SCORES_DROP_X,
    HS_RIGHT_SHOW_SCORES_DROP_Y,
    HS_RIGHT_SHOW_SCORES_VALUE_X,
    HS_RIGHT_SHOW_SCORES_VALUE_Y,
    HS_RIGHT_SHOW_SCORES_WIDGET_W,
    HS_RIGHT_SHOW_SCORES_WIDGET_X,
    HS_RIGHT_SHOW_SCORES_WIDGET_Y,
    HS_RIGHT_SHOW_SCORES_X,
    HS_RIGHT_SHOW_SCORES_Y,
    HS_SCORE_FRAME_H,
    HS_SCORE_FRAME_W,
    HS_SCORE_FRAME_X,
    HS_SCORE_FRAME_Y,
    HS_TITLE_UNDERLINE_Y,
    hs_right_panel_pos_x,
)
from .frontend.menu import (
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
from .frontend.panels.base import PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS, PanelMenuView
from .frontend.panels.controls import ControlsMenuView
from .frontend.panels.credits import CreditsView
from .frontend.panels.databases import UnlockedPerksDatabaseView, UnlockedWeaponsDatabaseView
from .frontend.panels.mods import ModsMenuView
from .frontend.panels.options import OptionsMenuView
from .frontend.panels.play_game import PlayGameMenuView
from .frontend.panels.stats import StatisticsMenuView
from .frontend.pause_menu import PauseMenuView
from .frontend.transitions import _draw_screen_fade, _update_screen_fade
from .persistence.save_status import GameStatus, ensure_game_status
from .ui.demo_trial_overlay import DEMO_PURCHASE_URL, DemoTrialOverlayUi
from .ui.menu_panel import draw_classic_menu_panel
from .ui.perk_menu import UiButtonState, UiButtonTextureSet, button_draw, button_update, button_width
from .paths import default_runtime_dir
from .assets_fetch import download_missing_paqs

if TYPE_CHECKING:
    from .modes.quest_mode import QuestRunOutcome
    from .persistence.highscores import HighScoreRecord


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
    debug: bool = False
    preserve_bugs: bool = False


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
    preserve_bugs: bool
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
QUEST_MENU_PANEL_OFFSET_X = -63.0

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

QUEST_BACK_BUTTON_X_OFFSET = 138.0
QUEST_BACK_BUTTON_Y_OFFSET = 212.0
QUEST_PANEL_HEIGHT = 378.0


@dataclass(frozen=True, slots=True)
class _QuestMenuLayout:
    title_pos: Vec2
    icons_start_pos: Vec2
    list_pos: Vec2


# game_update_victory_screen (0x00406350): used as the "end note" screen after the final quest.
END_NOTE_PANEL_POS_X = -45.0
END_NOTE_PANEL_POS_Y = 110.0
END_NOTE_PANEL_GEOM_X0 = -63.0
END_NOTE_PANEL_GEOM_Y0 = -81.0
END_NOTE_PANEL_W = 510.0
END_NOTE_PANEL_H = 378.0

END_NOTE_HEADER_X_OFFSET = 214.0  # v11 + 44 - 10 in the decompile, relative to panel-left
END_NOTE_HEADER_Y_OFFSET = 46.0  # (base_y + 40) + 6 in the decompile, relative to panel-top
END_NOTE_BODY_X_OFFSET = END_NOTE_HEADER_X_OFFSET - 8.0
END_NOTE_BODY_Y_GAP = 32.0
END_NOTE_LINE_STEP_Y = 14.0
END_NOTE_AFTER_BODY_Y_GAP = 22.0  # 14 + 8 in the decompile

END_NOTE_BUTTON_X_OFFSET = 266.0  # (v11 + 44 + 20) - 4 + 26, relative to panel-left
END_NOTE_BUTTON_Y_OFFSET = 210.0  # (base_y + 40) + 170 in the decompile, relative to panel-top
END_NOTE_BUTTON_STEP_Y = 32.0

# `quest_failed_screen_update` panel geometry/anchors:
# - panel is the classic ui_menuPanel at (-45, 110) with geom x0/y0 (-63, -81)
# - reaper banner X = panel-left + 214; message/buttons are derived from that anchor.
QUEST_FAILED_PANEL_POS_X = -45.0
QUEST_FAILED_PANEL_POS_Y = 110.0
QUEST_FAILED_PANEL_GEOM_X0 = -63.0
QUEST_FAILED_PANEL_GEOM_Y0 = -81.0
QUEST_FAILED_PANEL_W = 510.0
QUEST_FAILED_PANEL_H = 378.0

QUEST_FAILED_BANNER_X_OFFSET = 214.0
QUEST_FAILED_BANNER_Y_OFFSET = 40.0
QUEST_FAILED_BANNER_W = 256.0
QUEST_FAILED_BANNER_H = 64.0

QUEST_FAILED_MESSAGE_X_OFFSET = QUEST_FAILED_BANNER_X_OFFSET + 30.0
QUEST_FAILED_MESSAGE_Y_OFFSET = 126.0  # (base_y + 40) + 70 + 16
QUEST_FAILED_SCORE_X_OFFSET = QUEST_FAILED_BANNER_X_OFFSET + 40.0
QUEST_FAILED_SCORE_Y_OFFSET = 152.0  # message_y + 16 + 10 in native
QUEST_FAILED_BUTTON_X_OFFSET = QUEST_FAILED_BANNER_X_OFFSET + 52.0
QUEST_FAILED_BUTTON_Y_OFFSET = 240.0  # score_y baseline + 98 in native
QUEST_FAILED_BUTTON_STEP_Y = 32.0


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
        self._panel_tex: rl.Texture | None = None

        self._small_font: SmallFontData | None = None
        self._text_quest: rl.Texture | None = None
        self._stage_icons: dict[int, rl.Texture | None] = {}
        self._check_on: rl.Texture | None = None
        self._check_off: rl.Texture | None = None
        self._button_sm: rl.Texture | None = None
        self._button_md: rl.Texture | None = None
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
        status = self._state.status

        # The original forcibly clears hardcore in the demo build.
        if self._state.demo_enabled:
            if int(config.data.get("hardcore_flag", 0) or 0) != 0:
                config.data["hardcore_flag"] = 0
                self._dirty = True

        if debug_enabled() and rl.is_key_pressed(rl.KeyboardKey.KEY_F5):
            unlock = 49
            if int(status.quest_unlock_index) < unlock:
                status.quest_unlock_index = unlock
            if int(status.quest_unlock_index_full) < unlock:
                status.quest_unlock_index_full = unlock
            self._state.console.log.log("debug: unlocked all quests")

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
        if hovered_stage is not None and rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
            self._stage = hovered_stage
            return

        if self._hardcore_checkbox_clicked(layout):
            return

        textures = self._button_textures
        if textures is not None and (textures.button_sm is not None or textures.button_md is not None):
            back_pos = Vec2(layout.list_pos.x, self._rows_y0(layout)) + Vec2(
                QUEST_BACK_BUTTON_X_OFFSET,
                QUEST_BACK_BUTTON_Y_OFFSET,
            )
            dt_ms = min(float(dt), 0.1) * 1000.0
            font = self._ensure_small_font()
            back_w = button_width(font, self._back_button.label, scale=1.0, force_wide=self._back_button.force_wide)
            mouse = rl.get_mouse_position()
            click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
            if button_update(
                self._back_button,
                pos=back_pos,
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
        if hovered_row is not None and rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
            self._try_start_quest(self._stage, hovered_row)
            return

        if hovered_row is not None and rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER):
            self._try_start_quest(self._stage, hovered_row)
            return

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        if self._ground is not None:
            self._ground.draw(Vec2())

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

    def _layout(self) -> _QuestMenuLayout:
        # `sub_447d40` base sums:
        #   x_sum = <ui_element_x> + <ui_element_offset_x>  (x=-5)
        #   y_sum = <ui_element_y> + <ui_element_offset_y>  (y=185 + widescreen shift via ui_menu_layout_init)
        x_sum = QUEST_MENU_BASE_X + QUEST_MENU_PANEL_OFFSET_X
        y_sum = QUEST_MENU_BASE_Y + MENU_PANEL_OFFSET_Y + self._widescreen_y_shift

        title_pos = Vec2(x_sum + QUEST_TITLE_X_OFFSET, y_sum + QUEST_TITLE_Y_OFFSET)
        icons_start_pos = title_pos + Vec2(QUEST_STAGE_ICON_X_OFFSET, QUEST_STAGE_ICON_Y_OFFSET)
        last_icon_x = icons_start_pos.x + QUEST_STAGE_ICON_STEP * 4.0
        list_pos = Vec2(last_icon_x - 208.0 + 16.0, title_pos.y + QUEST_LIST_Y_OFFSET)
        return _QuestMenuLayout(
            title_pos=title_pos,
            icons_start_pos=icons_start_pos,
            list_pos=list_pos,
        )

    def _hovered_stage(self, layout: _QuestMenuLayout) -> int | None:
        title_y = layout.title_pos.y
        x0 = layout.icons_start_pos.x
        mouse_pos = Vec2.from_xy(rl.get_mouse_position())
        for stage in range(1, 6):
            x = x0 + float(stage - 1) * QUEST_STAGE_ICON_STEP
            # Hover bounds are fixed 32x32, anchored at (x, title_y) (not icons_y).
            stage_rect = Rect.from_top_left(Vec2(x, title_y), QUEST_STAGE_ICON_SIZE, QUEST_STAGE_ICON_SIZE)
            if stage_rect.contains(mouse_pos):
                return stage
        return None

    def _hardcore_checkbox_clicked(self, layout: _QuestMenuLayout) -> bool:
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

        check_pos = layout.list_pos + Vec2(QUEST_HARDCORE_CHECKBOX_X_OFFSET, QUEST_HARDCORE_CHECKBOX_Y_OFFSET)
        rect_w = float(check_on.width) + 6.0 + label_w
        rect_h = max(float(check_on.height), font.cell_size * text_scale)

        mouse_pos = Vec2.from_xy(rl.get_mouse_position())
        hovered = Rect.from_top_left(check_pos, rect_w, rect_h).contains(mouse_pos)
        if hovered and rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
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

    def _rows_y0(self, layout: _QuestMenuLayout) -> float:
        # `sub_447d40` adds +10 to the list Y after rendering the Hardcore checkbox.
        status = self._state.status
        y0 = layout.list_pos.y
        if int(status.quest_unlock_index) >= QUEST_HARDCORE_UNLOCK_INDEX:
            y0 += QUEST_HARDCORE_LIST_Y_SHIFT
        return y0

    def _hovered_row(self, layout: _QuestMenuLayout) -> int | None:
        list_x = layout.list_pos.x
        y0 = self._rows_y0(layout)
        mouse_pos = Vec2.from_xy(rl.get_mouse_position())
        for row in range(10):
            y = y0 + float(row) * QUEST_LIST_ROW_STEP
            left = list_x - QUEST_LIST_HOVER_LEFT_PAD
            top = y - QUEST_LIST_HOVER_TOP_PAD
            right = list_x + QUEST_LIST_HOVER_RIGHT_PAD
            bottom = y + QUEST_LIST_HOVER_BOTTOM_PAD
            row_rect = Rect.from_top_left(Vec2(left, top), right - left, bottom - top)
            if row_rect.contains(mouse_pos):
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
        title_pos = layout.title_pos
        icons_start_pos = layout.icons_start_pos
        list_pos = layout.list_pos

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
                rl.Rectangle(title_pos.x, title_pos.y, QUEST_TITLE_W, QUEST_TITLE_H),
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
            x = icons_start_pos.x + float(idx - 1) * QUEST_STAGE_ICON_STEP
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
                rl.Rectangle(x, icons_start_pos.y, size, size),
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
                check_pos = list_pos + Vec2(QUEST_HARDCORE_CHECKBOX_X_OFFSET, QUEST_HARDCORE_CHECKBOX_Y_OFFSET)
                rl.draw_texture_pro(
                    check_tex,
                    rl.Rectangle(0.0, 0.0, float(check_tex.width), float(check_tex.height)),
                    rl.Rectangle(check_pos.x, check_pos.y, float(check_tex.width), float(check_tex.height)),
                    rl.Vector2(0.0, 0.0),
                    0.0,
                    rl.WHITE,
                )
                draw_small_text(
                    font,
                    "Hardcore",
                    check_pos + Vec2(float(check_tex.width) + 6.0, 1.0),
                    1.0,
                    base_color,
                )

        # Quest list (10 rows).
        for row in range(10):
            y = y0 + float(row) * QUEST_LIST_ROW_STEP
            unlocked = self._quest_unlocked(stage, row)
            color = hover_color if hovered_row == row else base_color

            draw_small_text(font, f"{stage}.{row + 1}", Vec2(list_pos.x, y), 1.0, color)

            if unlocked:
                title = self._quest_title(stage, row)
            else:
                title = "???"
            draw_small_text(font, title, Vec2(list_pos.x + QUEST_LIST_NAME_X_OFFSET, y), 1.0, color)
            title_w = measure_small_text_width(font, title, 1.0) if unlocked else 0.0
            if unlocked:
                line_y = y + 13.0
                rl.draw_line(int(list_pos.x), int(line_y), int(list_pos.x + title_w + 32.0), int(line_y), color)

            if show_counts and unlocked:
                counts = self._quest_counts(stage=stage, row=row)
                if counts is not None:
                    completed, games = counts
                    counts_x = list_pos.x + QUEST_LIST_NAME_X_OFFSET + title_w + 12.0
                    draw_small_text(font, f"({completed}/{games})", Vec2(counts_x, y), 1.0, color)

        if show_counts:
            # Header is drawn below the list, aligned with the count column.
            header_x = list_pos.x + 96.0
            header_y = y0 + QUEST_LIST_ROW_STEP * 10.0 - 2.0
            draw_small_text(font, "(completed/games)", Vec2(header_x, header_y), 1.0, base_color)

        # Back button.
        textures = self._button_textures
        if textures is not None and (textures.button_sm is not None or textures.button_md is not None):
            back_pos = Vec2(list_pos.x, y0) + Vec2(QUEST_BACK_BUTTON_X_OFFSET, QUEST_BACK_BUTTON_Y_OFFSET)
            back_w = button_width(font, self._back_button.label, scale=1.0, force_wide=self._back_button.force_wide)
            button_draw(
                textures,
                font,
                self._back_button,
                pos=back_pos,
                width=float(back_w),
                scale=1.0,
            )

    def _draw_sign(self) -> None:
        assets = self._assets
        if assets is None or assets.sign is None:
            return
        screen_w = float(self._state.config.screen_width)
        scale, shift_x = MenuView._sign_layout_scale(int(screen_w))
        sign_pos = Vec2(
            screen_w + MENU_SIGN_POS_X_PAD,
            MENU_SIGN_POS_Y if screen_w > MENU_SCALE_SMALL_THRESHOLD else MENU_SIGN_POS_Y_SMALL,
        )
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

    def _draw_panel(self) -> None:
        panel = self._panel_tex
        if panel is None:
            return
        fx_detail = bool(self._state.config.data.get("fx_detail_0", 0))
        draw_classic_menu_panel(
            panel,
            dst=rl.Rectangle(
                float(QUEST_MENU_BASE_X + QUEST_MENU_PANEL_OFFSET_X),
                float(QUEST_MENU_BASE_Y + MENU_PANEL_OFFSET_Y + self._widescreen_y_shift),
                float(MENU_PANEL_WIDTH),
                float(QUEST_PANEL_HEIGHT),
            ),
            shadow=fx_detail,
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
            ViewContext(assets_dir=state.assets_dir, preserve_bugs=state.preserve_bugs),
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
            ViewContext(assets_dir=state.assets_dir, preserve_bugs=state.preserve_bugs),
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
            ViewContext(assets_dir=state.assets_dir, preserve_bugs=state.preserve_bugs),
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
            ViewContext(assets_dir=state.assets_dir, preserve_bugs=state.preserve_bugs),
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
            ViewContext(assets_dir=state.assets_dir, preserve_bugs=state.preserve_bugs),
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
        self._quest_level: str = ""
        self._quest_title: str = ""
        self._quest_stage_major = 0
        self._quest_stage_minor = 0
        self._unlock_weapon_name: str = ""
        self._unlock_perk_name: str = ""
        self._ui = None
        self._action: str | None = None

    def open(self) -> None:
        from .persistence.highscores import HighScoreRecord
        from .quests.results import compute_quest_final_time
        from .ui.quest_results import QuestResultsUi

        self._action = None
        self._ground = None if self._state.pause_background is not None else ensure_menu_ground(self._state)
        self._state.quest_fail_retry_count = 0
        outcome = self._state.quest_outcome
        self._state.quest_outcome = None
        self._quest_level = ""
        self._quest_title = ""
        self._quest_stage_major = 0
        self._quest_stage_minor = 0
        self._unlock_weapon_name = ""
        self._unlock_perk_name = ""
        self._ui = None
        if outcome is None:
            return
        self._quest_level = str(outcome.level or "")

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
                    self._unlock_weapon_name = (
                        weapon_entry.name
                        if weapon_entry is not None and weapon_entry.name
                        else f"weapon_{weapon_id_native}"
                    )

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
        player_name_default = _player_name_default(self._state.config) or "Player"
        record.set_name(player_name_default)

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

        self._ui = QuestResultsUi(
            assets_root=self._state.assets_dir,
            base_dir=self._state.base_dir,
            config=self._state.config,
        )
        self._ui.open(
            record=record,
            breakdown=breakdown,
            quest_level=str(outcome.level or ""),
            quest_title=str(self._quest_title or ""),
            quest_stage_major=int(self._quest_stage_major),
            quest_stage_minor=int(self._quest_stage_minor),
            unlock_weapon_name=str(self._unlock_weapon_name or ""),
            unlock_perk_name=str(self._unlock_perk_name or ""),
            player_name_default=player_name_default,
        )

    def close(self) -> None:
        if self._ui is not None:
            self._ui.close()
            self._ui = None
        self._ground = None
        self._quest_stage_major = 0
        self._quest_stage_minor = 0
        self._quest_level = ""
        self._quest_title = ""
        self._unlock_weapon_name = ""
        self._unlock_perk_name = ""

    def update(self, dt: float) -> None:
        if self._state.audio is not None:
            update_audio(self._state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        ui = self._ui
        if ui is None:
            return
        audio = self._state.audio
        rng = self._state.rng

        def _play(name: str) -> None:
            if audio is None:
                return
            play_sfx(audio, name, rng=rng)

        action = ui.update(dt, play_sfx=_play if audio is not None else None, rand=lambda: rng.getrandbits(32))
        if action == "play_again":
            self._state.pending_quest_level = self._quest_level
            self._action = "start_quest"
            return
        if action == "play_next":
            if int(self._quest_stage_major) == 5 and int(self._quest_stage_minor) == 10:
                self._action = "end_note"
                return
            next_level = _next_quest_level(self._quest_level)
            if next_level is not None:
                self._state.pending_quest_level = next_level
                self._action = "start_quest"
            else:
                self._action = "back_to_menu"
            return
        if action == "high_scores":
            self._open_high_scores_list()
            return
        if action == "main_menu":
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
        ui = self._ui
        if ui is not None:
            ui.draw()
            return

        rl.draw_text("Quest results unavailable.", 32, 140, 28, rl.Color(235, 235, 235, 255))
        rl.draw_text("Press ESC to return to the menu.", 32, 180, 18, rl.Color(190, 190, 200, 255))

    def take_action(self) -> str | None:
        action = self._action
        self._action = None
        return action

    def _open_high_scores_list(self) -> None:
        highlight_rank = None
        if self._ui is not None:
            highlight_rank = self._ui.highlight_rank
        self._state.pending_high_scores = HighScoresRequest(
            game_mode_id=3,
            quest_stage_major=int(self._quest_stage_major),
            quest_stage_minor=int(self._quest_stage_minor),
            highlight_rank=highlight_rank,
        )
        self._action = "open_high_scores"


class EndNoteView:
    """Final quest "Show End Note" flow.

    Classic:
      - quest_results_screen_update uses "Show End Note" instead of "Play Next" for quest 5.10
      - clicking it transitions to state 0x15 (game_update_victory_screen @ 0x00406350)
    """

    def __init__(self, state: GameState) -> None:
        self._state = state
        self._ground: GroundRenderer | None = None
        self._small_font: SmallFontData | None = None
        self._panel_tex: rl.Texture | None = None
        self._button_textures: UiButtonTextureSet | None = None
        self._action: str | None = None
        self._cursor_pulse_time = 0.0

        self._survival_button = UiButtonState("Survival", force_wide=True)
        self._rush_button = UiButtonState("  Rush  ", force_wide=True)
        self._typo_button = UiButtonState("Typ'o'Shooter", force_wide=True)
        self._main_menu_button = UiButtonState("Main Menu", force_wide=True)

    def open(self) -> None:
        self._action = None
        self._cursor_pulse_time = 0.0
        self._ground = None if self._state.pause_background is not None else ensure_menu_ground(self._state)

        cache = _ensure_texture_cache(self._state)
        self._panel_tex = cache.get_or_load("ui_menuPanel", "ui/ui_menuPanel.jaz").texture
        button_md = cache.get_or_load("ui_buttonMd", "ui/ui_button_128x32.jaz").texture
        button_sm = cache.get_or_load("ui_buttonSm", "ui/ui_button_64x32.jaz").texture
        self._button_textures = UiButtonTextureSet(button_sm=button_sm, button_md=button_md)
        self._small_font = None

    def close(self) -> None:
        self._ground = None
        self._small_font = None
        self._panel_tex = None
        self._button_textures = None

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
        if textures is None or (textures.button_sm is None and textures.button_md is None):
            return

        screen_w = float(rl.get_screen_width())
        scale = 1.0

        layout_w = screen_w / scale if scale else screen_w
        widescreen_shift_y = MenuView._menu_widescreen_y_shift(layout_w)

        panel_top_left = Vec2(
            (END_NOTE_PANEL_GEOM_X0 + END_NOTE_PANEL_POS_X) * scale,
            (END_NOTE_PANEL_GEOM_Y0 + END_NOTE_PANEL_POS_Y + widescreen_shift_y) * scale,
        )
        button_pos = panel_top_left + Vec2(END_NOTE_BUTTON_X_OFFSET * scale, END_NOTE_BUTTON_Y_OFFSET * scale)

        font = self._ensure_small_font()
        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        dt_ms = min(float(dt), 0.1) * 1000.0

        survival_w = button_width(
            font, self._survival_button.label, scale=scale, force_wide=self._survival_button.force_wide
        )
        if button_update(
            self._survival_button,
            pos=button_pos,
            width=survival_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self._state.config.data["game_mode"] = 1
            if self._state.audio is not None:
                play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
            self._action = "start_survival"
            return

        button_pos = button_pos.offset(dy=END_NOTE_BUTTON_STEP_Y * scale)
        rush_w = button_width(font, self._rush_button.label, scale=scale, force_wide=self._rush_button.force_wide)
        if button_update(
            self._rush_button,
            pos=button_pos,
            width=rush_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self._state.config.data["game_mode"] = 2
            if self._state.audio is not None:
                play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
            self._action = "start_rush"
            return

        button_pos = button_pos.offset(dy=END_NOTE_BUTTON_STEP_Y * scale)
        typo_w = button_width(font, self._typo_button.label, scale=scale, force_wide=self._typo_button.force_wide)
        if button_update(
            self._typo_button,
            pos=button_pos,
            width=typo_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self._state.config.data["game_mode"] = 4
            self._state.screen_fade_alpha = 0.0
            self._state.screen_fade_ramp = True
            if self._state.audio is not None:
                play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
            self._action = "start_typo"
            return

        button_pos = button_pos.offset(dy=END_NOTE_BUTTON_STEP_Y * scale)
        main_w = button_width(
            font, self._main_menu_button.label, scale=scale, force_wide=self._main_menu_button.force_wide
        )
        if button_update(
            self._main_menu_button,
            pos=button_pos,
            width=main_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
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

        panel_tex = self._panel_tex
        if panel_tex is None:
            return

        screen_w = float(rl.get_screen_width())
        scale = 1.0
        layout_w = screen_w / scale if scale else screen_w
        widescreen_shift_y = MenuView._menu_widescreen_y_shift(layout_w)

        panel_top_left = Vec2(
            (END_NOTE_PANEL_GEOM_X0 + END_NOTE_PANEL_POS_X) * scale,
            (END_NOTE_PANEL_GEOM_Y0 + END_NOTE_PANEL_POS_Y + widescreen_shift_y) * scale,
        )
        panel = rl.Rectangle(
            panel_top_left.x,
            panel_top_left.y,
            float(END_NOTE_PANEL_W * scale),
            float(END_NOTE_PANEL_H * scale),
        )

        fx_detail = bool(int(self._state.config.data.get("fx_detail_0", 0) or 0))
        draw_classic_menu_panel(panel_tex, dst=panel, tint=rl.WHITE, shadow=fx_detail)

        font = self._ensure_small_font()
        hardcore = bool(int(self._state.config.data.get("hardcore_flag", 0) or 0))
        header = "   Incredible!" if hardcore else "Congratulations!"
        body_lines = (
            [
                "You've done the thing we all thought was",
                "virtually impossible. To reward your",
                "efforts a new weapon has been unlocked ",
                "for you: Splitter Gun.",
                "",
                "",
            ]
            if hardcore
            else [
                "You've completed all the levels but the battle",
                "isn't over yet! With all of the unlocked perks",
                "and weapons your Survival is just a bit easier.",
                "You can also replay the quests in Hardcore.",
                "As an additional reward for your victorious",
                "playing, a completely new and different game",
                "mode is unlocked for you: Typ'o'Shooter.",
            ]
        )

        header_pos = panel_top_left + Vec2(END_NOTE_HEADER_X_OFFSET * scale, END_NOTE_HEADER_Y_OFFSET * scale)
        header_color = rl.Color(255, 255, 255, int(255 * 0.8))
        body_color = rl.Color(255, 255, 255, int(255 * 0.5))

        draw_small_text(font, header, header_pos, 1.5 * scale, header_color)

        body_pos = Vec2(panel_top_left.x + END_NOTE_BODY_X_OFFSET * scale, header_pos.y + END_NOTE_BODY_Y_GAP * scale)
        for idx, line in enumerate(body_lines):
            draw_small_text(font, line, body_pos, 1.0 * scale, body_color)
            if idx != len(body_lines) - 1:
                body_pos = body_pos.offset(dy=END_NOTE_LINE_STEP_Y * scale)
        body_pos = body_pos.offset(dy=END_NOTE_AFTER_BODY_Y_GAP * scale)
        draw_small_text(font, "Good luck with your battles, trooper!", body_pos, 1.0 * scale, body_color)

        textures = self._button_textures
        if textures is not None and (textures.button_sm is not None or textures.button_md is not None):
            button_pos = panel_top_left + Vec2(END_NOTE_BUTTON_X_OFFSET * scale, END_NOTE_BUTTON_Y_OFFSET * scale)
            survival_w = button_width(
                font, self._survival_button.label, scale=scale, force_wide=self._survival_button.force_wide
            )
            button_draw(textures, font, self._survival_button, pos=button_pos, width=survival_w, scale=scale)
            button_pos = button_pos.offset(dy=END_NOTE_BUTTON_STEP_Y * scale)
            rush_w = button_width(font, self._rush_button.label, scale=scale, force_wide=self._rush_button.force_wide)
            button_draw(textures, font, self._rush_button, pos=button_pos, width=rush_w, scale=scale)
            button_pos = button_pos.offset(dy=END_NOTE_BUTTON_STEP_Y * scale)
            typo_w = button_width(font, self._typo_button.label, scale=scale, force_wide=self._typo_button.force_wide)
            button_draw(textures, font, self._typo_button, pos=button_pos, width=typo_w, scale=scale)
            button_pos = button_pos.offset(dy=END_NOTE_BUTTON_STEP_Y * scale)
            main_w = button_width(
                font, self._main_menu_button.label, scale=scale, force_wide=self._main_menu_button.force_wide
            )
            button_draw(textures, font, self._main_menu_button, pos=button_pos, width=main_w, scale=scale)

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


class QuestFailedView:
    def __init__(self, state: GameState) -> None:
        self._state = state
        self._ground: GroundRenderer | None = None
        self._outcome: QuestRunOutcome | None = None
        self._record: HighScoreRecord | None = None
        self._quest_title: str = ""
        self._action: str | None = None
        self._cursor_pulse_time = 0.0
        self._small_font: SmallFontData | None = None
        self._panel_tex: rl.Texture | None = None
        self._reaper_tex: rl.Texture | None = None
        self._button_textures: UiButtonTextureSet | None = None
        self._retry_button = UiButtonState("Play Again", force_wide=True)
        self._quest_list_button = UiButtonState("Play Another", force_wide=True)
        self._main_menu_button = UiButtonState("Main Menu", force_wide=True)

    def open(self) -> None:
        self._action = None
        self._ground = None if self._state.pause_background is not None else ensure_menu_ground(self._state)
        self._cursor_pulse_time = 0.0
        self._outcome = self._state.quest_outcome
        self._state.quest_outcome = None
        self._quest_title = ""
        self._record = None
        self._small_font = None
        self._panel_tex = None
        self._reaper_tex = None
        self._button_textures = None
        self._retry_button = UiButtonState("Play Again", force_wide=True)
        self._quest_list_button = UiButtonState("Play Another", force_wide=True)
        self._main_menu_button = UiButtonState("Main Menu", force_wide=True)
        outcome = self._outcome
        if outcome is not None:
            try:
                from .quests import quest_by_level

                quest = quest_by_level(outcome.level)
                self._quest_title = quest.title if quest is not None else ""
            except Exception:
                self._quest_title = ""

        self._build_score_preview(outcome)

        cache = _ensure_texture_cache(self._state)
        self._panel_tex = cache.get_or_load("ui_menuPanel", "ui/ui_menuPanel.jaz").texture
        self._reaper_tex = cache.get_or_load("ui_textReaper", "ui/ui_textReaper.jaz").texture
        button_md = cache.get_or_load("ui_buttonMd", "ui/ui_button_128x32.jaz").texture
        button_sm = cache.get_or_load("ui_buttonSm", "ui/ui_button_64x32.jaz").texture
        self._button_textures = UiButtonTextureSet(button_sm=button_sm, button_md=button_md)

    def close(self) -> None:
        self._ground = None
        self._outcome = None
        self._record = None
        self._quest_title = ""
        self._small_font = None
        self._panel_tex = None
        self._reaper_tex = None
        self._button_textures = None

    def update(self, dt: float) -> None:
        if self._state.audio is not None:
            update_audio(self._state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        self._cursor_pulse_time += min(dt, 0.1) * 1.1

        outcome = self._outcome
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._activate_main_menu()
            return
        if outcome is not None and rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER):
            self._activate_retry()
            return
        if rl.is_key_pressed(rl.KeyboardKey.KEY_Q):
            self._activate_play_another()
            return

        panel_top_left = self._panel_origin()
        textures = self._button_textures
        if outcome is None or textures is None or (textures.button_sm is None and textures.button_md is None):
            return
        scale = 1.0

        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        dt_ms = min(float(dt), 0.1) * 1000.0

        font = self._ensure_small_font()
        button_pos = panel_top_left + Vec2(QUEST_FAILED_BUTTON_X_OFFSET * scale, QUEST_FAILED_BUTTON_Y_OFFSET * scale)

        retry_w = button_width(font, self._retry_button.label, scale=scale, force_wide=self._retry_button.force_wide)
        if button_update(
            self._retry_button,
            pos=button_pos,
            width=retry_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self._activate_retry()
            return
        button_pos = button_pos.offset(dy=QUEST_FAILED_BUTTON_STEP_Y * scale)

        play_another_w = button_width(
            font,
            self._quest_list_button.label,
            scale=scale,
            force_wide=self._quest_list_button.force_wide,
        )
        if button_update(
            self._quest_list_button,
            pos=button_pos,
            width=play_another_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self._activate_play_another()
            return
        button_pos = button_pos.offset(dy=QUEST_FAILED_BUTTON_STEP_Y * scale)

        main_menu_w = button_width(
            font,
            self._main_menu_button.label,
            scale=scale,
            force_wide=self._main_menu_button.force_wide,
        )
        if button_update(
            self._main_menu_button,
            pos=button_pos,
            width=main_menu_w,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self._activate_main_menu()
            return

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        pause_background = self._state.pause_background
        if pause_background is not None:
            pause_background.draw_pause_background()
        elif self._ground is not None:
            self._ground.draw(Vec2())
        _draw_screen_fade(self._state)

        panel_top_left = self._panel_origin()
        panel_tex = self._panel_tex
        if panel_tex is not None:
            panel = rl.Rectangle(
                panel_top_left.x,
                panel_top_left.y,
                float(QUEST_FAILED_PANEL_W),
                float(QUEST_FAILED_PANEL_H),
            )
            fx_detail = bool(int(self._state.config.data.get("fx_detail_0", 0) or 0))
            draw_classic_menu_panel(panel_tex, dst=panel, tint=rl.WHITE, shadow=fx_detail)

        reaper_tex = self._reaper_tex
        if reaper_tex is not None:
            src = rl.Rectangle(0.0, 0.0, float(reaper_tex.width), float(reaper_tex.height))
            banner_pos = panel_top_left + Vec2(QUEST_FAILED_BANNER_X_OFFSET, QUEST_FAILED_BANNER_Y_OFFSET)
            dst = rl.Rectangle(
                banner_pos.x,
                banner_pos.y,
                float(QUEST_FAILED_BANNER_W),
                float(QUEST_FAILED_BANNER_H),
            )
            rl.draw_texture_pro(reaper_tex, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

        font = self._ensure_small_font()
        text_color = rl.Color(235, 235, 235, 255)
        draw_small_text(
            font,
            self._failure_message(),
            panel_top_left + Vec2(QUEST_FAILED_MESSAGE_X_OFFSET, QUEST_FAILED_MESSAGE_Y_OFFSET),
            1.0,
            text_color,
        )
        self._draw_score_preview(font, panel_top_left=panel_top_left)

        textures = self._button_textures
        if textures is not None and (textures.button_sm is not None or textures.button_md is not None):
            scale = 1.0
            button_pos = panel_top_left + Vec2(QUEST_FAILED_BUTTON_X_OFFSET, QUEST_FAILED_BUTTON_Y_OFFSET)

            retry_w = button_width(
                font, self._retry_button.label, scale=scale, force_wide=self._retry_button.force_wide
            )
            button_draw(textures, font, self._retry_button, pos=button_pos, width=retry_w, scale=scale)
            button_pos = button_pos.offset(dy=QUEST_FAILED_BUTTON_STEP_Y)

            play_another_w = button_width(
                font,
                self._quest_list_button.label,
                scale=scale,
                force_wide=self._quest_list_button.force_wide,
            )
            button_draw(
                textures,
                font,
                self._quest_list_button,
                pos=button_pos,
                width=play_another_w,
                scale=scale,
            )
            button_pos = button_pos.offset(dy=QUEST_FAILED_BUTTON_STEP_Y)

            main_menu_w = button_width(
                font,
                self._main_menu_button.label,
                scale=scale,
                force_wide=self._main_menu_button.force_wide,
            )
            button_draw(
                textures,
                font,
                self._main_menu_button,
                pos=button_pos,
                width=main_menu_w,
                scale=scale,
            )

        _draw_menu_cursor(self._state, pulse_time=self._cursor_pulse_time)

    def take_action(self) -> str | None:
        action = self._action
        self._action = None
        return action

    def _panel_origin(self) -> Vec2:
        screen_w = float(rl.get_screen_width())
        widescreen_shift_y = MenuView._menu_widescreen_y_shift(screen_w)
        return Vec2(
            QUEST_FAILED_PANEL_GEOM_X0 + QUEST_FAILED_PANEL_POS_X,
            QUEST_FAILED_PANEL_GEOM_Y0 + QUEST_FAILED_PANEL_POS_Y + widescreen_shift_y,
        )

    def _failure_message(self) -> str:
        retry_count = int(self._state.quest_fail_retry_count)
        if retry_count == 1:
            return "You didn't make it, do try again."
        if retry_count == 2:
            return "Third time no good."
        if retry_count == 3:
            return "No luck this time, have another go?"
        if retry_count == 4:
            return "Persistence will be rewarded."
        if retry_count == 5:
            return "Try one more time?"
        return "Quest failed, try again."

    def _build_score_preview(self, outcome: QuestRunOutcome | None) -> None:
        from .persistence.highscores import HighScoreRecord

        self._record = None
        if outcome is None:
            return

        major = 0
        minor = 0
        try:
            major_text, minor_text = str(outcome.level).split(".", 1)
            major = int(major_text)
            minor = int(minor_text)
        except Exception:
            pass

        record = HighScoreRecord.blank()
        record.set_name(_player_name_default(self._state.config) or "Player")
        record.game_mode_id = 3
        record.quest_stage_major = major
        record.quest_stage_minor = minor
        record.survival_elapsed_ms = max(1, int(outcome.base_time_ms))
        record.score_xp = int(outcome.experience)
        record.creature_kill_count = int(outcome.kill_count)
        record.most_used_weapon_id = int(outcome.most_used_weapon_id)
        fired = max(0, int(outcome.shots_fired))
        hit = max(0, min(int(outcome.shots_hit), fired))
        record.shots_fired = fired
        record.shots_hit = hit

        self._record = record

    def _activate_retry(self) -> None:
        outcome = self._outcome
        if outcome is None:
            return
        self._state.quest_fail_retry_count = int(self._state.quest_fail_retry_count) + 1
        self._state.pending_quest_level = outcome.level
        if self._state.audio is not None:
            play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
        self._action = "start_quest"

    def _activate_play_another(self) -> None:
        self._state.quest_fail_retry_count = 0
        if self._state.audio is not None:
            play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
        self._action = "open_quests"

    def _activate_main_menu(self) -> None:
        self._state.quest_fail_retry_count = 0
        if self._state.audio is not None:
            play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
        self._action = "back_to_menu"

    def _text_width(self, text: str, scale: float) -> float:
        font = self._small_font
        if font is None:
            return float(rl.measure_text(text, int(20 * scale)))
        return float(measure_small_text_width(font, text, scale))

    def _draw_score_preview(self, font: SmallFontData, *, panel_top_left: Vec2) -> None:
        record = self._record
        if record is None:
            return

        score_pos = panel_top_left + Vec2(QUEST_FAILED_SCORE_X_OFFSET, QUEST_FAILED_SCORE_Y_OFFSET)

        label_color = rl.Color(230, 230, 230, int(255 * 0.8))
        value_color = rl.Color(230, 230, 255, 255)
        # `ui_text_input_render`: data_4965f8/5fc/600 = (149,175,198)/255.
        separator_color = rl.Color(149, 175, 198, int(255 * 0.7))

        score_label = "Score"
        score_label_w = self._text_width(score_label, 1.0)
        draw_small_text(font, score_label, score_pos.offset(dx=32.0 - score_label_w * 0.5), 1.0, label_color)

        score_value = f"{float(int(record.survival_elapsed_ms)) * 0.001:.2f} secs"
        score_value_w = self._text_width(score_value, 1.0)
        draw_small_text(font, score_value, score_pos + Vec2(32.0 - score_value_w * 0.5, 15.0), 1.0, value_color)

        sep_pos = score_pos.offset(dx=80.0)
        rl.draw_line(int(sep_pos.x), int(sep_pos.y), int(sep_pos.x), int(sep_pos.y + 48.0), separator_color)

        col2_pos = score_pos.offset(dx=96.0)
        draw_small_text(font, "Experience", col2_pos, 1.0, value_color)
        xp_value = f"{int(record.score_xp)}"
        xp_w = self._text_width(xp_value, 1.0)
        draw_small_text(font, xp_value, col2_pos + Vec2(32.0 - xp_w * 0.5, 15.0), 1.0, label_color)

        # `FUN_004411c0`: horizontal 192px separator at x-16 after the score row.
        line_pos = score_pos + Vec2(-16.0, 52.0)
        rl.draw_rectangle(int(line_pos.x), int(line_pos.y), int(192.0), int(1.0), separator_color)

    def _ensure_small_font(self) -> SmallFontData:
        if self._small_font is not None:
            return self._small_font
        missing_assets: list[str] = []
        self._small_font = load_small_font(self._state.assets_dir, missing_assets)
        return self._small_font


class HighScoresView:
    def __init__(self, state: GameState) -> None:
        self._state = state
        self._assets: MenuAssets | None = None
        self._ground: GroundRenderer | None = None
        self._action: str | None = None
        self._cursor_pulse_time = 0.0
        self._widescreen_y_shift = 0.0
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._small_font: SmallFontData | None = None
        self._button_tex: rl.Texture | None = None
        self._button_textures: UiButtonTextureSet | None = None
        self._check_on: rl.Texture | None = None
        self._drop_off: rl.Texture | None = None
        self._arrow_tex: rl.Texture | None = None
        self._wicons_tex: rl.Texture | None = None
        self._clock_table_tex: rl.Texture | None = None
        self._clock_pointer_tex: rl.Texture | None = None
        self._update_button = UiButtonState("Update scores", force_wide=True)
        self._play_button = UiButtonState("Play a game", force_wide=True)
        self._back_button = UiButtonState("Back", force_wide=False)

        self._request: HighScoresRequest | None = None
        self._records: list = []
        self._scroll_index = 0

    def open(self) -> None:
        from .persistence.highscores import read_highscore_table, scores_path_for_mode

        layout_w = float(self._state.config.screen_width)
        self._widescreen_y_shift = MenuView._menu_widescreen_y_shift(layout_w)
        self._action = None
        self._assets = load_menu_assets(self._state)
        self._ground = None if self._state.pause_background is not None else ensure_menu_ground(self._state)
        self._cursor_pulse_time = 0.0
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._small_font = None
        self._scroll_index = 0
        self._button_textures = None
        self._update_button = UiButtonState("Update scores", force_wide=True)
        self._play_button = UiButtonState("Play a game", force_wide=True)
        self._back_button = UiButtonState("Back", force_wide=False)

        cache = _ensure_texture_cache(self._state)
        self._button_tex = cache.get_or_load("ui_buttonMd", "ui/ui_button_128x32.jaz").texture
        button_sm = cache.get_or_load("ui_buttonSm", "ui/ui_button_64x32.jaz").texture
        self._button_textures = UiButtonTextureSet(button_sm=button_sm, button_md=self._button_tex)
        self._check_on = cache.get_or_load("ui_checkOn", "ui/ui_checkOn.jaz").texture
        self._drop_off = cache.get_or_load("ui_dropOff", "ui/ui_dropDownOff.jaz").texture
        self._arrow_tex = cache.get_or_load("ui_arrow", "ui/ui_arrow.jaz").texture
        self._wicons_tex = cache.get_or_load("ui_wicons", "ui/ui_wicons.jaz").texture
        self._clock_table_tex = cache.get_or_load("ui_clockTable", "ui/ui_clockTable.jaz").texture
        self._clock_pointer_tex = cache.get_or_load("ui_clockPointer", "ui/ui_clockPointer.jaz").texture

        request = self._state.pending_high_scores
        self._state.pending_high_scores = None
        if request is None:
            request = HighScoresRequest(game_mode_id=int(self._state.config.data.get("game_mode", 1) or 1))

        if int(request.game_mode_id) == 3 and (
            int(request.quest_stage_major) <= 0 or int(request.quest_stage_minor) <= 0
        ):
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
        self._wicons_tex = None
        self._clock_table_tex = None
        self._clock_pointer_tex = None
        self._assets = None
        self._button_tex = None
        self._button_textures = None
        self._check_on = None
        self._drop_off = None
        self._arrow_tex = None
        self._request = None
        self._records = []
        self._scroll_index = 0

    def _panel_top_left(self, *, pos: Vec2, scale: float) -> Vec2:
        return Vec2(
            pos.x + MENU_PANEL_OFFSET_X * scale,
            pos.y + self._widescreen_y_shift + MENU_PANEL_OFFSET_Y * scale,
        )

    def update(self, dt: float) -> None:
        if self._state.audio is not None:
            update_audio(self._state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        self._cursor_pulse_time += min(dt, 0.1) * 1.1

        dt_ms = int(min(float(dt), 0.1) * 1000.0)
        if dt_ms > 0:
            self._timeline_ms = min(self._timeline_max_ms, int(self._timeline_ms + dt_ms))

        enabled = self._timeline_ms >= self._timeline_max_ms

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) and enabled:
            if self._state.audio is not None:
                play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
            self._action = "back_to_previous"
            return

        textures = self._button_textures
        if enabled and textures is not None and (textures.button_sm is not None or textures.button_md is not None):
            scale = 0.9 if float(self._state.config.screen_width) < 641.0 else 1.0
            font = self._ensure_small_font()
            panel_top_left = self._panel_top_left(pos=Vec2(HS_LEFT_PANEL_POS_X, HS_LEFT_PANEL_POS_Y), scale=scale)
            button_base_pos = panel_top_left + Vec2(HS_BUTTON_X * scale, HS_BUTTON_Y0 * scale)
            mouse = rl.get_mouse_position()
            click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
            w = button_width(font, self._update_button.label, scale=scale, force_wide=self._update_button.force_wide)
            if button_update(
                self._update_button,
                pos=button_base_pos,
                width=w,
                dt_ms=dt_ms,
                mouse=mouse,
                click=click,
            ):
                # Reload scores from disk (no view transition).
                if self._state.audio is not None:
                    play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
                self.open()
                return
            w = button_width(font, self._play_button.label, scale=scale, force_wide=self._play_button.force_wide)
            if button_update(
                self._play_button,
                pos=button_base_pos.offset(dy=HS_BUTTON_STEP_Y * scale),
                width=w,
                dt_ms=dt_ms,
                mouse=mouse,
                click=click,
            ):
                if self._state.audio is not None:
                    play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
                self._action = "open_play_game"
                return
            back_w = button_width(font, self._back_button.label, scale=scale, force_wide=self._back_button.force_wide)
            if button_update(
                self._back_button,
                pos=panel_top_left + Vec2(HS_BACK_BUTTON_X * scale, HS_BACK_BUTTON_Y * scale),
                width=back_w,
                dt_ms=dt_ms,
                mouse=mouse,
                click=click,
            ):
                if self._state.audio is not None:
                    play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
                self._action = "back_to_previous"
                return

        rows = 10
        max_scroll = max(0, len(self._records) - rows)

        if enabled:
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
        pause_background = self._state.pause_background
        if pause_background is not None:
            pause_background.draw_pause_background()
        elif self._ground is not None:
            self._ground.draw(Vec2())
        _draw_screen_fade(self._state)

        assets = self._assets
        if assets is None or assets.panel is None:
            return

        font = self._ensure_small_font()
        request = self._request
        mode_id = (
            int(request.game_mode_id) if request is not None else int(self._state.config.data.get("game_mode", 1) or 1)
        )
        quest_major = int(request.quest_stage_major) if request is not None else 0
        quest_minor = int(request.quest_stage_minor) if request is not None else 0

        scale = 0.9 if float(self._state.config.screen_width) < 641.0 else 1.0
        fx_detail = bool(self._state.config.data.get("fx_detail_0", 0))
        panel_w = MENU_PANEL_WIDTH * scale
        _angle_rad, left_slide_x = MenuView._ui_element_anim(
            self,
            index=1,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w,
            direction_flag=0,
        )
        _angle_rad, right_slide_x = MenuView._ui_element_anim(
            self,
            index=2,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=panel_w,
            direction_flag=1,
        )

        left_top_left = self._panel_top_left(pos=Vec2(HS_LEFT_PANEL_POS_X, HS_LEFT_PANEL_POS_Y), scale=scale)
        right_panel_pos_x = hs_right_panel_pos_x(float(self._state.config.screen_width))
        right_top_left = self._panel_top_left(pos=Vec2(right_panel_pos_x, HS_RIGHT_PANEL_POS_Y), scale=scale)
        left_panel_top_left = left_top_left.offset(dx=float(left_slide_x))
        right_panel_top_left = right_top_left.offset(dx=float(right_slide_x))

        draw_classic_menu_panel(
            assets.panel,
            dst=rl.Rectangle(left_panel_top_left.x, left_panel_top_left.y, panel_w, HS_LEFT_PANEL_HEIGHT * scale),
            tint=rl.WHITE,
            shadow=fx_detail,
        )
        draw_classic_menu_panel(
            assets.panel,
            dst=rl.Rectangle(right_panel_top_left.x, right_panel_top_left.y, panel_w, HS_RIGHT_PANEL_HEIGHT * scale),
            tint=rl.WHITE,
            shadow=fx_detail,
            flip_x=True,
        )

        title = (
            "High scores - Quests"
            if int(mode_id) == 3
            else f"High scores - {self._mode_label(mode_id, quest_major, quest_minor)}"
        )
        title_x = 269.0
        if int(mode_id) == 1:
            # state_14:High scores - Survival title at x=168 (panel left_x0 is -98).
            title_x = 266.0
        title_draw_pos = left_panel_top_left + Vec2(title_x * scale, 41.0 * scale)
        draw_small_text(
            font,
            title,
            title_draw_pos,
            1.0 * scale,
            rl.Color(255, 255, 255, 255),
        )
        ul_w = measure_small_text_width(font, title, 1.0 * scale)
        ul_h = max(1, int(round(1.0 * scale)))
        ul_pos = left_panel_top_left + Vec2(title_x * scale, HS_TITLE_UNDERLINE_Y * scale)
        rl.draw_rectangle(
            int(round(ul_pos.x)),
            int(round(ul_pos.y)),
            int(round(ul_w)),
            ul_h,
            rl.Color(255, 255, 255, int(255 * 0.7)),
        )
        if int(mode_id) == 3:
            hardcore = bool(int(self._state.config.data.get("hardcore_flag", 0) or 0))
            if hardcore:
                quest_color = rl.Color(250, 70, 60, int(255 * 0.7))
            else:
                quest_color = rl.Color(70, 180, 240, int(255 * 0.7))
            quest_label = f"{int(quest_major)}.{int(quest_minor)}: {self._quest_title(quest_major, quest_minor)}"
            draw_small_text(
                font,
                quest_label,
                left_panel_top_left + Vec2(236.0 * scale, 63.0 * scale),
                1.0 * scale,
                quest_color,
            )
            arrow = self._arrow_tex
            if arrow is not None:
                dst_w = float(arrow.width) * scale
                dst_h = float(arrow.height) * scale
                # state_14 draws ui_arrow.jaz flipped (uv 1..0) to point left.
                src = rl.Rectangle(float(arrow.width), 0.0, -float(arrow.width), float(arrow.height))
                arrow_pos = left_panel_top_left + Vec2(HS_QUEST_ARROW_X * scale, HS_QUEST_ARROW_Y * scale)
                dst = rl.Rectangle(arrow_pos.x, arrow_pos.y, dst_w, dst_h)
                rl.draw_texture_pro(arrow, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

        header_color = rl.Color(255, 255, 255, int(255 * 0.85))
        draw_small_text(
            font, "Rank", left_panel_top_left + Vec2(211.0 * scale, 84.0 * scale), 1.0 * scale, header_color
        )
        draw_small_text(
            font, "Score", left_panel_top_left + Vec2(246.0 * scale, 84.0 * scale), 1.0 * scale, header_color
        )
        draw_small_text(
            font, "Player", left_panel_top_left + Vec2(302.0 * scale, 84.0 * scale), 1.0 * scale, header_color
        )

        # Score list viewport frame (white 1px border + black interior).
        frame_x = left_panel_top_left.x + HS_SCORE_FRAME_X * scale
        frame_y = left_panel_top_left.y + HS_SCORE_FRAME_Y * scale
        frame_w = HS_SCORE_FRAME_W * scale
        frame_h = HS_SCORE_FRAME_H * scale
        rl.draw_rectangle(int(round(frame_x)), int(round(frame_y)), int(round(frame_w)), int(round(frame_h)), rl.WHITE)
        rl.draw_rectangle(
            int(round(frame_x + 1.0 * scale)),
            int(round(frame_y + 1.0 * scale)),
            max(0, int(round(frame_w - 2.0 * scale))),
            max(0, int(round(frame_h - 2.0 * scale))),
            rl.BLACK,
        )

        row_step = 16.0 * scale
        rows = 10
        start = max(0, int(self._scroll_index))
        end = min(len(self._records), start + rows)
        y = left_panel_top_left.y + 103.0 * scale
        selected_rank = int(request.highlight_rank) if (request is not None and request.highlight_rank is not None) else None
        mouse = Vec2.from_xy(rl.get_mouse_position())
        frame_x = left_panel_top_left.x + HS_SCORE_FRAME_X * scale
        frame_y = left_panel_top_left.y + HS_SCORE_FRAME_Y * scale
        frame_w = HS_SCORE_FRAME_W * scale
        frame_h = HS_SCORE_FRAME_H * scale
        if (
            frame_x <= mouse.x < frame_x + frame_w
            and frame_y <= mouse.y < frame_y + frame_h
            and y <= mouse.y < y + row_step * rows
        ):
            row = int((mouse.y - y) // row_step)
            hovered_idx = start + row
            if start <= hovered_idx < end:
                selected_rank = hovered_idx

        if start >= end:
            draw_small_text(
                font,
                "No scores yet.",
                Vec2(left_panel_top_left.x + 211.0 * scale, y + 8.0 * scale),
                1.0 * scale,
                rl.Color(190, 190, 200, 255),
            )
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

                value = f"{int(getattr(entry, 'score_xp', 0))}"

                color = rl.Color(255, 255, 255, int(255 * 0.7))
                if selected_rank is not None and int(selected_rank) == idx:
                    color = rl.Color(255, 255, 255, 255)

                draw_small_text(font, f"{idx + 1}", Vec2(left_panel_top_left.x + 216.0 * scale, y), 1.0 * scale, color)
                draw_small_text(font, value, Vec2(left_panel_top_left.x + 246.0 * scale, y), 1.0 * scale, color)
                draw_small_text(font, name, Vec2(left_panel_top_left.x + 304.0 * scale, y), 1.0 * scale, color)
                y += row_step

        textures = self._button_textures
        if textures is not None and (textures.button_sm is not None or textures.button_md is not None):
            button_base_pos = left_panel_top_left + Vec2(HS_BUTTON_X * scale, HS_BUTTON_Y0 * scale)
            w = button_width(font, self._update_button.label, scale=scale, force_wide=self._update_button.force_wide)
            button_draw(textures, font, self._update_button, pos=button_base_pos, width=w, scale=scale)
            w = button_width(font, self._play_button.label, scale=scale, force_wide=self._play_button.force_wide)
            button_draw(
                textures,
                font,
                self._play_button,
                pos=button_base_pos.offset(dy=HS_BUTTON_STEP_Y * scale),
                width=w,
                scale=scale,
            )
            w = button_width(font, self._back_button.label, scale=scale, force_wide=self._back_button.force_wide)
            button_draw(
                textures,
                font,
                self._back_button,
                pos=left_panel_top_left + Vec2(HS_BACK_BUTTON_X * scale, HS_BACK_BUTTON_Y * scale),
                width=w,
                scale=scale,
            )

        self._draw_right_panel(
            font=font,
            right_top_left=right_panel_top_left,
            scale=scale,
            mode_id=mode_id,
            highlight_rank=selected_rank,
        )
        self._draw_sign(assets)
        _draw_menu_cursor(self._state, pulse_time=self._cursor_pulse_time)

    def _draw_right_panel(
        self,
        *,
        font: SmallFontData,
        right_top_left: Vec2,
        scale: float,
        mode_id: int,
        highlight_rank: int | None,
    ) -> None:
        if highlight_rank is None:
            self._draw_right_panel_quest_options(font=font, right_top_left=right_top_left, scale=scale)
            return
        self._draw_right_panel_local_score(
            font=font,
            right_top_left=right_top_left,
            scale=scale,
            highlight_rank=highlight_rank,
        )

    def _draw_right_panel_quest_options(self, *, font: SmallFontData, right_top_left: Vec2, scale: float) -> None:
        text_scale = 1.0 * scale
        text_color = rl.Color(255, 255, 255, int(255 * 0.8))

        check_on = self._check_on
        if check_on is not None:
            check_w = float(check_on.width) * scale
            check_h = float(check_on.height) * scale
            rl.draw_texture_pro(
                check_on,
                rl.Rectangle(0.0, 0.0, float(check_on.width), float(check_on.height)),
                rl.Rectangle(
                    right_top_left.x + HS_RIGHT_CHECK_X * scale,
                    right_top_left.y + HS_RIGHT_CHECK_Y * scale,
                    check_w,
                    check_h,
                ),
                rl.Vector2(0.0, 0.0),
                0.0,
                rl.WHITE,
            )
        draw_small_text(
            font,
            "Show internet scores",
            right_top_left + Vec2(HS_RIGHT_SHOW_INTERNET_X * scale, HS_RIGHT_SHOW_INTERNET_Y * scale),
            text_scale,
            text_color,
        )
        draw_small_text(
            font,
            "Number of players",
            right_top_left + Vec2(HS_RIGHT_NUMBER_PLAYERS_X * scale, HS_RIGHT_NUMBER_PLAYERS_Y * scale),
            text_scale,
            text_color,
        )
        draw_small_text(
            font,
            "Game mode",
            right_top_left + Vec2(HS_RIGHT_GAME_MODE_X * scale, HS_RIGHT_GAME_MODE_Y * scale),
            text_scale,
            text_color,
        )
        draw_small_text(
            font,
            "Show scores:",
            right_top_left + Vec2(HS_RIGHT_SHOW_SCORES_X * scale, HS_RIGHT_SHOW_SCORES_Y * scale),
            text_scale,
            text_color,
        )
        draw_small_text(
            font,
            "Selected score list:",
            right_top_left + Vec2(HS_RIGHT_SCORE_LIST_X * scale, HS_RIGHT_SCORE_LIST_Y * scale),
            text_scale,
            text_color,
        )

        # Closed list widgets (state_14 quest variant): white border + black fill.
        widget_h = 16.0 * scale
        for widget_offset, widget_width in (
            (Vec2(HS_RIGHT_PLAYER_COUNT_WIDGET_X, HS_RIGHT_PLAYER_COUNT_WIDGET_Y), HS_RIGHT_PLAYER_COUNT_WIDGET_W),
            (Vec2(HS_RIGHT_GAME_MODE_WIDGET_X, HS_RIGHT_GAME_MODE_WIDGET_Y), HS_RIGHT_GAME_MODE_WIDGET_W),
            (Vec2(HS_RIGHT_SHOW_SCORES_WIDGET_X, HS_RIGHT_SHOW_SCORES_WIDGET_Y), HS_RIGHT_SHOW_SCORES_WIDGET_W),
            (Vec2(HS_RIGHT_SCORE_LIST_WIDGET_X, HS_RIGHT_SCORE_LIST_WIDGET_Y), HS_RIGHT_SCORE_LIST_WIDGET_W),
        ):
            widget_pos = right_top_left + widget_offset * scale
            w = float(widget_width) * scale
            rl.draw_rectangle(int(widget_pos.x), int(widget_pos.y), int(w), int(widget_h), rl.WHITE)
            rl.draw_rectangle(
                int(widget_pos.x) + 1,
                int(widget_pos.y) + 1,
                max(0, int(w) - 2),
                max(0, int(widget_h) - 2),
                rl.BLACK,
            )

        # Values (static in the oracle).
        draw_small_text(
            font,
            "1 player",
            right_top_left + Vec2(HS_RIGHT_PLAYER_COUNT_VALUE_X * scale, HS_RIGHT_PLAYER_COUNT_VALUE_Y * scale),
            text_scale,
            text_color,
        )
        draw_small_text(
            font,
            "Quests",
            right_top_left + Vec2(HS_RIGHT_GAME_MODE_VALUE_X * scale, HS_RIGHT_GAME_MODE_VALUE_Y * scale),
            text_scale,
            text_color,
        )
        draw_small_text(
            font,
            "Best of all time",
            right_top_left + Vec2(HS_RIGHT_SHOW_SCORES_VALUE_X * scale, HS_RIGHT_SHOW_SCORES_VALUE_Y * scale),
            text_scale,
            text_color,
        )
        draw_small_text(
            font,
            "default",
            right_top_left + Vec2(HS_RIGHT_SCORE_LIST_VALUE_X * scale, HS_RIGHT_SCORE_LIST_VALUE_Y * scale),
            text_scale,
            text_color,
        )

        drop_off = self._drop_off
        if drop_off is None:
            return
        drop_w = float(drop_off.width) * scale
        drop_h = float(drop_off.height) * scale
        for drop_offset in (
            Vec2(HS_RIGHT_PLAYER_COUNT_DROP_X, HS_RIGHT_PLAYER_COUNT_DROP_Y),
            Vec2(HS_RIGHT_GAME_MODE_DROP_X, HS_RIGHT_GAME_MODE_DROP_Y),
            Vec2(HS_RIGHT_SHOW_SCORES_DROP_X, HS_RIGHT_SHOW_SCORES_DROP_Y),
            Vec2(HS_RIGHT_SCORE_LIST_DROP_X, HS_RIGHT_SCORE_LIST_DROP_Y),
        ):
            drop_pos = right_top_left + drop_offset * scale
            rl.draw_texture_pro(
                drop_off,
                rl.Rectangle(0.0, 0.0, float(drop_off.width), float(drop_off.height)),
                rl.Rectangle(
                    drop_pos.x,
                    drop_pos.y,
                    drop_w,
                    drop_h,
                ),
                rl.Vector2(0.0, 0.0),
                0.0,
                rl.WHITE,
            )

    def _draw_right_panel_local_score(
        self,
        *,
        font: SmallFontData,
        right_top_left: Vec2,
        scale: float,
        highlight_rank: int | None,
    ) -> None:
        if not self._records:
            return
        idx = int(highlight_rank) if highlight_rank is not None else int(self._scroll_index)
        if idx < 0:
            idx = 0
        if idx >= len(self._records):
            idx = len(self._records) - 1
        entry = self._records[idx]

        text_scale = 1.0 * scale
        text_color = rl.Color(int(255 * 0.9), int(255 * 0.9), int(255 * 0.9), int(255 * 0.8))
        value_color = rl.Color(int(255 * 0.9), int(255 * 0.9), 255, 255)
        lower_section_color = rl.Color(int(255 * 0.9), int(255 * 0.9), int(255 * 0.9), int(255 * 0.7))
        separator_color = rl.Color(149, 175, 198, int(255 * 0.7))

        name = ""
        try:
            name = str(entry.name())
        except Exception:
            name = ""
        if not name:
            name = "???"
        draw_small_text(
            font,
            name,
            right_top_left + Vec2(HS_LOCAL_NAME_X * scale, HS_LOCAL_NAME_Y * scale),
            text_scale,
            text_color,
        )
        draw_small_text(
            font,
            "Local score",
            right_top_left + Vec2(HS_LOCAL_LABEL_X * scale, HS_LOCAL_LABEL_Y * scale),
            text_scale,
            text_color,
        )
        rl.draw_line(
            int(right_top_left.x + 78.0 * scale),
            int(right_top_left.y + 57.0 * scale),
            int(right_top_left.x + 117.0 * scale),
            int(right_top_left.y + 57.0 * scale),
            separator_color,
        )

        date_text = self._format_score_date(entry)
        if date_text:
            date_width = measure_small_text_width(font, date_text, text_scale)
            date_x = (HS_LOCAL_DATE_CENTER_X * scale) - date_width * 0.5
            draw_small_text(
                font,
                date_text,
                right_top_left + Vec2(date_x, HS_LOCAL_DATE_Y * scale),
                text_scale,
                text_color,
            )
        rl.draw_line(
            int(right_top_left.x + 74.0 * scale),
            int(right_top_left.y + 72.0 * scale),
            int(right_top_left.x + 266.0 * scale),
            int(right_top_left.y + 72.0 * scale),
            separator_color,
        )

        draw_small_text(
            font,
            "Score",
            right_top_left + Vec2(HS_LOCAL_SCORE_LABEL_X * scale, HS_LOCAL_SCORE_LABEL_Y * scale),
            text_scale,
            text_color,
        )
        draw_small_text(
            font,
            "Game time",
            right_top_left + Vec2(HS_LOCAL_TIME_LABEL_X * scale, HS_LOCAL_TIME_LABEL_Y * scale),
            text_scale,
            text_color,
        )
        rl.draw_line(
            int(right_top_left.x + 170.0 * scale),
            int(right_top_left.y + 90.0 * scale),
            int(right_top_left.x + 170.0 * scale),
            int(right_top_left.y + 138.0 * scale),
            separator_color,
        )

        score_value = f"{int(getattr(entry, 'score_xp', 0))}"
        draw_small_text(
            font,
            score_value,
            right_top_left + Vec2(HS_LOCAL_SCORE_VALUE_X * scale, HS_LOCAL_SCORE_VALUE_Y * scale),
            text_scale,
            value_color,
        )

        elapsed_ms = int(getattr(entry, "survival_elapsed_ms", 0) or 0)
        self._draw_clock_gauge(
            elapsed_ms=elapsed_ms,
            pos=right_top_left + Vec2(HS_LOCAL_CLOCK_X * scale, HS_LOCAL_CLOCK_Y * scale),
            scale=scale,
        )
        draw_small_text(
            font,
            self._format_elapsed_mm_ss(elapsed_ms),
            right_top_left + Vec2(HS_LOCAL_TIME_VALUE_X * scale, HS_LOCAL_TIME_VALUE_Y * scale),
            text_scale,
            text_color,
        )

        draw_small_text(
            font,
            f"Rank: {self._ordinal(idx + 1)}",
            right_top_left + Vec2(HS_LOCAL_RANK_X * scale, HS_LOCAL_RANK_Y * scale),
            text_scale,
            text_color,
        )

        frags = int(getattr(entry, "creature_kill_count", 0) or 0)

        shots_fired = int(getattr(entry, "shots_fired", 0) or 0)
        shots_hit = int(getattr(entry, "shots_hit", 0) or 0)
        hit_pct = 0
        if shots_fired > 0:
            hit_pct = int((shots_hit * 100) // shots_fired)
        rl.draw_line(
            int(right_top_left.x + 74.0 * scale),
            int(right_top_left.y + 142.0 * scale),
            int(right_top_left.x + 266.0 * scale),
            int(right_top_left.y + 142.0 * scale),
            separator_color,
        )

        weapon_id = int(getattr(entry, "most_used_weapon_id", 0) or 0)
        weapon_name, icon_index = self._weapon_label_and_icon(weapon_id)
        if icon_index is not None:
            self._draw_wicon(
                icon_index,
                pos=right_top_left + Vec2(HS_LOCAL_WICON_X * scale, HS_LOCAL_WICON_Y * scale),
                scale=scale,
            )
        draw_small_text(
            font,
            weapon_name,
            right_top_left + Vec2(HS_LOCAL_WEAPON_X * scale, HS_LOCAL_WEAPON_Y * scale),
            text_scale,
            lower_section_color,
        )
        draw_small_text(
            font,
            f"Frags: {frags}",
            right_top_left + Vec2(HS_LOCAL_FRAGS_X * scale, HS_LOCAL_FRAGS_Y * scale),
            text_scale,
            lower_section_color,
        )
        draw_small_text(
            font,
            f"Hit %: {hit_pct}%",
            right_top_left + Vec2(HS_LOCAL_HIT_X * scale, HS_LOCAL_HIT_Y * scale),
            text_scale,
            lower_section_color,
        )
        rl.draw_line(
            int(right_top_left.x + 74.0 * scale),
            int(right_top_left.y + 194.0 * scale),
            int(right_top_left.x + 266.0 * scale),
            int(right_top_left.y + 194.0 * scale),
            separator_color,
        )

    def _draw_clock_gauge(self, *, elapsed_ms: int, pos: Vec2, scale: float) -> None:
        table_tex = self._clock_table_tex
        pointer_tex = self._clock_pointer_tex
        if table_tex is None or pointer_tex is None:
            return
        draw_w = 32.0 * scale
        draw_h = 32.0 * scale
        dst = rl.Rectangle(pos.x, pos.y, draw_w, draw_h)
        src_table = rl.Rectangle(0.0, 0.0, float(table_tex.width), float(table_tex.height))
        src_pointer = rl.Rectangle(0.0, 0.0, float(pointer_tex.width), float(pointer_tex.height))
        rl.draw_texture_pro(
            table_tex,
            src_table,
            dst,
            rl.Vector2(0.0, 0.0),
            0.0,
            rl.WHITE,
        )
        seconds = max(0, int(elapsed_ms) // 1000)
        rotation_deg = float(seconds) * 6.0
        center = Vec2(pos.x + draw_w * 0.5, pos.y + draw_h * 0.5)
        rl.draw_texture_pro(
            pointer_tex,
            src_pointer,
            rl.Rectangle(center.x, center.y, draw_w, draw_h),
            rl.Vector2(draw_w * 0.5, draw_h * 0.5),
            rotation_deg,
            rl.WHITE,
        )

    def _draw_wicon(self, icon_index: int, *, pos: Vec2, scale: float) -> None:
        tex = self._wicons_tex
        if tex is None:
            return
        idx = int(icon_index)
        if idx < 0 or idx > 31:
            return
        grid = 8
        cell_w = float(tex.width) / float(grid)
        cell_h = float(tex.height) / float(grid)
        frame = idx * 2
        src_x = float(frame % grid) * cell_w
        src_y = float(frame // grid) * cell_h
        icon_w = cell_w * 2.0
        icon_h = cell_h
        rl.draw_texture_pro(
            tex,
            rl.Rectangle(src_x, src_y, icon_w, icon_h),
            rl.Rectangle(pos.x, pos.y, icon_w * scale, icon_h * scale),
            rl.Vector2(0.0, 0.0),
            0.0,
            rl.WHITE,
        )

    @staticmethod
    def _ordinal(value: int) -> str:
        n = int(value)
        if 10 <= (n % 100) <= 20:
            return f"{n}th"
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
        return f"{n}{suffix}"

    @staticmethod
    def _format_elapsed_mm_ss(value_ms: int) -> str:
        total = max(0, int(value_ms)) // 1000
        minutes, seconds = divmod(total, 60)
        return f"{minutes}:{seconds:02d}"

    @staticmethod
    def _format_score_date(entry: object) -> str:
        try:
            day = int(getattr(entry, "day", 0) or 0)
            month = int(getattr(entry, "month", 0) or 0)
            year_off = int(getattr(entry, "year_offset", 0) or 0)
        except Exception:
            return ""
        if day <= 0 or month <= 0:
            return ""
        months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
        month_name = months[month - 1] if 1 <= month <= 12 else f"{month}"
        year = 2000 + year_off if year_off >= 0 else 2000
        return f"{day}. {month_name} {year}"

    @staticmethod
    def _weapon_label_and_icon(weapon_id: int) -> tuple[str, int | None]:
        try:
            from .weapons import WEAPON_BY_ID
        except Exception:
            WEAPON_BY_ID = {}
        weapon = WEAPON_BY_ID.get(int(weapon_id))
        if weapon is None:
            return f"Weapon {int(weapon_id)}", None
        name = weapon.name or f"weapon_{int(weapon.weapon_id)}"
        return name, weapon.icon_index

    def _draw_sign(self, assets: MenuAssets) -> None:
        if assets.sign is None:
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

    @staticmethod
    def _quest_title(major: int, minor: int) -> str:
        try:
            from .quests import quest_by_level

            q = quest_by_level(f"{int(major)}.{int(minor)}")
            if q is not None and q.title:
                return str(q.title)
        except Exception:
            pass
        return "???"

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
            "end_note": EndNoteView(state),
            "open_high_scores": HighScoresView(state),
            "start_survival": SurvivalGameView(state),
            "start_rush": RushGameView(state),
            "start_typo": TypoShooterGameView(state),
            "start_tutorial": TutorialGameView(state),
            "open_options": OptionsMenuView(state),
            "open_controls": ControlsMenuView(state),
            "open_statistics": StatisticsMenuView(state),
            "open_weapon_database": UnlockedWeaponsDatabaseView(state),
            "open_perk_database": UnlockedPerksDatabaseView(state),
            "open_credits": CreditsView(state),
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
                    self._state.pause_background = cast(PauseBackground, self._front_active)
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
                    if action in {"open_high_scores", "open_weapon_database", "open_perk_database", "open_credits"}:
                        if (self._front_active in self._gameplay_views) and (self._state.pause_background is None):
                            self._state.pause_background = cast(PauseBackground, self._front_active)
                        self._front_stack.append(self._front_active)
                    elif action in {"quest_results", "quest_failed"} and (self._front_active in self._gameplay_views):
                        self._state.pause_background = cast(PauseBackground, self._front_active)
                        self._front_stack.append(self._front_active)
                    else:
                        if action in {
                            "start_survival",
                            "start_rush",
                            "start_typo",
                            "start_tutorial",
                            "start_quest",
                            "open_play_game",
                            "open_quests",
                        }:
                            self._state.pause_background = None
                            while self._front_stack:
                                self._front_stack.pop().close()
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
        if (
            (not self._demo_active)
            and (not self._menu_active)
            and self._front_active is None
            and self._boot.is_theme_started()
        ):
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
            console.log.log("Command adjusts gamma ramp linearly by multiplying with given scalar")
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
        console.log.log(f"demo trial: quest grace={state.demo_trial_elapsed_ms}ms (total {DEMO_QUEST_GRACE_TIME_MS}ms)")

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
    if config.debug:
        set_debug_enabled(True)
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
            preserve_bugs=bool(config.preserve_bugs),
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
