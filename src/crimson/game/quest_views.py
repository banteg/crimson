from __future__ import annotations

from dataclasses import dataclass
import math
from typing import TYPE_CHECKING

import pyray as rl

from grim.audio import play_sfx, update_audio
from grim.config import CrimsonConfig
from grim.geom import Rect, Vec2
from grim.terrain_render import GroundRenderer
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width

from ..debug import debug_enabled
from ..frontend.assets import MenuAssets, _ensure_texture_cache, load_menu_assets
from ..frontend.menu import (
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
from ..frontend.panels.base import FADE_TO_GAME_ACTIONS, PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS
from ..frontend.transitions import _draw_screen_fade
from ..ui.menu_panel import draw_classic_menu_panel
from ..ui.perk_menu import UiButtonState, UiButtonTextureSet, button_draw, button_update, button_width
from .types import GameState, HighScoresRequest

if TYPE_CHECKING:
    from ..modes.quest_mode import QuestRunOutcome
    from ..persistence.highscores import HighScoreRecord

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
QUEST_FAILED_PANEL_SLIDE_DURATION_MS = 250.0


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
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._closing = False
        self._close_action: str | None = None
        self._panel_open_sfx_played = False

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
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._closing = False
        self._close_action = None
        self._panel_open_sfx_played = False
        self._back_button = UiButtonState("Back")

        # Ensure the quest registry is populated so titles render.
        # (The package import registers all tier builders.)
        try:
            from .. import quests as _quests

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
        dt_ms = int(min(float(dt), 0.1) * 1000.0)

        if self._closing:
            if dt_ms > 0 and self._action is None:
                self._timeline_ms -= dt_ms
                if self._timeline_ms < 0 and self._close_action is not None:
                    self._action = self._close_action
                    self._close_action = None
            return

        if dt_ms > 0:
            self._timeline_ms = min(self._timeline_max_ms, self._timeline_ms + dt_ms)
            if self._timeline_ms >= self._timeline_max_ms:
                self._state.menu_sign_locked = True
                if (not self._panel_open_sfx_played) and (self._state.audio is not None):
                    play_sfx(self._state.audio, "sfx_ui_panelclick", rng=self._state.rng)
                    self._panel_open_sfx_played = True

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

        enabled = self._timeline_ms >= self._timeline_max_ms

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) and enabled:
            self._begin_close_transition("open_play_game")
            return

        if not enabled:
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
                self._begin_close_transition("open_play_game")
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
            self._ground.draw(menu_ground_camera(self._state))
        _draw_screen_fade(self._state)

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
        _angle_rad, slide_x = MenuView._ui_element_anim(
            self,
            index=1,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=MENU_PANEL_WIDTH,
        )
        # `sub_447d40` base sums:
        #   x_sum = <ui_element_x> + <ui_element_offset_x>  (x=-5)
        #   y_sum = <ui_element_y> + <ui_element_offset_y>  (y=185 + widescreen shift via ui_menu_layout_init)
        x_sum = QUEST_MENU_BASE_X + slide_x + QUEST_MENU_PANEL_OFFSET_X
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
        self._begin_close_transition("start_quest")

    def _quest_title(self, stage: int, row: int) -> str:
        level = f"{int(stage)}.{int(row) + 1}"
        try:
            from ..quests import quest_by_level

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
        _angle_rad, slide_x = MenuView._ui_element_anim(
            self,
            index=1,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=MENU_PANEL_WIDTH,
        )
        fx_detail = bool(self._state.config.data.get("fx_detail_0", 0))
        draw_classic_menu_panel(
            panel,
            dst=rl.Rectangle(
                float(QUEST_MENU_BASE_X + slide_x + QUEST_MENU_PANEL_OFFSET_X),
                float(QUEST_MENU_BASE_Y + MENU_PANEL_OFFSET_Y + self._widescreen_y_shift),
                float(MENU_PANEL_WIDTH),
                float(QUEST_PANEL_HEIGHT),
            ),
            shadow=fx_detail,
        )

    def _begin_close_transition(self, action: str) -> None:
        if self._closing:
            return
        if action in FADE_TO_GAME_ACTIONS:
            self._state.screen_fade_alpha = 0.0
            self._state.screen_fade_ramp = True
        if self._state.audio is not None:
            play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
        self._closing = True
        self._close_action = action


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

    from ..quests import quest_by_level

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
        from ..persistence.highscores import HighScoreRecord
        from ..quests.results import compute_quest_final_time
        from ..ui.quest_results import QuestResultsUi

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
            from ..quests import quest_by_level

            quest = quest_by_level(outcome.level)
            self._quest_title = quest.title if quest is not None else ""
            if quest is not None:
                weapon_id_native = int(quest.unlock_weapon_id or 0)
                if weapon_id_native > 0:
                    from ..weapons import WEAPON_BY_ID, weapon_display_name

                    weapon_entry = WEAPON_BY_ID.get(weapon_id_native)
                    self._unlock_weapon_name = (
                        weapon_display_name(weapon_id_native, preserve_bugs=bool(self._state.preserve_bugs))
                        if weapon_entry is not None and weapon_entry.name
                        else f"weapon_{weapon_id_native}"
                    )

                from ..perks import PERK_BY_ID, PerkId, perk_display_name

                perk_id = int(quest.unlock_perk_id or 0)
                if perk_id != int(PerkId.ANTIPERK):
                    perk_entry = PERK_BY_ID.get(perk_id)
                    if perk_entry is not None and perk_entry.name:
                        fx_toggle = int(self._state.config.data.get("fx_toggle", 0) or 0)
                        self._unlock_perk_name = perk_display_name(
                            perk_id,
                            fx_toggle=fx_toggle,
                            preserve_bugs=bool(self._state.preserve_bugs),
                        )
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

        player_health_values = tuple(float(v) for v in getattr(outcome, "player_health_values", ()) or ())
        if len(player_health_values) == 0:
            player_health_values = (float(outcome.player_health),)
            if outcome.player2_health is not None:
                player_health_values = player_health_values + (float(outcome.player2_health),)
        breakdown = compute_quest_final_time(
            base_time_ms=int(outcome.base_time_ms),
            player_health=float(outcome.player_health),
            player2_health=(float(outcome.player2_health) if outcome.player2_health is not None else None),
            player_health_values=player_health_values,
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
            preserve_bugs=bool(self._state.preserve_bugs),
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
        ui = self._ui
        bg_alpha = 1.0
        if ui is not None:
            bg_alpha = float(ui.world_entity_alpha())
        pause_background = self._state.pause_background
        if pause_background is not None:
            pause_background.draw_pause_background(entity_alpha=bg_alpha)
        elif self._ground is not None:
            self._ground.draw(menu_ground_camera(self._state))
        _draw_screen_fade(self._state)
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
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._closing = False
        self._close_action: str | None = None

        self._survival_button = UiButtonState("Survival", force_wide=True)
        self._rush_button = UiButtonState("  Rush  ", force_wide=True)
        self._typo_button = UiButtonState("Typ'o'Shooter", force_wide=True)
        self._main_menu_button = UiButtonState("Main Menu", force_wide=True)

    def open(self) -> None:
        self._action = None
        self._cursor_pulse_time = 0.0
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._closing = False
        self._close_action = None
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
        self._closing = False
        self._close_action = None

    def update(self, dt: float) -> None:
        if self._state.audio is not None:
            update_audio(self._state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        dt_step = min(float(dt), 0.1)
        self._cursor_pulse_time += dt_step * 1.1
        dt_ms = int(dt_step * 1000.0)
        if self._closing:
            if dt_ms > 0 and self._action is None:
                self._timeline_ms -= dt_ms
                if self._timeline_ms < 0 and self._close_action is not None:
                    self._action = self._close_action
                    self._close_action = None
            return
        if dt_ms > 0:
            self._timeline_ms = min(self._timeline_max_ms, self._timeline_ms + dt_ms)

        enabled = self._timeline_ms >= self._timeline_max_ms
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) and enabled:
            self._begin_close_transition("back_to_menu")
            return

        textures = self._button_textures
        if textures is None or (textures.button_sm is None and textures.button_md is None):
            return
        if not enabled:
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
            self._begin_close_transition("start_survival")
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
            self._begin_close_transition("start_rush")
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
            self._begin_close_transition("start_typo", fade_to_black=True)
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
            self._begin_close_transition("back_to_menu")
            return

    def draw(self) -> None:
        rl.clear_background(rl.BLACK)
        pause_background = self._state.pause_background
        if pause_background is not None:
            pause_background.draw_pause_background(entity_alpha=self._world_entity_alpha())
        elif self._ground is not None:
            self._ground.draw(menu_ground_camera(self._state))
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
        levels_line = (
            "You've completed all the levels but the battle"
            if bool(self._state.preserve_bugs)
            else "You've completed all the levels, but the battle"
        )
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
                levels_line,
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

    def _world_entity_alpha(self) -> float:
        if not self._closing:
            return 1.0
        span = PANEL_TIMELINE_START_MS - PANEL_TIMELINE_END_MS
        if span <= 0:
            return 0.0
        alpha = (float(self._timeline_ms) - PANEL_TIMELINE_END_MS) / float(span)
        if alpha < 0.0:
            return 0.0
        if alpha > 1.0:
            return 1.0
        return alpha

    def _begin_close_transition(self, action: str, *, fade_to_black: bool = False) -> None:
        if self._closing:
            return
        if fade_to_black:
            self._state.screen_fade_alpha = 0.0
            self._state.screen_fade_ramp = True
        if self._state.audio is not None:
            play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
        self._closing = True
        self._close_action = action


class QuestFailedView:
    def __init__(self, state: GameState) -> None:
        self._state = state
        self._ground: GroundRenderer | None = None
        self._outcome: QuestRunOutcome | None = None
        self._record: HighScoreRecord | None = None
        self._quest_title: str = ""
        self._action: str | None = None
        self._cursor_pulse_time = 0.0
        self._intro_ms = 0.0
        self._closing = False
        self._close_action: str | None = None
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
        self._intro_ms = 0.0
        self._closing = False
        self._close_action = None
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
                from ..quests import quest_by_level

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
        dt_step = min(float(dt), 0.1)
        self._cursor_pulse_time += dt_step * 1.1
        dt_ms = dt_step * 1000.0
        if self._closing:
            self._intro_ms = max(0.0, float(self._intro_ms) - dt_ms)
            if self._intro_ms <= 1e-3 and self._close_action is not None:
                self._action = self._close_action
                self._close_action = None
            return
        self._intro_ms = min(QUEST_FAILED_PANEL_SLIDE_DURATION_MS, self._intro_ms + dt_ms)

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

        panel_top_left = self._panel_top_left()
        textures = self._button_textures
        if outcome is None or textures is None or (textures.button_sm is None and textures.button_md is None):
            return
        scale = 1.0

        mouse = rl.get_mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
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
            pause_background.draw_pause_background(entity_alpha=self._world_entity_alpha())
        elif self._ground is not None:
            self._ground.draw(menu_ground_camera(self._state))
        _draw_screen_fade(self._state)

        panel_top_left = self._panel_top_left()
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

    def _panel_slide_x(self) -> float:
        if QUEST_FAILED_PANEL_SLIDE_DURATION_MS <= 1e-6:
            return 0.0
        t = float(self._intro_ms) / QUEST_FAILED_PANEL_SLIDE_DURATION_MS
        if t < 0.0:
            t = 0.0
        elif t > 1.0:
            t = 1.0
        eased = 1.0 - (1.0 - t) ** 3
        return -QUEST_FAILED_PANEL_W * (1.0 - eased)

    def _world_entity_alpha(self) -> float:
        if not self._closing:
            return 1.0
        if QUEST_FAILED_PANEL_SLIDE_DURATION_MS <= 1e-6:
            return 0.0
        alpha = float(self._intro_ms) / QUEST_FAILED_PANEL_SLIDE_DURATION_MS
        if alpha < 0.0:
            return 0.0
        if alpha > 1.0:
            return 1.0
        return alpha

    def _panel_top_left(self) -> Vec2:
        return self._panel_origin().offset(dx=self._panel_slide_x())

    def _failure_message(self) -> str:
        retry_count = int(self._state.quest_fail_retry_count)
        if retry_count == 1:
            return "You didn't make it, do try again."
        if retry_count == 2:
            return "Third time no good."
        if retry_count == 3:
            return "No luck this time, have another go?"
        if retry_count == 4:
            if bool(self._state.preserve_bugs):
                return "Persistence will be rewared."
            return "Persistence will be rewarded."
        if retry_count == 5:
            return "Try one more time?"
        return "Quest failed, try again."

    def _build_score_preview(self, outcome: QuestRunOutcome | None) -> None:
        from ..persistence.highscores import HighScoreRecord

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
        self._begin_close("start_quest")

    def _activate_play_another(self) -> None:
        self._state.quest_fail_retry_count = 0
        if self._state.audio is not None:
            play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
        self._begin_close("open_quests")

    def _activate_main_menu(self) -> None:
        self._state.quest_fail_retry_count = 0
        if self._state.audio is not None:
            play_sfx(self._state.audio, "sfx_ui_buttonclick", rng=self._state.rng)
        self._begin_close("back_to_menu")

    def _begin_close(self, action: str) -> None:
        if self._closing:
            return
        self._closing = True
        self._close_action = action

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
