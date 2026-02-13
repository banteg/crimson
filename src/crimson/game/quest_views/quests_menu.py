from __future__ import annotations

import math

import pyray as rl

from grim.audio import play_sfx, update_audio
from grim.geom import Rect, Vec2
from grim.terrain_render import GroundRenderer
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width

from ...debug import debug_enabled
from ...frontend.assets import MenuAssets, _ensure_texture_cache, load_menu_assets
from ...frontend.menu import (
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
from ...frontend.panels.base import FADE_TO_GAME_ACTIONS, PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS
from ...frontend.transitions import _draw_screen_fade
from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import UiButtonState, UiButtonTextureSet, button_draw, button_update, button_width
from ..types import GameState
from .shared import (
    QUEST_BACK_BUTTON_X_OFFSET,
    QUEST_BACK_BUTTON_Y_OFFSET,
    QUEST_HARDCORE_CHECKBOX_X_OFFSET,
    QUEST_HARDCORE_CHECKBOX_Y_OFFSET,
    QUEST_HARDCORE_LIST_Y_SHIFT,
    QUEST_HARDCORE_UNLOCK_INDEX,
    QUEST_LIST_HOVER_BOTTOM_PAD,
    QUEST_LIST_HOVER_LEFT_PAD,
    QUEST_LIST_HOVER_RIGHT_PAD,
    QUEST_LIST_HOVER_TOP_PAD,
    QUEST_LIST_NAME_X_OFFSET,
    QUEST_LIST_ROW_STEP,
    QUEST_LIST_Y_OFFSET,
    QUEST_MENU_BASE_X,
    QUEST_MENU_BASE_Y,
    QUEST_MENU_PANEL_OFFSET_X,
    QUEST_PANEL_HEIGHT,
    QUEST_STAGE_ICON_SCALE_UNSELECTED,
    QUEST_STAGE_ICON_SIZE,
    QUEST_STAGE_ICON_STEP,
    QUEST_STAGE_ICON_X_OFFSET,
    QUEST_STAGE_ICON_Y_OFFSET,
    QUEST_TITLE_H,
    QUEST_TITLE_W,
    QUEST_TITLE_X_OFFSET,
    QUEST_TITLE_Y_OFFSET,
    _QuestMenuLayout,
)

class QuestsMenuView:
    """Quest selection menu.

    Layout and gating are based on `sub_447d40` (crimsonland.exe).

    The classic game treats this as a distinct UI state (transition target `0x0b`),
    entered from the Play Game panel.
    """

    def __init__(self, state: GameState) -> None:
        self.state = state
        self._is_open = False
        self._assets: MenuAssets | None = None
        self._ground: GroundRenderer | None = None

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
        layout_w = float(self.state.config.screen_width)
        self._menu_screen_width = int(layout_w)
        self._widescreen_y_shift = MenuView._menu_widescreen_y_shift(layout_w)
        cache = _ensure_texture_cache(self.state)

        # Sign and ground match the main menu/panels.
        self._assets = load_menu_assets(self.state)
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
        from ... import quests as _quests

        _ = _quests
        self._is_open = True

    def close(self) -> None:
        self._is_open = False
        if self._dirty:
            try:
                self.state.config.save()
            except Exception:
                pass
            self._dirty = False
        self._ground = None
        self._button_textures = None

    def update(self, dt: float) -> None:
        self._assert_open()
        if self.state.audio is not None:
            update_audio(self.state.audio, dt)
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
                self.state.menu_sign_locked = True
                if (not self._panel_open_sfx_played) and (self.state.audio is not None):
                    play_sfx(self.state.audio, "sfx_ui_panelclick", rng=self.state.rng)
                    self._panel_open_sfx_played = True

        config = self.state.config
        status = self.state.status

        # The original forcibly clears hardcore in the demo build.
        if self.state.demo_enabled:
            if config.hardcore:
                config.hardcore = False
                self._dirty = True

        if debug_enabled() and rl.is_key_pressed(rl.KeyboardKey.KEY_F5):
            unlock = 49
            if int(status.quest_unlock_index) < unlock:
                status.quest_unlock_index = unlock
            if int(status.quest_unlock_index_full) < unlock:
                status.quest_unlock_index_full = unlock
            self.state.console.log.log("debug: unlocked all quests")

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
        self._assert_open()
        rl.clear_background(rl.BLACK)
        if self._ground is not None:
            self._ground.draw(menu_ground_camera(self.state))
        _draw_screen_fade(self.state)

        self._draw_panel()
        self._draw_sign()
        self._draw_contents()
        _draw_menu_cursor(self.state, pulse_time=self._cursor_pulse_time)

    def take_action(self) -> str | None:
        self._assert_open()
        action = self._action
        self._action = None
        return action

    def _assert_open(self) -> None:
        assert self._is_open, "QuestsMenuView must be opened before use"

    def _ensure_small_font(self) -> SmallFontData:
        if self._small_font is not None:
            return self._small_font
        missing_assets: list[str] = []
        self._small_font = load_small_font(self.state.assets_dir, missing_assets)
        return self._small_font

    def _init_ground(self) -> None:
        self._ground = ensure_menu_ground(self.state)

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
        status = self.state.status
        if int(status.quest_unlock_index) < QUEST_HARDCORE_UNLOCK_INDEX:
            return False
        check_on = self._check_on
        check_off = self._check_off
        if check_on is None or check_off is None:
            return False
        config = self.state.config
        hardcore = config.hardcore

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
            config.hardcore = not hardcore
            self._dirty = True
            if self.state.demo_enabled:
                config.hardcore = False
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
        status = self.state.status
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
        status = self.state.status
        config = self.state.config
        unlock = int(status.quest_unlock_index)
        if config.hardcore:
            unlock = int(status.quest_unlock_index_full)
        global_index = (int(stage) - 1) * 10 + int(row)
        return unlock >= global_index

    def _try_start_quest(self, stage: int, row: int) -> None:
        if not self._quest_unlocked(stage, row):
            return
        level = f"{int(stage)}.{int(row) + 1}"
        self.state.pending_quest_level = level
        self.state.config.game_mode = 3
        self._dirty = True
        self._begin_close_transition("start_quest")

    def _quest_title(self, stage: int, row: int) -> str:
        level = f"{int(stage)}.{int(row) + 1}"
        from ...quests import quest_by_level

        quest = quest_by_level(level)
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

        status = self.state.status
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

        config = self.state.config
        status = self.state.status
        hardcore_flag = config.hardcore
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
        assert assets is not None, "QuestsMenuView assets must be loaded before drawing sign"
        screen_w = float(self.state.config.screen_width)
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
        if not self.state.menu_sign_locked:
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
        fx_detail = self.state.config.fx_detail(level=0, default=False)
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
        assets = self._assets
        assert assets is not None, "QuestsMenuView assets must be loaded before drawing panel"
        panel = assets.panel
        _angle_rad, slide_x = MenuView._ui_element_anim(
            self,
            index=1,
            start_ms=PANEL_TIMELINE_START_MS,
            end_ms=PANEL_TIMELINE_END_MS,
            width=MENU_PANEL_WIDTH,
        )
        fx_detail = self.state.config.fx_detail(level=0, default=False)
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
            self.state.screen_fade_alpha = 0.0
            self.state.screen_fade_ramp = True
        if self.state.audio is not None:
            play_sfx(self.state.audio, "sfx_ui_buttonclick", rng=self.state.rng)
        self._closing = True
        self._close_action = action



__all__ = ["QuestsMenuView"]
