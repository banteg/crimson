from __future__ import annotations

from crimson.game_states import GameStateId
from crimson.quests.level import QUEST_COUNT, QuestLevel
from crimson.quests.status import quest_completed_counter_index, quest_games_counter_index
from crimson.screens.actions import Route, StartRun
from crimson.ui.cursor import ui_cursor_render
from crimson.ui.menu_chrome import draw_menu_sign
from grim import canvas
from grim.assets import TextureId
from grim.draw import grim_draw_rect_outline
from grim.fonts.small import draw_small_text, measure_small_text_width
from grim.geom import Rect, Vec2
from grim.raylib_api import rl

from ...debug import debug_enabled
from ...game.types import GameState
from ...game_modes import GameMode
from ...ui.checkbox import UiCheckbox, ui_checkbox_draw, ui_checkbox_update
from ...ui.menu_panel import draw_ui_panel, ui_panel_rect
from ...ui.perk_menu import UiButtonState, UiMenuItem, button_draw, button_update, ui_menu_item_update
from ..assets import require_runtime_resources
from ..menu_screen import MenuScreen
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


class QuestsMenuView(MenuScreen):
    """Quest selection menu.

    Layout and gating are based on `quest_select_menu_update` (crimsonland.exe).

    The classic game treats this as a distinct UI state (transition target `0x0b`),
    entered from the Play Game panel.
    """

    game_state = GameStateId.QUEST_SELECT

    def __init__(self, state: GameState) -> None:
        super().__init__(state)
        self._back_button = UiButtonState("Back")
        self._hardcore_checkbox = UiCheckbox("Hardcore")
        # Port focus targets for the ten quest rows: native picks a row only by mouse or the number keys.
        self._row_items = tuple(UiMenuItem() for _ in range(10))

        self._menu_screen_width = 0
        self._stage = 1

    def open(self) -> None:
        self._menu_screen_width = int(self.state.config.display.width)
        super().open()
        self._dirty = False
        self._stage = max(1, min(5, int(self._stage)))
        self._back_button = UiButtonState("Back")

        # Ensure the quest registry is populated so titles render.
        # (The package import registers all tier builders.)
        from ... import quests as _quests

        _ = _quests

    def close(self) -> None:
        if self._dirty:
            try:
                self.state.config.save()
            except (OSError, ValueError) as exc:
                self.state.console.log.log(f"failed to save quest menu config: {exc}")
            self._dirty = False
        super().close()

    def update(self, dt: float) -> None:
        if not self._advance(dt):
            return
        self._lock_sign(dt)

        status = self.state.status

        if debug_enabled() and rl.is_key_pressed(rl.KeyboardKey.KEY_F5):
            # Every quest completed, 5.10's reward included.
            unlock = QUEST_COUNT
            if int(status.quest_unlock_index) < unlock:
                status.quest_unlock_index = unlock
            if int(status.quest_unlock_index_full) < unlock:
                status.quest_unlock_index_full = unlock
            self.state.console.log.log("debug: unlocked everything")

        enabled = self.state.ui.timeline_ms >= self.state.ui.max_timeline_ms

        if self.state.focus.escape and enabled:
            self._begin_close_transition(Route.BACK)
            return

        if not enabled:
            return

        focus = self.state.focus
        if focus.left:
            self._stage = max(1, self._stage - 1)
        if focus.right:
            self._stage = min(5, self._stage + 1)

        layout = self._layout()

        # Stage icons: hover is tracked, but stage selection requires a click.
        hovered_stage = self._hovered_stage(layout)
        if hovered_stage is not None and rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
            self._stage = hovered_stage
            return

        # Focus order: the Hardcore checkbox, the port's quest rows, then Back (native has the checkbox and Back).
        self._update_hardcore_checkbox(layout)

        mouse = canvas.mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        picked_row: int | None = None
        for row, item in enumerate(self._row_items):
            if ui_menu_item_update(item, focus=focus, hit=self._row_rect(layout, row), mouse=mouse, click=click):
                picked_row = row

        back_pos = Vec2(layout.list_pos.x, self._rows_y0(layout)) + Vec2(
            QUEST_BACK_BUTTON_X_OFFSET,
            QUEST_BACK_BUTTON_Y_OFFSET,
        )
        dt_ms = min(float(dt), 0.1) * 1000.0
        resources = require_runtime_resources(self.state)
        if button_update(
            resources,
            self._back_button,
            focus=focus,
            pos=back_pos,
            dt_ms=float(dt_ms),
            mouse=mouse,
            click=bool(click),
        ):
            self._begin_close_transition(Route.BACK)
            return

        # Quick-select row numbers 1..0 (10).
        row_from_key = self._digit_row_pressed()
        if row_from_key is not None:
            self._try_start_quest(self._stage, row_from_key)
            return

        if picked_row is not None:
            self._try_start_quest(self._stage, picked_row)

    def draw(self) -> None:
        self._assert_open()
        self._draw_background()

        self._draw_panel()
        draw_menu_sign(
            require_runtime_resources(self.state),
            width=self.state.config.display.width,
            shadows=self.state.config.display.shadows_enabled,
            locked=self.state.menu_sign_locked,
            timeline_ms=self.state.ui.timeline_ms,
        )
        self._draw_contents()
        ui_cursor_render(require_runtime_resources(self.state), dt=self.state.frame_dt)

    def _panel_rect(self) -> Rect:
        """`quest_select_menu_update` lays out on `ui_element_slot_37`'s panel."""
        return ui_panel_rect(37, self.state.ui.timeline_ms, self._menu_screen_width)

    def _layout(self) -> _QuestMenuLayout:
        panel_top_left = self._panel_rect().top_left
        x_sum = panel_top_left.x
        y_sum = panel_top_left.y

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
        mouse_pos = Vec2.from_xy(canvas.mouse_position())
        for stage in range(1, 6):
            x = x0 + float(stage - 1) * QUEST_STAGE_ICON_STEP
            # Hover bounds are fixed 32x32, anchored at (x, title_y) (not icons_y).
            stage_rect = Rect.from_top_left(Vec2(x, title_y), QUEST_STAGE_ICON_SIZE, QUEST_STAGE_ICON_SIZE)
            if stage_rect.contains(mouse_pos):
                return stage
        return None

    def _update_hardcore_checkbox(self, layout: _QuestMenuLayout) -> None:
        if self.state.status.quest_unlock_index < QUEST_HARDCORE_UNLOCK_INDEX:
            return
        config = self.state.config
        checkbox = self._hardcore_checkbox
        checkbox.checked = config.gameplay.hardcore
        if ui_checkbox_update(
            require_runtime_resources(self.state),
            checkbox,
            layout.list_pos + Vec2(QUEST_HARDCORE_CHECKBOX_X_OFFSET, QUEST_HARDCORE_CHECKBOX_Y_OFFSET),
            focus=self.state.focus,
            mouse=Vec2.from_xy(canvas.mouse_position()),
            click=rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT),
        ):
            config.gameplay.hardcore = checkbox.checked
            self._dirty = True

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
        # `quest_select_menu_update` adds +10 to the list Y after rendering the Hardcore checkbox.
        status = self.state.status
        y0 = layout.list_pos.y
        if int(status.quest_unlock_index) >= QUEST_HARDCORE_UNLOCK_INDEX:
            y0 += QUEST_HARDCORE_LIST_Y_SHIFT
        return y0

    def _row_rect(self, layout: _QuestMenuLayout, row: int) -> Rect:
        list_x = layout.list_pos.x
        y = self._rows_y0(layout) + float(row) * QUEST_LIST_ROW_STEP
        left = list_x - QUEST_LIST_HOVER_LEFT_PAD
        top = y - QUEST_LIST_HOVER_TOP_PAD
        right = list_x + QUEST_LIST_HOVER_RIGHT_PAD
        bottom = y + QUEST_LIST_HOVER_BOTTOM_PAD
        return Rect.from_top_left(Vec2(left, top), right - left, bottom - top)

    def _hovered_row(self, layout: _QuestMenuLayout) -> int | None:
        mouse_pos = Vec2.from_xy(canvas.mouse_position())
        for row in range(10):
            if self._row_rect(layout, row).contains(mouse_pos):
                return row
        return None

    def _quest_unlocked(self, stage: int, row: int) -> bool:
        status = self.state.status
        config = self.state.config
        unlock = int(status.quest_unlock_index)
        if config.gameplay.hardcore:
            unlock = int(status.quest_unlock_index_full)
        level = QuestLevel(int(stage), int(row) + 1)
        return unlock >= int(level.global_index)

    def _try_start_quest(self, stage: int, row: int) -> None:
        if not self._quest_unlocked(stage, row):
            return
        level = QuestLevel(int(stage), int(row) + 1)
        self.state.config.gameplay.mode = GameMode.QUESTS
        self.state.config.gameplay.quest_level = level
        self._dirty = True
        self._begin_close_transition(StartRun(GameMode.QUESTS, level), fade_to_black=True)

    def _quest_title(self, stage: int, row: int) -> str:
        from ...quests import quest_by_level

        quest = quest_by_level(QuestLevel(int(stage), int(row) + 1))
        if quest is None:
            return "???"
        return quest.title

    @staticmethod
    def _quest_row_colors(*, hardcore: bool) -> tuple[rl.Color, rl.Color]:
        # `quest_select_menu_update` uses different RGB when hardcore is toggled.
        if hardcore:
            # (0.980392, 0.274509, 0.235294, alpha)
            r, g, b = 250, 70, 60
        else:
            # (0.274509, 0.707..., 0.941..., alpha)
            r, g, b = 70, 180, 240
        return (rl.Color(r, g, b, 153), rl.Color(r, g, b, 255))

    def _quest_counts(self, *, stage: int, row: int) -> tuple[int, int] | None:
        # In `quest_select_menu_update`, counts are indexed by (row + stage*10) and split across two
        # arrays at offsets 0xDC (games) and 0x17C (completed) within game.cfg.
        #
        # Stage 5 does not fit cleanly in the saved blob:
        # - The "games" index range would overlap stage-1 completion counters.
        # - The "completed" index range reads into trailing fields (mode counters,
        #   play_time_ms, and unknown tail bytes), and the last row would run past
        #   the decoded payload.
        #
        # We emulate this layout so the debug `F1` overlay matches the classic build.
        level = QuestLevel(int(stage), int(row) + 1)
        global_index = int(level.global_index)

        status = self.state.status
        games_idx = quest_games_counter_index(level)
        completed_idx = quest_completed_counter_index(level)
        try:
            games = int(status.quest_play_count(games_idx))
        except IndexError:
            return None

        try:
            completed = int(status.quest_play_count(completed_idx))
        except IndexError:
            # Stage-5 completed reads into trailing fields (and beyond).
            if int(stage) != 5:
                return None
            tail_slot = int(global_index) - 40
            if tail_slot == 0:
                completed = int(status.mode_play_count_for_mode(GameMode.SURVIVAL))
            elif tail_slot == 1:
                completed = int(status.mode_play_count_for_mode(GameMode.RUSH))
            elif tail_slot == 2:
                completed = int(status.mode_play_count_for_mode(GameMode.TYPO))
            elif tail_slot == 3:
                completed = int(status.mode_play_other)
            elif tail_slot == 4:
                completed = int(status.play_time_ms)
            elif 5 <= tail_slot <= 8:
                tail = status.reserved_seed_words
                off = (tail_slot - 5) * 4
                if len(tail) < off + 4:
                    completed = 0
                else:
                    completed = int.from_bytes(tail[off : off + 4], "little") & 0xFFFFFFFF
            else:
                completed = 0
        return completed, games

    def _draw_contents(self) -> None:
        resources = require_runtime_resources(self.state)
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
        # Native shows the times-played counts while F1 is held.
        show_counts = rl.is_key_down(rl.KeyboardKey.KEY_F1)

        # Title texture is tinted by (0.7, 0.7, 0.7, 0.7).
        title_tex = resources.texture(TextureId.UI_TEXT_QUEST)
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
        stage_icons = {
            1: resources.texture(TextureId.UI_NUM1),
            2: resources.texture(TextureId.UI_NUM2),
            3: resources.texture(TextureId.UI_NUM3),
            4: resources.texture(TextureId.UI_NUM4),
            5: resources.texture(TextureId.UI_NUM5),
        }
        for idx in range(1, 6):
            icon = stage_icons[idx]
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
        hardcore_flag = config.gameplay.hardcore
        base_color, hover_color = self._quest_row_colors(hardcore=hardcore_flag)

        font = resources.small_font

        y0 = self._rows_y0(layout)
        # Hardcore checkbox (only drawn once tier5 is reachable in normal mode).
        if status.quest_unlock_index >= QUEST_HARDCORE_UNLOCK_INDEX:
            ui_checkbox_draw(
                resources,
                self._hardcore_checkbox,
                list_pos + Vec2(QUEST_HARDCORE_CHECKBOX_X_OFFSET, QUEST_HARDCORE_CHECKBOX_Y_OFFSET),
                focus=self.state.focus,
            )

        # Quest list (10 rows).
        for row in range(10):
            y = y0 + float(row) * QUEST_LIST_ROW_STEP
            unlocked = self._quest_unlocked(stage, row)
            color = hover_color if hovered_row == row else base_color
            if self._row_items[row].focused:
                self.state.focus.draw(Vec2(list_pos.x - 16.0, y))

            draw_small_text(font, f"{stage}.{row + 1}", Vec2(list_pos.x, y), color)

            if unlocked:
                title = self._quest_title(stage, row)
            else:
                title = "???"
            draw_small_text(font, title, Vec2(list_pos.x + QUEST_LIST_NAME_X_OFFSET, y), color)
            title_w = measure_small_text_width(font, title) if unlocked else 0.0
            if unlocked:
                grim_draw_rect_outline(Vec2(list_pos.x, y + 13.0), title_w + 32.0, 1.0, color)

            if show_counts and unlocked:
                counts = self._quest_counts(stage=stage, row=row)
                if counts is not None:
                    completed, games = counts
                    counts_x = list_pos.x + QUEST_LIST_NAME_X_OFFSET + title_w + 12.0
                    draw_small_text(font, f"({completed}/{games})", Vec2(counts_x, y), color)

        if show_counts:
            # Header is drawn below the list, aligned with the count column.
            header_x = list_pos.x + 96.0
            header_y = y0 + QUEST_LIST_ROW_STEP * 10.0 - 2.0
            draw_small_text(font, "(completed/games)", Vec2(header_x, header_y), base_color)

        # Back button.
        back_pos = Vec2(list_pos.x, y0) + Vec2(QUEST_BACK_BUTTON_X_OFFSET, QUEST_BACK_BUTTON_Y_OFFSET)
        button_draw(
            resources,
            self._back_button,
            focus=self.state.focus,
            pos=back_pos,
        )

    def _draw_panel(self) -> None:
        draw_ui_panel(
            require_runtime_resources(self.state), 37, self._panel_rect(),
            shadow=self.state.config.display.shadows_enabled,
        )


__all__ = ["QuestsMenuView"]
