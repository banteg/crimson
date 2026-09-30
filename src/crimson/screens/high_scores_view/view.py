from __future__ import annotations

from crimson.game_states import GameStateId
from crimson.quests.level import QuestLevel
from crimson.screens.actions import Route, ScreenAction, StartRun
from crimson.ui.animation import ui_transition_alpha
from crimson.ui.cursor import ui_cursor_render
from crimson.ui.menu_chrome import draw_menu_sign
from grim import canvas
from grim.assets import RuntimeResources, TextureId
from grim.audio import play_sfx
from grim.config import SAVED_NAME_ENTRY_SIZE, HighScoreDateMode
from grim.geom import Rect, Vec2
from grim.raylib_api import rl
from grim.sfx_map import SfxId

from ...game.types import GameState
from ...game_modes import GameMode
from ...persistence.highscores import HighScoreRecord
from ...ui.button import UiButtonState, button_update
from ...ui.checkbox import UiCheckbox, ui_checkbox_update
from ...ui.dropdown import UiListWidget, ui_list_widget_update
from ...ui.menu_panel import draw_ui_panel, ui_panel_rect
from ...ui.scrollbar import UiScrollbar, ui_scrollbar_update
from ...ui.text_input import UiTextInput, ui_text_input_focus, update_name_entry_text
from ..actions import ShowScores
from ..assets import require_runtime_resources
from ..high_scores_layout import (
    HS_BACK_BUTTON_X,
    HS_BACK_BUTTON_Y,
    HS_BUTTON_STEP_Y,
    HS_BUTTON_X,
    HS_BUTTON_Y0,
    HS_HARDCORE_CHECKBOX_OFFSET,
    HS_QUEST_ARROW_X,
    HS_QUEST_ARROW_Y,
    HS_RIGHT_CHECK_X,
    HS_RIGHT_CHECK_Y,
    HS_RIGHT_GAME_MODE_WIDGET,
    HS_RIGHT_PLAYER_COUNT_WIDGET,
    HS_RIGHT_SCORE_LIST_WIDGET,
    HS_RIGHT_SHOW_SCORES_WIDGET,
    HS_SCORE_FRAME_X,
    HS_SCORE_FRAME_Y,
    PROFILE_ADD_ITEM,
    PROFILE_NAME_INPUT_W,
    hs_right_options_x_shift,
)
from ..menu_screen import MenuScreen
from ..quest_views.shared import QUEST_HARDCORE_UNLOCK_INDEX
from .main_panel import draw_main_panel
from .records import load_records
from .right_panel import draw_right_panel

DATE_FILTER_ITEMS = ("Best of all time", "Best of month", "Best of week", "Best of day")
# Native lists two players; the port plays up to four.
PLAYER_COUNT_ITEMS = ("1 player", "2 players", "3 players", "4 players")


class HighScoresView(MenuScreen):
    game_state = GameStateId.HIGHSCORES

    def __init__(self, state: GameState, request: ShowScores) -> None:
        super().__init__(state)
        self._dt = 0.0
        self._play_button = UiButtonState("Play a game", force_wide=True)
        self._back_button = UiButtonState("Back", force_wide=False)

        self._request = request.query
        self._return_context = request.return_context
        self._records: list[HighScoreRecord] = []
        # `highscore_screen`'s score list scrollbar: ten rows of rank, score and name.
        self.score_scroll = UiScrollbar(column_offsets=(10, 30, 44, 0, 0, 0, 0, 0), visible_rows=10)

        # `highscore_screen`'s list widgets; the score list is `ui_profile_menu_update`'s named lists.
        self.score_list = UiListWidget()
        # `ui_profile_menu_update`: the list stays open until toggled, and "<add new named list>" opens a name box.
        self._profile_list_open = False
        self._profile_add_mode = False
        self._profile_name_field = UiTextInput()
        self._profile_name = ""
        self._profile_caret = 0
        self._profile_add_button = UiButtonState("Add")
        self._profile_delete_button = UiButtonState("Delete")
        self.date_filter_list = UiListWidget()
        self.player_count_list = UiListWidget()
        self.game_mode_list = UiListWidget()
        self.internet_checkbox = UiCheckbox("Show internet scores")
        self.hardcore_checkbox = UiCheckbox("Hardcore")

    def open(self) -> None:
        
        super().open()
        self.score_scroll.scroll_offset = 0.0
        self.score_scroll.hovered_index = -1
        # The port's rank to show (a finished quest's) is the list's selected row.
        self.score_scroll.selected_index = self._request.highlight_rank or 0
        self._dirty = False
        self._update_button = UiButtonState("Update scores", force_wide=True)
        self._play_button = UiButtonState("Play a game", force_wide=True)
        self._back_button = UiButtonState("Back", force_wide=False)

        self._close_lists()

        self._reload_records()
        if self.state.audio is not None:
            play_sfx(self.state.audio, SfxId.UI_PANELCLICK)

    def close(self) -> None:
        super().close()
        self._return_context = None
        self._records = []
        self.score_scroll.items = []
        self.score_scroll.scroll_offset = 0.0
        self._dirty = False
        self._close_lists()

    def _lists(self) -> tuple[UiListWidget, ...]:
        return (self.score_list, self.date_filter_list, self.player_count_list, self.game_mode_list)

    def _close_lists(self) -> None:
        for widget in self._lists():
            widget.open = False
        self._profile_list_open = False
        self._profile_add_mode = False

    def _mode_items(self) -> tuple[tuple[str, GameMode], ...]:
        # Typ'o'Shooter is listed from 40 unlocked quests.
        modes = (("Quests", GameMode.QUESTS), ("Rush", GameMode.RUSH), ("Survival", GameMode.SURVIVAL))
        if self.state.status.quest_unlock_index >= 40:
            modes += (("Typ'o'Shooter", GameMode.TYPO),)
        return modes

    def sync_lists(self) -> None:
        """`highscore_screen`: refill the lists from the config, and disable the lists an open one covers."""
        config = self.state.config
        self.score_list.items = (*config.profile.saved_name_labels(), PROFILE_ADD_ITEM)
        self.score_list.selected_index = config.profile.selected_saved_name_slot
        self.date_filter_list.items = DATE_FILTER_ITEMS
        self.date_filter_list.selected_index = int(config.profile.score_date_mode)
        self.player_count_list.items = PLAYER_COUNT_ITEMS
        self.player_count_list.selected_index = config.gameplay.player_count - 1
        modes = self._mode_items()
        self.game_mode_list.items = tuple(label for label, _mode in modes)
        self.game_mode_list.selected_index = next(
            (index for index, (_label, mode) in enumerate(modes) if mode == config.gameplay.mode), 0,
        )

        self.game_mode_list.enabled = not (self.player_count_list.open or self.date_filter_list.open)
        self.date_filter_list.enabled = not (self.game_mode_list.open or self.player_count_list.open)
        self.score_list.enabled = not (
            self.game_mode_list.open or self.player_count_list.open or self.date_filter_list.open
        )
        # Typ'o'Shooter scores are single-player only.
        self.player_count_list.enabled = config.gameplay.mode != GameMode.TYPO
        if not self.player_count_list.enabled:
            self.player_count_list.selected_index = 0

    def _panel_rect(self, index: int) -> Rect:
        """`highscore_screen` lays out on `ui_element_slot_09` (the scores) and slot 33 (the options)."""
        return ui_panel_rect(index, self.state.ui.timeline_ms, self.state.config.display.width)

    def update(self, dt: float) -> None:
        self._dt = min(dt, 0.1)
        if not self._advance(dt):
            return
        dt_ms = int(min(float(dt), 0.1) * 1000.0)

        enabled = self.state.ui.opened
        focus = self.state.focus

        if focus.escape and enabled:
            if any(widget.open for widget in self._lists()):
                self._close_lists()
                return
            self._begin_close_transition(Route.BACK)
            return

        if not enabled:
            return

        resources = require_runtime_resources(self.state)
        left_panel_top_left = self._panel_rect(9).top_left
        right_panel_top_left = self._panel_rect(33).top_left

        # `highscore_screen` focus order: the Hardcore checkbox, the score list, Update / Play / Back, then the
        # right panel's checkbox and lists. A press while a list is open belongs to the lists only.
        dropdown_was_open = any(widget.open for widget in self._lists())
        mouse = canvas.mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT) and not dropdown_was_open
        self._update_quest_arrows(left_panel_top_left=left_panel_top_left, resources=resources, click=click)
        self._update_score_scroll(left_panel_top_left, mouse=mouse, click=click)

        button_base_pos = left_panel_top_left + Vec2(HS_BUTTON_X, HS_BUTTON_Y0)
        if button_update(
            resources,
            self._update_button,
            focus=focus,
            pos=button_base_pos,
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            # Reload scores from disk (no view transition).
            if self.state.audio is not None:
                play_sfx(self.state.audio, SfxId.UI_BUTTONCLICK)
            self._reload_records()
        if button_update(
            resources,
            self._play_button,
            focus=focus,
            pos=button_base_pos.offset(dy=HS_BUTTON_STEP_Y),
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self._start_selected_game()
        if button_update(
            resources,
            self._back_button,
            focus=focus,
            pos=left_panel_top_left + Vec2(HS_BACK_BUTTON_X, HS_BACK_BUTTON_Y),
            dt_ms=dt_ms,
            mouse=mouse,
            click=click,
        ):
            self._begin_close_transition(Route.BACK)

        # Native only runs the right panel's widgets while no score card covers them.
        if self.score_scroll.hovered_index == -1 and self._request.highlight_rank is None:
            self._update_right_panel_widgets(right_top_left=right_panel_top_left, resources=resources)

    def _update_score_scroll(self, left_panel_top_left: Vec2, *, mouse: rl.Vector2, click: bool) -> None:
        """`highscore_screen`'s `ui_scrollbar_update` over the scores; the port adds Home/End."""
        bar = self.score_scroll
        ui_scrollbar_update(
            self.state.focus,
            bar,
            left_panel_top_left + Vec2(HS_SCORE_FRAME_X, HS_SCORE_FRAME_Y),
            mouse=Vec2.from_xy(mouse),
            click=click,
            down=rl.is_mouse_button_down(rl.MouseButton.MOUSE_BUTTON_LEFT),
            wheel=rl.get_mouse_wheel_move(),
        )
        if rl.is_key_pressed(rl.KeyboardKey.KEY_HOME):
            bar.scroll_offset = 0.0
        if rl.is_key_pressed(rl.KeyboardKey.KEY_END):
            bar.scroll_offset = float(bar.max_scroll)

    def _begin_close_transition(self, action: ScreenAction, *, fade_to_black: bool = False) -> None:
        # `highscore_return_latch`: back to a run's results restores the settings the scores were browsed with.
        if action == Route.BACK and not self.state.ui.closing and self._return_context is not None:
            self._return_context.restore(self.state.config)
        super()._begin_close_transition(action, fade_to_black=fade_to_black)

    def _start_selected_game(self) -> None:
        request = self._request
        if request.game_mode_id == GameMode.QUESTS:
            level = request.quest_level
            assert level is not None
            unlock = (
                self.state.status.quest_unlock_index_full
                if self.state.config.gameplay.hardcore
                else self.state.status.quest_unlock_index
            )
            if level.global_index > unlock:
                return
        self._begin_close_transition(StartRun(request.game_mode_id, request.quest_level), fade_to_black=True)

    def _reload_records(self) -> None:
        """`highscore_load_table`, then `highscore_screen`'s score lines: rank, score (seconds in Rush and Quests)
        and name, green for a score the server took."""
        self._records = load_records(self.state, self._request)
        items = []
        for rank, record in enumerate(self._records, start=1):
            flags = record.flags
            prefix = "\\g" if (flags & 1 or flags & 4) and (not flags & 2 or flags & 4) else ""
            match self._request.game_mode_id:
                case GameMode.RUSH | GameMode.QUESTS:
                    items.append(f"{prefix}{rank}\t{record.survival_elapsed_ms // 1000}\t{record.name()}")
                case _:
                    items.append(f"{prefix}{rank}\t{record.score_xp}\t{record.name()}")
        self.score_scroll.items = items

    def _update_right_panel_widgets(
        self,
        *,
        right_top_left: Vec2,
        resources: RuntimeResources,
    ) -> None:
        request = self._request
        focus = self.state.focus
        small_width_shift_x = hs_right_options_x_shift(float(self.state.config.display.width))
        shifted_right_top_left = right_top_left + Vec2(small_width_shift_x, 0.0)
        mouse = Vec2.from_xy(canvas.mouse_position())
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        # `input_primary_just_pressed() || grim_was_key_pressed(Enter)`.
        pressed = click or focus.enter

        # Checkbox: "Show internet scores" (config.show_online_scores); an open list covers it.
        checkbox = self.internet_checkbox
        checkbox.checked = self.state.config.profile.show_internet_scores
        checkbox.disabled = any(widget.open for widget in self._lists())
        if ui_checkbox_update(
            resources,
            checkbox,
            shifted_right_top_left + Vec2(HS_RIGHT_CHECK_X, HS_RIGHT_CHECK_Y),
            focus=focus,
            mouse=mouse,
            click=click,
        ):
            self.state.config.profile.show_internet_scores = checkbox.checked
            self._dirty = True
            self._reload_records()

        self.sync_lists()

        self._update_profile_menu(
            shifted_right_top_left + HS_RIGHT_SCORE_LIST_WIDGET, resources=resources, mouse=mouse, click=click,
        )

        # Show scores: the date filter (config.highscore_date_mode).
        widget = self.date_filter_list
        selected = ui_list_widget_update(
            resources, widget, shifted_right_top_left + HS_RIGHT_SHOW_SCORES_WIDGET, focus=focus, mouse=mouse, click=click,
            preserve_bugs=self.state.preserve_bugs,
        )
        if selected > -2 and pressed:
            widget.open = not widget.open
            if selected >= 0:
                self.state.config.profile.score_date_mode = HighScoreDateMode(selected)
                self._dirty = True
                self._reload_records()

        # Number of players (config.player_count).
        widget = self.player_count_list
        selected = ui_list_widget_update(
            resources, widget, shifted_right_top_left + HS_RIGHT_PLAYER_COUNT_WIDGET, focus=focus, mouse=mouse, click=click,
            preserve_bugs=self.state.preserve_bugs,
        )
        if selected > -2 and pressed:
            widget.open = not widget.open
            if selected >= 0 and self.state.config.gameplay.player_count != selected + 1:
                self.state.config.gameplay.player_count = selected + 1
                self._dirty = True
                self._reload_records()

        # Game mode (config.game_mode / request.game_mode_id).
        widget = self.game_mode_list
        selected = ui_list_widget_update(
            resources, widget, shifted_right_top_left + HS_RIGHT_GAME_MODE_WIDGET, focus=focus, mouse=mouse, click=click,
            preserve_bugs=self.state.preserve_bugs,
        )
        if selected > -2 and pressed:
            widget.open = not widget.open
            if selected >= 0:
                _label, mode_id = self._mode_items()[selected]
                self.state.config.gameplay.mode = mode_id
                request.game_mode_id = mode_id
                match mode_id:
                    case GameMode.TYPO:
                        # Native forces Typ-o shooter scores to 1 player.
                        self.state.config.gameplay.player_count = 1
                    case GameMode.QUESTS:
                        # Ensure quest selection exists when switching into quests.
                        if request.quest_level is None:
                            request.quest_level = self.state.config.gameplay.quest_level or QuestLevel(1, 1)
                    case _:
                        pass
                self._dirty = True
                self._reload_records()

    def _update_profile_menu(self, xy: Vec2, *, resources: RuntimeResources, mouse: Vec2, click: bool) -> None:
        """`ui_profile_menu_update`: the named score lists, with a name box and Add for a new one, or Delete."""
        focus = self.state.focus
        profile = self.state.config.profile
        dt_ms = self._dt * 1000.0
        enter = focus.enter
        if self._profile_add_mode:
            input_pos = xy.offset(dy=29.0)
            ui_text_input_focus(focus, self._profile_name_field, input_pos, width=PROFILE_NAME_INPUT_W, mouse=mouse)
            self._profile_name, self._profile_caret = update_name_entry_text(
                self._profile_name,
                self._profile_caret,
                max_len=SAVED_NAME_ENTRY_SIZE - 1,
                rng=self.state.rng,
                play_sfx=self._play_sfx,
            )
            # The name box takes Enter wherever the focus is, before the list sees it.
            submitted = enter
            enter = False
            added = button_update(
                resources,
                self._profile_add_button,
                focus=focus,
                pos=xy + Vec2(180.0, 22.0),
                dt_ms=dt_ms,
                mouse=canvas.mouse_position(),
                click=click,
            )
            # Port: an empty name would name the default list's file, so it is not added.
            if (submitted or added) and self._profile_name.strip():
                self._play_sfx(SfxId.UI_TYPEENTER)
                profile.add_saved_name(self._profile_name)
                self._profile_name, self._profile_caret = "", 0
                self._profile_add_mode = False
                self._dirty = True
                self._reload_records()
        elif not self._profile_list_open and profile.selected_saved_name_slot != 0:
            if button_update(
                resources,
                self._profile_delete_button,
                focus=focus,
                pos=xy.offset(dy=22.0),
                dt_ms=dt_ms,
                mouse=canvas.mouse_position(),
                click=click,
            ):
                profile.delete_selected_saved_name()
                self._dirty = True
                self._reload_records()

        self.sync_lists()
        widget = self.score_list
        selected = ui_list_widget_update(
            resources, widget, xy, focus=focus, mouse=mouse, click=click, preserve_bugs=self.state.preserve_bugs,
        )
        if selected > -2 and (click or enter):
            self._profile_list_open = not self._profile_list_open
            add_item = len(widget.items) - 1
            if selected >= 0:
                profile.selected_saved_name_slot = selected
                if selected != add_item:
                    self._dirty = True
                    self._reload_records()
            self._profile_add_mode = selected == add_item
        widget.open = self._profile_list_open

    def _play_sfx(self, sfx: SfxId) -> None:
        if self.state.audio is not None:
            play_sfx(self.state.audio, sfx)

    def _update_quest_arrows(
        self,
        *,
        left_panel_top_left: Vec2,
        resources: RuntimeResources,
        click: bool,
    ) -> None:
        """`highscore_screen`'s quest header: the Hardcore checkbox, and paging the quest with the arrows or with
        Left/Right."""
        request = self._request
        if request.game_mode_id != GameMode.QUESTS:
            return

        level = request.quest_level
        if level is None:
            return

        global_index = int(level.global_index)
        mouse = Vec2.from_xy(canvas.mouse_position())
        focus = self.state.focus

        # `highscore_screen`: the Hardcore checkbox beside the column headers, from 40 unlocked quests.
        hardcore_toggled = False
        if self.state.status.quest_unlock_index >= QUEST_HARDCORE_UNLOCK_INDEX:
            checkbox = self.hardcore_checkbox
            checkbox.checked = self.state.config.gameplay.hardcore
            if ui_checkbox_update(
                resources,
                checkbox,
                left_panel_top_left + HS_HARDCORE_CHECKBOX_OFFSET,
                focus=focus,
                mouse=mouse,
                click=click,
            ):
                self.state.config.gameplay.hardcore = checkbox.checked
                hardcore_toggled = True

        unlock = (
            int(self.state.status.quest_unlock_index_full)
            if self.state.config.gameplay.hardcore
            else int(self.state.status.quest_unlock_index)
        )
        max_index = max(0, min(49, unlock))
        arrow = resources.texture(TextureId.UI_ARROW)
        arrow_w = float(arrow.width)
        arrow_h = float(arrow.height)

        # The native has two arrows spaced 255px apart; at 1.1 only the "next" arrow is drawn.
        prev_pos = left_panel_top_left + Vec2(HS_QUEST_ARROW_X - 255.0, HS_QUEST_ARROW_Y)
        next_pos = left_panel_top_left + Vec2(HS_QUEST_ARROW_X, HS_QUEST_ARROW_Y)
        prev_rect = Rect.from_top_left(prev_pos, arrow_w, arrow_h)
        next_rect = Rect.from_top_left(next_pos, arrow_w, arrow_h)

        def _set_level(index: int) -> None:
            index = max(0, min(max_index, int(index)))
            level = QuestLevel.from_global_index(index)
            request.quest_level = level
            self.state.config.gameplay.quest_level = level
            self._dirty = True
            self._reload_records()

        # Native pages with the arrow keys too; switching tables reloads and clamps to the unlocked quests.
        if global_index > 0 and ((prev_rect.contains(mouse) and click) or focus.left):
            _set_level(global_index - 1)
        elif global_index < max_index and ((next_rect.contains(mouse) and click) or focus.right):
            _set_level(global_index + 1)
        elif hardcore_toggled:
            _set_level(global_index)

    def draw(self) -> None:
        self._assert_open()
        self._draw_background(entity_alpha=self._world_entity_alpha())

        resources = require_runtime_resources(self.state)
        font = resources.small_font
        request = self._request
        mode_id = request.game_mode_id
        quest_major = int(request.quest_level.major) if request.quest_level is not None else 0
        quest_minor = int(request.quest_level.minor) if request.quest_level is not None else 0

        shadows_enabled = self.state.config.display.shadows_enabled
        left_panel = self._panel_rect(9)
        right_panel = self._panel_rect(33)
        draw_ui_panel(resources, 9, left_panel, shadow=shadows_enabled)
        draw_ui_panel(resources, 33, right_panel, shadow=shadows_enabled)
        left_panel_top_left = left_panel.top_left
        right_panel_top_left = right_panel.top_left

        selected_rank = draw_main_panel(
            self,
            resources=resources,
            font=font,
            left_panel_top_left=left_panel_top_left,
            mode_id=mode_id,
            quest_major=quest_major,
            quest_minor=quest_minor,
            request=request,
        )

        draw_right_panel(
            self,
            resources=resources,
            font=font,
            right_top_left=right_panel_top_left,
            highlight_rank=selected_rank,
        )
        draw_menu_sign(
            require_runtime_resources(self.state),
            width=self.state.config.display.width,
            shadows=self.state.config.display.shadows_enabled,
        )
        ui_cursor_render(resources, dt=self.state.frame_dt)

    def _world_entity_alpha(self) -> float:
        # A run under the scores is the quest results' (a dead run's game over leaves only its terrain); going back
        # to its results keeps it lit.
        match self.state.ui.pending:
            case None:
                pending = None
            case StartRun(mode=GameMode.TYPO):
                pending = GameStateId.TYPO_GAMEPLAY
            case StartRun():
                pending = GameStateId.GAMEPLAY
            case _ if self._return_context is None:
                pending = GameStateId.STATISTICS_MENU
            case _:
                quest = self._return_context.game_mode_id == GameMode.QUESTS
                pending = GameStateId.QUEST_RESULTS if quest else GameStateId.GAME_OVER
        return ui_transition_alpha(self.state.ui.timeline_ms, state=GameStateId.HIGHSCORES, pending=pending)

    def _visible_rows(self, font) -> int:
        row_step = float(font.cell_size)
        table_top = 188.0 + row_step
        reserved_bottom = 96.0
        available = max(0.0, float(canvas.height()) - table_top - reserved_bottom)
        return max(1, int(available // row_step))


__all__ = ["HighScoresView"]
