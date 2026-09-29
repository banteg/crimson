from __future__ import annotations

from crimson.game_states import GameStateId
from crimson.quests.level import QuestLevel
from crimson.screens.actions import Route, ScreenAction, StartRun
from crimson.screens.chrome import draw_screen_background, ensure_menu_ground
from crimson.ui.animation import ui_element_anim, ui_elements_max_timeline
from crimson.ui.cursor import ui_cursor_render
from crimson.ui.layout import menu_widescreen_y_shift
from crimson.ui.menu_chrome import draw_menu_sign
from crimson.ui.menu_layout import (
    MENU_PANEL_OFFSET_X,
    MENU_PANEL_OFFSET_Y,
    MENU_PANEL_WIDTH,
)
from grim import canvas
from grim.assets import RuntimeResources, TextureId
from grim.audio import play_sfx, update_audio
from grim.config import HighScoreDateMode
from grim.geom import Rect, Vec2
from grim.raylib_api import rl
from grim.sfx_map import SfxId
from grim.terrain_render import GroundRenderer

from ...game.types import GameState
from ...game_modes import GameMode
from ...persistence.highscores import HighScoreRecord
from ...ui.checkbox import UiCheckbox, ui_checkbox_update
from ...ui.dropdown import UiListWidget, ui_list_widget_update
from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import UiButtonState, button_update
from ...ui.scrollbar import UiScrollbar, ui_scrollbar_update_keys
from ..actions import ShowScores
from ..assets import require_runtime_resources
from ..high_scores_layout import (
    HS_BACK_BUTTON_X,
    HS_BACK_BUTTON_Y,
    HS_BUTTON_STEP_Y,
    HS_BUTTON_X,
    HS_BUTTON_Y0,
    HS_HARDCORE_CHECKBOX_OFFSET,
    HS_LEFT_PANEL_HEIGHT,
    HS_LEFT_PANEL_POS_Y,
    HS_QUEST_ARROW_X,
    HS_QUEST_ARROW_Y,
    HS_RIGHT_CHECK_X,
    HS_RIGHT_CHECK_Y,
    HS_RIGHT_GAME_MODE_WIDGET,
    HS_RIGHT_PANEL_HEIGHT,
    HS_RIGHT_PANEL_POS_Y,
    HS_RIGHT_PLAYER_COUNT_WIDGET,
    HS_RIGHT_SCORE_LIST_WIDGET,
    HS_RIGHT_SHOW_SCORES_WIDGET,
    hs_left_panel_pos_x,
    hs_right_options_x_shift,
    hs_right_panel_pos_x,
)
from ..quest_views.shared import QUEST_HARDCORE_UNLOCK_INDEX
from ..transitions import _draw_screen_fade
from .main_panel import draw_main_panel, score_row_under_mouse
from .records import load_records
from .right_panel import draw_right_panel

DATE_FILTER_ITEMS = ("Best of all time", "Best of month", "Best of week", "Best of day")
# Native lists two players; the port plays up to four.
PLAYER_COUNT_ITEMS = ("1 player", "2 players", "3 players", "4 players")


class HighScoresView:
    def __init__(self, state: GameState, request: ShowScores) -> None:
        self.state = state
        self._is_open = False
        self._ground: GroundRenderer | None = None
        self._dt = 0.0
        self._widescreen_y_shift = 0.0
        self._play_button = UiButtonState("Play a game", force_wide=True)
        self._back_button = UiButtonState("Back", force_wide=False)

        self._request = request.query
        self._return_context = request.return_context
        self._records: list[HighScoreRecord] = []
        # `highscore_screen`'s score list scrollbar: ten rows.
        self.score_scroll = UiScrollbar(visible_rows=10)
        self._dirty = False

        # `highscore_screen`'s list widgets. The score list stands in for `ui_profile_menu_update`'s name list
        # (the port has no add/delete flow).
        self.score_list = UiListWidget()
        self.date_filter_list = UiListWidget()
        self.player_count_list = UiListWidget()
        self.game_mode_list = UiListWidget()
        self.internet_checkbox = UiCheckbox("Show internet scores")
        self.hardcore_checkbox = UiCheckbox("Hardcore")

    def open(self) -> None:
        layout_w = float(self.state.config.display.width)
        self._widescreen_y_shift = menu_widescreen_y_shift(layout_w)
        self._ground = None if self.state.pause_background is not None else ensure_menu_ground(self.state)
        self.state.ui.enter(ui_elements_max_timeline(GameStateId.HIGHSCORES))
        self.score_scroll.scroll_offset = 0
        self._dirty = False
        self._update_button = UiButtonState("Update scores", force_wide=True)
        self._play_button = UiButtonState("Play a game", force_wide=True)
        self._back_button = UiButtonState("Back", force_wide=False)

        self._close_lists()

        request = self._request
        self._records = load_records(self.state, request)
        if self.state.audio is not None:
            play_sfx(self.state.audio, SfxId.UI_PANELCLICK)
        self._is_open = True

    def close(self) -> None:
        self._return_context = None
        self._is_open = False
        self._records = []
        self.score_scroll.scroll_offset = 0
        self._dirty = False
        self._close_lists()

    def _lists(self) -> tuple[UiListWidget, ...]:
        return (self.score_list, self.date_filter_list, self.player_count_list, self.game_mode_list)

    def _close_lists(self) -> None:
        for widget in self._lists():
            widget.open = False

    def _mode_items(self) -> tuple[tuple[str, GameMode], ...]:
        # Typ'o'Shooter is listed from 40 unlocked quests.
        modes = (("Quests", GameMode.QUESTS), ("Rush", GameMode.RUSH), ("Survival", GameMode.SURVIVAL))
        if self.state.status.quest_unlock_index >= 40:
            modes += (("Typ'o'Shooter", GameMode.TYPO),)
        return modes

    def sync_lists(self) -> None:
        """`highscore_screen`: refill the lists from the config, and disable the lists an open one covers."""
        config = self.state.config
        names = config.profile.saved_name_labels()
        self.score_list.items = names
        self.score_list.selected_index = min(config.profile.selected_saved_name_slot, len(names) - 1)
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

    def _panel_top_left(self, *, pos: Vec2) -> Vec2:
        return Vec2(
            pos.x + MENU_PANEL_OFFSET_X,
            pos.y + self._widescreen_y_shift + MENU_PANEL_OFFSET_Y,
        )

    def update(self, dt: float) -> None:
        self._assert_open()
        if self.state.audio is not None:
            update_audio(self.state.audio, dt)
        if self._ground is not None:
            self._ground.process_pending()
        self._dt = min(dt, 0.1)

        dt_ms = int(min(float(dt), 0.1) * 1000.0)
        if not self.state.ui.advance(dt_ms):
            return

        enabled = self.state.ui.timeline_ms >= self.state.ui.max_timeline_ms
        focus = self.state.focus

        if focus.escape and enabled:
            if any(widget.open for widget in self._lists()):
                self._close_lists()
                return
            self._begin_close_transition(Route.BACK)
            return

        if not enabled:
            return

        screen_width = float(self.state.config.display.width)
        resources = require_runtime_resources(self.state)

        # Compute animated panel positions so hit-tests match the draw path even while sliding.
        panel_w = MENU_PANEL_WIDTH
        _angle_rad, left_slide_x = ui_element_anim(
            self.state.ui.timeline_ms,
            index=9,
            width=panel_w,
            direction_flag=0,
        )
        _angle_rad, right_slide_x = ui_element_anim(
            self.state.ui.timeline_ms,
            index=33,
            width=panel_w,
            direction_flag=1,
        )
        left_panel_pos_x = hs_left_panel_pos_x(screen_width)
        left_top_left = self._panel_top_left(pos=Vec2(left_panel_pos_x, HS_LEFT_PANEL_POS_Y))
        right_panel_pos_x = hs_right_panel_pos_x(screen_width)
        right_top_left = self._panel_top_left(pos=Vec2(right_panel_pos_x, HS_RIGHT_PANEL_POS_Y))
        left_panel_top_left = left_top_left.offset(dx=float(left_slide_x))
        right_panel_top_left = right_top_left.offset(dx=float(right_slide_x))

        # `highscore_screen` focus order: the Hardcore checkbox, the score list, Update / Play / Back, then the
        # right panel's checkbox and lists. A press while a list is open belongs to the lists only.
        dropdown_was_open = any(widget.open for widget in self._lists())
        mouse = canvas.mouse_position()
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT) and not dropdown_was_open
        self._update_quest_arrows(left_panel_top_left=left_panel_top_left, resources=resources, click=click)
        self._update_score_scroll()

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
        if score_row_under_mouse(self, left_panel_top_left) is None and self._request.highlight_rank is None:
            self._update_right_panel_widgets(right_top_left=right_panel_top_left, resources=resources)

    def _update_score_scroll(self) -> None:
        """`highscore_screen`'s `ui_scrollbar_update` over the scores: the wheel, Up/Down while focused, PgUp/PgDn;
        the port adds Home/End."""
        bar = self.score_scroll
        bar.item_count = len(self._records)
        bar.scroll_offset -= int(rl.get_mouse_wheel_move())
        ui_scrollbar_update_keys(self.state.focus, bar)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_HOME):
            bar.scroll_offset = 0
        if rl.is_key_pressed(rl.KeyboardKey.KEY_END):
            bar.scroll_offset = bar.max_scroll

    def _begin_close_transition(self, action: ScreenAction) -> None:
        if self.state.ui.closing:
            return
        if action == Route.BACK and self._return_context is not None:
            self._return_context.restore(self.state.config)
        if self._dirty:
            try:
                self.state.config.save()
            except (OSError, ValueError) as exc:
                self.state.console.log.log(f"config: save failed: {exc}")
            else:
                self._dirty = False
        if isinstance(action, StartRun):
            self.state.screen_fade_alpha = 0.0
            self.state.screen_fade_ramp = True
        if self.state.audio is not None:
            play_sfx(self.state.audio, SfxId.UI_BUTTONCLICK)
        self.state.ui.begin(action)

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
        self._begin_close_transition(
            StartRun(request.game_mode_id, request.quest_level),
        )

    def _reload_records(self) -> None:
        request = self._request
        self._records = load_records(self.state, request)
        self.score_scroll.item_count = len(self._records)
        self.score_scroll.clamp()

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

        # Selected score list (profile slots).
        widget = self.score_list
        selected = ui_list_widget_update(
            resources, widget, shifted_right_top_left + HS_RIGHT_SCORE_LIST_WIDGET, focus=focus, mouse=mouse,
        )
        if selected > -2 and pressed:
            widget.open = not widget.open
            if selected >= 0:
                self.state.config.profile.selected_saved_name_slot = selected
                self._dirty = True
                self._reload_records()

        # Show scores: the date filter (config.highscore_date_mode).
        widget = self.date_filter_list
        selected = ui_list_widget_update(
            resources, widget, shifted_right_top_left + HS_RIGHT_SHOW_SCORES_WIDGET, focus=focus, mouse=mouse,
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
            resources, widget, shifted_right_top_left + HS_RIGHT_PLAYER_COUNT_WIDGET, focus=focus, mouse=mouse,
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
            resources, widget, shifted_right_top_left + HS_RIGHT_GAME_MODE_WIDGET, focus=focus, mouse=mouse,
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
        draw_screen_background(self.state, self._ground, entity_alpha=self._world_entity_alpha())
        _draw_screen_fade(self.state)

        resources = require_runtime_resources(self.state)
        font = resources.small_font
        request = self._request
        mode_id = request.game_mode_id
        quest_major = int(request.quest_level.major) if request.quest_level is not None else 0
        quest_minor = int(request.quest_level.minor) if request.quest_level is not None else 0

        screen_width = float(self.state.config.display.width)
        shadows_enabled = self.state.config.display.shadows_enabled
        panel_w = MENU_PANEL_WIDTH
        _angle_rad, left_slide_x = ui_element_anim(
            self.state.ui.timeline_ms,
            index=9,
            width=panel_w,
            direction_flag=0,
        )
        _angle_rad, right_slide_x = ui_element_anim(
            self.state.ui.timeline_ms,
            index=33,
            width=panel_w,
            direction_flag=1,
        )

        left_panel_pos_x = hs_left_panel_pos_x(screen_width)
        left_top_left = self._panel_top_left(pos=Vec2(left_panel_pos_x, HS_LEFT_PANEL_POS_Y))
        right_panel_pos_x = hs_right_panel_pos_x(screen_width)
        right_top_left = self._panel_top_left(pos=Vec2(right_panel_pos_x, HS_RIGHT_PANEL_POS_Y))
        left_panel_top_left = left_top_left.offset(dx=float(left_slide_x))
        right_panel_top_left = right_top_left.offset(dx=float(right_slide_x))

        draw_classic_menu_panel(
            resources.texture(TextureId.UI_MENU_PANEL),
            dst=rl.Rectangle(left_panel_top_left.x, left_panel_top_left.y, panel_w, HS_LEFT_PANEL_HEIGHT),
            tint=rl.WHITE,
            shadow=shadows_enabled,
        )
        draw_classic_menu_panel(
            resources.texture(TextureId.UI_MENU_PANEL),
            dst=rl.Rectangle(right_panel_top_left.x, right_panel_top_left.y, panel_w, HS_RIGHT_PANEL_HEIGHT),
            tint=rl.WHITE,
            shadow=shadows_enabled,
            flip_x=True,
        )

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
        if not self.state.ui.closing:
            return 1.0
        alpha = float(self.state.ui.timeline_ms) / ui_elements_max_timeline(GameStateId.HIGHSCORES)
        if alpha < 0.0:
            return 0.0
        if alpha > 1.0:
            return 1.0
        return alpha

    def take_action(self) -> ScreenAction | None:
        self._assert_open()
        return self.state.ui.take_action()

    def _assert_open(self) -> None:
        assert self._is_open, "HighScoresView must be opened before use"

    def _visible_rows(self, font) -> int:
        row_step = float(font.cell_size)
        table_top = 188.0 + row_step
        reserved_bottom = 96.0
        available = max(0.0, float(canvas.height()) - table_top - reserved_bottom)
        return max(1, int(available // row_step))


__all__ = ["HighScoresView"]
