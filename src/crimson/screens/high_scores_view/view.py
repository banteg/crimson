from __future__ import annotations

from crimson.quests.level import QuestLevel
from grim.assets import RuntimeResources, TextureId
from grim.audio import play_sfx, update_audio
from grim.config import HighScoreDateMode
from grim.fonts.small import SmallFontData, measure_small_text_width
from grim.geom import Rect, Vec2
from grim.raylib_api import rl
from grim.sfx_map import SfxId
from grim.terrain_render import GroundRenderer

from ...game.types import GameState, HighScoresRequest
from ...game_modes import GameMode
from ...persistence.highscores import HighScoreRecord
from ...ui.layout import DropdownLayoutBase
from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import UiButtonState, button_update, button_width
from ..assets import require_runtime_resources
from ..high_scores_layout import (
    HS_BACK_BUTTON_X,
    HS_BACK_BUTTON_Y,
    HS_BUTTON_STEP_Y,
    HS_BUTTON_X,
    HS_BUTTON_Y0,
    HS_LEFT_PANEL_HEIGHT,
    HS_LEFT_PANEL_POS_Y,
    HS_QUEST_ARROW_X,
    HS_QUEST_ARROW_Y,
    HS_RIGHT_CHECK_X,
    HS_RIGHT_CHECK_Y,
    HS_RIGHT_GAME_MODE_WIDGET_W,
    HS_RIGHT_GAME_MODE_WIDGET_X,
    HS_RIGHT_GAME_MODE_WIDGET_Y,
    HS_RIGHT_PANEL_HEIGHT,
    HS_RIGHT_PANEL_POS_Y,
    HS_RIGHT_PLAYER_COUNT_WIDGET_W,
    HS_RIGHT_PLAYER_COUNT_WIDGET_X,
    HS_RIGHT_PLAYER_COUNT_WIDGET_Y,
    HS_RIGHT_SCORE_LIST_WIDGET_W,
    HS_RIGHT_SCORE_LIST_WIDGET_X,
    HS_RIGHT_SCORE_LIST_WIDGET_Y,
    HS_RIGHT_SHOW_SCORES_WIDGET_W,
    HS_RIGHT_SHOW_SCORES_WIDGET_X,
    HS_RIGHT_SHOW_SCORES_WIDGET_Y,
    hs_left_panel_pos_x,
    hs_right_options_x_shift,
    hs_right_panel_pos_x,
)
from ..menu import (
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
    menu_ground_camera,
)
from ..panels.base import FADE_TO_GAME_ACTIONS, PANEL_TIMELINE_END_MS, PANEL_TIMELINE_START_MS
from ..panels.hit_test import mouse_inside_rect_with_padding
from ..transitions import _draw_screen_fade
from .main_panel import draw_main_panel
from .records import load_records, resolve_request
from .right_panel import draw_right_panel


class _ScoresDropdownLayout(DropdownLayoutBase, frozen=True):
    pass


class HighScoresView:
    def __init__(self, state: GameState) -> None:
        self.state = state
        self._is_open = False
        self._ground: GroundRenderer | None = None
        self._action: str | None = None
        self._cursor_pulse_time = 0.0
        self._widescreen_y_shift = 0.0
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._closing = False
        self._close_action: str | None = None
        self._update_button = UiButtonState("Update scores", force_wide=True)
        self._play_button = UiButtonState("Play a game", force_wide=True)
        self._back_button = UiButtonState("Back", force_wide=False)

        self._request: HighScoresRequest | None = None
        self._records: list[HighScoreRecord] = []
        self._scroll_index = 0
        self._dirty = False

        # Right-panel list widget state (quests variant).
        self._player_count_open = False
        self._game_mode_open = False
        self._show_scores_open = False
        self._score_list_open = False

    def open(self) -> None:
        layout_w = float(self.state.config.display.width)
        self._widescreen_y_shift = MenuView._menu_widescreen_y_shift(layout_w)
        self._action = None
        self._ground = None if self.state.pause_background is not None else ensure_menu_ground(self.state)
        self._cursor_pulse_time = 0.0
        self._timeline_ms = 0
        self._timeline_max_ms = PANEL_TIMELINE_START_MS
        self._closing = False
        self._close_action = None
        self._scroll_index = 0
        self._dirty = False
        self._update_button = UiButtonState("Update scores", force_wide=True)
        self._play_button = UiButtonState("Play a game", force_wide=True)
        self._back_button = UiButtonState("Back", force_wide=False)

        self._player_count_open = False
        self._game_mode_open = False
        self._show_scores_open = False
        self._score_list_open = False

        request = resolve_request(self.state)
        self._request = request
        self._records = load_records(self.state, request)
        if self.state.audio is not None:
            play_sfx(self.state.audio, SfxId.UI_PANELCLICK)
        self._is_open = True

    def close(self) -> None:
        self._is_open = False
        self._request = None
        self._records = []
        self._scroll_index = 0
        self._dirty = False
        self._player_count_open = False
        self._game_mode_open = False
        self._show_scores_open = False
        self._score_list_open = False
        self._closing = False
        self._close_action = None

    def _panel_top_left(self, *, pos: Vec2, scale: float) -> Vec2:
        return Vec2(
            pos.x + MENU_PANEL_OFFSET_X * scale,
            pos.y + self._widescreen_y_shift + MENU_PANEL_OFFSET_Y * scale,
        )

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
            self._timeline_ms = min(self._timeline_max_ms, int(self._timeline_ms + dt_ms))

        enabled = self._timeline_ms >= self._timeline_max_ms

        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE) and enabled:
            self._begin_close_transition("back_to_previous")
            return

        screen_width = float(self.state.config.display.width)
        scale = 1.0
        resources = require_runtime_resources(self.state)
        font = resources.small_font

        # Compute animated panel positions so hit-tests match the draw path even while sliding.
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
        left_panel_pos_x = hs_left_panel_pos_x(screen_width)
        left_top_left = self._panel_top_left(pos=Vec2(left_panel_pos_x, HS_LEFT_PANEL_POS_Y), scale=scale)
        right_panel_pos_x = hs_right_panel_pos_x(screen_width)
        right_top_left = self._panel_top_left(pos=Vec2(right_panel_pos_x, HS_RIGHT_PANEL_POS_Y), scale=scale)
        left_panel_top_left = left_top_left.offset(dx=float(left_slide_x))
        right_panel_top_left = right_top_left.offset(dx=float(right_slide_x))

        if enabled:
            if self._update_right_panel_widgets(
                right_top_left=right_panel_top_left,
                scale=scale,
                resources=resources,
                font=font,
            ):
                return
            if self._update_quest_arrows(
                left_panel_top_left=left_panel_top_left,
                scale=scale,
                resources=resources,
            ):
                return

        if enabled:
            button_base_pos = left_panel_top_left + Vec2(HS_BUTTON_X * scale, HS_BUTTON_Y0 * scale)
            mouse = rl.get_mouse_position()
            click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
            w = button_width(resources, self._update_button.label, scale=scale, force_wide=self._update_button.force_wide)
            if button_update(
                self._update_button,
                pos=button_base_pos,
                width=w,
                dt_ms=dt_ms,
                mouse=mouse,
                click=click,
            ):
                # Reload scores from disk (no view transition).
                if self.state.audio is not None:
                    play_sfx(self.state.audio, SfxId.UI_BUTTONCLICK)
                self.open()
                return
            w = button_width(resources, self._play_button.label, scale=scale, force_wide=self._play_button.force_wide)
            if button_update(
                self._play_button,
                pos=button_base_pos.offset(dy=HS_BUTTON_STEP_Y * scale),
                width=w,
                dt_ms=dt_ms,
                mouse=mouse,
                click=click,
            ):
                self._begin_close_transition("open_play_game")
                return
            back_w = button_width(resources, self._back_button.label, scale=scale, force_wide=self._back_button.force_wide)
            if button_update(
                self._back_button,
                pos=left_panel_top_left + Vec2(HS_BACK_BUTTON_X * scale, HS_BACK_BUTTON_Y * scale),
                width=back_w,
                dt_ms=dt_ms,
                mouse=mouse,
                click=click,
            ):
                self._begin_close_transition("back_to_previous")
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

    def _begin_close_transition(self, action: str) -> None:
        if self._dirty:
            try:
                self.state.config.save()
            except (OSError, ValueError) as exc:
                self.state.console.log.log(f"config: save failed: {exc}")
            else:
                self._dirty = False
        if self._closing:
            return
        if action in FADE_TO_GAME_ACTIONS:
            self.state.screen_fade_alpha = 0.0
            self.state.screen_fade_ramp = True
        if self.state.audio is not None:
            play_sfx(self.state.audio, SfxId.UI_BUTTONCLICK)
        self._closing = True
        self._close_action = action

    def _dropdown_layout(self, *, pos: Vec2, width: float, item_count: int, scale: float) -> _ScoresDropdownLayout:
        header_h = 16.0 * scale
        row_h = 16.0 * scale
        full_h = (float(item_count) * 16.0 + 24.0) * scale
        return _ScoresDropdownLayout(
            pos=pos,
            width=float(width),
            header_h=header_h,
            row_h=row_h,
            rows_y0=pos.y + 17.0 * scale,
            full_h=full_h,
        )

    def _update_dropdown(
        self,
        *,
        layout: _ScoresDropdownLayout,
        item_count: int,
        is_open: bool,
        enabled: bool,
        scale: float,
    ) -> tuple[bool, int | None, bool]:
        mouse = rl.get_mouse_position()
        click = bool(enabled) and rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        hovered_header = bool(enabled) and mouse_inside_rect_with_padding(
            mouse,
            pos=layout.pos,
            width=layout.width,
            height=14.0 * scale,
        )
        if hovered_header and click:
            return (not is_open), None, True
        if not is_open:
            return is_open, None, False

        list_hovered = Rect.from_top_left(layout.pos, layout.width, layout.full_h).contains(Vec2.from_xy(mouse))
        if click and not list_hovered:
            return False, None, True

        for idx in range(item_count):
            item_y = layout.rows_y0 + layout.row_h * float(idx)
            hovered = bool(enabled) and mouse_inside_rect_with_padding(
                mouse,
                pos=Vec2(layout.pos.x, item_y),
                width=layout.width,
                height=14.0 * scale,
            )
            if hovered and click:
                return False, idx, True

        return is_open, None, False

    def _reload_records(self) -> None:
        request = self._request
        if request is None:
            return
        self._records = load_records(self.state, request)
        rows = 10
        self._scroll_index = max(0, min(int(self._scroll_index), max(0, len(self._records) - rows)))

    def _update_right_panel_widgets(
        self,
        *,
        right_top_left: Vec2,
        scale: float,
        resources: RuntimeResources,
        font: SmallFontData,
    ) -> bool:
        request = self._request
        if request is None:
            return False

        # Widgets are only shown in the "options" right panel (not the local-score detail panel).
        # We don't explicitly track which right panel is active; hit tests are enough.
        dropdown_blocked = self._player_count_open or self._game_mode_open or self._show_scores_open or self._score_list_open
        small_width_shift_x = hs_right_options_x_shift(float(self.state.config.display.width))
        shifted_right_top_left = right_top_left + Vec2(small_width_shift_x * scale, 0.0)

        # Checkbox: "Show internet scores" (config.show_online_scores).
        if not dropdown_blocked:
            check_tex = (
                resources.texture(TextureId.UI_CHECK_ON)
                if self.state.config.profile.show_internet_scores
                else resources.texture(TextureId.UI_CHECK_OFF)
            )
            label = "Show internet scores"
            check_pos = shifted_right_top_left + Vec2(HS_RIGHT_CHECK_X * scale, HS_RIGHT_CHECK_Y * scale)
            label_w = measure_small_text_width(font, label)
            font_h = float(font.cell_size) * scale
            rect_w = float(check_tex.width) * scale + 6.0 * scale + label_w
            rect_h = max(float(check_tex.height) * scale, font_h)
            mouse_pos = Vec2.from_xy(rl.get_mouse_position())
            if Rect.from_top_left(check_pos, rect_w, rect_h).contains(mouse_pos) and rl.is_mouse_button_pressed(
                rl.MouseButton.MOUSE_BUTTON_LEFT,
            ):
                self.state.config.profile.show_internet_scores = not self.state.config.profile.show_internet_scores
                self._dirty = True
                self._reload_records()
                return True

        # Dropdown: show scores date filter (config.highscore_date_mode).
        show_scores_items = ("Best of all time", "Best of month", "Best of week", "Best of day")
        show_scores_pos = shifted_right_top_left + Vec2(HS_RIGHT_SHOW_SCORES_WIDGET_X * scale, HS_RIGHT_SHOW_SCORES_WIDGET_Y * scale)
        show_scores_layout = self._dropdown_layout(
            pos=show_scores_pos,
            width=float(HS_RIGHT_SHOW_SCORES_WIDGET_W) * scale,
            item_count=len(show_scores_items),
            scale=scale,
        )
        show_scores_enabled = not (self._player_count_open or self._game_mode_open or self._score_list_open)
        self._show_scores_open, show_scores_selected, consumed = self._update_dropdown(
            layout=show_scores_layout,
            item_count=len(show_scores_items),
            is_open=self._show_scores_open,
            enabled=bool(show_scores_enabled),
            scale=scale,
        )
        if show_scores_selected is not None:
            self.state.config.profile.score_date_mode = HighScoreDateMode(int(show_scores_selected))
            self._dirty = True
            self._reload_records()
        if consumed:
            # Close other dropdowns when this one opens.
            if self._show_scores_open:
                self._player_count_open = False
                self._game_mode_open = False
                self._score_list_open = False
            return True

        # Dropdown: player count (config.player_count).
        player_items = ("1 player", "2 players", "3 players", "4 players")
        player_pos = shifted_right_top_left + Vec2(HS_RIGHT_PLAYER_COUNT_WIDGET_X * scale, HS_RIGHT_PLAYER_COUNT_WIDGET_Y * scale)
        player_layout = self._dropdown_layout(
            pos=player_pos,
            width=float(HS_RIGHT_PLAYER_COUNT_WIDGET_W) * scale,
            item_count=len(player_items),
            scale=scale,
        )
        player_enabled = not (self._game_mode_open or self._show_scores_open or self._score_list_open)
        self._player_count_open, player_selected, consumed = self._update_dropdown(
            layout=player_layout,
            item_count=len(player_items),
            is_open=self._player_count_open,
            enabled=bool(player_enabled),
            scale=scale,
        )
        if player_selected is not None:
            new_count = int(player_selected) + 1
            if self.state.config.gameplay.player_count != new_count:
                self.state.config.gameplay.player_count = new_count
                self._dirty = True
                self._reload_records()
        if consumed:
            if self._player_count_open:
                self._game_mode_open = False
                self._show_scores_open = False
                self._score_list_open = False
            return True

        # Dropdown: game mode (config.game_mode / request.game_mode_id).
        # Typ-o shooter entry is unlocked at quest_unlock_index>=40 in the native.
        mode_items: list[tuple[str, GameMode]] = [
            ("Quests", GameMode.QUESTS),
            ("Rush", GameMode.RUSH),
            ("Survival", GameMode.SURVIVAL),
        ]
        if int(self.state.status.quest_unlock_index) >= 0x28:
            mode_items.append(("Typ'o'Shooter", GameMode.TYPO))
        game_mode_pos = shifted_right_top_left + Vec2(HS_RIGHT_GAME_MODE_WIDGET_X * scale, HS_RIGHT_GAME_MODE_WIDGET_Y * scale)
        game_mode_layout = self._dropdown_layout(
            pos=game_mode_pos,
            width=float(HS_RIGHT_GAME_MODE_WIDGET_W) * scale,
            item_count=len(mode_items),
            scale=scale,
        )
        game_mode_enabled = not (self._player_count_open or self._show_scores_open or self._score_list_open)
        self._game_mode_open, game_mode_selected, consumed = self._update_dropdown(
            layout=game_mode_layout,
            item_count=len(mode_items),
            is_open=self._game_mode_open,
            enabled=bool(game_mode_enabled),
            scale=scale,
        )
        if game_mode_selected is not None:
            _label, mode_id = mode_items[max(0, min(int(game_mode_selected), len(mode_items) - 1))]
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
        if consumed:
            if self._game_mode_open:
                self._player_count_open = False
                self._show_scores_open = False
                self._score_list_open = False
            return True

        # Dropdown: selected score list (profile slots). We currently expose the selection
        # but do not emulate the full native add/delete flow.
        score_list_enabled = not (self._player_count_open or self._game_mode_open or self._show_scores_open)
        names = list(self.state.config.profile.saved_name_labels())
        score_list_pos = shifted_right_top_left + Vec2(HS_RIGHT_SCORE_LIST_WIDGET_X * scale, HS_RIGHT_SCORE_LIST_WIDGET_Y * scale)
        score_list_layout = self._dropdown_layout(
            pos=score_list_pos,
            width=float(HS_RIGHT_SCORE_LIST_WIDGET_W) * scale,
            item_count=len(names),
            scale=scale,
        )
        self._score_list_open, score_list_selected, consumed = self._update_dropdown(
            layout=score_list_layout,
            item_count=len(names),
            is_open=self._score_list_open,
            enabled=bool(score_list_enabled),
            scale=scale,
        )
        if score_list_selected is not None:
            self.state.config.profile.selected_saved_name_slot = int(score_list_selected)
            self._dirty = True
            self._reload_records()
        if consumed:
            if self._score_list_open:
                self._player_count_open = False
                self._game_mode_open = False
                self._show_scores_open = False
            return True

        return False

    def _update_quest_arrows(
        self,
        *,
        left_panel_top_left: Vec2,
        scale: float,
        resources: RuntimeResources,
    ) -> bool:
        request = self._request
        if request is None:
            return False
        if request.game_mode_id != GameMode.QUESTS:
            return False

        level = request.quest_level
        if level is None:
            return False

        # Clamp to a sane range.
        global_index = int(level.global_index)

        unlock = int(self.state.status.quest_unlock_index_full) if self.state.config.gameplay.hardcore else int(self.state.status.quest_unlock_index)
        max_index = max(0, min(49, unlock))
        arrow = resources.texture(TextureId.UI_ARROW)

        mouse = Vec2.from_xy(rl.get_mouse_position())
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        arrow_w = float(arrow.width) * scale
        arrow_h = float(arrow.height) * scale

        # The native has two arrows spaced 255px apart; at 1.1 only the "next" arrow is drawn.
        prev_pos = left_panel_top_left + Vec2((HS_QUEST_ARROW_X - 255.0) * scale, HS_QUEST_ARROW_Y * scale)
        next_pos = left_panel_top_left + Vec2(HS_QUEST_ARROW_X * scale, HS_QUEST_ARROW_Y * scale)
        prev_rect = Rect.from_top_left(prev_pos, arrow_w, arrow_h)
        next_rect = Rect.from_top_left(next_pos, arrow_w, arrow_h)

        def _set_level(index: int) -> None:
            index = max(0, min(max_index, int(index)))
            level = QuestLevel.from_global_index(index)
            request.quest_level = level
            self.state.config.gameplay.quest_level = level
            self._dirty = True
            self._reload_records()

        if global_index > 0 and prev_rect.contains(mouse) and click:
            _set_level(global_index - 1)
            return True
        if global_index < max_index and next_rect.contains(mouse) and click:
            _set_level(global_index + 1)
            return True
        return False

    def draw(self) -> None:
        self._assert_open()
        rl.clear_background(rl.BLACK)
        pause_background = self.state.pause_background
        if pause_background is not None:
            pause_background.draw_pause_background(entity_alpha=self._world_entity_alpha())
        elif self._ground is not None:
            self._ground.draw(menu_ground_camera(self.state))
        _draw_screen_fade(self.state)

        resources = require_runtime_resources(self.state)
        font = resources.small_font
        request = self._request
        if request is not None:
            mode_id = request.game_mode_id
        else:
            try:
                mode_id = GameMode(self.state.config.gameplay.mode)
            except ValueError:
                mode_id = GameMode.DEMO
        quest_major = int(request.quest_level.major) if request is not None and request.quest_level is not None else 0
        quest_minor = int(request.quest_level.minor) if request is not None and request.quest_level is not None else 0

        screen_width = float(self.state.config.display.width)
        scale = 1.0
        shadows_enabled = self.state.config.display.shadows_enabled
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

        left_panel_pos_x = hs_left_panel_pos_x(screen_width)
        left_top_left = self._panel_top_left(pos=Vec2(left_panel_pos_x, HS_LEFT_PANEL_POS_Y), scale=scale)
        right_panel_pos_x = hs_right_panel_pos_x(screen_width)
        right_top_left = self._panel_top_left(pos=Vec2(right_panel_pos_x, HS_RIGHT_PANEL_POS_Y), scale=scale)
        left_panel_top_left = left_top_left.offset(dx=float(left_slide_x))
        right_panel_top_left = right_top_left.offset(dx=float(right_slide_x))

        draw_classic_menu_panel(
            resources.texture(TextureId.UI_MENU_PANEL),
            dst=rl.Rectangle(left_panel_top_left.x, left_panel_top_left.y, panel_w, HS_LEFT_PANEL_HEIGHT * scale),
            tint=rl.WHITE,
            shadow=shadows_enabled,
        )
        draw_classic_menu_panel(
            resources.texture(TextureId.UI_MENU_PANEL),
            dst=rl.Rectangle(right_panel_top_left.x, right_panel_top_left.y, panel_w, HS_RIGHT_PANEL_HEIGHT * scale),
            tint=rl.WHITE,
            shadow=shadows_enabled,
            flip_x=True,
        )

        selected_rank = draw_main_panel(
            self,
            resources=resources,
            font=font,
            left_panel_top_left=left_panel_top_left,
            scale=scale,
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
            scale=scale,
            highlight_rank=selected_rank,
        )
        self._draw_sign(resources=resources)
        _draw_menu_cursor(self.state, resources=resources, pulse_time=self._cursor_pulse_time)

    def _draw_sign(self, *, resources: RuntimeResources) -> None:
        sign = resources.texture(TextureId.UI_SIGN_CRIMSON)
        screen_w = float(self.state.config.display.width)
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
        shadows_enabled = self.state.config.display.shadows_enabled
        if shadows_enabled:
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

    def take_action(self) -> str | None:
        self._assert_open()
        action = self._action
        self._action = None
        return action

    def _assert_open(self) -> None:
        assert self._is_open, "HighScoresView must be opened before use"

    def _visible_rows(self, font) -> int:
        row_step = float(font.cell_size)
        table_top = 188.0 + row_step
        reserved_bottom = 96.0
        available = max(0.0, float(rl.get_screen_height()) - table_top - reserved_bottom)
        return max(1, int(available // row_step))


__all__ = ["HighScoresView"]
