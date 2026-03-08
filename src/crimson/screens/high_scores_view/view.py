from __future__ import annotations

from crimson.quests.level import QuestLevel
from grim.assets import RuntimeResources, TextureId
from grim.audio import play_sfx, update_audio
from grim.fonts.small import SmallFontData, measure_small_text_width
from grim.geom import Rect, Vec2
from grim.raylib_api import rl

from ...game.types import GameState, HighScoresRequest
from ...game_modes import GameMode
from ...persistence.highscores import HighScoreRecord
from ...ui.layout import DropdownLayoutBase
from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import UiButtonState, button_update, button_width
from ..assets import require_runtime_resources
from ..chrome import (
    ActionDispatchPolicy,
    BackdropPolicy,
    ChromeSpec,
    SignPolicy,
    dropdown_update,
    ensure_menu_ground,
    list_window,
    split_panel_frame,
)
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
from ..menu import _draw_menu_cursor
from ..panels.base import (
    FADE_TO_GAME_ACTIONS,
    PANEL_TIMELINE_END_MS,
    PANEL_TIMELINE_START_MS,
    _ChromePanelView,
    save_dirty_config,
)
from ..transitions import _draw_screen_fade
from .main_panel import draw_main_panel
from .records import load_records, resolve_request
from .right_panel import draw_right_panel


class _ScoresDropdownLayout(DropdownLayoutBase, frozen=True):
    pass


class HighScoresView(_ChromePanelView):
    def __init__(self, state: GameState) -> None:
        super().__init__(
            state,
            chrome_spec=ChromeSpec(
                backdrop=BackdropPolicy(
                    entity_alpha_mode="close_timeline_fraction",
                    entity_alpha_duration_ms=PANEL_TIMELINE_START_MS - PANEL_TIMELINE_END_MS,
                ),
                sign=SignPolicy(),
                dispatch=ActionDispatchPolicy(mode="direct_action"),
                open_sfx="sfx_ui_panelclick",
                open_sfx_mode="on_open",
                close_sfx="sfx_ui_buttonclick",
                fade_to_game_actions=FADE_TO_GAME_ACTIONS,
            ),
        )
        self._chrome.ensure_menu_ground_fn = lambda runtime_state, *, regenerate=False: ensure_menu_ground(
            runtime_state,
            regenerate=regenerate,
        )
        self._chrome.update_audio_fn = lambda audio_state, dt_s: update_audio(audio_state, dt_s)
        self._chrome.draw_fade_fn = lambda runtime_state: _draw_screen_fade(runtime_state)
        self._chrome.clear_background_fn = lambda color: rl.clear_background(color)
        self._chrome.play_sfx_fn = lambda audio_state, sfx_name, *, rng: play_sfx(audio_state, sfx_name, rng=rng)
        self._chrome.cursor_draw_fn = (
            lambda runtime_state, resources, pulse_time: _draw_menu_cursor(
                runtime_state,
                resources=resources,
                pulse_time=pulse_time,
            )
        )
        self._update_button = UiButtonState("Update scores", force_wide=True)
        self._play_button = UiButtonState("Play a game", force_wide=True)
        self._back_button = UiButtonState("Back", force_wide=False)
        self._request: HighScoresRequest | None = None
        self._records: list[HighScoreRecord] = []
        self._scroll_index = 0
        self._dirty = False
        self._player_count_open = False
        self._game_mode_open = False
        self._show_scores_open = False
        self._score_list_open = False

    def _reset_view_state(self) -> None:
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

    def _reset_closed_state(self) -> None:
        self._request = None
        self._records = []
        self._scroll_index = 0
        self._dirty = False
        self._player_count_open = False
        self._game_mode_open = False
        self._show_scores_open = False
        self._score_list_open = False

    def _before_close_transition(self, action: str) -> None:
        del action
        if self._dirty and save_dirty_config(self.state):
            self._dirty = False

    def _split_frame(self):
        screen_width = float(self.state.config.screen_width)
        return split_panel_frame(
            self._timeline_ms,
            left_panel_pos=Vec2(hs_left_panel_pos_x(screen_width), HS_LEFT_PANEL_POS_Y),
            left_panel_height=HS_LEFT_PANEL_HEIGHT,
            right_panel_pos=Vec2(hs_right_panel_pos_x(screen_width), HS_RIGHT_PANEL_POS_Y),
            right_panel_height=HS_RIGHT_PANEL_HEIGHT,
            screen_width=screen_width,
            widescreen_y_shift=self._widescreen_y_shift,
            small_scale=1.0,
        )

    def update(self, dt: float) -> None:
        self._assert_open()
        tick = self._chrome.update(dt)
        if self._closing:
            return

        frame = self._split_frame()
        resources = require_runtime_resources(self.state)
        font = resources.small_font

        if tick.interactive:
            if self._update_right_panel_widgets(
                right_top_left=frame.right_top_left,
                scale=frame.scale,
                resources=resources,
                font=font,
            ):
                return
            if self._update_quest_arrows(
                left_panel_top_left=frame.left_top_left,
                scale=frame.scale,
                resources=resources,
            ):
                return

        if tick.interactive and rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._begin_close_transition("back_to_previous")
            return

        if tick.interactive:
            button_base_pos = frame.left_top_left + Vec2(HS_BUTTON_X * frame.scale, HS_BUTTON_Y0 * frame.scale)
            mouse = rl.get_mouse_position()
            click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
            update_w = button_width(resources, self._update_button.label, scale=frame.scale, force_wide=self._update_button.force_wide)
            if button_update(
                self._update_button,
                pos=button_base_pos,
                width=update_w,
                dt_ms=float(tick.dt_ms),
                mouse=mouse,
                click=bool(click),
            ):
                if self.state.audio is not None:
                    play_sfx(self.state.audio, "sfx_ui_buttonclick", rng=self.state.rng)
                self.open()
                return
            play_w = button_width(resources, self._play_button.label, scale=frame.scale, force_wide=self._play_button.force_wide)
            if button_update(
                self._play_button,
                pos=button_base_pos.offset(dy=HS_BUTTON_STEP_Y * frame.scale),
                width=play_w,
                dt_ms=float(tick.dt_ms),
                mouse=mouse,
                click=bool(click),
            ):
                self._begin_close_transition("open_play_game")
                return
            back_w = button_width(resources, self._back_button.label, scale=frame.scale, force_wide=self._back_button.force_wide)
            if button_update(
                self._back_button,
                pos=frame.left_top_left + Vec2(HS_BACK_BUTTON_X * frame.scale, HS_BACK_BUTTON_Y * frame.scale),
                width=back_w,
                dt_ms=float(tick.dt_ms),
                mouse=mouse,
                click=bool(click),
            ):
                self._begin_close_transition("back_to_previous")
                return

        rows = 10
        _start, _end, max_scroll = list_window(
            count=len(self._records),
            visible_rows=rows,
            scroll_index=self._scroll_index,
        )
        if tick.interactive:
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

    def _reload_records(self) -> None:
        request = self._request
        if request is None:
            return
        self._records = load_records(self.state, request)
        _start, _end, max_scroll = list_window(
            count=len(self._records),
            visible_rows=10,
            scroll_index=self._scroll_index,
        )
        self._scroll_index = max(0, min(int(self._scroll_index), max_scroll))

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

        dropdown_blocked = self._player_count_open or self._game_mode_open or self._show_scores_open or self._score_list_open
        small_width_shift_x = hs_right_options_x_shift(float(self.state.config.screen_width))
        shifted_right_top_left = right_top_left + Vec2(small_width_shift_x * scale, 0.0)

        if not dropdown_blocked:
            check_tex = (
                resources.texture(TextureId.UI_CHECK_ON)
                if self.state.config.score_load_gate
                else resources.texture(TextureId.UI_CHECK_OFF)
            )
            label = "Show internet scores"
            check_pos = shifted_right_top_left + Vec2(HS_RIGHT_CHECK_X * scale, HS_RIGHT_CHECK_Y * scale)
            label_w = measure_small_text_width(font, label)
            font_h = float(font.cell_size) * scale
            rect_w = float(check_tex.width) * scale + 6.0 * scale + label_w
            rect_h = max(float(check_tex.height) * scale, font_h)
            mouse_pos = Vec2.from_xy(rl.get_mouse_position())
            if Rect.from_top_left(check_pos, rect_w, rect_h).contains(mouse_pos):
                if rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
                    self.state.config.score_load_gate = not self.state.config.score_load_gate
                    self._dirty = True
                    self._reload_records()
                    return True

        show_scores_items = ("Best of all time", "Best of month", "Best of week", "Best of day")
        show_scores_pos = shifted_right_top_left + Vec2(HS_RIGHT_SHOW_SCORES_WIDGET_X * scale, HS_RIGHT_SHOW_SCORES_WIDGET_Y * scale)
        show_scores_layout = self._dropdown_layout(
            pos=show_scores_pos,
            width=float(HS_RIGHT_SHOW_SCORES_WIDGET_W) * scale,
            item_count=len(show_scores_items),
            scale=scale,
        )
        show_scores_enabled = not (self._player_count_open or self._game_mode_open or self._score_list_open)
        show_scores_result = dropdown_update(
            layout=show_scores_layout,
            item_count=len(show_scores_items),
            is_open=self._show_scores_open,
            enabled=bool(show_scores_enabled),
            scale=scale,
        )
        self._show_scores_open = show_scores_result.is_open
        if show_scores_result.selected_index is not None:
            self.state.config.highscore_date_mode = int(show_scores_result.selected_index)
            self._dirty = True
            self._reload_records()
        if show_scores_result.consumed:
            if self._show_scores_open:
                self._player_count_open = False
                self._game_mode_open = False
                self._score_list_open = False
            return True

        player_items = ("1 player", "2 players", "3 players", "4 players")
        player_pos = shifted_right_top_left + Vec2(HS_RIGHT_PLAYER_COUNT_WIDGET_X * scale, HS_RIGHT_PLAYER_COUNT_WIDGET_Y * scale)
        player_layout = self._dropdown_layout(
            pos=player_pos,
            width=float(HS_RIGHT_PLAYER_COUNT_WIDGET_W) * scale,
            item_count=len(player_items),
            scale=scale,
        )
        player_enabled = not (self._game_mode_open or self._show_scores_open or self._score_list_open)
        player_result = dropdown_update(
            layout=player_layout,
            item_count=len(player_items),
            is_open=self._player_count_open,
            enabled=bool(player_enabled),
            scale=scale,
        )
        self._player_count_open = player_result.is_open
        if player_result.selected_index is not None:
            new_count = int(player_result.selected_index) + 1
            if self.state.config.player_count != new_count:
                self.state.config.player_count = new_count
                self._dirty = True
                self._reload_records()
        if player_result.consumed:
            if self._player_count_open:
                self._game_mode_open = False
                self._show_scores_open = False
                self._score_list_open = False
            return True

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
        game_mode_result = dropdown_update(
            layout=game_mode_layout,
            item_count=len(mode_items),
            is_open=self._game_mode_open,
            enabled=bool(game_mode_enabled),
            scale=scale,
        )
        self._game_mode_open = game_mode_result.is_open
        if game_mode_result.selected_index is not None:
            _label, mode_id = mode_items[max(0, min(int(game_mode_result.selected_index), len(mode_items) - 1))]
            self.state.config.game_mode = int(mode_id)
            request.game_mode_id = mode_id
            match mode_id:
                case GameMode.TYPO:
                    self.state.config.player_count = 1
                case GameMode.QUESTS:
                    if request.quest_level is None:
                        request.quest_level = self.state.config.quest_level_value or QuestLevel(1, 1)
                case _:
                    pass
            self._dirty = True
            self._reload_records()
        if game_mode_result.consumed:
            if self._game_mode_open:
                self._player_count_open = False
                self._show_scores_open = False
                self._score_list_open = False
            return True

        score_list_enabled = not (self._player_count_open or self._game_mode_open or self._show_scores_open)
        slot_count = max(1, min(8, int(self.state.config.int_value("saved_name_index", 1))))
        names_blob = self.state.config.blob_value("saved_names", size=0x1B * 8, default=b"")
        names: list[str] = []
        for idx in range(slot_count):
            entry = names_blob[idx * 0x1B : (idx + 1) * 0x1B]
            label = entry.split(b"\x00", 1)[0].decode("latin-1", errors="ignore").strip() or f"slot_{idx}"
            names.append(label)
        score_list_pos = shifted_right_top_left + Vec2(HS_RIGHT_SCORE_LIST_WIDGET_X * scale, HS_RIGHT_SCORE_LIST_WIDGET_Y * scale)
        score_list_layout = self._dropdown_layout(
            pos=score_list_pos,
            width=float(HS_RIGHT_SCORE_LIST_WIDGET_W) * scale,
            item_count=len(names),
            scale=scale,
        )
        score_list_result = dropdown_update(
            layout=score_list_layout,
            item_count=len(names),
            is_open=self._score_list_open,
            enabled=bool(score_list_enabled),
            scale=scale,
        )
        self._score_list_open = score_list_result.is_open
        if score_list_result.selected_index is not None:
            self.state.config.set_int_value("selected_name_slot", int(score_list_result.selected_index))
            self._dirty = True
            self._reload_records()
        if score_list_result.consumed:
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
        if request is None or request.game_mode_id != GameMode.QUESTS or request.quest_level is None:
            return False

        level = request.quest_level
        global_index = int(level.global_index)
        unlock = int(self.state.status.quest_unlock_index_full) if self.state.config.hardcore else int(self.state.status.quest_unlock_index)
        max_index = max(0, min(49, unlock))
        arrow = resources.texture(TextureId.UI_ARROW)

        mouse = Vec2.from_xy(rl.get_mouse_position())
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        arrow_w = float(arrow.width) * scale
        arrow_h = float(arrow.height) * scale

        prev_pos = left_panel_top_left + Vec2((HS_QUEST_ARROW_X - 255.0) * scale, HS_QUEST_ARROW_Y * scale)
        next_pos = left_panel_top_left + Vec2(HS_QUEST_ARROW_X * scale, HS_QUEST_ARROW_Y * scale)
        prev_rect = Rect.from_top_left(prev_pos, arrow_w, arrow_h)
        next_rect = Rect.from_top_left(next_pos, arrow_w, arrow_h)

        def _set_level(index: int) -> None:
            clamped = max(0, min(max_index, int(index)))
            quest_level = QuestLevel.from_global_index(clamped)
            request.quest_level = quest_level
            self.state.config.quest_level_value = quest_level
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
        self._draw_background()
        self._chrome.draw_fade()

        resources = require_runtime_resources(self.state)
        font = resources.small_font
        request = self._request
        if request is not None:
            mode_id = request.game_mode_id
        else:
            try:
                mode_id = GameMode(self.state.config.game_mode)
            except ValueError:
                mode_id = GameMode.DEMO
        quest_major = int(request.quest_level.major) if request is not None and request.quest_level is not None else 0
        quest_minor = int(request.quest_level.minor) if request is not None and request.quest_level is not None else 0

        frame = self._split_frame()
        fx_detail = self.state.config.fx_detail(level=0, default=False)
        panel = resources.texture(TextureId.UI_MENU_PANEL)

        draw_classic_menu_panel(
            panel,
            dst=rl.Rectangle(frame.left_top_left.x, frame.left_top_left.y, frame.panel_width, frame.left_panel_height),
            tint=rl.WHITE,
            shadow=fx_detail,
        )
        draw_classic_menu_panel(
            panel,
            dst=rl.Rectangle(frame.right_top_left.x, frame.right_top_left.y, frame.panel_width, frame.right_panel_height),
            tint=rl.WHITE,
            shadow=fx_detail,
            flip_x=True,
        )

        selected_rank = draw_main_panel(
            self,
            resources=resources,
            font=font,
            left_panel_top_left=frame.left_top_left,
            scale=frame.scale,
            mode_id=mode_id,
            quest_major=quest_major,
            quest_minor=quest_minor,
            request=request,
        )
        draw_right_panel(
            self,
            resources=resources,
            font=font,
            right_top_left=frame.right_top_left,
            scale=frame.scale,
            highlight_rank=selected_rank,
        )
        self._draw_sign()
        _draw_menu_cursor(self.state, resources=resources, pulse_time=self._cursor_pulse_time)

    def _draw_sign(self, *, animated: bool = False) -> None:
        self._chrome.draw_sign(resources=require_runtime_resources(self.state), animated=animated)

    def _world_entity_alpha(self) -> float:
        alpha = self._chrome._pause_background_entity_alpha()
        if alpha is None:
            return 1.0
        return alpha

    def _visible_rows(self, font) -> int:
        row_step = float(font.cell_size)
        table_top = 188.0 + row_step
        reserved_bottom = 96.0
        available = max(0.0, float(rl.get_screen_height()) - table_top - reserved_bottom)
        return max(1, int(available // row_step))


__all__ = [
    "HighScoresView",
    "_ScoresDropdownLayout",
    "_draw_menu_cursor",
    "_draw_screen_fade",
    "ensure_menu_ground",
    "update_audio",
]
