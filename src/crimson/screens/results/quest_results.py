from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import msgspec

from crimson.game_states import GameStateId
from crimson.screens.actions import ResultAction
from crimson.screens.ui_timeline import UiTimeline
from crimson.ui.animation import ui_elements_max_timeline, ui_transition_alpha
from crimson.ui.cursor import ui_cursor_render
from grim import canvas
from grim.assets import TextureId, runtime_resources_for
from grim.color import grim_color
from grim.config import CrimsonConfig
from grim.draw import grim_draw_rect_outline
from grim.fonts.small import draw_small_text
from grim.geom import Rect, Vec2
from grim.rand import CrandLike
from grim.raylib_api import rl
from grim.sfx_map import SfxId

from ...game_modes import GameMode
from ...persistence.highscores import (
    TABLE_MAX,
    HighScoreRecord,
    rank_index,
    read_highscore_table,
    scores_path_for_mode,
)
from ...quests.level import QuestLevel
from ...quests.results import QuestFinalTime, QuestResultsReveal
from ...ui.focus import UiFocus
from ...ui.formatting import format_time_mm_ss
from ...ui.highscore_card import ui_text_input_render
from ...ui.menu_panel import draw_ui_panel, ui_panel_rect
from ...ui.name_entry import HighScoreNameEntry
from ...ui.perk_menu import UiButtonState, button_draw, button_update

TEXTURE_TOP_BANNER_W = 256.0
TEXTURE_TOP_BANNER_H = 64.0

# `quest_results_screen_update` uses the classic UI element sums for positioning:
#   content_x = (pos_x + offset_x + slide_x) + 180.0 + 40.0
#   banner_x  = content_x - 18.0
#   score_x   = content_x + 30.0
QUEST_RESULTS_CONTENT_X = 220.0
QUEST_RESULTS_BANNER_X_FROM_CONTENT = -18.0
QUEST_RESULTS_SCORE_CARD_X_FROM_CONTENT = 30.0


COLOR_TEXT = rl.Color(255, 255, 255, 255)
COLOR_TEXT_MUTED = rl.Color(255, 255, 255, int(255 * 0.8))
COLOR_TEXT_SUBTLE = rl.Color(255, 255, 255, int(255 * 0.7))
COLOR_GREEN = rl.Color(25, 200, 25, 255)
# `render_tint_color_global_init_thunk` initializes `render_tint_color` to this
# blue tint (149,175,198),
# reused by quest/game-over captions and score-card separator outlines.
COLOR_UI_ACCENT = rl.Color(149, 175, 198, 255)


class QuestResultsUi(msgspec.Struct):
    assets_root: Path
    base_dir: Path
    config: CrimsonConfig
    preserve_bugs: bool = False

    phase: int = -1  # -1 init, 0 breakdown, 1 name entry (if qualifies), 2 results/buttons
    rank: int = TABLE_MAX
    highlight_rank: int | None = None

    quest_level: QuestLevel | None = None
    quest_title: str = ""
    unlock_weapon_name: str = ""
    unlock_perk_name: str = ""

    record: HighScoreRecord | None = None
    breakdown: QuestFinalTime | None = None
    _reveal: QuestResultsReveal = msgspec.field(default_factory=QuestResultsReveal)
    # Native `quest_results_anim_timer`: blink ticks during the breakdown, then ms of the name/results fade-in.
    _anim_timer: int = 0
    _scores_path: Path | None = None

    name_entry: HighScoreNameEntry = msgspec.field(default_factory=HighScoreNameEntry)
    _player_name_default: str = ""

    # Shares GameState.ui and GameState.focus in the game; the defaults only serve standalone use.
    timeline: UiTimeline = msgspec.field(default_factory=UiTimeline)
    focus: UiFocus = msgspec.field(default_factory=UiFocus)
    _dt: float = 0.0
    _panel_open_sfx_played: bool = False
    _close_action: ResultAction | None = None
    _consume_enter: bool = False

    _play_next_button: UiButtonState = msgspec.field(
        default_factory=lambda: UiButtonState("Play Next", force_wide=True),
    )
    _play_again_button: UiButtonState = msgspec.field(
        default_factory=lambda: UiButtonState("Play Again", force_wide=True),
    )
    _high_scores_button: UiButtonState = msgspec.field(
        default_factory=lambda: UiButtonState("High scores", force_wide=True),
    )
    _main_menu_button: UiButtonState = msgspec.field(
        default_factory=lambda: UiButtonState("Main Menu", force_wide=True),
    )

    def open(
        self,
        *,
        record: HighScoreRecord,
        breakdown: QuestFinalTime,
        quest_level: QuestLevel,
        quest_title: str,
        unlock_weapon_name: str,
        unlock_perk_name: str,
        player_name_default: str,
    ) -> None:
        self.close()
        self.phase = -1
        self.rank = TABLE_MAX
        self.highlight_rank = None
        self.quest_level = quest_level
        self.quest_title = str(quest_title or "")
        self.unlock_weapon_name = str(unlock_weapon_name or "")
        self.unlock_perk_name = str(unlock_perk_name or "")
        self.record = record.copy()
        self.breakdown = breakdown
        self._reveal = QuestResultsReveal()
        self._anim_timer = 0
        self.name_entry = HighScoreNameEntry()

        # Native behavior: the final quest replaces "Play Next" with "Show End Note".
        if self.quest_level == QuestLevel(5, 10):
            self._play_next_button.label = "Show End Note"
        else:
            self._play_next_button.label = "Play Next"

        assert self.quest_level is not None, "quest results require quest level"
        hardcore = self.config.gameplay.hardcore
        self._scores_path = scores_path_for_mode(
            self.base_dir,
            GameMode.QUESTS,
            hardcore=hardcore,
            quest_stage_major=int(self.quest_level.major),
            quest_stage_minor=int(self.quest_level.minor),
            player_count=self.config.gameplay.player_count,
            named_list=self.config.profile.named_score_list,
        )

        try:
            records = read_highscore_table(
                self._scores_path, game_mode_id=GameMode.QUESTS, date_mode=self.config.profile.score_date_mode,
            )
            self.rank = int(rank_index(records, self.record))
        except (OSError, ValueError):
            self.rank = TABLE_MAX

        self._player_name_default = player_name_default

        self.timeline.enter(ui_elements_max_timeline(GameStateId.QUEST_RESULTS))
        self._panel_open_sfx_played = False
        self._close_action = None
        self._consume_enter = True
        self.phase = 0

    def resume(self) -> None:
        """Back from the high scores: `game_state_set` slides the panel in again, and `highscore_return_latch`
        takes the screen straight to its buttons."""
        self.timeline.enter(ui_elements_max_timeline(GameStateId.QUEST_RESULTS))
        self._panel_open_sfx_played = False
        self._close_action = None
        self.phase = 2

    def close(self) -> None:
        return None

    def _begin_close_transition(self, action: ResultAction) -> None:
        if self.timeline.closing:
            return
        self._close_action = action
        self.timeline.begin()

    def _enter_rank_phase(self, *, qualifies: bool) -> None:
        if qualifies:
            self.phase = 1
            self.name_entry.start(self._player_name_default, focus=self.focus)
        else:
            self.phase = 2

    def _fade_alpha(self) -> float:
        return min(1.0, self._anim_timer * 0.002)

    def world_entity_alpha(self) -> float:
        # `quest_results_screen_update`'s buttons set `game_state_pending`; the next quest and a replay keep the run lit.
        match self._close_action:
            case None:
                pending = None
            case ResultAction.PLAY_NEXT if self.quest_level == QuestLevel(5, 10):
                pending = GameStateId.FINAL_QUEST_END_NOTE
            case ResultAction.PLAY_NEXT | ResultAction.PLAY_AGAIN:
                pending = GameStateId.GAMEPLAY
            case ResultAction.HIGH_SCORES:
                pending = GameStateId.HIGHSCORES
            case _:
                pending = GameStateId.MAIN_MENU
        return ui_transition_alpha(self.timeline.timeline_ms, state=GameStateId.QUEST_RESULTS, pending=pending)

    def _panel_layout(self, *, screen_w: float) -> Rect:
        """`quest_results_screen_update` lays out on `ui_element_slot_35`'s panel."""
        return ui_panel_rect(35, self.timeline.timeline_ms, screen_w)

    def update(
        self,
        dt: float,
        *,
        play_sfx: Callable[[SfxId], None] | None = None,
        rng: CrandLike,
        mouse: rl.Vector2 | None = None,
    ) -> ResultAction | None:
        dt_s = float(min(dt, 0.1))
        self._dt = dt_s
        dt_ms = dt_s * 1000.0
        if mouse is None:
            mouse = canvas.mouse_position()

        if self.record is None or self.breakdown is None:
            return None

        if not self.timeline.advance(int(dt_ms)):
            if self.timeline.ready and self._close_action is not None:
                action = self._close_action
                self._close_action = None
                return action
            return None

        if (not self._panel_open_sfx_played) and play_sfx is not None and self.timeline.opened:
            play_sfx(SfxId.UI_PANELCLICK)
            self._panel_open_sfx_played = True
        if self._consume_enter:
            self._consume_enter = False
            self.focus.enter = False

        if self.focus.escape:
            if play_sfx is not None:
                play_sfx(SfxId.UI_BUTTONCLICK)
            self._begin_close_transition(ResultAction.MAIN_MENU)
            return None

        qualifies = int(self.rank) < TABLE_MAX

        if self.phase == 0:
            match self._reveal.tick(int(dt_ms), self.breakdown):
                case "clink":
                    if play_sfx is not None:
                        play_sfx(SfxId.UI_CLINK_01)
                case "blink":
                    self._anim_timer += 1
            if rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE) or rl.is_mouse_button_pressed(
                rl.MouseButton.MOUSE_BUTTON_LEFT,
            ):
                self._enter_rank_phase(qualifies=qualifies)
            elif self._anim_timer > 10:
                self._anim_timer = 0
                self._enter_rank_phase(qualifies=qualifies)
            return None

        # Name entry and results fade in together: native keeps counting the same timer.
        self._anim_timer = self._anim_timer + int(dt_ms) if self._anim_timer < 500 else 500

        if self.phase == 1:
            content_pos = self._panel_layout(screen_w=float(canvas.width())).top_left.offset(dx=QUEST_RESULTS_CONTENT_X)
            input_pos = content_pos.offset(dy=150.0)
            self.name_entry.ok_button.alpha = self._fade_alpha()
            name = self.name_entry.update(
                runtime_resources_for(self.assets_root),
                focus=self.focus,
                config=self.config,
                input_pos=input_pos,
                ok_pos=input_pos + Vec2(170.0, -8.0),
                dt_ms=dt_ms,
                mouse=mouse,
                rng=rng,
                play_sfx=play_sfx,
            )
            if name is None:
                return None
            assert self._scores_path is not None
            index = self.name_entry.save(self.record, self._scores_path, config=self.config)
            if index is None:
                return None
            if index >= 0:
                self.highlight_rank = index if index < TABLE_MAX else None
                self.rank = index
            self.phase = 2
            return None

        if self.phase == 2:
            click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
            if rl.is_key_pressed(rl.KeyboardKey.KEY_N):
                if play_sfx is not None:
                    play_sfx(SfxId.UI_BUTTONCLICK)
                self._begin_close_transition(ResultAction.PLAY_NEXT)
                return None
            if rl.is_key_pressed(rl.KeyboardKey.KEY_H):
                if play_sfx is not None:
                    play_sfx(SfxId.UI_BUTTONCLICK)
                self._begin_close_transition(ResultAction.HIGH_SCORES)
                return None

            screen_w = float(canvas.width())
            panel_layout = self._panel_layout(screen_w=screen_w)
            qualifies = int(self.rank) < TABLE_MAX
            content_pos = panel_layout.top_left.offset(dx=QUEST_RESULTS_CONTENT_X)
            score_card_pos = content_pos.offset(dx=QUEST_RESULTS_SCORE_CARD_X_FROM_CONTENT)

            var_c_12 = panel_layout.top_left.y + (96.0 if qualifies else 108.0)
            var_c_14 = var_c_12 + 84.0
            if self.unlock_weapon_name:
                var_c_14 += 30.0
            if self.unlock_perk_name:
                var_c_14 += 30.0

            button_pos = Vec2(score_card_pos.x + 20.0, var_c_14 + 6.0)
            resources = runtime_resources_for(self.assets_root)
            alpha = self._fade_alpha()
            for button in (self._play_next_button, self._play_again_button, self._high_scores_button, self._main_menu_button):
                button.alpha = alpha

            if button_update(
                resources,
                self._play_next_button,
                focus=self.focus,
                pos=button_pos,
                dt_ms=dt_ms,
                mouse=mouse,
                click=click,
            ):
                if play_sfx is not None:
                    play_sfx(SfxId.UI_BUTTONCLICK)
                self._begin_close_transition(ResultAction.PLAY_NEXT)
                return None
            button_pos = button_pos.offset(dy=32.0)

            if button_update(
                resources,
                self._play_again_button,
                focus=self.focus,
                pos=button_pos,
                dt_ms=dt_ms,
                mouse=mouse,
                click=click,
            ):
                if play_sfx is not None:
                    play_sfx(SfxId.UI_BUTTONCLICK)
                self._begin_close_transition(ResultAction.PLAY_AGAIN)
                return None
            button_pos = button_pos.offset(dy=32.0)

            if button_update(
                resources,
                self._high_scores_button,
                focus=self.focus,
                pos=button_pos,
                dt_ms=dt_ms,
                mouse=mouse,
                click=click,
            ):
                if play_sfx is not None:
                    play_sfx(SfxId.UI_BUTTONCLICK)
                self._begin_close_transition(ResultAction.HIGH_SCORES)
                return None
            button_pos = button_pos.offset(dy=32.0)

            if button_update(
                resources,
                self._main_menu_button,
                focus=self.focus,
                pos=button_pos,
                dt_ms=dt_ms,
                mouse=mouse,
                click=click,
            ):
                if play_sfx is not None:
                    play_sfx(SfxId.UI_BUTTONCLICK)
                self._begin_close_transition(ResultAction.MAIN_MENU)
                return None
            return None

        return None

    def draw(self, *, mouse: rl.Vector2 | None = None) -> None:
        if self.record is None or self.breakdown is None:
            return
        if mouse is None:
            mouse = canvas.mouse_position()

        screen_w = float(canvas.width())

        resources = runtime_resources_for(self.assets_root)
        font = resources.small_font
        panel_layout = self._panel_layout(screen_w=screen_w)
        draw_ui_panel(resources, 35, panel_layout, shadow=self.config.display.shadows_enabled)

        content_pos = panel_layout.top_left.offset(dx=QUEST_RESULTS_CONTENT_X)
        banner_pos = content_pos + Vec2(QUEST_RESULTS_BANNER_X_FROM_CONTENT, 36.0)
        text_well_done = resources.texture(TextureId.UI_TEXT_WELL_DONE)
        src = rl.Rectangle(0.0, 0.0, float(text_well_done.width), float(text_well_done.height))
        dst = rl.Rectangle(banner_pos.x, banner_pos.y, TEXTURE_TOP_BANNER_W, TEXTURE_TOP_BANNER_H)
        rl.draw_texture_pro(text_well_done, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

        qualifies = int(self.rank) < TABLE_MAX

        if self.phase == 0:
            label_x = content_pos.x + 32.0
            value_x = label_x + 132.0
            reveal = self._reveal
            alpha = max(0.0, min(1.0, 1.0 - self._anim_timer * 0.1))
            current = grim_color(0.1, 0.8, 0.1, alpha)

            def _row_color(row: int) -> rl.Color:
                # The revealing row is green, earlier and later rows dimmed (later ones more).
                if reveal.step == row:
                    return current
                return grim_color(1.0, 1.0, 1.0, alpha * (0.2 if reveal.step < row else 0.4))

            y = panel_layout.top_left.y + 156.0
            rows = (
                ("Base Time:", format_time_mm_ss(reveal.base_time_ms)),
                ("Life Bonus:", format_time_mm_ss(reveal.health_bonus_ms)),
                ("Unpicked Perk Bonus:", format_time_mm_ss(reveal.perk_bonus_s * 1000)),
            )
            for row, (label, value) in enumerate(rows):
                draw_small_text(font, label, Vec2(label_x, y), _row_color(row))
                draw_small_text(font, value, Vec2(value_x, y), _row_color(row))
                y += 20.0

            total_color = grim_color(1.0, 1.0, 1.0, alpha)
            grim_draw_rect_outline(Vec2(label_x - 4.0, y + 1.0), 168.0, 1.0, total_color)
            y += 8.0
            draw_small_text(font, "Final Time:", Vec2(label_x, y), total_color)
            draw_small_text(font, format_time_mm_ss(reveal.total_time_ms), Vec2(value_x, y), total_color)

        elif self.phase == 1:
            alpha = self._fade_alpha()
            text_y = panel_layout.top_left.y + 118.0
            draw_small_text(
                font,
                "State your name trooper!",
                Vec2(content_pos.x + 42.0, text_y),
                rl.Color(COLOR_UI_ACCENT.r, COLOR_UI_ACCENT.g, COLOR_UI_ACCENT.b, int(255 * alpha)),
            )

            input_pos = content_pos.offset(dy=150.0)
            self.name_entry.draw(resources, focus=self.focus, input_pos=input_pos, ok_pos=input_pos + Vec2(170.0, -8.0))

            # Native phase 1 still renders the quest score card while entering the name.
            score_card_pos = input_pos + Vec2(26.0, 46.0)
            ui_text_input_render(
                score_card_pos, self.record, alpha, self.rank + 1,
                game_state=GameStateId.QUEST_RESULTS, ui_phase=self.phase, resources=resources, mouse=mouse, dt=self._dt,
            )

        else:
            alpha = self._fade_alpha()
            score_card_pos = content_pos.offset(dx=QUEST_RESULTS_SCORE_CARD_X_FROM_CONTENT)
            var_c_12 = panel_layout.top_left.y + (96.0 if qualifies else 108.0)
            if not qualifies:
                draw_small_text(
                    font,
                    "Score too low for top100.",
                    Vec2(score_card_pos.x + 8.0, panel_layout.top_left.y + 102.0),
                    grim_color(1.0, 1.0, 1.0, alpha),
                )

            card_y = var_c_12 + 16.0
            ui_text_input_render(
                Vec2(score_card_pos.x, card_y), self.record, alpha, self.rank + 1,
                game_state=GameStateId.QUEST_RESULTS, ui_phase=self.phase, resources=resources, mouse=mouse, dt=self._dt,
            )

            # Unlock lines (their presence shifts the buttons down in native).
            var_c_14 = var_c_12 + 84.0
            if self.unlock_weapon_name:
                draw_small_text(
                    font,
                    "Weapon unlocked:",
                    Vec2(score_card_pos.x, var_c_14 + 1.0),
                    COLOR_TEXT_SUBTLE,
                )
                draw_small_text(
                    font,
                    self.unlock_weapon_name,
                    Vec2(score_card_pos.x, var_c_14 + 14.0),
                    COLOR_TEXT,
                )
                var_c_14 += 30.0
            if self.unlock_perk_name:
                draw_small_text(
                    font,
                    "Perk unlocked:",
                    Vec2(score_card_pos.x, var_c_14 + 1.0),
                    COLOR_TEXT_SUBTLE,
                )
                draw_small_text(
                    font,
                    self.unlock_perk_name,
                    Vec2(score_card_pos.x, var_c_14 + 14.0),
                    COLOR_TEXT,
                )
                var_c_14 += 30.0

            # Buttons
            button_pos = Vec2(score_card_pos.x + 20.0, var_c_14 + 6.0)
            button_draw(
                resources,
                self._play_next_button,
                focus=self.focus,
                pos=button_pos,
            )
            button_pos = button_pos.offset(dy=32.0)
            button_draw(
                resources,
                self._play_again_button,
                focus=self.focus,
                pos=button_pos,
            )
            button_pos = button_pos.offset(dy=32.0)
            button_draw(
                resources,
                self._high_scores_button,
                focus=self.focus,
                pos=button_pos,
            )
            button_pos = button_pos.offset(dy=32.0)
            button_draw(
                resources,
                self._main_menu_button,
                focus=self.focus,
                pos=button_pos,
            )

        ui_cursor_render(resources, dt=self._dt, pos=Vec2.from_xy(mouse))
