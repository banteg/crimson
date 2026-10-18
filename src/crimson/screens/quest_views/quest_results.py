from __future__ import annotations

from pathlib import Path

from crimson.game_states import GameStateId
from crimson.quests.level import QuestLevel
from crimson.quests.results import QuestFinalTime, QuestResultsReveal, compute_quest_final_time
from crimson.screens.actions import (
    Route,
    ScoreQuery,
    ScoreReturnContext,
    ScreenAction,
    ShowScores,
    StartRun,
)
from crimson.ui.animation import ui_transition_alpha
from crimson.ui.cursor import ui_cursor_render
from grim import canvas
from grim.assets import TextureId
from grim.color import grim_color
from grim.draw import grim_draw_rect_outline
from grim.fonts.small import draw_small_text
from grim.geom import Rect, Vec2
from grim.raylib_api import rl, rl_color, rl_rectangle, rl_vector2
from grim.sfx import play_sfx
from grim.sfx_map import SfxId

from ...game.types import GameState
from ...game_modes import GameMode
from ...modes.quest_mode import QuestRunOutcome
from ...perks import PERK_BY_ID, PerkId, perk_display_name
from ...persistence.highscores import (
    TABLE_MAX,
    HighScoreRecord,
    rank_index,
    read_highscore_table,
    scores_path_for_mode,
)
from ...quests import quest_by_level
from ...ui.button import UiButtonState, button_draw, button_update
from ...ui.formatting import format_time_mm_ss
from ...ui.highscore_card import ui_text_input_render
from ...ui.menu_panel import draw_ui_panel, ui_panel_rect
from ...ui.name_entry import HighScoreNameEntry
from ...weapons import WeaponId, weapon_display_name
from ..assets import require_runtime_resources
from ..menu_screen import MenuScreen
from .shared import _next_quest_level, _player_name_default

TEXTURE_TOP_BANNER_W = 256.0
TEXTURE_TOP_BANNER_H = 64.0

# `quest_results_screen_update` uses the classic UI element sums for positioning:
#   content_x = (pos_x + offset_x + slide_x) + 180.0 + 40.0
#   banner_x  = content_x - 18.0
#   score_x   = content_x + 30.0
QUEST_RESULTS_CONTENT_X = 220.0
QUEST_RESULTS_BANNER_X_FROM_CONTENT = -18.0
QUEST_RESULTS_SCORE_CARD_X_FROM_CONTENT = 30.0

COLOR_TEXT = rl_color(255, 255, 255, 255)
COLOR_TEXT_SUBTLE = rl_color(255, 255, 255, int(255 * 0.7))
# `render_tint_color_global_init_thunk` initializes `render_tint_color` to this
# blue tint (149,175,198),
# reused by quest/game-over captions and score-card separator outlines.
COLOR_UI_ACCENT = rl_color(149, 175, 198, 255)


class QuestResultsView(MenuScreen):
    game_state = GameStateId.QUEST_RESULTS

    def __init__(self, state: GameState, outcome: QuestRunOutcome) -> None:
        super().__init__(state)
        self._outcome = outcome
        self.phase: int = -1  # -1 init, 0 breakdown, 1 name entry (if qualifies), 2 results/buttons
        self.rank: int = TABLE_MAX
        self.highlight_rank: int | None = None
        self.quest_level: QuestLevel | None = None
        self.quest_title: str = ""
        self.unlock_weapon_name: str = ""
        self.unlock_perk_name: str = ""
        self.record: HighScoreRecord | None = None
        self.breakdown: QuestFinalTime | None = None
        self._reveal = QuestResultsReveal()
        # Native `quest_results_anim_timer`: blink ticks during the breakdown, then ms of the name/results fade-in.
        self._anim_timer: int = 0
        self._scores_path: Path | None = None
        self.name_entry = HighScoreNameEntry()
        self._player_name_default: str = ""
        self._dt: float = 0.0
        self._consume_enter: bool = False
        self._play_next_button = UiButtonState("Play Next", force_wide=True)
        self._play_again_button = UiButtonState("Play Again", force_wide=True)
        self._high_scores_button = UiButtonState("High scores", force_wide=True)
        self._main_menu_button = UiButtonState("Main Menu", force_wide=True)

    def open(self) -> None:
        super().open()
        self.state.quest_fail_retry_count = 0
        outcome = self._outcome
        level = outcome.level
        assert level is not None, "stock results need a stock level"

        self.phase = 0
        self.rank = TABLE_MAX
        self.highlight_rank = None
        self.quest_level = level
        self.quest_title = ""
        self.unlock_weapon_name = ""
        self.unlock_perk_name = ""
        self._reveal = QuestResultsReveal()
        self._anim_timer = 0
        self.name_entry = HighScoreNameEntry()
        self._consume_enter = True
        self._play_next_button = UiButtonState(
            "Show End Note" if level == QuestLevel(5, 10) else "Play Next",
            force_wide=True,
        )
        self._play_again_button = UiButtonState("Play Again", force_wide=True)
        self._high_scores_button = UiButtonState("High scores", force_wide=True)
        self._main_menu_button = UiButtonState("Main Menu", force_wide=True)

        quest = quest_by_level(level)
        self.quest_title = str(quest.title or "") if quest is not None else ""
        if quest is not None:
            weapon_id_native = int(quest.unlock_weapon_id) if quest.unlock_weapon_id is not None else 0
            if weapon_id_native > 0:
                self.unlock_weapon_name = weapon_display_name(WeaponId(weapon_id_native))

            perk_id_native = int(quest.unlock_perk_id) if quest.unlock_perk_id is not None else 0
            if perk_id_native != int(PerkId.ANTIPERK):
                perk_id = PerkId(perk_id_native)
                perk_entry = PERK_BY_ID.get(perk_id)
                if perk_entry is not None and perk_entry.name:
                    self.unlock_perk_name = perk_display_name(
                        perk_id,
                        violence_disabled=self.state.config.display.violence_disabled,
                    )
                else:
                    self.unlock_perk_name = f"perk_{perk_id_native}"

        record = outcome.record.copy()
        breakdown = compute_quest_final_time(
            base_time_ms=outcome.base_time_ms,
            player_health_values=outcome.player_health_values,
            pending_perk_count=outcome.pending_perk_count,
        )
        record.run_elapsed_ms = int(breakdown.final_time_ms)
        player_name_default = _player_name_default(self.state.config) or "Player"
        record.set_name(player_name_default)
        self.record = record
        self.breakdown = breakdown
        self._player_name_default = player_name_default

        # `game_state_set(GAME_STATE_QUEST_RESULTS)` saves the status again; `quest_mode_update` already
        # counted the completion and raised the unlocks.
        try:
            self.state.status.save_if_dirty()
        except (OSError, ValueError) as exc:
            self._log_nonfatal("failed to save status", exc)

        config = self.state.config
        self._scores_path = scores_path_for_mode(
            self.state.base_dir,
            GameMode.QUESTS,
            hardcore=config.gameplay.hardcore,
            quest_stage_major=int(level.major),
            quest_stage_minor=int(level.minor),
            player_count=config.gameplay.player_count,
            named_list=config.profile.named_score_list,
        )
        try:
            records = read_highscore_table(
                self._scores_path,
                game_mode_id=GameMode.QUESTS,
                date_mode=config.profile.score_date_mode,
            )
            self.rank = int(rank_index(records, self.record))
        except (OSError, ValueError):
            self.rank = TABLE_MAX

    def resume(self) -> None:
        """Back from the high scores: `game_state_set` slides the panel in again, and `highscore_return_latch`
        takes the screen straight to its buttons."""
        super().resume()
        self.phase = 2

    def close(self) -> None:
        super().close()
        self.quest_level = None
        self.quest_title = ""
        self.unlock_weapon_name = ""
        self.unlock_perk_name = ""
        self.record = None
        self.breakdown = None

    def take_action(self) -> ScreenAction | None:
        action = super().take_action()
        if action is not None and self.state.leaderboard is not None:
            # Leaving the results settles the run's name: the one just typed, or the last one when it didn't qualify.
            self.state.leaderboard.release(str(self.state.config.profile.player_name or ""))
        return action

    def _enter_rank_phase(self, *, qualifies: bool) -> None:
        if qualifies:
            self.phase = 1
            self.name_entry.start(self._player_name_default, focus=self.state.focus)
        else:
            self.phase = 2

    def _fade_alpha(self) -> float:
        return min(1.0, self._anim_timer * 0.002)

    def world_entity_alpha(self) -> float:
        # `quest_results_screen_update`'s buttons set `game_state_pending`; the next quest and a replay keep the run lit.
        match self.state.ui.pending:
            case None:
                pending = None
            case Route.END_NOTE:
                pending = GameStateId.FINAL_QUEST_END_NOTE
            case StartRun():
                pending = GameStateId.GAMEPLAY
            case ShowScores():
                pending = GameStateId.HIGHSCORES
            case _:
                pending = GameStateId.MAIN_MENU
        return ui_transition_alpha(self.state.ui.timeline_ms, state=GameStateId.QUEST_RESULTS, pending=pending)

    def _panel_layout(self, *, screen_w: float) -> Rect:
        """`quest_results_screen_update` lays out on `ui_element_slot_35`'s panel."""
        return ui_panel_rect(35, self.state.ui.timeline_ms, screen_w)

    def update(self, dt: float) -> None:
        dt_s = float(min(dt, 0.1))
        self._dt = dt_s
        dt_ms = dt_s * 1000.0
        if self.record is None or self.breakdown is None:
            return
        if not self._advance(dt):
            return

        focus = self.state.focus
        if self._consume_enter:
            self._consume_enter = False
            focus.enter = False

        qualifies = int(self.rank) < TABLE_MAX
        audio = self.state.audio
        sfx = (lambda name: play_sfx(audio.sfx, name)) if audio is not None else None

        if self.phase == 0:
            match self._reveal.tick(int(dt_ms), self.breakdown):
                case "clink":
                    if sfx is not None:
                        sfx(SfxId.UI_CLINK_01)
                case "blink":
                    self._anim_timer += 1
            if rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE) or canvas.mouse_pressed():
                self._enter_rank_phase(qualifies=qualifies)
            elif self._anim_timer > 10:
                self._anim_timer = 0
                self._enter_rank_phase(qualifies=qualifies)
            return

        # Name entry and results fade in together: native keeps counting the same timer.
        self._anim_timer = self._anim_timer + int(dt_ms) if self._anim_timer < 500 else 500
        mouse = canvas.mouse_position()
        resources = require_runtime_resources(self.state)

        if self.phase == 1:
            content_pos = self._panel_layout(screen_w=float(canvas.width())).top_left.offset(dx=QUEST_RESULTS_CONTENT_X)
            input_pos = content_pos.offset(dy=150.0)
            self.name_entry.ok_button.alpha = self._fade_alpha()
            name = self.name_entry.update(
                resources,
                focus=focus,
                config=self.state.config,
                input_pos=input_pos,
                ok_pos=input_pos + Vec2(170.0, -8.0),
                dt_ms=dt_ms,
                mouse=mouse,
                rng=self.state.rng,
                play_sfx=sfx,
            )
            if name is None:
                return
            assert self._scores_path is not None
            index = self.name_entry.save(self.record, self._scores_path, config=self.state.config)
            if index is None:
                return
            if index >= 0:
                self.highlight_rank = index if index < TABLE_MAX else None
                self.rank = index
            self.phase = 2
            return

        if self.phase == 2:
            click = canvas.mouse_pressed()
            if rl.is_key_pressed(rl.KeyboardKey.KEY_N):
                self._activate_play_next()
                return
            if rl.is_key_pressed(rl.KeyboardKey.KEY_H):
                self._activate_high_scores()
                return

            screen_w = float(canvas.width())
            panel_layout = self._panel_layout(screen_w=screen_w)
            content_pos = panel_layout.top_left.offset(dx=QUEST_RESULTS_CONTENT_X)
            score_card_pos = content_pos.offset(dx=QUEST_RESULTS_SCORE_CARD_X_FROM_CONTENT)

            var_c_12 = panel_layout.top_left.y + (96.0 if qualifies else 108.0)
            var_c_14 = var_c_12 + 84.0
            if self.unlock_weapon_name:
                var_c_14 += 30.0
            if self.unlock_perk_name:
                var_c_14 += 30.0

            button_pos = Vec2(score_card_pos.x + 20.0, var_c_14 + 6.0)
            alpha = self._fade_alpha()
            for button in (
                self._play_next_button,
                self._play_again_button,
                self._high_scores_button,
                self._main_menu_button,
            ):
                button.alpha = alpha

            if button_update(
                resources,
                self._play_next_button,
                focus=focus,
                pos=button_pos,
                dt_ms=dt_ms,
                mouse=mouse,
                click=click,
            ):
                self._activate_play_next()
                return
            button_pos = button_pos.offset(dy=32.0)

            if button_update(
                resources,
                self._play_again_button,
                focus=focus,
                pos=button_pos,
                dt_ms=dt_ms,
                mouse=mouse,
                click=click,
            ):
                self._activate_play_again()
                return
            button_pos = button_pos.offset(dy=32.0)

            if button_update(
                resources,
                self._high_scores_button,
                focus=focus,
                pos=button_pos,
                dt_ms=dt_ms,
                mouse=mouse,
                click=click,
            ):
                self._activate_high_scores()
                return
            button_pos = button_pos.offset(dy=32.0)

            # Port: Escape (the pad's B) is Main Menu once the buttons show, past the reveal and the name entry.
            if button_update(
                resources,
                self._main_menu_button,
                focus=focus,
                pos=button_pos,
                dt_ms=dt_ms,
                mouse=mouse,
                click=click,
            ) or focus.escape:
                self._activate_main_menu()
                return

    def draw(self, *, mouse: rl.Vector2 | None = None) -> None:
        self._assert_open()
        self._draw_background(entity_alpha=self.world_entity_alpha())
        if self.record is None or self.breakdown is None:
            rl.draw_text("Quest results unavailable.", 32, 140, 28, rl_color(235, 235, 235, 255))
            rl.draw_text("Press ESC to return to the menu.", 32, 180, 18, rl_color(190, 190, 200, 255))
            return
        if mouse is None:
            mouse = canvas.mouse_position()

        screen_w = float(canvas.width())
        resources = require_runtime_resources(self.state)
        font = resources.small_font
        panel_layout = self._panel_layout(screen_w=screen_w)
        draw_ui_panel(resources, 35, panel_layout, shadow=self.state.config.display.shadows_enabled)

        content_pos = panel_layout.top_left.offset(dx=QUEST_RESULTS_CONTENT_X)
        banner_pos = content_pos + Vec2(QUEST_RESULTS_BANNER_X_FROM_CONTENT, 36.0)
        text_well_done = resources.texture(TextureId.UI_TEXT_WELL_DONE)
        src = rl_rectangle(0.0, 0.0, float(text_well_done.width), float(text_well_done.height))
        dst = rl_rectangle(banner_pos.x, banner_pos.y, TEXTURE_TOP_BANNER_W, TEXTURE_TOP_BANNER_H)
        rl.draw_texture_pro(text_well_done, src, dst, rl_vector2(0.0, 0.0), 0.0, rl.WHITE)

        qualifies = int(self.rank) < TABLE_MAX
        focus = self.state.focus

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
                rl_color(COLOR_UI_ACCENT.r, COLOR_UI_ACCENT.g, COLOR_UI_ACCENT.b, int(255 * alpha)),
            )

            input_pos = content_pos.offset(dy=150.0)
            self.name_entry.draw(resources, focus=focus, input_pos=input_pos, ok_pos=input_pos + Vec2(170.0, -8.0))

            # Native phase 1 still renders the quest score card while entering the name.
            score_card_pos = input_pos + Vec2(26.0, 46.0)
            ui_text_input_render(
                score_card_pos,
                self.record,
                alpha,
                self.rank + 1,
                game_state=GameStateId.QUEST_RESULTS,
                ui_phase=self.phase,
                resources=resources,
                mouse=mouse,
                dt=self._dt,
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
                Vec2(score_card_pos.x, card_y),
                self.record,
                alpha,
                self.rank + 1,
                game_state=GameStateId.QUEST_RESULTS,
                ui_phase=self.phase,
                resources=resources,
                mouse=mouse,
                dt=self._dt,
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

            button_pos = Vec2(score_card_pos.x + 20.0, var_c_14 + 6.0)
            button_draw(
                resources,
                self._play_next_button,
                focus=focus,
                pos=button_pos,
            )
            button_pos = button_pos.offset(dy=32.0)
            button_draw(
                resources,
                self._play_again_button,
                focus=focus,
                pos=button_pos,
            )
            button_pos = button_pos.offset(dy=32.0)
            button_draw(
                resources,
                self._high_scores_button,
                focus=focus,
                pos=button_pos,
            )
            button_pos = button_pos.offset(dy=32.0)
            button_draw(
                resources,
                self._main_menu_button,
                focus=focus,
                pos=button_pos,
            )

        ui_cursor_render(resources, dt=self._dt, pos=Vec2.from_xy(mouse))

    def _activate_play_again(self) -> None:
        assert self.quest_level is not None
        self._save_quest_selection(self.quest_level)
        self._begin_close_transition(StartRun(GameMode.QUESTS, self.quest_level))

    def _activate_play_next(self) -> None:
        if self.quest_level == QuestLevel(5, 10):
            self._begin_close_transition(Route.END_NOTE)
            return
        assert self.quest_level is not None
        next_level = _next_quest_level(self.quest_level)
        if next_level is not None:
            self._save_quest_selection(next_level)
            self._begin_close_transition(StartRun(GameMode.QUESTS, next_level))
        else:
            self._begin_close_transition(Route.MENU)

    def _activate_high_scores(self) -> None:
        assert self.quest_level is not None
        query = ScoreQuery(
            game_mode_id=GameMode.QUESTS,
            quest_level=self.quest_level,
            highlight_rank=self.highlight_rank,
        )
        self._begin_close_transition(ShowScores(query, ScoreReturnContext.capture(self.state.config)))

    def _activate_main_menu(self) -> None:
        self._begin_close_transition(Route.MENU)

    def _save_quest_selection(self, level: QuestLevel) -> None:
        self.state.config.gameplay.mode = GameMode.QUESTS
        self.state.config.gameplay.quest_level = level
        try:
            self.state.config.save()
        except (OSError, ValueError) as exc:
            self._log_nonfatal("failed to save quest selection config", exc)

    def _log_nonfatal(self, message: str, exc: Exception) -> None:
        self.state.console.log.log(f"quest results: {message}: {exc}")


__all__ = ["QuestResultsView"]
