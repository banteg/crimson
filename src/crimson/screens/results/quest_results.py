from __future__ import annotations

import math
from collections.abc import Callable
from pathlib import Path

import msgspec

from crimson.game_states import GameStateId
from crimson.screens.actions import ResultAction
from crimson.screens.ui_timeline import UiTimeline
from crimson.ui.animation import ui_element_anim, ui_elements_max_timeline, world_fade_alpha
from crimson.ui.cursor import ui_cursor_render
from grim import canvas
from grim.assets import TextureId, runtime_resources_for
from grim.color import grim_color
from grim.config import CrimsonConfig
from grim.fonts.small import SmallFontData, draw_small_text, measure_small_text_width
from grim.geom import Rect, Vec2
from grim.rand import CrandLike
from grim.raylib_api import rl
from grim.sfx_map import SfxId

from ...game_modes import GameMode
from ...persistence.highscores import (
    NAME_MAX_EDIT,
    TABLE_MAX,
    HighScoreRecord,
    rank_index,
    read_highscore_table,
    scores_path_for_mode,
    upsert_highscore_record,
)
from ...quests.level import QuestLevel
from ...quests.results import QuestFinalTime, QuestResultsReveal
from ...ui.focus import UiFocus
from ...ui.formatting import format_time_mm_ss
from ...ui.highscore_card import ui_text_input_render
from ...ui.layout import menu_widescreen_y_shift
from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import UiButtonState, button_draw, button_update, draw_ui_text
from ...ui.text_input import (
    UiTextInput,
    flush_text_input_events,
    gameplay_controls_held,
    ui_text_input_draw_focus,
    ui_text_input_focus,
    update_name_entry_text,
)

# `quest_results_screen_update` base layout (Crimsonland classic UI panel).
# Values are derived from `ui_menu_assets_init` + `ui_menu_layout_init` and how
# the quest results screen composes `ui_menuPanel` geometry:
#   panel_left = geom_x0 + pos_x + slide_x
#   panel_top  = geom_y0 + pos_y
#
# Where:
# - pos_x/pos_y are `ui_element_t` position fields set to (-45, 110)
# - geom_x0/geom_y0 are the first vertex coordinates of the `ui_menuPanel` geo,
#   after `ui_menu_assets_init` transforms it into an 8-vertex 3-slice panel.
QUEST_RESULTS_PANEL_POS_X = -45.0
QUEST_RESULTS_PANEL_POS_Y = 110.0
QUEST_RESULTS_PANEL_GEOM_X0 = -63.0
QUEST_RESULTS_PANEL_GEOM_Y0 = -81.0

QUEST_RESULTS_PANEL_W = 510.0
QUEST_RESULTS_PANEL_H = 378.0

TEXTURE_TOP_BANNER_W = 256.0
TEXTURE_TOP_BANNER_H = 64.0

# `quest_results_screen_update` uses the classic UI element sums for positioning:
#   content_x = (pos_x + offset_x + slide_x) + 180.0 + 40.0
#   banner_x  = content_x - 18.0
#   score_x   = content_x + 30.0
QUEST_RESULTS_CONTENT_X = 220.0
QUEST_RESULTS_BANNER_X_FROM_CONTENT = -18.0
QUEST_RESULTS_SCORE_CARD_X_FROM_CONTENT = 30.0

INPUT_BOX_W = 166.0
INPUT_BOX_H = 18.0

COLOR_TEXT = rl.Color(255, 255, 255, 255)
COLOR_TEXT_MUTED = rl.Color(255, 255, 255, int(255 * 0.8))
COLOR_TEXT_SUBTLE = rl.Color(255, 255, 255, int(255 * 0.7))
COLOR_GREEN = rl.Color(25, 200, 25, 255)
# `render_tint_color_global_init_thunk` initializes `render_tint_color` to this
# blue tint (149,175,198),
# reused by quest/game-over captions and score-card separator outlines.
COLOR_UI_ACCENT = rl.Color(149, 175, 198, 255)


class _QuestResultsPanelLayout(msgspec.Struct, frozen=True):
    panel: Rect
    top_left: Vec2


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

    save_error: str | None = None
    input_text: str = ""
    input_caret: int = 0
    _saved: bool = False

    # Shares GameState.ui and GameState.focus in the game; the defaults only serve standalone use.
    timeline: UiTimeline = msgspec.field(default_factory=UiTimeline)
    focus: UiFocus = msgspec.field(default_factory=UiFocus)
    _name_input: UiTextInput = msgspec.field(default_factory=UiTextInput)
    _dt: float = 0.0
    _panel_open_sfx_played: bool = False
    _close_action: ResultAction | None = None
    _consume_enter: bool = False
    _defer_name_input_until_controls_released: bool = False

    _ok_button: UiButtonState = msgspec.field(default_factory=lambda: UiButtonState("OK", force_wide=False))
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
        self._saved = False

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

        self.input_text = str(player_name_default or "")[:NAME_MAX_EDIT]
        self.save_error = None
        self.input_caret = len(self.input_text)

        self.timeline.enter(ui_elements_max_timeline(GameStateId.QUEST_RESULTS))
        self._panel_open_sfx_played = False
        self._close_action = None
        self._consume_enter = True
        self._defer_name_input_until_controls_released = False
        self.phase = 0

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
            self._arm_name_input_after_control_release()
        else:
            self.phase = 2

    def _fade_alpha(self) -> float:
        return min(1.0, self._anim_timer * 0.002)

    def _arm_name_input_after_control_release(self) -> None:
        self._defer_name_input_until_controls_released = True
        flush_text_input_events()
        self.focus.enter = False

    def world_entity_alpha(self) -> float:
        if not self.timeline.closing:
            return 1.0
        return world_fade_alpha(self.timeline.timeline_ms)

    def _text_width(self, font: SmallFontData, text: str) -> float:
        return float(measure_small_text_width(font, text))

    def _draw_small(self, font: SmallFontData, text: str, pos: Vec2, color: rl.Color) -> None:
        draw_small_text(font, text, pos, color)

    def _panel_layout(self, *, screen_w: float) -> _QuestResultsPanelLayout:
        panel_slide_x = ui_element_anim(self.timeline.timeline_ms, index=35, width=QUEST_RESULTS_PANEL_W)[1]

        panel_pos = Vec2(QUEST_RESULTS_PANEL_GEOM_X0 + QUEST_RESULTS_PANEL_POS_X + panel_slide_x, 0.0)
        widescreen_shift_y = menu_widescreen_y_shift(screen_w)
        panel_pos = Vec2(
            panel_pos.x,
            QUEST_RESULTS_PANEL_GEOM_Y0 + QUEST_RESULTS_PANEL_POS_Y + widescreen_shift_y,
        )
        panel = Rect.from_top_left(panel_pos, QUEST_RESULTS_PANEL_W, QUEST_RESULTS_PANEL_H)
        return _QuestResultsPanelLayout(panel=panel, top_left=panel_pos)

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
            if self._defer_name_input_until_controls_released:
                flush_text_input_events()
                self.focus.enter = False
                if not gameplay_controls_held(self.config):
                    self._defer_name_input_until_controls_released = False
                return None
            click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
            self.input_text, self.input_caret = update_name_entry_text(
                self.input_text,
                self.input_caret,
                max_len=NAME_MAX_EDIT,
                rng=rng,
                play_sfx=play_sfx,
            )

            screen_w = float(canvas.width())
            panel_layout = self._panel_layout(screen_w=screen_w)
            content_pos = panel_layout.top_left.offset(dx=QUEST_RESULTS_CONTENT_X)
            input_pos = content_pos.offset(dy=150.0)
            ok_pos = input_pos + Vec2(170.0, -8.0)
            resources = runtime_resources_for(self.assets_root)
            self._ok_button.alpha = self._fade_alpha()
            ok_clicked = button_update(resources, self._ok_button, focus=self.focus, pos=ok_pos, dt_ms=dt_ms, mouse=mouse, click=click)
            ui_text_input_focus(self.focus, self._name_input, input_pos, width=INPUT_BOX_W, mouse=Vec2.from_xy(mouse))

            # The text input submits on Enter wherever the focus is; a pad's A stands in for it.
            if ok_clicked or self.focus.enter:
                if self.input_text.strip():
                    if play_sfx is not None:
                        play_sfx(SfxId.UI_TYPEENTER)
                    try:
                        self.config.profile.set_player_name_input(self.input_text)
                        self.config.save()
                        if not self._saved:
                            assert self._scores_path is not None
                            candidate = self.record.copy()
                            candidate.set_name(self.input_text)
                            _table, idx = upsert_highscore_record(
                                self._scores_path, candidate, date_mode=self.config.profile.score_date_mode,
                            )
                            self.highlight_rank = idx if idx < TABLE_MAX else None
                            self.rank = idx
                            self._saved = True
                    except OSError:
                        self.save_error = "Could not save. Press OK to retry."
                        return None
                    self.save_error = None
                    self.phase = 2
                    return None
                if play_sfx is not None:
                    play_sfx(SfxId.SHOCK_HIT_01)
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
        panel = panel_layout.panel

        shadows_enabled = self.config.display.shadows_enabled
        draw_classic_menu_panel(
            resources.texture(TextureId.UI_MENU_PANEL),
            dst=panel.to_rl(),
            tint=rl.WHITE,
            shadow=shadows_enabled,
        )

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
                self._draw_small(font, label, Vec2(label_x, y), _row_color(row))
                self._draw_small(font, value, Vec2(value_x, y), _row_color(row))
                y += 20.0

            total_color = grim_color(1.0, 1.0, 1.0, alpha)
            rl.draw_rectangle(int(label_x - 4.0), int(y + 1.0), 168, 1, total_color)
            y += 8.0
            self._draw_small(font, "Final Time:", Vec2(label_x, y), total_color)
            self._draw_small(font, format_time_mm_ss(reveal.total_time_ms), Vec2(value_x, y), total_color)

        elif self.phase == 1:
            alpha = self._fade_alpha()
            text_y = panel_layout.top_left.y + 118.0
            self._draw_small(
                font,
                "State your name trooper!",
                Vec2(content_pos.x + 42.0, text_y),
                rl.Color(COLOR_UI_ACCENT.r, COLOR_UI_ACCENT.g, COLOR_UI_ACCENT.b, int(255 * alpha)),
            )

            input_pos = content_pos.offset(dy=150.0)
            rl.draw_rectangle_lines(
                int(input_pos.x),
                int(input_pos.y),
                int(INPUT_BOX_W),
                int(INPUT_BOX_H),
                grim_color(1.0, 1.0, 1.0, alpha),
            )
            rl.draw_rectangle(
                int(input_pos.x + 1.0),
                int(input_pos.y + 1.0),
                int(INPUT_BOX_W - 2.0),
                int(INPUT_BOX_H - 2.0),
                grim_color(0.0, 0.0, 0.0, alpha),
            )
            draw_ui_text(
                resources,
                self.input_text,
                input_pos + Vec2(4.0, 2.0),
                color=grim_color(1.0, 1.0, 1.0, 0.8 * alpha),
            )
            if self.save_error is not None:
                draw_ui_text(
                    resources, self.save_error, input_pos + Vec2(0.0, 22.0),
                    color=COLOR_TEXT_MUTED,
                )
            caret_alpha = 1.0
            if math.sin(float(rl.get_time()) * 4.0) > 0.0:
                caret_alpha = 0.4
            caret_color = grim_color(1.0, 1.0, 1.0, caret_alpha * alpha)
            caret_x = (
                input_pos.x + 4.0 + self._text_width(font, self.input_text[: self.input_caret])
            )
            rl.draw_rectangle(
                int(caret_x),
                int(input_pos.y + 2.0),
                1,
                14,
                caret_color,
            )

            ok_pos = input_pos + Vec2(170.0, -8.0)
            ui_text_input_draw_focus(self.focus, self._name_input, input_pos)
            button_draw(resources, self._ok_button, focus=self.focus, pos=ok_pos)

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
                self._draw_small(
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
                self._draw_small(
                    font,
                    "Weapon unlocked:",
                    Vec2(score_card_pos.x, var_c_14 + 1.0),
                    COLOR_TEXT_SUBTLE,
                )
                self._draw_small(
                    font,
                    self.unlock_weapon_name,
                    Vec2(score_card_pos.x, var_c_14 + 14.0),
                    COLOR_TEXT,
                )
                var_c_14 += 30.0
            if self.unlock_perk_name:
                self._draw_small(
                    font,
                    "Perk unlocked:",
                    Vec2(score_card_pos.x, var_c_14 + 1.0),
                    COLOR_TEXT_SUBTLE,
                )
                self._draw_small(
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
