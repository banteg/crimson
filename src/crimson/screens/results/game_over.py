from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import msgspec

from crimson.screens.actions import ResultAction
from crimson.ui.cursor import ui_cursor_render
from grim import canvas
from grim.assets import RuntimeResources, TextureId, runtime_resources_for
from grim.config import CrimsonConfig
from grim.fonts.small import draw_small_text
from grim.geom import Rect, Vec2
from grim.rand import CrandLike
from grim.raylib_api import rl, rl_color, rl_rectangle, rl_vector2
from grim.sfx_map import SfxId

from ...game_modes import GameMode
from ...game_states import GameStateId
from ...persistence.highscores import (
    TABLE_MAX,
    HighScoreRecord,
    rank_index,
    read_highscore_table,
    scores_path_for_config,
)
from ...ui.animation import ui_elements_max_timeline, ui_transition_alpha
from ...ui.button import UiButtonState, button_draw, button_update
from ...ui.focus import UiFocus
from ...ui.highscore_card import ui_text_input_render
from ...ui.menu_panel import draw_ui_panel, ui_panel_rect
from ...ui.name_entry import HighScoreNameEntry
from ...ui.text_input import (
    flush_text_input_events,
)
from ..ui_timeline import UiTimeline

TEXTURE_TOP_BANNER_W = 256.0
TEXTURE_TOP_BANNER_H = 64.0

# `game_over_screen_update` (0x0040ffc0) computes banner/content X from:
#   local_10 = quad0_x0 + pos_x + 180.0
#   local_18 = offset_x + local_10 + 44.0 - 10.0
# so banner/content anchor is +214 from the panel-left edge in steady state.
GAME_OVER_BANNER_X_OFFSET = 214.0

# The name form sits 8 right of and 84 below the banner.
_GAME_OVER_FORM_OFFSET = Vec2(GAME_OVER_BANNER_X_OFFSET + 8.0, 40.0 + 84.0)

COLOR_TEXT = rl_color(255, 255, 255, 255)
COLOR_TEXT_MUTED = rl_color(255, 255, 255, int(255 * 0.8))


def _draw_texture_centered(tex: rl.Texture, pos: Vec2, w: float, h: float, alpha: float) -> None:
    src = rl_rectangle(0.0, 0.0, float(tex.width), float(tex.height))
    dst = rl_rectangle(pos.x, pos.y, float(w), float(h))
    tint = rl_color(255, 255, 255, int(255 * max(0.0, min(1.0, alpha))))
    rl.draw_texture_pro(tex, src, dst, rl_vector2(0.0, 0.0), 0.0, tint)


class GameOverUi(msgspec.Struct):
    assets_root: Path
    base_dir: Path

    config: CrimsonConfig
    preserve_bugs: bool = False

    phase: int = -1  # -1 init, 0 name entry (if qualifies), 1 results/buttons
    rank: int = TABLE_MAX
    _candidate_record: HighScoreRecord | None = None
    _dt: float = 0.0
    name_entry: HighScoreNameEntry = msgspec.field(default_factory=HighScoreNameEntry)

    # Shares GameState.ui and GameState.focus in the game; the defaults only serve standalone use.
    timeline: UiTimeline = msgspec.field(default_factory=UiTimeline)
    focus: UiFocus = msgspec.field(default_factory=UiFocus)
    _panel_open_sfx_played: bool = False
    _close_action: ResultAction | None = None

    # Buttons (rendered via existing ui_button implementation)
    _play_again_button: UiButtonState = msgspec.field(
        default_factory=lambda: UiButtonState("Play Again", force_wide=True),
    )
    _high_scores_button: UiButtonState = msgspec.field(
        default_factory=lambda: UiButtonState("High scores", force_wide=True),
    )
    _main_menu_button: UiButtonState = msgspec.field(
        default_factory=lambda: UiButtonState("Main Menu", force_wide=True),
    )

    _consume_enter: bool = False

    def open(self) -> None:
        self.close()
        self.phase = -1
        self.rank = TABLE_MAX
        self._candidate_record = None
        self.name_entry = HighScoreNameEntry()
        self._dt = 0.0
        self.timeline.enter(ui_elements_max_timeline(GameStateId.GAME_OVER))
        self._panel_open_sfx_played = False
        self._close_action = None
        self._consume_enter = True

    def close(self) -> None:
        return None

    @property
    def closing(self) -> bool:
        return self.timeline.closing

    def world_entity_alpha(self) -> float:
        # `game_over_screen_update`'s buttons set `game_state_pending`; Play Again keeps the run lit.
        match self._close_action if self.timeline.closing else None:
            case None:
                pending = None
            case ResultAction.PLAY_AGAIN:
                typo = self.config.gameplay.mode == GameMode.TYPO
                pending = GameStateId.TYPO_GAMEPLAY if typo else GameStateId.GAMEPLAY
            case ResultAction.HIGH_SCORES:
                pending = GameStateId.HIGHSCORES
            case _:
                pending = GameStateId.MAIN_MENU
        return ui_transition_alpha(self.timeline.timeline_ms, state=GameStateId.GAME_OVER, pending=pending)

    def _panel_layout(self, *, screen_w: float) -> Rect:
        """`game_over_screen_update` lays out on `ui_element_slot_30`'s panel."""
        return ui_panel_rect(30, self.timeline.timeline_ms, screen_w)

    def _begin_close_transition(self, action: ResultAction) -> None:
        if self.timeline.closing:
            return
        self._close_action = action
        self.timeline.begin()

    def update(
        self,
        dt: float,
        *,
        record: HighScoreRecord,
        player_name_default: str,
        play_sfx: Callable[[SfxId], None] | None = None,
        rng: CrandLike,
        mouse: rl.Vector2 | None = None,
    ) -> ResultAction | None:
        self._dt = float(min(dt, 0.1))
        dt_ms = self._dt * 1000.0
        if mouse is None:
            mouse = canvas.mouse_position()

        resources = runtime_resources_for(self.assets_root)

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
        if self.phase == -1:
            # If in the top 100, prompt for a name. Otherwise show score-too-low message and buttons.
            try:
                game_mode_id = GameMode(self.config.gameplay.mode)
            except ValueError:
                game_mode_id = GameMode.DEMO
            candidate = record.copy()
            candidate.game_mode_id = game_mode_id
            self._candidate_record = candidate

            path = scores_path_for_config(self.base_dir, self.config)
            records = read_highscore_table(
                path, game_mode_id=game_mode_id, date_mode=self.config.profile.score_date_mode,
            )
            idx = rank_index(records, candidate)
            self.rank = int(idx)
            # Native flushes the input, and `grim_was_key_pressed(ENTER)` swallows this frame's Enter.
            flush_text_input_events()
            self.focus.enter = False
            if idx < TABLE_MAX:
                self.phase = 0
                self.name_entry.start(player_name_default, focus=self.focus)
                return None
            self.phase = 1

        if self.phase == 0:
            form_pos = self._panel_layout(screen_w=float(canvas.width())).top_left + _GAME_OVER_FORM_OFFSET
            name = self.name_entry.update(
                resources,
                focus=self.focus,
                config=self.config,
                input_pos=form_pos.offset(dy=40.0),
                ok_pos=form_pos + Vec2(170.0, 32.0),
                dt_ms=dt_ms,
                mouse=mouse,
                rng=rng,
                play_sfx=play_sfx,
            )
            if name is not None and self.name_entry.save(
                self._candidate_record or record, scores_path_for_config(self.base_dir, self.config), config=self.config,
            ) is not None:
                self.phase = 1
        else:
            # Buttons phase: let the caller handle navigation; we just report actions.
            click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
            screen_w = float(canvas.width())
            panel_layout = self._panel_layout(screen_w=screen_w)
            banner_pos = panel_layout.top_left + Vec2(GAME_OVER_BANNER_X_OFFSET, 40.0)
            button_pos = banner_pos + Vec2(52.0, (210.0 if self.rank < TABLE_MAX else 208.0))
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

    def draw(
        self,
        *,
        record: HighScoreRecord,
        banner_kind: str,
        resources: RuntimeResources,
        mouse: rl.Vector2 | None = None,
    ) -> None:
        if mouse is None:
            mouse = canvas.mouse_position()
        font = resources.small_font

        screen_w = float(canvas.width())

        panel = self._panel_layout(screen_w=screen_w)
        draw_ui_panel(resources, 30, panel, shadow=self.config.display.shadows_enabled)
        panel_top_left = panel.top_left

        # Banner (Reaper / Well done)
        banner_pos = panel_top_left + Vec2(GAME_OVER_BANNER_X_OFFSET, 40.0)
        banner = (
            resources.texture(TextureId.UI_TEXT_REAPER)
            if banner_kind == "reaper"
            else resources.texture(TextureId.UI_TEXT_WELL_DONE)
        )
        _draw_texture_centered(
            banner,
            banner_pos,
            TEXTURE_TOP_BANNER_W,
            TEXTURE_TOP_BANNER_H,
            1.0,
        )

        if self.phase == 0:
            form_pos = panel_top_left + _GAME_OVER_FORM_OFFSET
            draw_small_text(font, "State your name, trooper!", form_pos.offset(dx=42.0), COLOR_TEXT)
            self.name_entry.draw(
                resources, focus=self.focus, input_pos=form_pos.offset(dy=40.0), ok_pos=form_pos + Vec2(170.0, 32.0),
            )

            score_pos = form_pos + Vec2(16.0, 116.0)
            ui_text_input_render(
                score_pos, record, 1.0, self.rank + 1,
                game_state=GameStateId.GAME_OVER, ui_phase=self.phase, resources=resources, mouse=mouse, dt=self._dt,
            )
        else:
            score_card_pos = banner_pos + Vec2(
                30.0,
                (80.0 if self.rank < TABLE_MAX else 78.0),
            )
            if self.rank >= TABLE_MAX and banner_kind == "reaper":
                draw_small_text(
                    font,
                    "Score too low for top100.",
                    banner_pos + Vec2(38.0, 62.0),
                    rl_color(200, 200, 200, 255),
                )

            ui_text_input_render(
                score_card_pos, record, 1.0, self.rank + 1,
                game_state=GameStateId.GAME_OVER, ui_phase=self.phase, resources=resources, mouse=mouse, dt=self._dt,
            )

        # Buttons phase rendering.
        if self.phase == 1:
            button_pos = banner_pos + Vec2(52.0, (210.0 if self.rank < TABLE_MAX else 208.0))
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
