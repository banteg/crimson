from __future__ import annotations

import math
from collections.abc import Callable
from pathlib import Path

import msgspec

from crimson.screens.actions import ResultAction
from crimson.ui.cursor import ui_cursor_render
from grim import canvas
from grim.assets import RuntimeResources, TextureId, runtime_resources_for
from grim.config import CrimsonConfig
from grim.fonts.small import SmallFontData, draw_small_text, measure_small_text_width
from grim.geom import Rect, Vec2
from grim.rand import CrandLike
from grim.raylib_api import rl
from grim.sfx_map import SfxId

from ...game_modes import GameMode
from ...game_states import GameStateId
from ...persistence.highscores import (
    NAME_MAX_EDIT,
    TABLE_MAX,
    HighScoreRecord,
    rank_index,
    read_highscore_table,
    scores_path_for_config,
    upsert_highscore_record,
)
from ...ui.animation import ui_element_anim, ui_elements_max_timeline, world_fade_alpha
from ...ui.highscore_card import ui_text_input_render
from ...ui.layout import menu_widescreen_y_shift
from ...ui.menu_panel import draw_classic_menu_panel
from ...ui.perk_menu import UiButtonState, button_draw, button_update, draw_ui_text
from ...ui.text_input import flush_text_input_events, gameplay_controls_held, update_name_entry_text
from ..ui_timeline import UiTimeline

GAME_OVER_PANEL_X = -45.0
# `ui_menu_layout_init` sets game-over panel pos to (-45, 110):
#   _DAT_0048cc60 = 0xc2340000 (-45.0)
#   _DAT_0048cc64 = 0x42dc0000 (110.0)
GAME_OVER_PANEL_Y = 110.0
# `ui_element_slot_30` is cloned from the 3-slice menu panel layout (`ui_menu_item_element._pad4+0xac`)
# in `ui_menu_layout_init`; trace confirms a 510x378 bbox for both phase 0 and phase 1.
GAME_OVER_PANEL_W = 510.0
GAME_OVER_PANEL_H = 378.0

# Measured from ui_render_trace at 1024x768 (stable timeline):
# panel top-left is (pos_x + 21, pos_y - 81) and size is 510x254, plus a shadow pass at +7,+7.
GAME_OVER_PANEL_OFFSET_X = 21.0
GAME_OVER_PANEL_OFFSET_Y = -81.0

TEXTURE_TOP_BANNER_W = 256.0
TEXTURE_TOP_BANNER_H = 64.0

# `game_over_screen_update` (0x0040ffc0) computes banner/content X from:
#   local_10 = quad0_x0 + pos_x + 180.0
#   local_18 = offset_x + local_10 + 44.0 - 10.0
# so banner/content anchor is +214 from the panel-left edge in steady state.
GAME_OVER_BANNER_X_OFFSET = 214.0

INPUT_BOX_W = 166.0  # `game_over_name_input_state_width_px = 0xa6` before `ui_text_input_update`
INPUT_BOX_H = 18.0

COLOR_TEXT = rl.Color(255, 255, 255, 255)
COLOR_TEXT_MUTED = rl.Color(255, 255, 255, int(255 * 0.8))


class _GameOverPanelLayout(msgspec.Struct, frozen=True):
    panel: Rect
    top_left: Vec2


def _draw_texture_centered(tex: rl.Texture, pos: Vec2, w: float, h: float, alpha: float) -> None:
    src = rl.Rectangle(0.0, 0.0, float(tex.width), float(tex.height))
    dst = rl.Rectangle(pos.x, pos.y, float(w), float(h))
    tint = rl.Color(255, 255, 255, int(255 * max(0.0, min(1.0, alpha))))
    rl.draw_texture_pro(tex, src, dst, rl.Vector2(0.0, 0.0), 0.0, tint)


class GameOverUi(msgspec.Struct):
    assets_root: Path
    base_dir: Path

    config: CrimsonConfig
    preserve_bugs: bool = False

    save_error: str | None = None
    input_text: str = ""
    input_caret: int = 0
    phase: int = -1  # -1 init, 0 name entry (if qualifies), 1 results/buttons
    rank: int = TABLE_MAX
    _candidate_record: HighScoreRecord | None = None
    _saved: bool = False
    _dt: float = 0.0

    # Shares GameState.ui in the game; the default only serves standalone use.
    timeline: UiTimeline = msgspec.field(default_factory=UiTimeline)
    _panel_open_sfx_played: bool = False
    _close_action: ResultAction | None = None

    # Buttons (rendered via existing ui_button implementation)
    _ok_button: UiButtonState = msgspec.field(default_factory=lambda: UiButtonState("OK", force_wide=False))
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
    _defer_name_input_until_controls_released: bool = False

    def open(self) -> None:
        self.close()
        self.phase = -1
        self.rank = TABLE_MAX
        self._candidate_record = None
        self._saved = False
        self._dt = 0.0
        self.timeline.enter(ui_elements_max_timeline(GameStateId.GAME_OVER))
        self._panel_open_sfx_played = False
        self._close_action = None
        self.save_error = None
        self.input_text = ""
        self.input_caret = 0
        self._consume_enter = True
        self._defer_name_input_until_controls_released = False

    def close(self) -> None:
        return None

    def consume_enter(self) -> bool:
        if self._consume_enter:
            self._consume_enter = False
            return True
        return False

    @property
    def closing(self) -> bool:
        return self.timeline.closing

    def world_entity_alpha(self) -> float:
        if not self.timeline.closing:
            return 1.0
        return world_fade_alpha(self.timeline.timeline_ms)

    def _text_width(self, font: SmallFontData, text: str) -> float:
        return float(measure_small_text_width(font, text))

    def _draw_small(self, font: SmallFontData, text: str, pos: Vec2, color: rl.Color) -> None:
        draw_small_text(font, text, pos, color)

    def _panel_layout(self, *, screen_w: float) -> _GameOverPanelLayout:
        # Keep consistent with the main menu panel offsets.
        panel_slide_x = ui_element_anim(self.timeline.timeline_ms, index=30, width=GAME_OVER_PANEL_W)[1]

        panel_pos = Vec2(GAME_OVER_PANEL_X + panel_slide_x, 0.0)
        widescreen_shift_y = menu_widescreen_y_shift(screen_w)
        panel_pos = Vec2(panel_pos.x, GAME_OVER_PANEL_Y + widescreen_shift_y)
        panel_origin = Vec2(-GAME_OVER_PANEL_OFFSET_X, -GAME_OVER_PANEL_OFFSET_Y)
        top_left = panel_pos - panel_origin
        panel = Rect.from_top_left(top_left, GAME_OVER_PANEL_W, GAME_OVER_PANEL_H)
        return _GameOverPanelLayout(panel=panel, top_left=top_left)

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
            rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER)
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
            flush_text_input_events()
            # Match native `grim_was_key_pressed(ENTER)` after the input flush.
            rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER)
            rl.is_key_pressed(rl.KeyboardKey.KEY_KP_ENTER)
            if idx < TABLE_MAX:
                self.phase = 0
                self.input_text = player_name_default[:NAME_MAX_EDIT]
                self.input_caret = len(self.input_text)
                self._defer_name_input_until_controls_released = True
                return None
            self.phase = 1

        # Basic text input behavior for the name-entry phase.
        if self.phase == 0:
            if self._defer_name_input_until_controls_released:
                flush_text_input_events()
                rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER)
                rl.is_key_pressed(rl.KeyboardKey.KEY_KP_ENTER)
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
            banner_pos = panel_layout.top_left + Vec2(GAME_OVER_BANNER_X_OFFSET, 40.0)
            form_pos = banner_pos + Vec2(8.0, 84.0)
            ok_pos = form_pos + Vec2(170.0, 32.0)
            ok_clicked = button_update(resources, self._ok_button, pos=ok_pos, dt_ms=dt_ms, mouse=mouse, click=click)

            if ok_clicked or rl.is_key_pressed(rl.KeyboardKey.KEY_ENTER):
                if self.input_text.strip():
                    if play_sfx is not None:
                        play_sfx(SfxId.UI_TYPEENTER)
                    candidate = (self._candidate_record or record).copy()
                    candidate.set_name(self.input_text)
                    try:
                        self.config.profile.set_player_name_input(self.input_text)
                        self.config.save()
                        if not self._saved:
                            path = scores_path_for_config(self.base_dir, self.config)
                            upsert_highscore_record(
                                path, candidate, date_mode=self.config.profile.score_date_mode,
                            )
                            self._saved = True
                    except OSError:
                        self.save_error = "Could not save. Press OK to retry."
                        return None
                    self.save_error = None
                    self.phase = 1
                    return None
                if play_sfx is not None:
                    play_sfx(SfxId.SHOCK_HIT_01)
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

        panel_layout = self._panel_layout(screen_w=screen_w)
        panel = panel_layout.panel
        panel_top_left = panel_layout.top_left

        # Panel background
        shadows_enabled = self.config.display.shadows_enabled
        draw_classic_menu_panel(
            resources.texture(TextureId.UI_MENU_PANEL),
            dst=panel.to_rl(),
            tint=rl.WHITE,
            shadow=shadows_enabled,
        )

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
            form_pos = banner_pos + Vec2(8.0, 84.0)
            self._draw_small(
                font,
                "State your name, trooper!",
                form_pos.offset(dx=42.0),
                COLOR_TEXT,
            )

            input_pos = form_pos.offset(dy=40.0)
            rl.draw_rectangle_lines(
                int(input_pos.x),
                int(input_pos.y),
                int(INPUT_BOX_W),
                int(INPUT_BOX_H),
                rl.WHITE,
            )
            rl.draw_rectangle(
                int(input_pos.x + 1.0),
                int(input_pos.y + 1.0),
                int(INPUT_BOX_W - 2.0),
                int(INPUT_BOX_H - 2.0),
                rl.Color(0, 0, 0, 255),
            )
            draw_ui_text(
                resources,
                self.input_text,
                input_pos + Vec2(4.0, 2.0),
                color=COLOR_TEXT_MUTED,
            )
            if self.save_error is not None:
                draw_ui_text(
                    resources, self.save_error, input_pos + Vec2(0.0, 22.0),
                    color=COLOR_TEXT_MUTED,
                )
            caret_alpha = 1.0
            if math.sin(float(rl.get_time()) * 4.0) > 0.0:
                caret_alpha = 0.4
            caret_color = rl.Color(255, 255, 255, int(255 * caret_alpha))
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

            ok_pos = form_pos + Vec2(170.0, 32.0)
            button_draw(
                resources,
                self._ok_button,
                pos=ok_pos,
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
                self._draw_small(
                    font,
                    "Score too low for top100.",
                    banner_pos + Vec2(38.0, 62.0),
                    rl.Color(200, 200, 200, 255),
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
                pos=button_pos,
            )
            button_pos = button_pos.offset(dy=32.0)

            button_draw(
                resources,
                self._high_scores_button,
                pos=button_pos,
            )
            button_pos = button_pos.offset(dy=32.0)

            button_draw(
                resources,
                self._main_menu_button,
                pos=button_pos,
            )

        ui_cursor_render(resources, dt=self._dt, pos=Vec2.from_xy(mouse))
