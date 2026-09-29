from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import msgspec

from grim.assets import RuntimeResources
from grim.config import CrimsonConfig
from grim.geom import Vec2
from grim.rand import CrandLike
from grim.raylib_api import rl
from grim.sfx_map import SfxId

from ..persistence.highscores import NAME_MAX_EDIT, HighScoreRecord, upsert_highscore_record
from .focus import UiFocus
from .perk_menu import UiButtonState, button_draw, button_update, draw_ui_text
from .text_input import (
    UiTextInput,
    flush_text_input_events,
    gameplay_controls_held,
    ui_text_input_draw,
    ui_text_input_draw_focus,
    ui_text_input_focus,
    update_name_entry_text,
)

# The name box width both result screens pass to `ui_text_input_update` (`width_px = 0xa6`).
NAME_INPUT_W = 166.0
_COLOR_SAVE_ERROR = rl.Color(255, 255, 255, int(255 * 0.8))


class HighScoreNameEntry(msgspec.Struct):
    """The name prompt of `game_over_screen_update` and `quest_results_screen_update`: a name box with its OK button.

    Typing waits until the gameplay controls are released, so a held fire key does not type or submit.
    """

    text: str = ""
    caret: int = 0
    save_error: str | None = None
    saved: bool = False
    waiting_for_release: bool = False
    field: UiTextInput = msgspec.field(default_factory=UiTextInput)
    ok_button: UiButtonState = msgspec.field(default_factory=lambda: UiButtonState("OK", force_wide=False))

    def start(self, default_name: str, *, focus: UiFocus) -> None:
        """Prefill the name and swallow the frame's typed text and Enter (`grim_flush_input`)."""
        self.text = default_name[:NAME_MAX_EDIT]
        self.caret = len(self.text)
        self.save_error = None
        self.saved = False
        self.waiting_for_release = True
        flush_text_input_events()
        focus.enter = False

    def update(
        self,
        resources: RuntimeResources,
        *,
        focus: UiFocus,
        config: CrimsonConfig,
        input_pos: Vec2,
        ok_pos: Vec2,
        dt_ms: float,
        mouse: rl.Vector2,
        rng: CrandLike,
        play_sfx: Callable[[SfxId], None] | None,
    ) -> str | None:
        """Type, then submit on OK or Enter: returns the submitted name, or None."""
        if self.waiting_for_release:
            flush_text_input_events()
            focus.enter = False
            if not gameplay_controls_held(config):
                self.waiting_for_release = False
            return None
        click = rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT)
        self.text, self.caret = update_name_entry_text(
            self.text, self.caret, max_len=NAME_MAX_EDIT, rng=rng, play_sfx=play_sfx,
        )
        ok_clicked = button_update(
            resources, self.ok_button, focus=focus, pos=ok_pos, dt_ms=dt_ms, mouse=mouse, click=click,
        )
        ui_text_input_focus(focus, self.field, input_pos, width=NAME_INPUT_W, mouse=Vec2.from_xy(mouse))
        # The name box submits on Enter wherever the focus is; a pad's A stands in for it, so a pad alone can
        # accept the prefilled name.
        if not (ok_clicked or focus.enter):
            return None
        if not self.text.strip():
            if play_sfx is not None:
                play_sfx(SfxId.SHOCK_HIT_01)
            return None
        if play_sfx is not None:
            play_sfx(SfxId.UI_TYPEENTER)
        return self.text

    def save(self, record: HighScoreRecord, path: Path, *, config: CrimsonConfig) -> int | None:
        """Remember the name and save the named record once; the table index, or None (and a retry prompt)."""
        candidate = record.copy()
        candidate.set_name(self.text)
        try:
            config.profile.set_player_name_input(self.text)
            config.save()
            index = -1
            if not self.saved:
                _table, index = upsert_highscore_record(path, candidate, date_mode=config.profile.score_date_mode)
                self.saved = True
        except OSError:
            self.save_error = "Could not save. Press OK to retry."
            return None
        self.save_error = None
        return index

    def draw(self, resources: RuntimeResources, *, focus: UiFocus, input_pos: Vec2, ok_pos: Vec2) -> None:
        ui_text_input_draw_focus(focus, self.field, input_pos)
        ui_text_input_draw(resources, input_pos, width=NAME_INPUT_W, text=self.text, caret=self.caret)
        if self.save_error is not None:
            draw_ui_text(resources, self.save_error, input_pos + Vec2(0.0, 22.0), color=_COLOR_SAVE_ERROR)
        button_draw(resources, self.ok_button, focus=focus, pos=ok_pos)
