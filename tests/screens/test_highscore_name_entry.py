from __future__ import annotations

import pytest

from crimson.game_modes import GameMode
from crimson.persistence.highscores import NAME_MAX_EDIT, read_highscore_table, scores_dir_for_base_dir
from crimson.screens.actions import StartRun
from grim.config import CRIMSON_CFG_NAME, load_crimson_cfg
from grim.raylib_api import rl
from grim.sfx_map import SfxId
from tests.support.audio import HeadlessAudio
from tests.support.screens import start_run, update_frame

pytestmark = pytest.mark.usefixtures("headless_resources", "headless_window")

PROFILE_NAME = "Lieutenant Maximilian"
# At 640x480 the slid-in panel's top left is (-24, 29); the name form sits at panel + (222, 124) and its OK
# button 170 right and 32 below that, hot from 2px lower.
OK_BUTTON = rl.Vector2(-24.0 + 222.0 + 170.0 + 10.0, 29.0 + 124.0 + 32.0 + 2.0 + 10.0)


class RaylibInput:
    """This frame's key edges, typed chars, mouse and held fire button, as raylib reports them."""

    def __init__(self, mocker) -> None:
        self.pressed: set[int] = set()
        self.chars: list[int] = []
        self.fire_held = False
        self.click = False
        self.mouse = rl.Vector2(0.0, 0.0)
        mocker.patch.object(rl, "is_key_pressed", side_effect=lambda key: int(key) in self.pressed)
        mocker.patch.object(rl, "get_char_pressed", side_effect=lambda: self.chars.pop(0) if self.chars else 0)
        mocker.patch.object(rl, "is_mouse_button_down", side_effect=lambda _button: self.fire_held)
        mocker.patch.object(rl, "is_mouse_button_pressed", side_effect=lambda _button: self.click)
        mocker.patch.object(rl, "get_mouse_position", side_effect=lambda: self.mouse)


class GameOver:
    """A survival run that just ended, its game-over panel asking the player for a name."""

    def __init__(self, make_game_state, headless_resources, mocker) -> None:
        self.audio = HeadlessAudio(mocker)
        self.input = RaylibInput(mocker)
        self.state = make_game_state(
            resources=headless_resources, audio=self.audio.state, config_updates={"player_name": PROFILE_NAME},
        )
        self.state.config.save()
        _navigator, self.run = start_run(self.state, StartRun(GameMode.SURVIVAL))
        self.run._enter_game_over()
        self.ui = self.run._game_over_ui
        for _ in range(30):
            update_frame(self.run, self.state, 0.1)
            if self.ui.phase == 0:
                break
        assert self.ui.phase == 0
        self.entry = self.ui.name_entry
        self.scores_dir = scores_dir_for_base_dir(self.state.base_dir)

    def frame(self, *keys: int, chars: str = "", click: bool = False) -> None:
        self.input.pressed = {int(key) for key in keys}
        self.input.chars.extend(ord(char) for char in chars)
        self.input.click = click
        # Frames of 0.1s outlast the sfx cooldown, so each refusal is heard.
        update_frame(self.run, self.state, 0.1)
        self.input.pressed = set()
        self.input.click = False

    def release_controls(self) -> None:
        self.frame()
        assert not self.entry.waiting_for_release

    def clear_name(self) -> None:
        for _ in range(len(self.entry.text)):
            self.frame(rl.KeyboardKey.KEY_BACKSPACE)
        assert self.entry.text == ""

    def saved_names(self) -> list[str]:
        table = read_highscore_table(self.scores_dir / "survival.hi", game_mode_id=GameMode.SURVIVAL)
        return [record.name() for record in table]

    def remembered_name(self) -> str:
        return load_crimson_cfg(self.state.base_dir / CRIMSON_CFG_NAME).profile.player_name


@pytest.fixture
def game_over(make_game_state, headless_resources, mocker) -> GameOver:
    return GameOver(make_game_state, headless_resources, mocker)


def test_enter_saves_the_prefilled_profile_name_once_controls_are_released(game_over: GameOver) -> None:
    prefill = PROFILE_NAME[:NAME_MAX_EDIT]
    assert game_over.entry.text == prefill
    assert game_over.entry.caret == len(prefill)

    # Fire held over from the fatal moment: Enter does not submit until every gameplay control is released.
    game_over.input.fire_held = True
    game_over.frame(rl.KeyboardKey.KEY_ENTER)
    game_over.frame(rl.KeyboardKey.KEY_ENTER)
    assert game_over.ui.phase == 0
    game_over.input.fire_held = False
    game_over.release_controls()

    game_over.frame(rl.KeyboardKey.KEY_ENTER)

    assert game_over.ui.phase == 1
    assert game_over.audio.played()[-1] == SfxId.UI_TYPEENTER
    assert game_over.saved_names() == [prefill]
    assert game_over.remembered_name() == prefill


def test_ok_button_submits_a_typed_name(game_over: GameOver) -> None:
    game_over.release_controls()
    game_over.clear_name()
    game_over.frame(chars="Bob")
    game_over.input.mouse = OK_BUTTON

    game_over.frame(click=True)

    assert game_over.ui.phase == 1
    assert game_over.saved_names() == ["Bob"]
    assert game_over.remembered_name() == "Bob"


def test_blank_name_is_refused_with_a_shock(game_over: GameOver) -> None:
    game_over.release_controls()
    game_over.clear_name()

    game_over.frame(rl.KeyboardKey.KEY_ENTER)
    game_over.frame(chars="   ")
    game_over.frame(rl.KeyboardKey.KEY_ENTER)

    assert game_over.ui.phase == 0
    assert [sfx for sfx in game_over.audio.played() if sfx == SfxId.SHOCK_HIT_01] == [SfxId.SHOCK_HIT_01] * 2
    assert game_over.audio.played()[-1] == SfxId.SHOCK_HIT_01
    assert not game_over.scores_dir.exists()
    assert game_over.remembered_name() == PROFILE_NAME


def test_failed_save_prompts_a_retry_that_saves_the_record_once(game_over: GameOver) -> None:
    game_over.release_controls()
    # A file where the scores directory belongs makes the table unwritable.
    game_over.scores_dir.write_bytes(b"")

    game_over.frame(rl.KeyboardKey.KEY_ENTER)

    assert game_over.ui.phase == 0
    assert game_over.entry.save_error == "Could not save. Press OK to retry."

    game_over.scores_dir.unlink()
    game_over.frame(rl.KeyboardKey.KEY_ENTER)

    prefill = PROFILE_NAME[:NAME_MAX_EDIT]
    assert game_over.ui.phase == 1
    assert game_over.entry.save_error is None
    assert game_over.saved_names() == [prefill]
    # The entry remembers its record went in: saving again only rewrites the name in the config.
    record = game_over.run._game_over_record
    assert record is not None
    assert game_over.entry.save(record, game_over.scores_dir / "survival.hi", config=game_over.state.config) == -1
    assert game_over.saved_names() == [prefill]
