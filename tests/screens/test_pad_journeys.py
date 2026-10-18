from __future__ import annotations

from collections.abc import Callable

import pytest

from crimson.game.loop_view import GameLoopView
from crimson.game_modes import GameMode
from crimson.input_codes import PadCode
from crimson.modes.quest_mode import QuestMode
from crimson.modes.survival_mode import SurvivalMode
from crimson.perks.selection import perk_selection_open_choices
from crimson.quests.level import QuestLevel
from crimson.screens import menu
from crimson.screens.actions import Route, StartRun
from crimson.screens.assets import require_runtime_resources
from crimson.screens.menu import MenuView
from crimson.screens.panels.controls import ControlsMenuView, RebindCapture
from crimson.screens.panels.controls_labels import RebindRowSpec, RebindTarget
from crimson.screens.panels.credits import CreditsView
from crimson.screens.panels.databases_perks import UnlockedPerksDatabaseView
from crimson.screens.panels.databases_weapons import UnlockedWeaponsDatabaseView
from crimson.screens.panels.options import OptionsMenuView
from crimson.screens.panels.play_game import PlayGameMenuView
from crimson.screens.panels.stats import StatisticsMenuView
from crimson.screens.quest_views import QuestsMenuView
from crimson.screens.quest_views.quest_failed import QuestFailedView
from crimson.ui.focus import UI_FOCUS_TIMER_MS
from crimson.ui.menu_layout import MENU_LABEL_ROW_OPTIONS, MENU_LABEL_ROW_PLAY_GAME, menu_item_bounds
from grim import canvas
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.texture_ids import TextureId
from tests.support.screens import finish_transition

DPAD_UP = rl.GamepadButton.GAMEPAD_BUTTON_LEFT_FACE_UP
DPAD_DOWN = rl.GamepadButton.GAMEPAD_BUTTON_LEFT_FACE_DOWN
DPAD_RIGHT = rl.GamepadButton.GAMEPAD_BUTTON_LEFT_FACE_RIGHT
RIGHT_X = int(rl.GamepadAxis.GAMEPAD_AXIS_RIGHT_X)
RIGHT_Y = int(rl.GamepadAxis.GAMEPAD_AXIS_RIGHT_Y)
PAD_A = rl.GamepadButton.GAMEPAD_BUTTON_RIGHT_FACE_DOWN
PAD_B = rl.GamepadButton.GAMEPAD_BUTTON_RIGHT_FACE_RIGHT
PAD_START = rl.GamepadButton.GAMEPAD_BUTTON_MIDDLE_RIGHT


@pytest.fixture
def pad(headless_window, mocker):
    """One pad in the second slot, sticks at rest; `press` supplies its button edges, `steer` its right stick."""
    mocker.patch.object(rl, "is_gamepad_available", side_effect=lambda gamepad: int(gamepad) == 1)
    mocker.patch.object(rl, "get_gamepad_axis_movement", return_value=0.0)
    mocker.patch.object(rl, "is_gamepad_button_pressed", return_value=False)
    mocker.patch.object(rl, "is_gamepad_button_down", return_value=False)
    yield
    canvas.steer_mouse(None)
    canvas.press_mouse(False)


def press(loop: GameLoopView, mocker, *buttons: int) -> None:
    """One loop frame with `buttons` pressed on the pad, and nothing else."""
    pressed = {int(button) for button in buttons}
    for edge in ("is_gamepad_button_pressed", "is_gamepad_button_down"):
        mocker.patch.object(rl, edge, side_effect=lambda gamepad, button: int(gamepad) == 1 and int(button) in pressed)
    loop.update(0.016)
    for edge in ("is_gamepad_button_pressed", "is_gamepad_button_down"):
        mocker.patch.object(rl, edge, return_value=False)


def steer(loop: GameLoopView, mocker, target: Vec2) -> None:
    """Tilt the right stick toward `target` each frame, gentler near it, until the cursor is there."""
    axes: dict[int, float] = {}
    mocker.patch.object(rl, "get_gamepad_axis_movement", side_effect=lambda _pad, axis: axes.get(int(axis), 0.0))
    for _ in range(300):
        offset = target - Vec2.from_xy(canvas.mouse_position())
        if offset.length() < 2.0:
            mocker.patch.object(rl, "get_gamepad_axis_movement", return_value=0.0)
            return
        tilt = offset.normalized() * max(0.3, min(1.0, offset.length() / 40.0))
        axes.update({RIGHT_X: tilt.x, RIGHT_Y: tilt.y})
        loop.update(0.016)
    raise AssertionError("the right stick never brought the cursor there")


def dpad_to(loop: GameLoopView, mocker, focused: Callable[[], bool]) -> None:
    """D-pad down until the widget reports the focus."""
    for _ in range(40):
        if focused():
            return
        press(loop, mocker, DPAD_DOWN)
    raise AssertionError("the D-pad never reached the widget")


pytestmark = pytest.mark.usefixtures("pad")


def test_main_menu_to_a_survival_run_with_only_the_pad(loop, mocker) -> None:
    state = loop.state
    state.config.gameplay.player_count = 1
    finish_transition(loop)
    main = state.screens.active
    assert isinstance(main, MenuView)
    # The first item, Play Game, holds the focus of a fresh menu.
    press(loop, mocker, PAD_A)
    finish_transition(loop)

    panel = state.screens.active
    assert isinstance(panel, PlayGameMenuView)
    entries, *_ = panel._mode_entries()
    survival = next(entry for entry in entries if entry.game_mode == GameMode.SURVIVAL)
    finish_transition(loop)
    dpad_to(loop, mocker, lambda: panel._mode_buttons[survival.key].focused)
    press(loop, mocker, PAD_A)
    assert state.ui.pending == StartRun(GameMode.SURVIVAL)
    assert state.config.gameplay.mode == GameMode.SURVIVAL


def test_player_count_list_with_the_pad(loop, mocker) -> None:
    state = loop.state
    state.config.gameplay.player_count = 1
    loop.navigation.navigate(Route.PLAY_GAME)
    finish_transition(loop)
    panel = state.screens.active
    assert isinstance(panel, PlayGameMenuView)
    widget = panel.player_count_list

    dpad_to(loop, mocker, lambda: widget.focused)
    # A opens the focused list; the D-pad then walks its rows instead of the focus, and A takes one.
    press(loop, mocker, PAD_A)
    assert widget.open
    assert widget.active_index == 0
    press(loop, mocker, DPAD_DOWN)
    press(loop, mocker, DPAD_DOWN)
    assert widget.focused
    assert widget.active_index == 2
    press(loop, mocker, DPAD_UP)
    press(loop, mocker, PAD_A)
    assert not widget.open
    assert state.config.gameplay.player_count == 2
    # Closed again, the D-pad moves the focus on.
    press(loop, mocker, DPAD_DOWN)
    assert not widget.focused


def test_options_slider_with_the_pad(loop, mocker) -> None:
    finish_transition(loop)
    main = loop.state.screens.active
    assert isinstance(main, MenuView)
    options_entry = next(entry for entry in main._menu_entries if entry.row == MENU_LABEL_ROW_OPTIONS)
    dpad_to(loop, mocker, lambda: options_entry.focused)
    press(loop, mocker, PAD_A)
    finish_transition(loop)

    options = loop.state.screens.active
    assert isinstance(options, OptionsMenuView)
    slider = options._slider_detail
    slider.value = 3
    dpad_to(loop, mocker, lambda: slider.focused)
    press(loop, mocker, DPAD_RIGHT)
    assert slider.value == 4
    assert loop.state.config.display.detail_preset == 4


@pytest.mark.parametrize(
    ("routes", "screen", "below"),
    [
        ((Route.PLAY_GAME,), PlayGameMenuView, MenuView),
        ((Route.PLAY_GAME, Route.QUESTS), QuestsMenuView, PlayGameMenuView),
        ((Route.OPTIONS,), OptionsMenuView, MenuView),
        ((Route.OPTIONS, Route.CONTROLS), ControlsMenuView, OptionsMenuView),
        ((Route.STATISTICS,), StatisticsMenuView, MenuView),
        ((Route.STATISTICS, Route.WEAPONS), UnlockedWeaponsDatabaseView, StatisticsMenuView),
        ((Route.STATISTICS, Route.PERKS), UnlockedPerksDatabaseView, StatisticsMenuView),
        ((Route.STATISTICS, Route.CREDITS), CreditsView, StatisticsMenuView),
    ],
)
def test_pad_b_backs_out_of_every_menu_screen(loop, mocker, routes, screen, below) -> None:
    for route in routes:
        loop.navigation.navigate(route)
        finish_transition(loop)
    assert isinstance(loop.state.screens.active, screen)
    press(loop, mocker, PAD_B)
    finish_transition(loop)
    assert isinstance(loop.state.screens.active, below)


def test_pad_b_closes_the_open_player_count_list_before_backing_out(loop, mocker) -> None:
    loop.navigation.navigate(Route.PLAY_GAME)
    finish_transition(loop)
    panel = loop.state.screens.active
    assert isinstance(panel, PlayGameMenuView)
    panel.player_count_list.open = True
    press(loop, mocker, PAD_B)
    finish_transition(loop)
    assert loop.state.screens.active is panel
    assert not panel.player_count_list.open
    press(loop, mocker, PAD_B)
    finish_transition(loop)
    assert isinstance(loop.state.screens.active, MenuView)


@pytest.mark.parametrize(
    ("row", "binds"),
    [
        (RebindRowSpec("Up/Down Axis:", RebindTarget.PLAYER_MOVE_AXIS_CODES, 0, axis=True), False),
        (RebindRowSpec("Fire:", RebindTarget.PLAYER_FIRE_CODE), True),
    ],
)
def test_pad_b_cancels_an_axis_rebind_and_binds_a_button_row(loop, mocker, row, binds) -> None:
    loop.navigation.navigate(Route.OPTIONS)
    loop.navigation.navigate(Route.CONTROLS)
    finish_transition(loop)
    view = loop.state.screens.active
    assert isinstance(view, ControlsMenuView)
    # Player 2's rows, which read the pad in the second slot.
    view._capture = RebindCapture(row, 1, skip_frames=0)
    press(loop, mocker, PAD_B)
    finish_transition(loop)
    # An axis row takes no buttons, so B cancels it; a button row takes B as its binding. The screen stays.
    assert view._capture is None
    assert loop.state.screens.active is view
    assert (loop.state.config.controls.player(1).fire_code == PadCode.FACE_RIGHT) == binds
    press(loop, mocker, PAD_B)
    finish_transition(loop)
    assert isinstance(loop.state.screens.active, OptionsMenuView)


@pytest.mark.parametrize("button", [PAD_B, PAD_START])
def test_pad_b_or_start_backs_out_of_the_perk_menu(loop, mocker, button) -> None:
    loop.navigation.navigate(StartRun(GameMode.SURVIVAL))
    run = loop.state.screens.gameplay
    assert isinstance(run, SurvivalMode)
    run.state.perk_selection.pending_count = 1
    perk_selection_open_choices(run.state, run.world.players, game_mode=GameMode.SURVIVAL)
    run._perk_menu.open_menu()
    for _ in range(4):
        loop.update(0.1)
    press(loop, mocker, button)
    finish_transition(loop)
    # Start, the pad's Escape, closes the menu like B instead of pausing the run.
    assert not run._perk_menu.open
    assert loop.state.screens.active is run


def _fail_a_quest(loop: GameLoopView) -> QuestFailedView:
    loop.navigation.navigate(StartRun(GameMode.QUESTS, QuestLevel(1, 1)))
    run = loop.state.screens.gameplay
    assert isinstance(run, QuestMode)
    run.world.players[0].health = 0.0
    for _ in range(900):
        if isinstance(loop.state.screens.active, QuestFailedView):
            break
        loop.update(1.0 / 60.0)
    view = loop.state.screens.active
    assert isinstance(view, QuestFailedView)
    finish_transition(loop)
    return view


def test_pad_focus_stays_lit_until_the_mouse_moves(loop, mocker) -> None:
    view = _fail_a_quest(loop)
    press(loop, mocker, DPAD_DOWN)
    for _ in range(120):
        loop.update(1.0 / 60.0)
    # Native's marker fades a second after each move; with the pad in use the focus stays in view.
    assert view._quest_list_button.focused
    assert loop.state.focus.timer_ms == UI_FOCUS_TIMER_MS
    assert view._quest_list_button.hover_t == 1000

    mocker.patch.object(rl, "get_mouse_delta", return_value=rl.Vector2(3.0, 0.0))
    loop.update(1.0 / 60.0)
    mocker.patch.object(rl, "get_mouse_delta", return_value=rl.Vector2(0.0, 0.0))
    for _ in range(120):
        loop.update(1.0 / 60.0)
    assert loop.state.focus.timer_ms == 0


def test_main_menu_after_a_failed_quest_starts_on_its_first_item(loop, mocker) -> None:
    view = _fail_a_quest(loop)
    dpad_to(loop, mocker, lambda: view._main_menu_button.focused)
    press(loop, mocker, PAD_A)
    for _ in range(300):
        if isinstance(loop.state.screens.active, menu.MenuView):
            break
        loop.update(1.0 / 60.0)
    finish_transition(loop)
    main = loop.state.screens.active
    assert isinstance(main, menu.MenuView)
    # The quest-failed screen's third button must not carry over as the menu's third item.
    assert main._menu_entries[0].focused


def test_dpad_right_pages_the_quest_list_with_nothing_that_way(loop, mocker) -> None:
    loop.navigation.navigate(Route.QUESTS)
    finish_transition(loop)
    view = loop.state.screens.active
    assert isinstance(view, QuestsMenuView)
    dpad_to(loop, mocker, lambda: view._row_items[0].focused)
    # No widget lies right of the quest rows, so right is the arrow key, which pages the stage.
    press(loop, mocker, DPAD_RIGHT)
    assert view._stage == 2
    assert view._row_items[0].focused


def test_right_stick_points_and_a_clicks_there(loop, mocker) -> None:
    finish_transition(loop)
    main = loop.state.screens.active
    assert isinstance(main, MenuView)
    play = next(entry for entry in main._menu_entries if entry.row == MENU_LABEL_ROW_PLAY_GAME)
    options = next(entry for entry in main._menu_entries if entry.row == MENU_LABEL_ROW_OPTIONS)
    item = require_runtime_resources(loop.state).texture(TextureId.UI_MENU_ITEM)
    bounds = menu_item_bounds(options.pos, Vec2(float(item.width), float(item.height)), options.scale, options.rise)
    press(loop, mocker, DPAD_DOWN)
    press(loop, mocker, DPAD_UP)
    assert play.focused

    steer(loop, mocker, bounds.center)
    # The cursor stays where the stick left it, over Options, while the focus stays on Play Game.
    for _ in range(30):
        loop.update(0.016)
    assert options.hovered
    assert play.focused
    # A clicks where the cursor points instead of entering the focused item.
    press(loop, mocker, PAD_A)
    finish_transition(loop)
    assert isinstance(loop.state.screens.active, OptionsMenuView)

    # Moving the mouse hands the cursor back to the window's.
    mocker.patch.object(rl, "get_mouse_delta", return_value=rl.Vector2(3.0, 0.0))
    loop.update(0.016)
    window = rl.get_mouse_position()
    assert (canvas.mouse_position().x, canvas.mouse_position().y) == (window.x, window.y)
