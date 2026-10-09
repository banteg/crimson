from __future__ import annotations

import pytest

from crimson.game_states import GameStateId
from crimson.ui.animation import ui_element_anim, ui_transition_alpha


@pytest.mark.parametrize(
    ("timeline_ms", "expected"),
    [(100.0, -400.0), (250.0, -200.0), (399.0, -400.0 / 300.0), (400.0, 0.0)],
)
def test_results_panel_slides_in_linearly_between_100_and_400_ms(timeline_ms: float, expected: float) -> None:
    # ui_element_update: render_offset_x = -(1 - (t - start) / (end - start)) * width for slots 30/35.
    assert ui_element_anim(timeline_ms, index=30, width=400.0)[1] == pytest.approx(expected)


@pytest.mark.parametrize(
    ("state", "pending", "latch", "expected"),
    [
        # Gameplay holds the run lit, unless a fresh run is still fading in.
        (GameStateId.GAMEPLAY, None, False, 1.0),
        (GameStateId.GAMEPLAY, GameStateId.PAUSE_MENU, True, 0.5),
        # The results screens hold it while open and while heading back into a run.
        (GameStateId.GAME_OVER, None, False, 1.0),
        (GameStateId.GAME_OVER, GameStateId.GAMEPLAY, False, 1.0),
        (GameStateId.GAME_OVER, GameStateId.TYPO_GAMEPLAY, False, 0.5),
        (GameStateId.QUEST_RESULTS, GameStateId.HIGHSCORES, False, 0.5),
        # The pause menu fades it only on the way to the main menu.
        (GameStateId.PAUSE_MENU, None, False, 1.0),
        (GameStateId.PAUSE_MENU, GameStateId.MAIN_MENU, False, 0.5),
        # Screens outside the list follow the timeline even while open.
        (GameStateId.FINAL_QUEST_END_NOTE, None, False, 0.5),
        (GameStateId.HIGHSCORES, GameStateId.QUEST_RESULTS, False, 1.0),
    ],
)
def test_ui_transition_alpha_holds_the_run_through_native_transitions(
    state: GameStateId, pending: GameStateId | None, latch: bool, expected: float,
) -> None:
    # `gameplay_render_world`: the timeline over `ui_element_table[28]`'s 500 ms, or 1 through the listed transitions.
    assert ui_transition_alpha(250.0, state=state, pending=pending, latch=latch) == pytest.approx(expected)


@pytest.mark.parametrize(("timeline_ms", "expected"), [(-5.0, 0.0), (400.0, 0.8), (600.0, 1.0)])
def test_ui_transition_alpha_clamps_the_timeline_fraction(timeline_ms: float, expected: float) -> None:
    assert ui_transition_alpha(timeline_ms, state=GameStateId.MAIN_MENU) == pytest.approx(expected)
