from __future__ import annotations

from ..game_states import GameStateId

_HALF_PI = 1.5707964  # native 1.57079637f


def ui_element_timeline_window(index: int) -> tuple[int, int]:
    """`ui_menu_layout_init`: `ui_element_table[index]` is hidden until `timeline_start_ms`
    and fully in at `timeline_end_ms` (`ui_element_init_defaults` sets 0..300)."""
    match index:
        case 1 | 2 | 3 | 4 | 5 | 6 | 7:
            return index * 100, index * 100 + 300
        case 23 | 24 | 25:
            return (index - 22) * 100, (index - 22) * 100 + 300
        case 27 | 30 | 35:
            return 100, 400
        case 28:
            return 0, 500
        case _:
            return 0, 300


def ui_element_direction_flag(index: int) -> bool:
    """`ui_menu_layout_init` flips the right-hand panels (slots 33 and 40): they slide in from the right and mirror."""
    return index in (33, 40)


def ui_element_anim(timeline_ms: float, *, index: int, width: float) -> tuple[float, float]:
    """`ui_element_update`: rotation angle and slide-in offset of `ui_element_table[index]`.

    Elements slide in from the left, flipped ones from the right; the sign (index 0) turns the other way.
    """
    start_ms, end_ms = ui_element_timeline_window(index)
    side = 1.0 if ui_element_direction_flag(index) else -1.0
    if timeline_ms >= end_ms:
        angle = 0.0
        offset_x = 0.0
    elif timeline_ms >= start_ms:
        duration = float(end_ms - start_ms)
        angle = _HALF_PI - (timeline_ms - start_ms) * _HALF_PI / duration
        offset_x = side * (1.0 - (timeline_ms - start_ms) / duration) * abs(width)
    else:
        angle = _HALF_PI
        offset_x = side * abs(width)
    if index == 0:
        angle = -abs(angle)
    return angle, offset_x


def game_state_elements(
    state: GameStateId, *, mods_available: bool = False, other_games: bool = False,
) -> tuple[int, ...]:
    """`game_state_set`: the `ui_element_table` entries each screen turns on."""
    match state:
        case GameStateId.MAIN_MENU:
            return (0, *((2,) if mods_available else ()), 3, 4, 5, 6, *((7,) if other_games else ()))
        case GameStateId.GAMEPLAY | GameStateId.TYPO_GAMEPLAY:
            return (28,)
        case GameStateId.PLAY_GAME_MENU:
            return (0, 11, 12)
        case GameStateId.OPTIONS_MENU:
            return (0, 31, 32)
        case GameStateId.STATISTICS_MENU:
            return (0, 39)
        case GameStateId.CONTROLS_MENU:
            return (0, 14, 18, 40)
        case GameStateId.HIGHSCORES | GameStateId.WEAPON_DATABASE | GameStateId.PERK_DATABASE:
            return (0, 9, 33)
        case (
            GameStateId.HIGHSCORE_LEGACY
            | GameStateId.MENU_LEGACY_VARIANT
            | GameStateId.CREDITS_SECRET
            | GameStateId.MODS_MENU
            | GameStateId.CREDITS
        ):
            return (0, 9)
        case GameStateId.QUEST_SELECT:
            return (0, 37)
        case GameStateId.PAUSE_MENU:
            return (0, 23, 24, 25)
        case GameStateId.PERK_SELECTION:
            return (27,)
        case GameStateId.QUEST_RESULTS | GameStateId.FINAL_QUEST_END_NOTE | GameStateId.QUEST_FAILED:
            return (35,)
        case GameStateId.GAME_OVER:
            return (30,)
        case _:
            return ()


def ui_elements_max_timeline(state: GameStateId, *, mods_available: bool = False, other_games: bool = False) -> int:
    """`ui_elements_max_timeline`: the latest `timeline_end_ms` among the screen's active elements."""
    elements = game_state_elements(state, mods_available=mods_available, other_games=other_games)
    return max((ui_element_timeline_window(index)[1] for index in elements), default=0)


def ui_transition_alpha(
    timeline_ms: float, *, state: GameStateId, pending: GameStateId | None = None, latch: bool = False,
) -> float:
    """`gameplay_render_world`: `ui_transition_alpha`, which fades the world's creatures, players, projectiles and bonuses.

    It is the timeline over `ui_element_table[28]`'s span, held at 1 while a transition keeps a run on screen unless
    `gameplay_transition_latch` (`latch`) is fading a fresh run in. `pending` is `game_state_pending`, None while idle,
    which is also when `ui_transition_direction` runs the timeline forward.
    """
    start_ms, end_ms = ui_element_timeline_window(28)
    alpha = float(timeline_ms) / float(end_ms - start_ms)
    if not latch and (
        state in (GameStateId.GAMEPLAY, GameStateId.PERK_SELECTION)
        or (state in (GameStateId.QUEST_RESULTS, GameStateId.QUEST_FAILED, GameStateId.GAME_OVER) and pending is None)
        or pending
        in (
            GameStateId.GAMEPLAY,
            GameStateId.PERK_SELECTION,
            GameStateId.PAUSE_MENU,
            GameStateId.OPTIONS_MENU,
            GameStateId.CONTROLS_MENU,
        )
        or (state == GameStateId.PAUSE_MENU and pending != GameStateId.MAIN_MENU)
        or state in (GameStateId.OPTIONS_MENU, GameStateId.CONTROLS_MENU)
        or pending
        in (
            GameStateId.FINAL_QUEST_END_NOTE,
            GameStateId.GAME_OVER,
            GameStateId.QUEST_RESULTS,
            GameStateId.QUEST_FAILED,
        )
    ):
        alpha = 1.0
    return min(1.0, max(0.0, alpha))
