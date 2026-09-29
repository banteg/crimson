from common import *

# Keyboard and pad focus through the main menu, options and play game, the mouse parked throughout. A panel's
# slide-in only registers its back element, so each panel opens with the focus on Back.
DOWN, UP, LEFT = "GAMEPAD_BUTTON_LEFT_FACE_DOWN", "GAMEPAD_BUTTON_LEFT_FACE_UP", "GAMEPAD_BUTTON_LEFT_FACE_LEFT"
A, B = "GAMEPAD_BUTTON_RIGHT_FACE_DOWN", "GAMEPAD_BUTTON_RIGHT_FACE_RIGHT"


def key(name, shot):
    return [("key", name), ("wait", 2), ("shot", shot)]


def pad(button, shot):
    return [("pad", button), ("wait", 2), ("shot", shot)]


STEPS = [
    *boot(),
    ("shot", "main_idle"),
    # Tab lights Options while the focus timer runs, then it fades.
    *key("KEY_TAB", "main_tab_options"),
    ("wait", 30),
    ("shot", "main_tab_fading"),
    ("wait", 60),
    ("shot", "main_tab_faded"),
    ("key", "KEY_ENTER"),
    ("wait", 120),
    ("shot", "options_in"),
    # From Back, Tab and the pad walk the checkbox and the sliders; the pad's left steps a slider, A toggles.
    *key("KEY_TAB", "options_tab_checkbox"),
    *pad(DOWN, "options_pad_sfx"),
    *pad(LEFT, "options_pad_sfx_left"),
    ("hold", "KEY_LEFT_SHIFT", 3),
    *key("KEY_TAB", "options_shift_tab_checkbox"),
    *pad(A, "options_pad_checkbox_off"),
    ("pad", B),
    ("wait", 120),
    ("shot", "main_back"),
    *pad(DOWN, "main_pad_options"),
    *pad(UP, "main_pad_play"),
    ("pad", A),
    ("wait", 120),
    ("shot", "play_in"),
    # The D-pad walks the mode buttons down to the player-count list, which A opens and takes a row from.
    *pad(DOWN, "play_pad_tutorial"),
    *pad(DOWN, "play_pad_quests"),
    ("wait", 60),
    ("shot", "play_pad_quests_faded"),
    *pad(DOWN, "play_pad_rush"),
    *pad(DOWN, "play_pad_survival"),
    *pad(DOWN, "play_pad_players"),
    *pad(A, "play_pad_players_open"),
    *pad(DOWN, "play_pad_players_row"),
    *pad(A, "play_pad_players_taken"),
    ("pad", B),
    ("wait", 120),
    ("shot", "main_back_again"),
]
