from common import *

from crimson.game_modes import GameMode
from crimson.quests.level import QuestLevel

# Unlocked, so the high score game mode list carries Typ'o'Shooter.
STATUS = unlock_all
# List headers at 1024x768 and a row inside each open list.
PLAY_PLAYERS = ((238, 270), (248, 307))
CONTROLS_LISTS = {
    "controls_move": ((70, 353), (80, 390)),
    "controls_aim": ((70, 311), (80, 364)),
    "controls_player": ((196, 265), (206, 334)),
}
HISCORES_LISTS = {
    "hiscores_players": ((676, 287), (686, 340)),
    "hiscores_mode": ((804, 287), (814, 324)),
    "hiscores_date": ((674, 329), (684, 398)),
    "hiscores_score_list": ((674, 373), (684, 394)),
}


def quest_mode(gs):
    gs.config.gameplay.mode = GameMode.QUESTS
    gs.config.gameplay.quest_level = QuestLevel(1, 1)


def list_steps(name, header, row):
    """Hover the closed header, open it, hover a row, then leave so it closes.

    The trailing click on empty space closes lists that stay open once the mouse leaves.
    """
    over = (header[0] + 5, header[1] + 5)
    return [
        ("move", *over), ("wait", 10), ("shot", f"{name}_header_hover"),
        ("click", *over), ("wait", 10), ("shot", f"{name}_open"),
        ("move", *row), ("wait", 10), ("shot", f"{name}_row_hover"),
        ("move", *IDLE), ("wait", 10), ("shot", f"{name}_left"),
        ("click", *IDLE), ("wait", 10),
    ]


s = [*boot(), ("hook", quest_mode), *nav("play_in", MAIN["play"]), *list_steps("play_players", *PLAY_PLAYERS)]
s += nav("play_out", PLAY["back"]) + nav("options_in", MAIN["options"]) + nav("controls_in", OPTIONS["controls"])
for name, (header, row) in CONTROLS_LISTS.items():
    s += list_steps(name, header, row)
s += nav("controls_out", BACKS["controls"]) + nav("options_out", OPTIONS["back"])
s += nav("stats_in", MAIN["stats"]) + nav("hiscores_in", STATS["hiscores"])
for name, (header, row) in HISCORES_LISTS.items():
    s += list_steps(name, header, row)
# `ui_profile_menu_update`: pick "<add new named list>" (row 1), name it, add it, then delete it again.
PROFILE_HEADER, PROFILE_ADD_ROW = (679, 378), (684, 409)
s += [
    ("click", *PROFILE_HEADER), ("wait", 10), ("click", *PROFILE_ADD_ROW), ("wait", 10), ("shot", "profile_add_mode"),
    ("text", "Bob"), ("wait", 10), ("shot", "profile_typed"),
    ("key", "KEY_ENTER"), ("move", *IDLE), ("wait", 10), ("shot", "profile_added"),
    ("click", 684, 400), ("wait", 10), ("shot", "profile_deleted"),
]
STEPS = s
