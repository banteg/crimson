from common import *

from crimson.game_modes import GameMode
from crimson.quests.level import QuestLevel
from crimson.screens.actions import ResultAction, StartRun


def unlock_final(status):
    status.quest_unlock_index = 49
    status.quest_unlock_index_hardcore = 49


STATUS = unlock_final
STEPS = [*boot(), go(StartRun(GameMode.QUESTS, QuestLevel(5, 10))), ("wait", 240), finish_quest(), ("wait", 600),
         ("key", "KEY_ENTER"), ("wait", 120), ("shot", "results_buttons"), results_go(ResultAction.PLAY_NEXT),
         *burst("end_note_in", 90, 3), ("wait", 60), ("shot", "end_note_settled"),
         go(StartRun(GameMode.SURVIVAL)), *burst("end_note_out", 60, 3), ("wait", 60), ("shot", "survival_settled")]
