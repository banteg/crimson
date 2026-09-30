from common import *

from crimson.screens.actions import ResultAction

STEPS = [*boot(), ("click", *MAIN["play"]), ("wait", 120), ("click", *PLAY["quests"]), ("wait", 120),
         ("click", *QUEST_1_1), ("wait", 240), finish_quest(), ("wait", 600), ("key", "KEY_ENTER"), ("wait", 120),
         ("shot", "results_buttons"), results_go(ResultAction.PLAY_NEXT), *burst("next", 60, 3), ("wait", 60),
         ("shot", "next_settled")]
