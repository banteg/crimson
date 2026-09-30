from common import *

from crimson.screens.actions import ResultAction

STEPS = [*boot(), ("click", *MAIN["play"]), ("wait", 120), ("click", *PLAY["quests"]), ("wait", 120),
         ("click", *QUEST_1_1), ("wait", 240), finish_quest(), ("wait", 600), ("key", "KEY_ENTER"), ("wait", 120),
         results_go(ResultAction.HIGH_SCORES), *burst("scores", 60, 3), ("wait", 60), ("shot", "scores_settled"),
         ("key", "KEY_ESCAPE"), *burst("scores_out", 60, 3), ("wait", 60), ("shot", "scores_out_settled")]
