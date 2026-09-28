from common import *

STEPS = [*boot(), ("click", *MAIN["play"]), ("wait", 120), ("click", *PLAY["quests"]), ("wait", 120),
         ("click", *QUEST_1_1), *burst("quest_start", 180, 10), ("wait", 120), ("shot", "quest_hud"),
         finish_quest(), *burst("quest_done", 480, 12), ("wait", 120), ("shot", "results_settled"),
         ("key", "KEY_ENTER"), *burst("results_submit", 120, 8), ("wait", 60), ("shot", "results_after_submit")]
