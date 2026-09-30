from common import *

STEPS = [*boot(), ("click", *MAIN["play"]), ("wait", 120), ("click", *PLAY["quests"]), ("wait", 120),
         ("click", *QUEST_1_1), ("wait", 240), kill_player(), *burst("quest_fail", 300, 10), ("wait", 120), ("shot", "failed_settled"),
         # Enter takes the focused Play Again.
         ("key", "KEY_ENTER"), *burst("retry", 60, 3), ("wait", 60), ("shot", "retry_settled")]
