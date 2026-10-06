from common import *

RANKED = (316, 300)
# With Ranked on, the menu lists Quests and Survival in the first two rows.
RANKED_ROWS = {"quests": (231, 317), "survival": (231, 349)}


def report(gs):
    print("ranked_run", gs.screens.active_gameplay.ranked_run)


STEPS = [*boot(), ("click", *MAIN["play"]), ("wait", 120), ("move", *IDLE), ("wait", 30), ("shot", "play_menu"),
         ("move", *RANKED), ("wait", 60), ("shot", "ranked_hover"),
         ("click", *RANKED), ("wait", 20), ("move", *IDLE), ("wait", 30), ("shot", "ranked_on"),
         ("click", *RANKED_ROWS["quests"]), ("wait", 120), ("move", *IDLE), ("wait", 30), ("shot", "ranked_quests"),
         ("click", *QUEST_1_1), ("wait", 150), ("hook", report), ("shot", "ranked_quest_run")]
