from common import *

s = [("move", *IDLE), *burst("main_in", 90, 6), ("wait", 30), ("shot", "main_settled")]
for name, pos in MAIN.items():
    s += hover(f"main_{name}", pos)
s += nav("play_in", MAIN["play"]) + hover("play_tutorial", PLAY["tutorial"]) + nav("play_out", PLAY["back"])
s += nav("options_in", MAIN["options"]) + hover("options_controls", OPTIONS["controls"])
s += nav("controls_in", OPTIONS["controls"]) + nav("controls_out", BACKS["controls"])
s += nav("options_out", OPTIONS["back"])
s += nav("stats_in", MAIN["stats"])
for sub in ("hiscores", "weapons", "perks", "credits"):
    s += nav(f"{sub}_in", STATS[sub]) + nav(f"{sub}_out", BACKS[sub])
s += nav("stats_out", STATS["back"])
s += nav("play2_in", MAIN["play"]) + nav("quests_in", PLAY["quests"]) + hover("quest_1_1", QUEST_1_1)
s += nav("quests_out", BACKS["quests"])
STEPS = s
