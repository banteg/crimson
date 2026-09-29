from common import *

from crimson.game_modes import GameMode
from crimson.quests.level import QuestLevel

STATUS = unlock_all
# Quest high scores (40+ unlocks) show the Hardcore checkbox; Left/Right page the quests.
HARDCORE = (272, 285)


def quest_mode(gs):
    gs.config.gameplay.mode = GameMode.QUESTS
    gs.config.gameplay.quest_level = QuestLevel(1, 1)


s = [*boot(), ("hook", quest_mode), *nav("stats_in", MAIN["stats"]), *nav("hiscores_in", STATS["hiscores"])]
s += [("key", "KEY_RIGHT"), ("wait", 10), ("shot", "hiscores_right"), ("key", "KEY_LEFT"), ("wait", 10), ("shot", "hiscores_left")]
s += hover("hiscores_hardcore", HARDCORE)
s += [("click", *HARDCORE), ("wait", 20), ("move", *IDLE), ("wait", 20), ("shot", "hiscores_hardcore_on")]
STEPS = s
