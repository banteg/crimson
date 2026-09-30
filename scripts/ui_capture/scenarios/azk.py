from common import *

from crimson.screens.actions import Route


def unlock_secret(gs):
    gs.screens.active._secret_unlock = True


STEPS = [*boot(), *nav("stats_in", MAIN["stats"]), *nav("credits_in", STATS["credits"]), ("hook", unlock_secret),
         ("wait", 10), ("shot", "credits_secret"), *go_nav("azk_in", Route.ALIEN_ZOOKEEPER, 60, 3),
         *key_nav("azk_out", "KEY_ESCAPE", 60, 3)]
