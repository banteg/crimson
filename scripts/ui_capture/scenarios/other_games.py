import os

from common import *

from crimson.screens.actions import Route

# `grim_get_config_var(100)` turns on the other-games entry.
os.environ["CRIMSON_GRIM_CONFIG_VAR_100"] = "1"


STEPS = [*boot(), go(Route.MENU), ("wait", 150), ("shot", "main_other"),
         # The main menu takes 700 ms to run out before the panel slides in.
         *go_nav("other_in", Route.OTHER_GAMES, 90), *key_nav("other_out")]
