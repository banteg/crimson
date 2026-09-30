from common import *

from crimson.screens.actions import Route

STEPS = [*start("survival"), ("wait", 240), ("key", "KEY_ESCAPE"), ("wait", 60), ("shot", "pause_settled"),
         go(Route.MENU), *burst("pause_quit", 60, 3), ("wait", 60), ("shot", "menu_settled")]
