from common import *

from crimson.screens.actions import ResultAction

STEPS = [*die_to_game_over(), game_over_go(ResultAction.MAIN_MENU), *burst("to_menu", 60, 3), ("wait", 60),
         ("shot", "to_menu_settled")]
