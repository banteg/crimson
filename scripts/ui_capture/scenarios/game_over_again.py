from common import *

from crimson.screens.actions import ResultAction

STEPS = [*die_to_game_over(), game_over_go(ResultAction.PLAY_AGAIN), *burst("again", 60, 3), ("wait", 60),
         ("shot", "again_settled")]
