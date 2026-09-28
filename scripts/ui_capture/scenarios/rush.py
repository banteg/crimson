from common import *

STEPS = [*start("rush"), ("shot", "rush_hud"), ("wait", 300), ("shot", "rush_hud_5s"), doom_player(),
         *burst("rush_death", 240, 12), ("wait", 60), ("shot", "rush_over")]
