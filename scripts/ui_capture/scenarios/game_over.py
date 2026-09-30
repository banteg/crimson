from common import *

STEPS = [*start("survival"), ("wait", 120), kill_player(), *burst("death", 240, 8), ("wait", 60), ("shot", "over_settled"),
         ("text", "tester"), ("wait", 10), ("shot", "over_typed"), ("key", "KEY_ENTER"), *burst("over_submit", 120, 8),
         ("wait", 60), ("shot", "over_after_submit"),
         ("move", game_over_at(359.0, 197.0)), ("wait", 40), ("shot", "over_hit_tooltip"),
         ("move", game_over_at(368.0, 149.0)), ("wait", 40), ("shot", "over_time_tooltip"), ("move", *IDLE), ("wait", 40),
         ("move", game_over_at(339.0, 300.0)), ("wait", 20), ("shot", "over_hiscores_hover"), ("move", *IDLE), ("wait", 20),
         ("click", game_over_at(339.0, 300.0)), *burst("hiscores_in", 120, 8), ("move", *IDLE), ("wait", 60),
         ("shot", "hiscores_in_settled"), ("move", 200, 304), ("wait", 40), ("shot", "hiscore_row_hover")]
