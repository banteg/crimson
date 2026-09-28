from common import *

STEPS = [*start("survival"), ("wait", 120), kill_player(), *burst("death", 240, 8), ("wait", 60), ("shot", "over_settled"),
         ("text", "tester"), ("wait", 10), ("shot", "over_typed"), ("key", "KEY_ENTER"), *burst("over_submit", 120, 8),
         ("wait", 60), ("shot", "over_after_submit"),
         ("move", 335, 316), ("wait", 40), ("shot", "over_hit_tooltip"),
         ("move", 344, 268), ("wait", 40), ("shot", "over_time_tooltip"), ("move", *IDLE), ("wait", 40),
         *hover("over_hiscores", (315, 419)), *nav("hiscores_in", (315, 419), 120, 8),
         ("move", 200, 304), ("wait", 40), ("shot", "hiscore_row_hover")]
