from common import *

s = [*start("survival"), ("wait", 60), grant_xp(2001), ("wait", 30), ("shot", "levelup_hud")]
s += [("move", 512, 200), ("rclick",), *burst("perk_in", 60, 6), ("wait", 30), ("shot", "perk_settled")]
for i, pos in enumerate(PERK_ROWS):
    s += hover(f"perk_row{i}", pos)
s += [("click", *PERK_ROWS[0]), *burst("perk_out", 60, 6)]
STEPS = s
