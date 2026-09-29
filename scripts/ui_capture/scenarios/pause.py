from common import *

s = [*start("survival"), ("shot", "hud"), ("key", "KEY_ESCAPE"), *burst("pause_in", 60, 3), ("wait", 30), ("shot", "pause_settled")]
for name, pos in PAUSE.items():
    s += hover(f"pause_{name}", pos)
s += [("key", "KEY_ESCAPE"), *burst("pause_out", 60, 3)]
s += [("wait", 30), ("key", "KEY_ESCAPE"), ("wait", 60), *nav("pause_options_in", PAUSE["options"])]
STEPS = s
