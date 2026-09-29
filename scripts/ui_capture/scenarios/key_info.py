from common import *

# F1 pauses gameplay and fades in the key info; F1 again fades it out.
s = [*start("survival"), ("wait", 60), ("key", "KEY_F1"), *burst("key_info_in", 36, 6), ("wait", 30), ("shot", "key_info_settled")]
s += [("key", "KEY_F1"), *burst("key_info_out", 30, 6)]
# Esc while paused still runs the timeline down to the pause menu.
s += [("key", "KEY_F1"), ("wait", 40), ("key", "KEY_ESCAPE"), *burst("key_info_escape", 60, 12)]
STEPS = s
