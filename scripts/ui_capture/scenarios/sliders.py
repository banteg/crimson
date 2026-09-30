from common import *

# The options sliders at 1024x768 start at x=326: Sound at y=306, Music at 326, Graphics detail at 346 (8px segments,
# hot 3px either side and from a pixel above, 18px tall). A click's y sits mid-row.
X, SFX, MUSIC, DETAIL = 326, 312, 332, 352

s = [*boot(), *nav("options_in", MAIN["options"])]
s += [("click", X + 59, SFX), ("wait", 5), ("shot", "sfx_click_seg_7")]
s += [("click", X + 3, SFX), ("wait", 5), ("shot", "sfx_click_seg_0")]
# Drag right along Sound, off below it, back on, then past its right end.
s += [("move", X + 4, SFX), ("fire", 70), ("wait", 3), ("shot", "sfx_drag_start")]
for name, x, y in (("20", X + 20, SFX), ("44", X + 44, SFX), ("below", X + 74, 400), ("back", X + 64, SFX), ("past_end", X + 104, SFX)):
    s += [("move", x, y), ("wait", 5), ("shot", f"sfx_drag_{name}")]
s += [("wait", 70), ("move", *IDLE), ("wait", 5), ("shot", "sfx_drag_released")]
s += [("click", X + 14, MUSIC), ("wait", 5), ("shot", "music_click_seg_1")]
s += [("click", X + 11, DETAIL), ("wait", 5), ("move", *IDLE), ("wait", 5), ("shot", "detail_click_seg_1")]
# Hovering focuses a slider; the arrow keys then step it.
s += [("move", X + 40, SFX), ("wait", 2), ("key", "KEY_RIGHT"), ("wait", 5), ("shot", "sfx_key_right")]
s += [("key", "KEY_LEFT"), ("wait", 2), ("key", "KEY_LEFT"), ("wait", 5), ("shot", "sfx_key_left_twice")]
s += nav("options_out", OPTIONS["back"])
STEPS = s
