---
tags:
  - rewrite
  - parity
---

# Typ-o input rendering

The native reference is `typo_gameplay_update_and_render` (`0x004457c0`), recovered
in `tools/match/scratches/typo_gameplay_update_and_render/scratch.cpp`.
Python draws it through `src/crimson/ui/overlays/typo_run.py`.

| Element | Native geometry and content |
| --- | --- |
| Panel | `ui_hudPanel`, 182 × 53, alpha 0.7, at `(-1, screen_height - 144)` |
| Input | Small font at `(6, screen_height - 127)`, prompt `>` immediately followed by input, with no extra space |
| Caret | `_` at `(measure(input) + 14, screen_height - 127)` |
| Caret alpha | 0.4 when `sin(game_time_s * 4) > 0`, otherwise 1.0 |

Caret X is an absolute coordinate; do not add the input origin or prompt width
again. The native strings are `console_caret_string` at `0x004712b8` and
`console_prompt_format` (`>%s`) at `0x004712bc`, recorded in the data map.
The port uses presentation time for the pulse; it does not advance simulation RNG.
