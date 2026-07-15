# `ui_element_update`

Native target: `crimsonland.exe` at `0x00446900` (831 bytes).

Live Binary Ninja evidence recovers the element hover/focus state machine,
activation gate, hover interpolation, transition offsets, and rotation matrix.

Exact verified match: 100.00%, with 226/226 normalized instructions and
masked references `29/0/0`, using Microsoft Visual C++ 6.5 with
`/O2 /GB /W3 /GR-`.

## Recovered source shape

- Inactive or focus-disabled elements return immediately. Hover uses strict
  interior bounds and is suppressed by the mouse and focus-input locks.
- A hovered, enabled callback element becomes the focus pointer. Its focus
  index counts only enabled elements that are eligible in the current game
  state; disabled and callback-less main-menu entries are skipped.
- The ready timer advances every update. Hover interpolation rises by six
  frame milliseconds or falls by two, clamps to `[0, 1000]`, and gates the
  primary-click callback after 255 milliseconds.
- Completed transitions play the panel sound once, enable the element, and
  clear its render offset. Active transitions use a quarter-turn angle and
  slide by the absolute vertex width, with the element direction selecting
  the sign.
- The first table element negates the transition angle. Elements are disabled
  before their timeline end, then receive the native `{cos, -sin, sin, cos}`
  rotation matrix.

The exact match also resolves a decompiler ambiguity in the focus scan: the
global focus index increments inside the eligibility predicate, not once per
raw table slot.
