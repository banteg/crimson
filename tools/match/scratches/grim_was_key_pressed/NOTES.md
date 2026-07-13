# grim_was_key_pressed

Native target: `grim.dll` at `0x10007390` (119 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 31/31
normalized instructions, full prefix, and masked references `10/0/0`.

## Recovered source shape

- Live callers establish a virtual C++ member: `ECX` carries `this`, one key is
  pushed, the callee uses `retn 4`, and callers test the byte result in `AL`.
- The full key is passed to `grim_keyboard_key_down`; repeat timers and latches
  deliberately index only `(unsigned char)key`, matching the helper's low-byte
  aliasing.
- A newly pressed key loads the global 0.5-second delay. Once the first-press
  latch is clear, the delay is multiplied by `0.2f`, producing 0.1-second held
  repeats. The separate keyboard poll decrements and clamps these timers.
- Releasing a key clears its timer and restores its first-press latch. A held
  key whose timer remains positive returns false without changing state.

No inline assembly, volatile state, dummy reference, forced address, or
layout-only control flow is used.
