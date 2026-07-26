# grim_keyboard_key_down

Native target: `grim.dll` at `0x1000a370` (19 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 5/5
normalized instructions, full prefix, and masked references `1/0/0`.

## Recovered source shape

- The helper truncates every key code to its low byte before indexing the
  256-byte DirectInput keyboard-state array; larger values therefore alias.
- It loads the cached state byte, shifts that byte right by seven, and returns
  the resulting 0/1 byte. There is no bounds check or live device query.
- Keeping the loaded byte as a named local and applying `>>=` naturally
  recovers the native byte-width load, shift, and return without widening.

No inline assembly, volatile state, dummy reference, forced address, or
layout-only expression is used.
