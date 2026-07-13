# input_primary_just_pressed

Native target: `crimsonland.exe` at `0x00446030..0x004460ec` (188 bytes).
Binary Ninja presents cdecl `int32_t()`, but a C++ `bool` return is the natural
ABI spelling that reproduces the native byte result in `al`.

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 62/62
normalized instructions, full prefix, and masked references `14/0/0`.
The explicit end excludes the alignment gap before the next function.

## Recovered source shape

- An open console returns false without reading or changing the latch.
- With `input_primary_latch == 0`, the function polls mouse button 0 and a
  pointer loop over the `fire_key` field in exactly two 0x360-byte player
  records. Any held source sets the latch and returns true once.
- With the latch already set, it polls all three sources again and clears the
  latch only after a full release. That branch always returns false, so a
  second query while the same input remains held consumes no new edge.
- The scan starts at `0x00490bec`, advances by `0x360`, and stops before
  `0x004912ac`. There is no player-count read or bounds check. Byte casts on
  the key-active results preserve the native `test al, al` checks.
- Binary Ninja reports 24 callers across gameplay, player update, menus,
  controls, highscore, quest, credits, and demo paths.

## Port relationship

Python generalizes the source set to a clamped one-to-four player count and
uses `_PRESSED_STATE` with a sentinel key. Its per-frame cache returns the
same edge result to repeated queries in one frame; native's query-driven latch
returns true only to the first query and false to the second while held.
Those semantics are now documented rather than silently treated as identical.

No inline assembly, volatile state, fake extern, dummy reference, forced
address, or layout-only control flow is used.
