# ui_focus_update

Native target: `crimsonland.exe` at `0x0043d830` (268 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 78/78
normalized instructions, full prefix, and masked references `27/0/0`.

## Recovered source shape

- The function reports whether the supplied widget id was focused in the
  previous candidate list, then builds the current frame's list.
- Once per frame it decreases the one-second focus marker timer, processes Tab,
  and reverses direction when either Shift key is held.
- Focus wraps across the prior frame's candidate count.
- Repeated calls in the same frame append candidates, clamping the write slot
  to 31 while still publishing a count of 32.
- The native callers only consume the low byte, matching the recovered
  `unsigned char` result.

No inline assembly, volatile state, dummy dependencies, or layout-only control
flow is used.
