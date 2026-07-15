# `ui_draw_clock_gauge`

Native target: `crimsonland.exe` at `0x004061e0` (362 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 99/99
normalized instructions, full prefix, and masked references `17/0/0`.

Live Binary Ninja shows two ordinary batched quads. The first draws the clock
table at the supplied integer position and alpha. The second switches to the
pointer texture and rotates it by six degrees for each whole elapsed second.
Both quads are 32 by 32 pixels and share the converted position values.

No inline assembly, volatile state, dummy references, or dead expressions are
used.
