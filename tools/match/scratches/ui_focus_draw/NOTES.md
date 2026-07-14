# ui_focus_draw

Native target: `crimsonland.exe` at `0x0043d940` (104 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 24/24
normalized instructions, full prefix, and masked references `4/0/0`.

The focus marker is a 6-by-6 filled rectangle at `(x, y + 4)`, tinted
`(0.8, 0.8, 0.6, timer * 0.0008)`. Expressing the alpha scale as the plausible
source calculation `0.8f / 1000.0f` produces the native rounded constant; the
decimal literal lands one ULP lower under this compiler.

The position and color are ordinary constructed values. No inline assembly,
volatile state, dummy dependencies, or forced data addresses are used.
