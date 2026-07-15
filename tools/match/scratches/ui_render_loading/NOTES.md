# `ui_render_loading`

Native target: `crimsonland.exe` at `0x00402d50` (375 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 107/107
normalized instructions, full prefix, and masked references `15/0/0`.

Live Binary Ninja shows a centered 220 by 60 loading panel: a half-alpha black
fill, a white outline, and a centered `Please wait...` label. The routine sets
the renderer alpha/config state before drawing and marks the loading frame as
presented afterward.

The panel position and color are ordinary constructed two- and four-float
values. Reusing the position through its inlined `set` method explains both the
native stack slot reuse and VC6 evaluation order.

No inline assembly, volatile state, dummy references, or dead expressions are
used.
