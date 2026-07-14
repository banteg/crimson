# High-score card dividers

Native targets: `crimsonland.exe` at `0x4411c0` and `0x441220`.

Both helpers select the shared RGBA color beginning at `0x4ccca8`, shift the
caller-owned X coordinate left by 16 pixels, draw an outlined rectangle, and
restore X. The horizontal divider is `192 x 1` and advances Y by 4; the
vertical divider is `1 x 48` and leaves Y unchanged.

Natural C++ matches the horizontal target at 23/23 instructions with 6
references and the vertical target at 20/20 with 5 references.
