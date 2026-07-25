# `fx_queue_global_init`

Native target: `crimsonland.exe` at `0x0041e1b0` (147 bytes).

The CRT initializer constructs all 128 entries of the 0x28-byte FX queue. Live
Binary Ninja evidence shows loop-invariant `(0,0)` position and opaque-white
color value objects, with effect id, rotation, height, and width reset to zero
for every entry.

MSVC 6.5 reproduces the native position-based induction cursor when those
members are initialized in declaration order: effect id, rotation, position,
height, width, then color. That ordinary constructor order matches all 42
instructions and the queue reference at `0x004912b8`.

The recovered source uses ordinary C++ value construction and assignment. No
dummy references, inline assembly, volatile ordering constraints, or dead
expressions are used.

The loop now walks the canonical `fx_queue_entry_t` array and uses its named
position, extent, and color members. Only the two small C++ value views remain
to reproduce the original aggregate assignments. The 42/42 instruction and
single-reference exact match is unchanged.
