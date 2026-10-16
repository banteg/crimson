# `quest_build_evil_zombies_at_large`

Native target: `crimsonland.exe` at `0x004374a0` (244 bytes).

Live Binary Ninja evidence recovers ten waves of four template `0x41` zombie
spawns, starting at 1500 ms and advancing by 5500 ms. Each wave enters from
the right, left, bottom, and top edge midpoints. The per-entry count starts at
four and advances through thirteen, producing 40 entries in total.

The exact source shape keeps the entry cursor and emitted count together in a
small builder and tests `spawn_count - 4 < 10`. That expression explains the
native shifted induction test (`lea eax, [esi-4]` followed by `cmp eax, 10`),
while direct integer-to-float coordinate assignments reproduce the x87 store
schedule. The VC6 candidate matches all 81 instructions exactly.

The builder cursor now uses the canonical `quest_spawn_entry_t` and its flat
`pos_x`/`pos_y` fields directly. Removing the private layout duplicate is
byte-neutral: the exact 81-instruction body and reference audit are unchanged.

Binary Ninja strength-reduces the exact four-entry loop to a pointer advanced
by `0x60` before the stores, leaving nineteen negative offsets in HLIL. An
honest one-past `quest_spawn_entry_t[4]` presentation type was tested live:
it preserved the stride but did not normalize those stores and produced a
misleading huge array index for the final count. The annotation was reverted;
the canonical entry pointer plus raw negative induction offsets is the more
truthful decompilation.

## 1.9.8 (2026-10-16)

Guard: 1.9.8 fills each record through a cursor record pointer. Under both C2 builds, filling a record through a local record pointer lets the integer metadata stores schedule ahead of the float conversions, while repeated index or cursor expressions keep them in source order. The 1.9.8 native has the free schedule and 1.9.93 the strict one, so the guard records a spelling difference between the two releases.
