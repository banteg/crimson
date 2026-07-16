# `terrain_generate_random`

Native target: `crimsonland.exe` at `0x004181b0` (1,764 bytes).

Live Binary Ninja evidence identifies this as the random/default sibling of
`terrain_generate`. It consumes three initial CRT RNG draws while assigning a
three-entry global terrain selector array, then immediately fixes the selectors
to `{0, 1, 0}`. The third random result is never stored because no external
call can observe it before the fixed zero overwrites it; the first two stores
remain observable across the following `crt_rand` calls.

Unlock indices 40, 30, and 20 each gate a one-in-eight attempt to delegate to
`terrain_generate` with the corresponding quest terrain descriptor. The
default path bakes base, overlay, and base texture slots at densities 800, 35,
and 15, preserving the native rotation/Y/X RNG order and complete Grim2D render
state setup and restoration. Failed render-target creation returns directly.
Successful generation optionally logs under `cv_verbose`.

VC6 scalar-replaces the source's three-entry local texture-handle array into
two registers plus one spill. That ordinary array shape accounts for the
native 0x24-byte frame and the base/overlay/base bind sequence; together with
one reused patch-size local, it matches all 465 normalized instructions
exactly. The global selector references are independently named at
`0x0048f53c`, yielding references `110/0/0`.

The source uses ordinary arrays, global assignments, constructors, and
in-place vector scaling. It contains no inline assembly, volatile state, dummy
references, or dead expressions introduced for matching.
