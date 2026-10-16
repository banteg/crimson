# `quest_build_the_killing`

Native target: `crimsonland.exe` at `0x004384a0` (602 bytes).

Live Binary Ninja evidence confirms the native RNG bug preserved by the ports.
Each of ten waves calls `crt_rand()` twice, but both return values are discarded:
the signed remainders are calculated from the wave counter itself. `wave % 3`
cycles templates `0x1a`, `0x1b`, and `0x1c`; `wave % 5` cycles the layout.

The four fixed layouts use the square terrain width for both axes and emit one
count-12 entry at the current trigger:

- right: `(terrain_texture_width + 64, terrain_texture_width / 2)`;
- left: `(-64, terrain_texture_width / 2)`;
- bottom: `(terrain_texture_width / 2, terrain_texture_width + 64)`;
- top: `(terrain_texture_width / 2, -64)`.

The fifth layout emits three template-`0x07` spawners with count three and
triggers at the current time, plus 1000, and plus 2000. Each coordinate draws y
first and then x as `crt_rand() % 768 + 128`, consuming six additional draws.
The builder produces fourteen entries total.

Native timing retains a revealing two-stage shape: every recognized layout
branch advances the trigger by 5000, then the common loop tail advances it by
another 1000. With waves zero through nine, the layout is always recognized,
so this is reachably equivalent to the ports' single 6000 increment. Keeping
the split explains the two distinct native shared tails without inventing a
dependency.

An explicit cursor/count builder recovers the native `esi`/`ebx` allocation.
Bottom and top must assign y before x; reversing them removes four native
conversion instructions through unwanted commoning. Logical count increments
precede cursor increments in source, while VC6 schedules the cursor early only
when the next random entry depends on it. The `while` spelling also preserves
the native wave-local versus conversion-scratch stack coloring; a `for` loop
swaps those slots.

The scalar declaration order is also observable. Declaring trigger time,
template id, and then wave before the cursor builder makes VC6 initialize the
two register-resident values before spilling wave zero, matching the native
prologue without an artificial dependency.

The candidate is exact: 173/173 instructions and 14/0/0 audited references.

The cursor/count builder now owns a canonical `quest_spawn_entry_t *` rather
than a private layout duplicate. Using the flat position fields preserves the
exact 173-instruction body and all 14 references.

## 1.9.8 (2026-10-16)

Guard on the five record sites: 1.9.8 fills each record through a cursor record pointer, which also removes two instructions (171 against 173). Under both C2 builds, filling a record through a local record pointer lets the integer metadata stores schedule ahead of the float conversions, while repeated index or cursor expressions keep them in source order. The 1.9.8 native has the free schedule and 1.9.93 the strict one, so the guard records a spelling difference between the two releases. Function-scope and per-branch declarations and early or late counting are equivalent.
