# `unlocked_weapons_database_update`

Native target: `crimsonland.exe` at `0x00440110` (2,085 bytes).

Live Binary Ninja evidence recovers the complete unlocked-weapons database
callback:

- derives the list panel from UI element 09, draws the centered title and
  separator, and counts unlocked weapon ids 1 through 63;
- handles Up/Down focus movement, clamps the two focus regions, builds the
  frame-local list of unlocked weapon-name pointers, and feeds ten visible rows
  to the function-local scrollbar;
- maps the scrollbar's compact hovered row back to the real weapon id;
- lazily constructs the scrollbar and Back button under the native two-bit
  guard, with both native `atexit` destructor thunks identified separately;
- returns to Statistics through the Back button or Escape; and
- renders the selected weapon's native id, name, icon, fire rate (including
  the ammo-class-1 `n/a` case), reload time, and clip size, including the
  narrow-screen horizontal adjustment.

The natural `msvc6.5 /O2 /GB` reconstruction matches 78.59% of 523 target
instructions with 528 candidate instructions and `132/0/5` audited references.
All object, guard, function, string, and gameplay-data references resolve. The
five residual reference mismatches are constant-pool alignments caused by the
remaining vector-temporary/x87 schedule difference; the corresponding native
constants and source operations are present elsewhere in the aligned flow. The
native frame is `0x118` bytes versus `0x124` for the current candidate.
`msvc6.5pp` falls to 74.43%; `msvc6.6` produces the same result as `msvc6.5`.

This remains an honest work in progress: no register hints, dead expressions,
fake aliases, or unreachable shaping are used.
