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

The natural `msvc6.5 /O2 /GB` reconstruction matches 85.74% of 523 target
instructions with 522 candidate instructions, a nine-instruction exact prefix,
the exact native `0x118`-byte frame, and `143/0/2` audited references. All
object, guard, function, string, and gameplay-data references resolve. The two
residual reference mismatches are constant-pool alignments caused by the
remaining vector-temporary/x87 schedule difference; the corresponding native
constants and source operations are present elsewhere in the aligned flow.

The frame and control-flow improvement comes from source-supported structure:
the title separator and three panel anchors have their native disjoint
lifetimes, the native `20 + 10`, `20 + 8`, and `16 + 4` vertical spacings remain
separate operations, the compact-to-real-id mapping uses its native
post-increment test, and the fire-rate branches place the RPM path before the
ammo-class-1 `n/a` path.

This remains an honest work in progress: no register hints, dead expressions,
fake aliases, or unreachable shaping are used.
