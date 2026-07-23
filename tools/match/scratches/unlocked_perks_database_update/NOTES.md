# `unlocked_perks_database_update`

Native target: `crimsonland.exe` at `0x00440960` (2,064 bytes).

Live Binary Ninja evidence recovers the complete unlocked-perks database
callback:

- derives the list panel from UI element 09, draws the centered title and
  separator, and counts the byte-sized availability flags for perk ids 1
  through 127;
- handles Up/Down focus movement, clamps the two focus regions, builds the
  frame-local list of available perk-name pointers, and feeds ten visible rows
  to the function-local scrollbar;
- maps the scrollbar's compact hovered row back to the real perk id;
- lazily constructs the scrollbar and Back button under the native two-bit
  guard, with both native `atexit` destructor thunks identified separately;
- returns to Statistics through the Back button, focused Enter, or Escape; and
- renders the selected perk's native id, centered name and separator, optional
  prerequisite name, and wrapped description, including the narrow-screen
  horizontal adjustment.

The natural `msvc6.5 /O2 /GB` reconstruction matches 85.18% of 511 target
instructions with 508 candidate instructions and `135/0/2` audited references.
All object, guard, function, string, and gameplay-data references resolve. The
two residual reference mismatches are constant-pool alignments caused by the
remaining vector-temporary/x87 schedule difference; the corresponding native
constants and source operations are present elsewhere in the aligned flow. The
native frame is `0x218` bytes versus `0x21c` for the current candidate.

The improved source shape keeps the title and panel-vector lifetimes distinct,
preserves the native `20 + 8` and `16 + 4` vertical spacings, and uses the
native compact-row post-increment test. Selected-perk rendering also performs
the native direct metadata reads instead of decompiler-style cached name and
prerequisite locals; that recovery accounts for most of the control-flow and
register-allocation gain.

This remains an honest work in progress: no register hints, dead expressions,
fake aliases, or unreachable shaping are used.
