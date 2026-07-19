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

The natural `msvc6.5 /O2 /GB` reconstruction matches 72.73% of 511 target
instructions with 512 candidate instructions and `118/0/5` audited references.
All object, guard, function, string, and gameplay-data references resolve. The
five residual reference mismatches are constant-pool alignments caused by the
remaining vector-temporary/x87 schedule difference; the corresponding native
constants and source operations are present elsewhere in the aligned flow. The
native frame is `0x218` bytes versus `0x224` for the current candidate.
`msvc6.5pp` falls to 69.93%; `msvc6.6` produces the same result as `msvc6.5`.

This remains an honest work in progress: no register hints, dead expressions,
fake aliases, or unreachable shaping are used.
