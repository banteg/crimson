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

The natural `msvc6.5 /O2 /GB` reconstruction now matches 90.89% of 511 target
instructions with 510 candidate instructions, a nine-instruction exact prefix,
the exact native `0x218`-byte frame, and `141/0/2` audited references. All
object, guard, function, string, and gameplay-data references resolve. The two
residual reference mismatches are constant-pool alignments caused by the
remaining vector-temporary/x87 schedule difference; the corresponding native
constants and source operations are present elsewhere in the aligned flow.

The improved source shape keeps both separator temporaries, the back-button
position, and the panel vectors in their native disjoint lexical lifetimes.
The button uses the copied x/y pair visible before the native call instead of
mutating the shared panel position. The scrollbar constructor initializes its
two active columns with a bounded loop; VC6 unrolls that loop to the native two
stores while recovering five additional aligned references. The source also
preserves the native `20 + 8` and `16 + 4` vertical spacings and compact-row
post-increment test. Selected-perk rendering performs the native direct
metadata reads instead of decompiler-style cached name and prerequisite
locals.

This remains an honest work in progress: no register hints, dead expressions,
fake aliases, or unreachable shaping are used.

## Reference residual re-audit

A fresh corpus audit keeps the candidate at 90.89%, 510/511 instructions, and
`141/0/2` references before and after classification. Both entries are aligned
mismatches; there are no unresolved references. They pair native reads of
`ui_element_slot_09.render_offset_x` (`0x00489de8`) with candidate constant-pool
adds from the differently scheduled opening and detail-panel vector
expressions. Live Binary Ninja confirms `0x00489de8` is `+0x08` inside the
mapped `0x318`-byte slot-09 element.

The UI field and both candidate constants occur in the recovered computation;
only their x87 ordering differs. No map or layout correction is supported, so
the residual is compiler scheduling only and `RESIDUAL=compiler` preserves the
two honest mismatches.

## Recorded lifetime and constructor recovery

Four bounded mutation families document the current source-shape recovery:

- `detail-separator-lifetime-mutations.json` found the scoped detail
  separator, adding 12.16 fuzzy-weighted bytes;
- `title-separator-lifetime-mutations.json` found the scoped title separator,
  adding 16.21 bytes, recovering the exact frame, and extending the exact
  prefix to nine instructions;
- `back-button-position-lifetime-mutations.json` found the scoped
  component-wise button-position copy visible in native, adding two
  instructions and 20.76 bytes without disturbing that prefix; and
- `scrollbar-zero-initializer-mutations.json` evaluated all eight ordinary
  initializer shapes. Its two-entry loop added 64.72 bytes and five resolved
  references while preserving the exact two-store behavior.

Together these retained changes move the fresh baseline from 85.38% to 90.89%,
from 508 to 510 candidate instructions, and from `135/0/2` to `141/0/2`
references. The complete append-only evidence is in `experiments.jsonl`
(`sha256:d8ce4688eb2bc431f351dcd26b71bd16d58ab691bce6d5befdc739e9f4a82990`).
