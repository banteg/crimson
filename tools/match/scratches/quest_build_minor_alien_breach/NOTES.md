# `quest_build_minor_alien_breach`

Native target: `crimsonland.exe` at `0x00435cc0` (466 bytes).

Live Binary Ninja evidence recovers 37 entries. The opening two template-`0x26`
waves are fixed at `(256, 256)` and `(256, 128)`, triggers 1000 and 1700,
count 2. Waves 2 through 17 always add a right-edge entry at
`(terrain_texture_width + 64, terrain_texture_height / 2)`. Their trigger is
`(wave * 5 - 10) * 720` and count is 1. Waves above 6 add a second right-edge
entry 256 units above center. Wave 13 adds one template-`0x29` bonus at
`(terrain_texture_width / 2, terrain_texture_height + 64)`, trigger 39600.
Waves above 10 add a left-edge entry at x `-64`, 256 units below center.
These halves are signed integer division before float conversion, matching the
ports' deliberate coordinate truncation for this builder.

The decisive source clue is statement order in the mandatory wave entry. The
native body stores position and template before calculating the trigger; that
calculation reuses the template register and therefore emits a template reload
on the loop backedge. Expressing those fields directly reproduces the target's
two extra instructions. Starting the append count at zero and incrementing it
after the two opening entries lets VC6 derive the native wave seed of two while
retaining the same opening-count constants.

The recovered source matches all 466 native bytes and all 135 instructions,
including the full instruction prefix and all seven audited references. One
continuous append count now publishes the opening pair and every conditional
wave entry before supplying the output count.

## Recorded opening audit

Two complete mutation sweeps record 16 plausible opening shapes without
retaining a change. `opening-scheduling-mutations.json` covers template/count
locals, named and scoped position aggregates, direct field stores, and the
entry setter. `opening-lifetime-boundary-mutations.json` then covers split
initialization, a reused position local, const aggregates, and movement of the
second position across the first entry's metadata boundary. Fourteen variants
are byte-neutral. Moving the second position earlier loses 3.45 weighted bytes,
and direct field stores lose 24.04; neither improves any other metric.

A 25-profile matrix across MSVC 6.0, 6.5, 6.5pp, 6.6, and 7.0 with the
baseline, `/Ob1`, `/Ot`, `/G5`, and `/G6` flag shapes finds no improvement.
MSVC 6.0, 6.5, and 6.6 reproduce the current best under the neutral flag
variants; the preprocessor build, VC7, and `/G6` regress. Together with the
exact post-opening body, this bounds the remaining mismatch as compiler
scheduling rather than unrecovered quest policy.

## 2026-08-08 exact recovery

Replacing the opening `entry_count = 2` shortcut and fixed indices with an
append count starting at zero resolves the complete former opening residual.
The candidate improves from 428/466 fuzzy-weighted bytes (91.85%) and a
two-instruction prefix to exact 466/466 bytes, 135/135 instructions, and a
135-instruction prefix. References remain 7/0/0. The exact source SHA-256 is
`daf96e86d1dda7d7464cb2370fa5ec3a23628ce7c2ab55cd3a60a673b0432aa5`.
