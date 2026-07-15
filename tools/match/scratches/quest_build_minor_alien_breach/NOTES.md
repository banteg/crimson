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
two extra instructions. The shared opening `entry_count = 2` also explains why
native reuses the same register for both initial counts and seeds `wave` from
it.

The candidate has the exact 135-instruction length and all seven audited
references, scoring 91.85%. Every instruction after the two opening entries
matches. Their remaining 11 mismatches are unconstrained VC6 scheduling of
four identical vector constants, callee-save pushes, and independent metadata
stores; direct fields and an inlined setter produce the same opening body.
