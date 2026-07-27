# `quest_build_nesting_grounds`

Native target: `crimsonland.exe` at `0x004364a0` (626 bytes).

Live Binary Ninja evidence recovers twelve fixed quest entries. Entries 0, 4,
5, 10, and 11 repeatedly recompute the same dynamic position from signed
integer `terrain_texture_width / 2` and `terrain_texture_height + 64`; the
remaining entries form a fixed nest pattern around the map. Heading is left
untouched. The entries are:

- template `0x1d`, trigger 1500, count `player_count * 2 + 6`;
- template `0x09` at (256, 256), trigger 8000, count 1;
- template `0x09` at (512, 512), trigger 13000, count 1;
- template `0x09` at (768, 768), trigger 18000, count 1;
- template `0x1d`, trigger 25000, count `player_count * 2 + 6`;
- template `0x1d`, trigger 39000, count `player_count * 3 + 3`;
- template `0x09` at (384, 512), trigger 41100, count 1;
- template `0x09` at (640, 512), trigger 42100, count 1;
- template `0x09` at (512, 640), trigger 43100, count 1;
- template `0x08` at (512, 512), trigger 44100, count 1;
- template `0x1e`, trigger 50000, count `player_count * 2 + 5`;
- template `0x1f`, trigger 55000, count `player_count * 2 + 2`.

The recovered two-field spawn metadata setter is the same source idiom that
matches `quest_build_two_fronts` and `quest_build_zombie_masters` exactly.
Using it consistently first raised the honest match from 94.93% to 97.10%.
A recorded lifetime sweep then found that naming the position pointer for entry
six preserves the source's typed aggregate boundary and delays its fixed stores
to the native schedule. That minimal retained form raises the match again to
98.55% while preserving the exact 138-instruction body and all fifteen audited
references. In particular, it eliminates both late metadata interleavings from
the x87 position conversions rather than constraining those stores artificially.
The typed pointer removes the third scheduling cluster without a barrier,
volatile access, or artificial dependency.

Two independent scheduling clusters remain: the template-register load and
`edi` save are swapped, and VC6 hoists the shared `768.0f` load across one
metadata setter. The values, addresses, conversions, and final count are
otherwise exact.
Attempts to model the positions as vector temporaries introduce 42 extra
instructions; fixed-position setters retain the same score while regressing
other scheduling. The direct position fields plus shared metadata setter are
therefore the strongest plausible source shape without artificial dependencies
or register forcing.

## Recorded mutation evidence

`scheduling-boundary-mutations.json` evaluates every one- and two-site
combination across five entry-three and five entry-six lifetime forms: 35
variants total. The minimal `quest_vec2_t *` for entry six improves the fuzzy
weight by 9.07 bytes and is retained; the entry-three pointer alone helped the
old baseline by 4.54 bytes but was subsumed by the stronger entry-six shape.
The plan SHA-256 is
`110552e57c2a5a750689f33613709f511e99e6d094633616fbd9bca7e2922621`.

Two follow-up matrices use the improved 98.55% baseline.
`entry-three-refinement-mutations.json` records eight pointer, scalar,
chained-assignment, and member-order forms; all are neutral or worse.
`prologue-register-lifetime-mutations.json` records six shared-template,
singleton-count, and first-position lifetime forms; all are byte-neutral.
Their SHA-256 values are
`b519e29a17081168087280e0a116d6b70ce6b0a9e2bc09da16f6a9e015480fc4`
and
`2002ffa7ab7dd3cb07d707c36f9269d23a4c46476bd76cc87929ab580e2bfb9f`.
