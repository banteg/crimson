# `quest_build_the_gang_wars`

Native target: `crimsonland.exe` at `0x00435120` (424 bytes).

Live Binary Ninja evidence recovers 24 entries. Two opening template-`0x12`
ring formations spawn at x `-150` and `1174`, y
`float(terrain_texture_height) * 0.5`, triggers 100 and 2500, and count 1.
Ten more right-side rings start at trigger 5500, advance by 4000, and use
count 2. Entry 12 is a template-`0x13` chain at the native fixed coordinate
`(512, 1152)`, trigger 50500, count 1. Ten left-side rings run from trigger
59500 through 95500 with the same 4000 step and count 2. Entry 23 is another
fixed `(512, 1152)` chain at trigger 107500, count 3.

The evidence also corrected two port assumptions. The chain coordinates are
not derived from the arena size, and the side-wave y value preserves a
fractional half-height rather than using integer floor division. Python and
Zig now share an explicitly exact-position append path for this proven
exception to the usual native quest-coordinate truncation.

The candidate reproduces the exact 92-instruction body and all seven audited
references, scoring 86.96%. An integer spawn index is strength-reduced into the
same native pointer anchors and improves substantially over an explicit cursor
(70.65%). Direct metadata stores regress to 83.70% and lose a reference; the
inlined setter remains the stronger source shape. Residuals are instruction
scheduling around constant loads, independent metadata stores, and epilogue
pops. VC6.5pp and VC6.6 produce the same result as the default profile, so no
override is justified.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all masked references resolved; its
localized residual is compiler scheduling/allocation only. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.
