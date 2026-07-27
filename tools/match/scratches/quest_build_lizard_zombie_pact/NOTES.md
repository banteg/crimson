# `quest_build_lizard_zombie_pact`

Native target: `crimsonland.exe` at `0x00438700` (311 bytes).

Live Binary Ninja evidence recovers sixteen paired template `0x41` zombie
waves from the right and left edge midpoints. Triggers begin at 1500 ms,
advance by 7000 ms, and stop before 113500 ms; each edge entry has count six.
On waves 0, 5, 10, and 15, the quest also adds two template `0x0c` alien
spawners at x 356. Their y coordinates are `wave / 5 * 180 + 256` and
`wave / 5 * 180 + 384`, with counts `wave / 5 + 1` and `wave / 5 + 2`.
The final count is 40.

The candidate preserves the native pointer-plus-count builder, signed width
halving, x87 integer-to-float conversions, 24-byte entry stride, signed
division for the five-wave predicate, separately lowered quotient for the
spawner group, loop arithmetic, and output count. It compiles to the same 95
instructions and resolves all three constant references.

The residual is a VC6 register-allocation cycle: native keeps the entry base in
EBP, wave in EDI, and trigger in EBX, while the candidate assigns those values
to EBX, EBP, and EDI. Independent metadata stores are consequently scheduled
around the x87 conversions differently. Pointer aliases, declaration and loop
forms, explicit quotient/remainder locals, direct y expressions, vector
setters, reversed builder fields, raw pointer/count storage, `msvc6.5pp`,
`msvc6.6`, `msvc7.0`, and `/G6` were checked. The exact-length default-profile
candidate remains an honest WIP without volatile state, dummy dependencies, or
forced-register constructs.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all masked references resolved; its
localized residual is compiler scheduling/allocation only. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.

## 2026-07-27 focused profile and mutation pass

MSVC 6.0, 6.5, and 6.6 tied at 56.84210526315789%; both the 6.5 Processor
Pack and MSVC 7.0 regressed to 43.24%. `/GB`, `/G5`, `/G7`, `/Ox`, and
`/Ob1` tied, while `/G6` regressed.

`local-declaration-order-mutations.json` (SHA-256
`7bcdd17056bc032b017c333b71f20bc1ebf1ad6f3dda5b97206675cbbbf5db79`)
recorded five complete variants. Three local-order spellings produced the
same winning bytes; the retained wave-trigger-builder order is the smallest
source-only representation of the native wave and trigger lifetimes. No
behavior, entry layout, or arithmetic changed.

Fresh scratch recomputation improved 176.77894736842106/311 to
180.05263157894737/311 weighted bytes: 56.84210526315789% to
57.89473684210527%, with the gap falling from 134.22105263157894 to
130.94736842105263. The validated result remains exactly 95/95 instructions,
prefix two, and references 3/0/0.
