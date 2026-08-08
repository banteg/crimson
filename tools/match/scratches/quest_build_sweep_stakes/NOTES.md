# `quest_build_sweep_stakes`

Native target: `crimsonland.exe` at `0x00437810` (258 bytes).

Live Binary Ninja evidence recovers sixteen waves of four template `0x36`
orbiters. Each wave chooses one angle as `(crt_rand() % 612) * 0.01` and emits
radii 84, 126, 168, and 210 around `(512, 512)`. Heading is the angle from the
center minus half pi. Trigger time starts at 2000 ms; its step also starts at
2000 ms, contributes at least 600 ms, decreases by 80 after each wave, and
continues while the reduced step is greater than 720. The native writes the
constant final count 64.

The candidate reproduces the signed remainder, 24-byte frame, saved cosine and
live sine, two-stage rounded vector construction, `fxch`/`fpatan` heading,
nested loop boundaries, trigger clamp, and all seven references. A separate
integer append count selects each record while the radius remains the inner
loop control. VC6 strength-reduces that source into the native trigger-field
induction base, restoring the missing pointer advance. The candidate now has
the exact 76-instruction count, a 30-instruction prefix, and scores 92.11%.

The remaining localized delta is independent metadata-store placement around
the radius advance and x87 vector construction, plus the resulting branch
displacement. Natural source-order, helper, position-local, and increment-
placement variants did not improve it. This remains an honest WIP without
encoding artificial dependencies into the source.

## Recovery classification audit

Binary Ninja confirms the complete 16-wave policy, random angle, four radii,
heading, trigger clamp, entry metadata, and final count. The candidate emits
the native 76 instructions with `7/0/0` references. The localized regions
reflect only the independent-store/x87 schedule described above. Recovery is
classified `semantic-complete` with a `compiler` residual.

`typed-trigger-cursor-mutations.json` records all fifteen single and combined
typed-cursor choices. The complete combination falls to 59.46%, and none
improves the 75.50% baseline, confirming that the negative-field cursor would
trade away the proven vector/x87 structure.

## Exact-tail follow-up (2026-07-27)

The five-compiler and six-flag profile matrices keep the VC6 `/O2 /GB` family
best. `/G5`, `/G7`, `/Ox`, and `/Ob1` are code-identical here; `/G6` and VC7
regress. A recorded 47-variant source-order sweep found one independent gain:
declaring trigger time and trigger step before the entry cursor changes VC6's
allocation without changing the quest policy. The retained ordering raises
weighted bytes from `194.7814569536424` to `198.19867549668876`, reduces the
gap from `63.21854304635761` to `59.801324503311236`, and preserves the
75/76 instruction counts, six-instruction prefix, and `7/0/0` references.

A five-variant helper-store-order follow-up found no additional improvement.
The complete sweeps are recorded in `experiments.jsonl`; the remaining
localized delta is still the native trigger-field induction anchor and x87
scheduling described above.

## Append-count recovery (2026-08-08)

`append-count-recovery-mutations.json` records the atomic replacement of the
persistent output cursor with a base pointer plus integer append count. The
complete two-site variant raises weighted bytes from
`198.19867549668876/258` to `237.6315789473684/258` (76.82% to 92.11%),
extends the exact prefix from 6 to 30 instructions, restores the exact 76/76
instruction count, and preserves `7/0/0` references. The two partial variants
correctly fail to compile because declaration and use form one source model.

The recorded mutation spec SHA-256 is
`257b3625f9c1ec1abcc8af17056e173dcf05fa31b117311021b8c336ae1aef1d`;
the retained source SHA-256 is
`72bc9f98ef7fdcdceef401ca34942a2e43382b49fac1d86f1a80393f29036484`.
Follow-up source-order and helper experiments were byte-neutral or regressed,
so the remaining metadata/x87 scheduler residual is left explicit.
