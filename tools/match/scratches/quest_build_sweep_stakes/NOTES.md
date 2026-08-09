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
nested loop boundaries, trigger clamp, and all seven references. A stable
spawn-array base plus one append count owns all 64 entries. Publishing position,
metadata, and heading directly through `spawns[entry_count]` lets VC6 derive the
native trigger-field-biased induction cursor, advance it before the x87 vector
work, and place the three metadata stores after both position stores.

The result is exact: **76/76 instructions**, **258/258 bytes**, and references
`7/0/0`. Retained source SHA-256:
`a8196650c0631035668cd39e664b336b240c394c3eb42bb7070b4984f4bdfa0e`.

## Recovery classification audit

Binary Ninja confirms the complete 16-wave policy, random angle, four radii,
heading, trigger clamp, entry metadata, and final count. Normalized instruction
identity and every audited reference now match, so no recovery or compiler
residual remains.

## Bounded search history

The earlier cursor-shaped source reached 75.50%. Fifteen typed trigger-cursor
variants in `typed-trigger-cursor-mutations.json` did not improve it; the full
combination fell to 59.46%. A five-compiler and six-flag matrix kept the VC6
`/O2 /GB` family best. A 47-variant source-order sweep found one useful local
ordering, and the five helper-store-order variants were neutral or regressive.
Those results remain recorded in `experiments.jsonl`.

On 2026-08-08, `append-count-recovery-mutations.json` replaced the persistent
output cursor with the stable array base and append count. That raised the
score from 76.82% to 92.11%, restored the exact 76-instruction count, and
extended the prefix from 6 to 30 instructions. The retained mutation spec is
`257b3625f9c1ec1abcc8af17056e173dcf05fa31b117311021b8c336ae1aef1d`.

The final indexed-publication step removes the loop-local record alias and
uses the append-count expression at each field access, following the same
house style as the exact target-practice builder. Unlike the older direct-store
probe, this combines direct publication with the later append-count recovery;
that interaction moves the metadata stores to their native position and closes
the remaining 20-byte fuzzy gap exactly.
