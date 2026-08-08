# quest_build_land_of_lizards

Native target: `crimsonland.exe` at `0x00437ba0` (204 bytes).

Recovered Tier 2 Quest 8's complete four-entry spawn policy. Spawn template
`0x0e` appears at the corners `(256, 256)`, `(768, 256)`, `(256, 768)`, and
`(768, 768)` at 2000, 12000, 22000, and 32000 ms respectively, one creature per
entry.

The candidate matches all 46 instructions exactly. One continuous append count
owns all four entries and the final output. The first record completes its
metadata before constructing the following position; the next two retain the
interleaved publication boundary recovered from the native schedule, and the
last record uses the shared full-entry setter. This reproduces the native
saved-`ESI`, template, position-temporary, and epilogue schedule.

`entry-shape-mutations.json` records six aggregate, direct-field, and shared
constant spellings. Shared constants are byte-neutral and every structural
rewrite regresses, so the canonical four-entry source remains unchanged.

`helper-and-entry-boundary-mutations.json` adds a complete 69-variant
single/pair sweep over helper forms and typed first/second-entry boundaries;
all are byte-neutral. `vector-helper-mutations.json` adds six constructor and
assignment shapes, with three neutral constructor spellings and three
regressing assignment operators. `setter-store-order-mutations.json` evaluates
seven remaining helper store orders; every one regresses, the least by 8.9
fuzzy-weighted bytes. Their SHA-256 values are
`5562164101b28435e511775872c5492e609f56f4a9c2ac780577c6cffa28a44a`,
`3345a931147cba67328d3a8fa60d9ada42e5b5669cba0e3c77ce624535bf1f30`,
and
`eb39de2a7c7c7a5a1ef3edb0db7393935c21bbfc0a45cf3188f91742b6d25829`.
MSVC 6.0/6.5/6.5 Processor Pack/6.6 tie, MSVC 7.0 regresses, and `/G5`,
`/G7`, `/Ox`, and `/Ob1` are neutral while `/G6` regresses.

## 2026-08-08 append and publication-boundary recovery

Applying the fixed-table house style recovered in Cross Fire and The Blighting
raises the result from 93.48% to 97.83% and extends the exact prefix from eight
to eleven instructions. Fixed indices and the literal output count become one
continuous append count. At each of the first three boundaries, the current
template is published before constructing the following position; the current
trigger and count follow that construction. The candidate remains 46/46
instructions with no reference debt. The one residual instruction is the
shared `mov ecx, 1` on the opposite side of the first following-position
construction.

## 2026-08-09 complete-entry house style

The same opening pattern that finishes Army of Three applies here: the source
completes the first record's trigger and count before declaring the next
position. VC6 schedules that following constructor between the shared
count-one load and the record stores, producing the native order exactly. The
result matches all 204 bytes and all 46 instructions.
