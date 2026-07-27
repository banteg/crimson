# quest_build_land_of_lizards

Native target: `crimsonland.exe` at `0x00437ba0` (204 bytes).

Recovered Tier 2 Quest 8's complete four-entry spawn policy. Spawn template
`0x0e` appears at the corners `(256, 256)`, `(768, 256)`, `(256, 768)`, and
`(768, 768)` at 2000, 12000, 22000, and 32000 ms respectively, one creature per
entry.

The candidate has the same 46 instructions and scores 93.48%. The remaining
differences are three independent VC6 scheduling choices around the inlined
position constructor/setter and the saved `esi` register. No dummy dependency
or synthetic control flow is used to reorder them, so this is intentionally
kept as a WIP.

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
