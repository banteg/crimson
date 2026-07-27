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
