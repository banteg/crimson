# `quest_build_hidden_evil`

Native target: `crimsonland.exe` at `0x00435a30` (407 bytes).

Live Binary Ninja evidence recovers five fixed waves at the same dynamic map
edge: x is signed integer `terrain_texture_width / 2`, and y is
`terrain_texture_height + 64`, with both converted to float separately for
every entry. Heading is left untouched. The waves are:

- template `0x21`, trigger 500, count 50;
- template `0x22`, trigger 15000, count 30;
- template `0x23`, trigger 25000, count 20;
- template `0x23`, trigger 30000, count 30;
- template `0x22`, trigger 35000, count 30.

The recovered source matches all 407 native bytes and all 101 instructions,
including the full instruction prefix and all ten audited global references.
One continuous append count publishes the five entries and supplies the output
count. That source shape keeps the first entry's three metadata stores after
both position stores, resolving the former 97.03% scheduling residual.

`first-position-lifetime-mutations.json` evaluated four aggregate, staged,
and scalar materializations of the first wave position. None improved the
match; the negative sweep leaves the documented VC6 store scheduling as the
only residual and retains the simpler source.

`first-entry-boundary-mutations.json` adds eight typed record/position aliases;
all are byte-neutral. `vector-helper-mutations.json` adds six constructor and
assignment shapes: three constructor spellings are neutral and explicit
assignment operators regress. `metadata-store-order-mutations.json` evaluates
all five non-baseline metadata permutations; every one regresses, the least by
16.1 fuzzy-weighted bytes. Their SHA-256 values are
`f53e79b788c65b77b5f31c06910fc427b7dadd914095313e8ad47ec0fa4479b8`,
`3345a931147cba67328d3a8fa60d9ada42e5b5669cba0e3c77ce624535bf1f30`,
and
`caabc677c87c39821efd82d268e8fb051cb0829252c1604fe4c9d78318efcaaa`.
MSVC 6.0/6.5/6.5 Processor Pack/6.6 tie, MSVC 7.0 regresses, and `/G5`,
`/G7`, `/Ox`, and `/Ob1` are neutral while `/G6` regresses.

## 2026-08-08 exact recovery

Replacing five fixed indices and the fixed output assignment with one append
count improves the candidate from 395/407 fuzzy-weighted bytes (97.03%), a
ten-instruction prefix, to an exact 407/407 bytes and 101/101-instruction
prefix. References remain 10/0/0. The exact source SHA-256 is
`9b360e8ef5961f3c589d2506294b757cc301c09609f3bd089b54243b7228acb0`.
