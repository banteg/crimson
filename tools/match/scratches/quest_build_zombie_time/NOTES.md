# `quest_build_zombie_time`

Native target: `crimsonland.exe` at `0x00437d70` (152 bytes).

The builder emits paired zombie waves just outside the right and left arena
edges every eight seconds, from 1.5 through 89.5 seconds. Each wave contains
eight random zombies; the native intentionally leaves heading untouched.

The native keeps the output base in `EBX` and the logical entry count in `ESI`,
recomputing each 24-byte record address instead of strength-reducing the loop
to a moving pointer. Modeling the same `{spawns, count}` builder abstraction
used by neighboring quest constructors recovers that allocation. Completing
each entry through repeated `builder.spawns[builder.count]` expressions before
publishing its count recovers the native conversion/store schedule. The second
entry uses direct metadata fields, matching the recurring final-entry boundary
in exact paired builders. The result matches all 50 instructions and all three
audited references exactly.

## Recorded paired-entry search

`paired-entry-mutations.json` exhaustively evaluated 80 single and pair
combinations across the right and left record schedules. Direct metadata,
named half-width, and several post-incremented-index spellings are byte-neutral;
placing metadata across the y conversion regresses. No variant improves the
82.00% baseline. The complete matrix is recorded in `experiments.jsonl` (spec
`685d991255aaf4bcbda4b11cfbf008562d427b6028789ce582136ecf9e0d7d74`).

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, constants,
record stores, induction policy, and output count. The candidate is an exact
normalized instruction and reference match, so no recovery or compiler
residual remains.

## 2026-08-08 exact indexed-publication recovery

Replacing both captured record pointers and early count increments with
complete indexed publication raises the candidate from 82.00% to 96.00%.
Spelling the second entry's metadata directly removes the final scheduling
cluster, producing an exact 50/50-instruction match with references `3/0/0`.
Retained source SHA-256:
`41d81263a878ab47c4bc9003ec9b866bfd985be9828ae658c81905b32099a8ef`.
