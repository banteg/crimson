# `quest_build_target_practice`

Native target: `crimsonland.exe` at `0x00437a00` (240 bytes).

Live Binary Ninja evidence recovers 30 randomized targets. Each angle is
`(crt_rand() % 612) * 0.01`; each radius is `(crt_rand() % 8 + 2) * 32`.
Targets use template `0x36`, count 1, and a center of `(512, 512)`. Trigger
time starts at 2000 ms. Its step starts at 2000 ms, falls by 50 each entry,
and contributes at least 1100 ms until the reduced step reaches 500.

The source constructs a rounded radial-offset vector and a translated position
vector, then computes heading through vector subtraction and `angle()`, minus
half pi. That reproduces the native signed remainder lowering, 20-byte frame,
x87 position sequence, and exact `fxch`/`fpatan` heading sequence. Retaining the
spawn-array base and indexing it with a logical entry count also reproduces the
native biased field cursor, its early advance, and the late metadata stores.
The result matches all 69 instructions and all eight audited references exactly.

## Recorded entry-lifetime search

`entry-lifetime-mutations.json` exhaustively evaluated 59 single and pair
combinations over the record cursor lifetime and trigger clamp. Reversed and
decrement-after-add clamp spellings are byte-neutral. Every natural named
post-incremented entry form instead changes the opening allocation and loses
52.17 weighted bytes, so the native early `ESI` advance is already a compiler
schedule of the retained cursor source. The complete matrix is recorded in
`experiments.jsonl` (spec
`37a3fb35eeddfaf0f75de96a3c995ae7cbec37460f86f39fdd208ce57c117be7`).

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, calls,
constants, record stores, and output-count policy. The candidate is an exact
normalized instruction and reference match, so no recovery or compiler
residual remains.

## 2026-08-08 indexed-builder exact recovery

The earlier retained-pointer source scored 89.86% at 69/69 instructions. Its
semantic shape hid that the native code keeps the spawn-array owner stable and
derives each record from a logical append count. Replacing the carried record
cursor with `spawns[entry_count]` lets VC6 derive the native trigger-field-biased
cursor and advance it before the x87 work without source-level pointer tricks.
It also keeps the position and heading expressions tied to the indexed record,
recovering the native late metadata publication. Retained source SHA-256:
`a781828bd80f01758fda51804c064519c1cd0d4c95db1d65b3176dde2e29c4a1`.
