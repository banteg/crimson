# `quest_build_the_random_factor`

Native target: `crimsonland.exe` at `0x00436350` (237 bytes).

Live Binary Ninja evidence recovers waves from 1500 ms while below 101500 ms,
advancing by 10000 ms. Every wave adds template `0x1d` from the right edge with
count `player_count * 2 + 4`, then from the left edge 200 ms later with count
6. When `crt_rand() % 5 == 3`, it also adds template `0x29` at the bottom-edge
midpoint with the current trigger and player count.

Keeping the entries base and emitted count in a builder object recovers the
native base-plus-scaled-index addressing and register allocation instead of
VC6 strength-reducing the loop to a cursor. Each entry is addressed separately
as `builder.spawns[builder.count]`, completed in position/metadata order, and
then published by incrementing the count. That house-style ownership matches
all 74 native instructions and all seven audited references exactly.

## Recorded entry-order search

`entry-order-interactions-mutations.json` exhaustively evaluated all 215
single, pair, and triple combinations over the two fixed entries and optional
entry. None improved the 90.54% baseline; several alternatives were byte-neutral
fixed points (spec
`7a6cee7264e5b8a6d42d180ec2c8957adee7bf981822c8866f4ce7c0113871b8`).
The stock VC6 profiles tie and VC7 is worse. The complete matrix is recorded in
`experiments.jsonl`.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, constants,
record stores, induction policy, and output count. The candidate is an exact
normalized instruction and reference match, so no recovery or compiler
residual remains.

## 2026-08-08 exact indexed-publication recovery

Replacing each captured record pointer and pre-metadata count increment with
repeated indexed entry expressions and post-entry publication raises the
candidate from 90.54% to 100%. The retained source matches 74/74 instructions
with references `7/0/0`. Source SHA-256:
`f75bc10430eacc4fef2b1e881693b6bfad80247400c3d0b3abf8804895e7f034`.
