# `quest_build_knee_deep_in_the_dead`

Native target: `crimsonland.exe` at `0x00434f00` (541 bytes).

Live Binary Ninja evidence recovers an opening template-`0x43` brute at
`(-50, terrain_texture_height * 0.5)`, trigger 100, count 1. The main loop
starts at trigger 500 and wave zero, advances both by 1500 and one
respectively, and continues while the trigger is below `0x178f4`. It produces
245 entries in total.

Every loop iteration adds a template-`0x41` random zombie at the vertical
center. Its count changes from one to two after wave `0x20`. Every eighth wave
first adds another template-`0x43` brute at trigger minus two. Four strictly
greater-than trigger thresholds add escalating flanking entries:

- above `0x30d4`, template `0x41` at center plus 158, trigger plus 500;
- above `0x5fb4`, template `0x41` at center minus 158, trigger plus 1000;
- above `0x8e94`, template `0x42` at center minus 258, trigger plus `0x514`;
- above `0xbd74`, template `0x42` at center plus 258, trigger plus 300.

The native function reloads the integer terrain height and performs the
multiply and optional offset on x87 for every emitted position; it does not
cache a rounded midpoint. Whole-vector construction reproduces each temporary,
and the inlined metadata setter reproduces the native cursor and count update
schedule. Signed `wave % 8` is required for the target's correction sequence,
even though the runtime wave never becomes negative. The opening count is also
the initial logical entry count, explaining the shared `edi` value.

The candidate has the exact 141-instruction length, resolves all 18 audited
references, and scores 99.29% with a 20-instruction exact prefix. The complete
loop body and backedge match. Publishing the opening brute through the append
count and spelling its metadata directly recovers the native opening vector,
callee-save, and metadata schedule. The sole residual is one independent swap
between the initial trigger load and the hoisted loop-position setup.

## Recorded opening-lifetime search

`opening-lifetime-mutations.json` exhaustively evaluated 43 single and pair
combinations over named/split opening vectors and loop-scalar initialization.
Natural named temporaries, direct metadata, declaration swaps, and split
trigger assignment are all byte-neutral; split component schedules regress.
The 95.74% baseline remains best. The complete result is recorded in
`experiments.jsonl` (spec
`0925043af860b29e4188ee7d85c81c28d2beb137cd807d35f7fbb2cd08a6ebf8`).

`vector-helper-mutations.json` then evaluated all six honest constructor and
assignment-helper shapes. Constructor body and inline annotations are
byte-neutral. Explicit assignment operators collapse the compiler-generated
temporary schedule and regress by 234.60 weighted bytes and 30 instructions.
No helper shape improves the baseline; the complete result is recorded in
`experiments.jsonl` (spec
`3345a931147cba67328d3a8fa60d9ada42e5b5669cba0e3c77ce624535bf1f30`).
Together with the opening-lifetime sweep, this bounds both the call-site and
type-helper levers for the localized residual.

## 2026-08-08 append-count improvement

Replacing the preseeded opening count with zero-based publication improves the
candidate from 95.74% to 96.45% while preserving 141/141 instructions and the
exact loop body. The retained source SHA-256 is
`4b8c28bcc0838ca0c9dcf673bc42044ad32e0d4957aee0007bedece2b4efcc70`.

## 2026-08-08 direct-opening improvement

Direct opening metadata was byte-neutral before the append-count recovery but
becomes decisive afterward. It improves the candidate from 96.45% to 99.29%
and extends the exact prefix from three to 20 instructions while preserving
141/141 instructions, references `18/0/0`, and the exact loop. Retained source
SHA-256:
`c4e32ace06f3df88560dae220780ffca00246e690d43a721ff31940a2aa464b6`.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all masked references resolved; its
localized residual is compiler scheduling/allocation only. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.
