# Point movement shares one frame-delta snapshot

The original point-click movement path loads `frame_dt` once and duplicates
that x87 value before multiplying the two stored velocity components. The
moving arm does this at `0x0041410b..0x0041411f`; the coasting arm at
`0x0041418e..0x004141a9`.

The recovered C++ read the global independently for X and Y. Two ordinary
`const float movement_dt = frame_dt` locals recover the shared snapshot. VC6
merges their common tail: the new body adds `fld st(0)` at object offset
`0x0a98` and removes the second global load. Branch displacements adjust to the
four-byte size reduction. It still multiplies X before Y; the native sequence
multiplies Y before X and uses different stack slots. This is an improvement,
not an exact match.

| Measurement | Before | Current |
| --- | ---: | ---: |
| Weighted matching bytes | 10407.941446890878 | 10411.874909266877 |
| Match ratio | 64.0212920397% | 64.0454875393% |
| Body bytes | 15867 | 15863 |
| Candidate instructions | 4060 | 4060 |
| Native instructions | 4206 | 4206 |
| Prefix instructions | 7 | 7 |
| Clean / unresolved / mismatched references | 805 / 0 / 2 | 805 / 0 / 2 |

The complete eight-case snapshot interaction test is recorded in
`tools/match/scratches/player_update/experiments.jsonl`, with mutation spec SHA
`81d271c26d9a431598949bc92dd1eee7362523deed4a4e72dd369dfa9e2dd7ae`.
Each one-arm change worsens the match; all four paired scope choices produce
the same metrics. The retained form uses the existing branch scopes.
The measured gain is 3.933462375999 weighted bytes.

## Execution proof and expanded controls

`verify.py` pins the prior source (`before.cpp`), checks the exact two-site
transformation, compiles both bodies, and executes them against the supplied
original image at x87 PC=24. Every case compares all observed final state bytes
and ordered modeled callback arguments. All 3,827 cases agree across native,
before, and current. The first 3,738 native observation hashes also agree with
the existing aim proof.

The extra 89 cases cover Long Distance Runner threshold/cap boundaries,
Living Fortress saturation, point-click reload input, Anxious Loader timer
underflow, zero cursor-axis distances, near computer aim, the fixed G shortcut,
and finite demo-target sentinel boundaries. They include all 38 shortcut
witnesses. The new zero-speed clamp control uses a player at `(512, 512)`, a
creature at `(0, 183.24853515625)`, and initial move speed `0.001`.

Instruction coverage reaches 4,198/4,206 native and 4,053/4,060 before/current
instructions. The eight unvisited native instructions are reported explicitly:

- Six signed-remainder adjustment instructions after the nonnegative CRT
  `rand()` result. This runner preserves the CRT's 0..32767 range.
- Two x87 pops in the point-click `heading == -1` arm after heading
  normalization. These did not execute in the finite point-click controls.

The coverage count describes this matrix, not exhaustive input coverage or a
proof that every unvisited instruction is universally unreachable. No invalid
RNG values or fabricated NaNs were introduced to raise the count.

The shared aim runner executes the original movement, heading, vector, and CRT
conversion helpers. Input, RNG, D3DX normalization, allocation, effects,
damage, reload, and sound boundaries are explicit models; damage and reload
callbacks do not execute their downstream game code. Layouts are checked by
the same 32-bit compiler. Unexpected execution, unlisted writes, modified
read-only fixtures, stack imbalance, callee-saved register changes, or changed
x87 state fail the run. This is a bounded routine proof, not whole-game
behavioral equivalence.

`results.json` records both source/object/body hashes, image/harness/fixture
hashes, complete covered instruction offsets, and the common observation hash
for each passing case. Generated complete case inputs are also written to the
requested output directory; their hash is in the receipt.

## Reproduce

```sh
uv run --with unicorn==2.1.4 python tools/match/evidence/player-point-frame-2026-09-11/verify.py --out /tmp/player-point-frame
```

The existing aim and G-shortcut native receipts are refreshed for the final
source as well. The port implementations do not change in this slice.
