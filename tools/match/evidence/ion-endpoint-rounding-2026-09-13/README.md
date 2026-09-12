# Ion endpoint position rounding

This investigation tested the second ion-chain strip first. Neither strip
differed in 256 new geometries at both PC24 and PC64. The full trace comparison
instead exposed one adjacent defect: the endpoint glow reused the rounded
screen position prepared for the strips. Native reloads camera and creature
coordinates at the endpoint draw, keeping their sum wide until subtraction.
Only those two draw arguments are corrected; widening remains unchanged.

The baseline is `9e629bbe53128d73fcc72b2ee82d750609d9776f`, pinned in
`before.cpp`, SHA-256
`a51887e6e550d8b414d5f109e6e046cc7f25b86f024a10eedf4f87a899adcc31`.
`source-controls.json` reconstructs every tested source from that baseline.

## Minimal failing case

Use Ion Minigun, projectile position `(0, 0)`, creature position `(0.8f, 0)`,
camera `(16, 0)`, and life `0.2f`. There is one eligible creature. Both strips
agree, but at diagnostic PC64 the endpoint's X coordinate differs:

| Source | Submitted float bits | Value |
| --- | --- | ---: |
| Native and corrected arguments | `0x35500000` | 0.0000007748603820800781 |
| Previous cached `end.x` | `0x00000000` | 0 |

The scale is `1.05f`, so the stored half-size is `16.799999237060547`.
Native subtracts it from the wide sum of 16 and `0.8f`. The cached float32 sum
has already rounded to the same value as the half-size, producing zero.
At PC24 the sum itself rounds before subtraction and both versions agree.
This is a recovered caller arithmetic boundary; no PC24 discrepancy is
demonstrated here.

Native `0x424f44..0x424f86` loads camera Y and creature Y, subtracts the
stored half-size and pushes the result; it then does the same for X. The
verifier pins the native x87 instruction sequence and checks both coordinate
words with an independent arithmetic oracle for all 524 cases. It does not
infer the boundary from an alignment score.

## Bounded result

The matrix has 512 deterministic random cases and 12 small cases covering
three ion weapons, both coordinate axes and both precisions. Creature search
executes the native body. Targets are within 20 units per axis of the
projectile, away from the search boundary; camera and projectile positions
vary over `[-512, 512]` in the random cases. Glow and Ion Gun Master vary too.

The corrected source agrees on all 524 complete call traces, creature-search
results and pool state. The previous source fails 69 cases, all at PC64 and
all exclusively at the endpoint draw. All 262 PC24 cases agree. Both strip
quads agree in every case for the baseline and the corrected source.

Seven freshly compiled controls separate the hypotheses:

- `before`: reproduces the endpoint failures, with both strips agreeing.
- `endpoint-reload`: changes only the endpoint's two coordinate expressions;
  retained because it fixes the observed failure with the closest alignment
  among the three endpoint fixes tested.
- `endpoint-pointer` and `endpoint-ctor`: fix the same endpoint cases, with
  worse whole-function alignment.
- `repeated` and `native-order`: repeat widening expressions in source order
  and native corner order. Both strips still agree, endpoint failures persist,
  and alignment decreases. These remain diagnostic.
- `wrong-widen`: changes only widening from 4 to 3. Every second strip fails
  while every first strip agrees, demonstrating that the test detects an
  incorrect widened strip.

The wrong-widening control retains the baseline's alignment score and reference
counts despite failing all 524 second-strip comparisons. Those measurements
alone would not detect this incorrect width in the already non-exact function.

The adapter changes only initial camera and x87 precision. At the historical
defaults its complete native and candidate results equal those from the
unmodified executor. It additionally checks caller memory, unchanged pools,
the x87 control word and empty x87 stack. Existing instruction-address,
stack-balance, saved-register and non-stack-write checks remain active.
Normalization is the previous deterministic D3DX model; Grim calls are
recording stubs. This is finite caller evidence, not arbitrary-input or GPU
equivalence.

## Matching and regressions

| Source | Alignment | Instructions | Clean/unresolved/mismatched refs |
| --- | ---: | ---: | ---: |
| Before | 62.934492% | 2,963/3,021 | 487/0/6 |
| Corrected endpoint | 62.358049% | 2,967/3,021 | 495/0/7 |

Frame allocation stays 388/412 bytes and prefix stays zero. Both exactness
flags remain false. The additional positional reference pairing is at
`0x422e22`, matching native camera Y with candidate camera X in the earlier
laser block. All six prior mismatch addresses persist. All 5,040 laser-trig
fixtures pass, including varied cameras; no laser source is changed.

The base-bound regression exception records this tradeoff without changing
aliases, compiler flags, native extent or exactness rules. The correction
removes a demonstrated arithmetic discrepancy despite the lower fuzzy score.

`replays.json` preserves fresh receipts for all 11,854 historical renderer
fixtures, omitting their redundant full CFG payloads. `position-replay.json`
checks the preceding 656 Fire/billboard fixtures and twelve type-reload
callback controls, including the separately compiled negative control.
`results.json` records all seven fresh compilations, reference problems,
native instructions, fixture hashes and the 69 endpoint differences.

## Reproduce

```sh
uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/ion-endpoint-rounding-2026-09-13/verify.py \
  --out /private/tmp/ion-endpoint-proof

uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/ion-endpoint-rounding-2026-09-13/replay_positions.py \
  --source /private/tmp/ion-endpoint-proof/endpoint-reload/scratch.cpp \
  --out /private/tmp/ion-endpoint-positions

for suite in historic conventional laser; do
  uv run --no-sync --with unicorn==2.1.4 python \
    tools/match/evidence/renderer-house-style-2026-09-13/replay.py \
    --source /private/tmp/ion-endpoint-proof/endpoint-reload/scratch.cpp \
    --suite "$suite" --out "/private/tmp/ion-endpoint-$suite"
done
```
