# Creature targeting distance recovery

The four early target-selection distances use the same accumulated-square
helper as the exact `creature_find_nearest` and `plaguebearer_spread_infection`
routines. The later interaction distance retains its direct-sum vector-length
helper. Native x87 instructions independently distinguish these two forms.

This fixes a finite-precision targeting difference. With players at `(0, 0)`
and a creature at `(1, 2)`, the initial distance is rounded to float. Native
keeps the alternate distance on the x87 stack while also storing its float
copy. With extended precision, the retained square root of 5 is less than the
rounded initial distance, so native switches to the other player. The old
source popped and reloaded the float copy before comparing and kept the target.
The same distinction occurs with separately positioned players at equal distance.

`recover.py` reconstructs each call independently. Across 768 cases spanning
identical, mirrored, one-ULP-neighbor player positions, both initial targets,
one/two-player modes, active/skipped retarget ticks, and 24/64-bit x87 precision:

| Source stage | Differences from native |
|---|---:|
| Before | 28 |
| Initial distance only | 28 |
| Alternate-player distance added | 0 |
| Single-player distance added | 0 |
| Auto-target distance added | 0 |

All 28 negative controls have two players, an active retarget tick, and 64-bit
x87 precision. The retained source also passes 2,472 historical cases (including
verification of their prior native hashes), 192 interaction-radius cases,
48 tiny corpse-size cases, and 12 transient target-player callback controls.
These compare full pool/player/slot state, scalar state, ordered writes, and
calls under the existing callback models. They are finite execution evidence.

The retained candidate has 1,306/1,338 instructions, 58.547655% agreement,
prefix 10, a native-sized `0x7c` frame, and reference audit `226/0/1`.
Normalized and encoded-body exactness remain false. This adds no exact match.
The source SHA-256 is
`b27f450cd219a514e9083ddfb87842a3a960130f6d5343b851ae6f7835b9ddae`.

Reproduce with the pinned optional interpreter dependency and local JIT access:

```sh
uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/creature-retarget-distance-2026-09-13/verify.py \
  --out /private/tmp/creature-retarget-distance-proof
```

`results.json` records the compiler, native image/body, source and harness
hashes, staged native observations, negative controls, and regression receipts.
