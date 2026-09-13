# Projectile movement and ion-chain boundaries

Two source changes recover independently observed native boundaries:

- Accumulate the microstep squared distance in two statements. Native
  `0x00420de3..0x00420e1f` stores both updated components, then reloads X,
  multiplies X, reloads Y, multiplies Y, adds, and takes the square root.
  The previous expression retained extended-precision Y across its float store.
- Use VC6's `atan2f` wrapper for the ion-chain direction. Native
  `0x004212a9..0x00421304` includes an otherwise unused address calculation
  between the component loads and `fpatan`. The wrapper recovers that sequence.
  The original-era SDK uses `atan2f` in `VEC2_Angle`, and the compiler's
  `math.h` supplies its inline float argument/return boundaries.

`recover.py` reconstructs all four combinations from the hash-checked
`before.cpp`. The retained source has **2,192/2,203 instructions**, **66.393629%**
agreement and **437/0/8 references**, compared with 2,190 instructions,
66.287275% and 435/0/10 before. Its frame remains `0xcc`, versus native `0xf4`.
Normalized and encoded-body exactness remain false. This adds no exact match.

The 1,000 movement cases reuse the existing threshold inputs under both PC24
and PC64 x87 control words. Before and the angle-only control differ from
native in four ordered movement/collision call traces, four write traces,
and two final states. All failures are PC64. The accumulated-distance and
combined sources have zero differences.

The 1,000 ion-chain cases execute native movement, collision and nearest-target
lookup. Every case reaches one projectile-spawn boundary, and all spawn argument
bits agree with native before and after. Spawn and presentation calls are
recording callbacks; this is not execution of the subsequently spawned chain.
The harness returns slot 1 without populating it. It checks pool/scalar state,
ordered writes, calls, RNG values, stack balance, saved registers, and x87 state.
Raw caller addresses differ between native and relocated code and are not
treated as comparable RNG identities.

Prior cases also compare before and after against fresh native observations:
4,817 particle trajectories, 1,230 particle impacts, and 1,000 primary impacts.
Before/after observations must agree in every case. Existing native differences
remain visible: particle impacts have 683 write-trace and 25 final-state
differences; primary and ion-chain impacts each have 70 call-trace differences.
Those unrelated geometry/decal issues are not fixed or credited by this change.

All five suites write identities, build inputs, observation hashes, differences,
and movement counterexamples to their output directory. The committed
`results-*.json` files are the retained receipts. These are finite CPU proofs,
not whole-game equivalence or an exact-function claim.

```sh
uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/projectile-rounding-boundaries-2026-09-13/verify.py \
  --suite movement --out /private/tmp/projectile-rounding-movement
```

Repeat with `--suite chain`, `particle-update`, `particle-impact`, and `primary`,
using separate output directories. Native x86 execution requires local Unicorn
JIT access. No compiler options, reference aliases, or comparison rules change.
