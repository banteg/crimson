# Primary impact template and decal-offset recovery

This source slice restores two independently observed native boundaries:
initialize effect flags before copying the color, and construct the 1.5× decal
offset as a vector value before adding the creature position. The first change
recovers native ordered stores; the second recovers PC64 rounding at the Y
product. The current 2.5× expression still has a measured PC64 residual.

The promoted source gains **16.6117 fuzzy-weighted bytes**, from
`5557.4853/8409` to `5574.0970/8409`, and five aligned references. It remains
WIP, with both exactness flags false. This package preserves the prior source
and a fully rounded alternate without hiding the alternate's additional
reference mismatches.

| Source | Score | Instructions | References ok/problems | Cases with argument differences: recorded/native helpers |
| --- | ---: | ---: | ---: | ---: |
| Before | 66.089729% | 2188 | 430/10 | 112/107 |
| Flags only | 66.226372% | 2188 | 432/10 | 112/107 |
| 1.5× vector only | 66.150694% | 2190 | 433/10 | 70/61 |
| Retained | 66.287275% | 2190 | 435/10 | 70/61 |
| All three scaled vectors | 64.680464% | 2194 | 425/13 | 0/0 |

Each execution mode has 1,000 cases. Every source agrees with native complete
observed state, globals, and RNG state. The before/scale-only variants differ
in ordered writes in every case; flags-only, promoted, and fully rounded
variants match native ordered writes in every case. Every retained argument
failure is a PC64 2.5× decal position, including its final enqueue argument when
the real randomized FX helper executes. The verifier rejects a newly failing
call and checks that every retained failure belongs to that scale slot.

## Reproduce

From the repository root with the existing VC6 toolchain:

```sh
uv run --with unicorn==2.1.4 --with capstone python tools/match/evidence/primary-impact-template-2026-09-11/verify.py --out /tmp/crimson-primary-impact-template-full
cmp /tmp/crimson-primary-impact-template-full/recovered/scratch.cpp tools/match/scratches/projectile_update/scratch.cpp
uv run --with unicorn==2.1.4 --with capstone python tools/match/evidence/primary-impact-template-2026-09-11/replay.py --out /tmp/crimson-primary-impact-template-replay
```

`before.cpp` and the native image are SHA-256 pinned. `recover.py` reconstructs
each control without modifying the canonical scratch. The proof records
source/object/body/build identities, compiled field and pool layouts, complete
native observation digests, exact input identities, and retained argument bits.
The local SDK vector header is independently identified in
`analysis/mod_sdk_provenance.json` by SHA-256
`f56d2713518c010ce3ed8c76508678c7e5beff79a6d8a25fd7e736114bdb860f`;
its scalar operators construct a two-component vector value before addition.
The promoted aggregate captures that value boundary without claiming original
source-text identity.

## Execution boundary

The 1,000 deterministic cases alternate PC24/PC64, vary frame time, projectile
angle, speed, position, and damage origin, and use a real native lookup to place
the target at the first movement check. Each uses one Pistol projectile,
three units of travel budget, one live 1,000-health creature, disabled violence,
no active perks, a damage-scale input of two, and latched playlist state.
The full effect-template storage begins with varying byte patterns so omitted
or accidentally overwritten fields remain observable.

The first mode records damage and randomized FX calls. The second executes the
real native `creature_apply_damage` and `fx_queue_add_random` bodies, including
heading jitter, HP/velocity changes, the native RNG sequence, static FX color
initialization, and the final enqueue arguments. The high creature health
keeps these fixtures nonlethal. Native vector addition and creature/player
lookup helpers execute normally. Perk lookup returns zero; audio, `crt_atexit`,
and final `fx_queue_add` are recording callbacks. Unknown transfers and writes
outside the declared pools, globals, or stack fail. ESP, callee-saved registers,
control word, and empty x87 stack must be restored.

Native's template stores interleave the flags assignment between the G and B
color stores. Moving the source flags assignment ahead of the struct color
copy lets VC6 reproduce that schedule naturally; no explicit interleaved color
stores or register constraints are introduced.

## Prior-fixture replay

`replay.py` compares all 7,539 prior fixtures between the before and recovered
sources: 4,817 particle trajectories, 1,230 particle impacts, 663 impacts through
native damage/FX helpers, 605 primary microsteps/player controls, and 224
inactive-target bubble expiries. All observed before/after state, globals,
ordered calls/writes, and RNG state remain equal. Trajectory, primary-microstep,
and bubble cases also compare directly with native execution. Particle-impact
replay preserves the earlier documented residuals; it does not relabel them
native-exact. The replay uses this runner's explicit observation model, and the
bubble suite uses its original death-prelude runner.

The new matrix does not cover every primary type, active perks, blood effects,
lethal handling, final queue storage, or pixels. Neither this proof nor the
fully rounded alternate establishes whole-function or encoded-body identity.

## Validation

All 526 matching, native-link, SDK, and library-matching tests pass, along with
Ruff, type checks, documentation checks, ast-grep rules/tests, and strict
experiment validation. Both native audits retain game-owned closure, and both
structural links report runnable. The checkpoint has zero scope, evaluation,
metadata, experiment, native, or regression errors.

The port scope remains 799/810 normalized matches and 261,971/341,992 exact
bytes. Rounded fuzzy-weighted bytes rise from 321,024 to 321,041; the exact
weighted improvement of this function is 16.6117 bytes. Full-scope normalized
and encoded-body totals are unchanged. The refreshed report includes changed
raw COFF hashes; normalized native object hashes change only for
`projectile_update`. One unchanged object's prior raw hash was reproduced by
substituting only its original COFF timestamp, confirming that collateral
object-hash churn is metadata rather than matching progress.
