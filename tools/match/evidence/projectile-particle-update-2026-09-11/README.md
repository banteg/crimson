# Particle vector and steering boundaries

Native `projectile_update` at `0x00420b90` disagreed with the previously declared
semantic-complete reconstruction. The old source is pinned in `before.cpp`;
`recover.py` reconstructs the retained SDK-vector expressions and angle field
reference without injecting stores, volatile variables, padding, or instructions.

The three motion changes restore the vector value boundaries visible at
`0x00422555`, `0x00422610`, and `0x00422665`. In each chain, the x component is
stored between vector operations while the y component can remain live on x87.
The existing local vector type follows the `vec2_t` scalar operators in the
recovered mod SDK's `cltypes.h`.

A reference to `particle->angle` also removes an extra stack copy. At native
`0x004227d6..0x004227ec` and `0x00422821..0x00422837`, the updated angle feeds
cosine before its live value is discarded; sine reloads the stored field.
Rounding both inputs through the extra temporary changes x velocity at PC=64.
A second natural source form using the existing velocity field owner is retained
as an independently executable positive control. These results identify useful
source boundaries; they do not establish the original spelling of either owner.

## Results

- 4,817 deterministic fixtures pass full observed pool/scalar bytes, callback
  arguments, RNG state, and non-stack write sequences with both recovered owner
  forms. Both preserve the stack, callee-saved registers, x87 control word, and an
  empty x87 stack.
- The previous source fails 783 fixtures. Restoring the three vector expressions
  without the angle owner still fails 184. `results.json` includes representative
  native/control field differences and both measurement identities.
- Static matching improves from 62.8818969% to 66.0592255%, gaining 267.1816
  fuzzy-weighted bytes. Instructions change from 2,183 to 2,187 against 2,203
  native instructions. Reference evidence changes from `426/0/13` to `429/0/10`.
  The velocity-owner control has the same score and `426/0/13` references.
- The function remains WIP, with neither normalized nor encoded-body exactness.
- Python matches all 1,039 applicable PC24 witnesses, including every observed
  particle field, RNG values, caller tags, and state for real-seed fixtures.
  Python and Zig both run the same 80 native regression cases, selected by
  `export_regressions.py`, under the normal test suites.

The runtime changes restore left-to-right PC24 multiplication through velocity,
particle decay/spin/steering/shade arithmetic, and the native bubble movement
render guard. Python also uses the native f32 0.8 expiry threshold. Steering
retains wide trigonometric results until the speed multiply. Zig tags the two
alternate flame styles with their actual native steering caller.

## Execution scope

`execute.py` relocates the compiled candidate with the existing plasma evidence
loader. Native `crt_ftol`, `vec2_add`, and `vec2_add_inplace` execute directly.
Callbacks for perk lookup, no-hit collision lookup, RNG, radius damage, and FX
queue insertion are explicit shared models; damage/FX calls record arguments
without executing those subsystems. Unknown control transfers and writes outside
all six observed pools plus seven scalars fail. `fixtures.py` verifies each pool
extent and initialized field offset/width with VC6 against the project headers.

Fixtures include primary projectiles with and without movement, secondary
projectiles without hits, sprites, all four valid particle styles, generic style
3, both render states, thresholds, randomized finite values, and mixed particle
pools. The particle cases independently cross PC=24/PC=64 and render states.

This is bounded evidence. Collision impacts, expiry with an attached live target,
external callee behavior, NaNs/infinities, and every possible game state are not
covered. Runtime verification uses positive-dt PC24 cases and valid particle
enums. The ports keep their existing positive-dt update guard. PC64 remains a
reconstruction check rather than a runtime-port promise.

## Reproduce

Optional `unicorn==2.1.4`, the pinned VC6 toolchain, and local JIT permission are
required for native execution. From the repository root:

```sh
uv run --no-sync --with unicorn==2.1.4 python tools/match/evidence/projectile-particle-update-2026-09-11/verify.py --out /tmp/projectile-particle-proof
PYTHONPATH=. uv run --no-sync python tools/match/evidence/projectile-particle-update-2026-09-11/verify_ports.py --native-results /tmp/projectile-particle-proof/port-witnesses.json --out /tmp/projectile-particle-proof/python-ports.json
uv run --no-sync python tools/match/evidence/projectile-particle-update-2026-09-11/export_regressions.py --native-results /tmp/projectile-particle-proof/port-witnesses.json --out /tmp/particle-update.json
cmp /tmp/particle-update.json crimson-zig/src/runtime/testdata/particle-update.json
uv run --no-sync pytest tests/gameplay/test_particle_update_native.py
cd crimson-zig
zig build test --summary all
zig build test -Doptimize=ReleaseFast --summary all
```

The generated `cases.json` and full `port-witnesses.json` remain in the chosen
output directory; their hashes and counts are retained in the checked-in receipt.
The compact shared fixture stores native observations, not values calculated by
the port implementation.
