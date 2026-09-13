# Projectile ownership and remaining stack lifetimes

This continues the [primary/secondary investigation](../projectile-primary-secondary-residuals-2026-09-13/README.md)
from its frozen `primary-f7-tick-before-scale` candidate. It retains 73 compiling
experiments and a 20-step path to `primary-q1-chained-zero`. The canonical scratch
and matching credit remain unchanged.

The final source SHA-256 is
`f46d40ef618dd67ddc365fc30fa4280966dcb4eec7f248fc165e9b15e138e078`;
its extracted body SHA-256 is
`b744a17a696a3ba2a2963d94bd7acf525f35cf331bd45fc4ed5a1f9b38af66f2`.
It has 2,202/2,203 instructions, a `0xe8` frame versus native `0xf4`, and
483 explained paired references with six remaining alignment problems.
Neither normalized nor encoded-body exactness is claimed.

## Recovered boundaries

Each retained step has a concrete instruction or data-flow motivation. The
ordered path and every alternative's exact source edits are in `experiments.json`.

- Staging the squared speed accumulation recovers the rocket, minigun and seeker
  x87 sequences. Separate cosine constructor arguments restore the trail's
  component materialization: one component reloads the rounded cosine while the
  other retains its live result.
- References to actual particle fields restore the late intensity, render flag
  and style reads. Moving the collision position reference into its used scope,
  retaining the record owner for previous-position Y, and clearing velocity
  through the vector reference recover the native geometry and velocity cursor.
- Constructing the scaled explosion impulse as a vector product recovers its
  argument-push schedule. Later controls still move the commutative radius
  operand order; that residual remains visible.
- Moving primary impulse construction inside its branches restores the damage
  comparison timing. Reading the second speed multiplier through a reference to
  the real field prevents the premature common-subexpression merge. This
  reproduces the 43-instruction impulse window without mixed float/double casts.
- A conventional primary microstep `for` loop restores its backedge. A reference
  for seeker rollback X restores the field reload instead of the cached spill.
  Indexed sprite and particle loops recover their endpoint comparisons; a style
  reference bound after expiry restores the late read in the indexed particle loop.
- Chained `delta.x = delta.y = 0.0f` resets recover native's Y-before-X stores.
  This was found by mapping actual stack accesses, after a displacement-insensitive
  comparison had hidden the difference.

Register and stack allocation changes elsewhere are retained in each compiled
control. A local recovery does not imply that all other windows improve.
Returning from the clamp helper, changing its return type, changing its bounds
parameters, several position-owner spellings, and scalar multiplication operand
order produce identical bodies. Separate clamp tests, indexed secondary loops,
and broader owner changes leave documented residuals rather than receiving credit.
The private header-overlay experiment is not part of this source-only graph.

## Native replay

All 12,402 cases have zero final-candidate differences in pool/scalar state,
recorded calls, ordered writes and RNG state within the harness boundaries.
The comparator is the previous frozen candidate, not the canonical scratch.

| Suite | Cases | Previous candidate differences | Final candidate differences |
| --- | ---: | --- | --- |
| Particle trajectories | 4,817 | none | none |
| Particle impacts | 1,230 | none | none |
| Integrated particle helpers | 663 | none | none |
| Bubble expiry | 224 | none | none |
| Primary movement | 1,000 | none | none |
| Primary impacts | 1,000 | none | none |
| Expanded primary weapons | 576 | none | none |
| Rocket/minigun impacts | 300 | none | none |
| Explosion thresholds | 192 | none | none |
| Steering thresholds | 1,200 | none | none |
| Trail generation | 1,200 | 313 state; 313 calls; 313 writes | none |

The new steering/trail fixtures cover three secondary types, speeds near their
350/500/600 thresholds and a wider random range, both x87 PC24/PC64 settings,
and deterministic seeds. Native callers and the selected game helpers execute;
FX/audio/damage/spawn boundaries are recorded as described in the preceding
package and each underlying suite. Expanded suites share a deterministic external
D3DX normalization model and record its inputs; they do not execute its DLL.
These fixtures do not prove arbitrary-input or whole-game equivalence.

## Reproduce and inspect

```sh
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/projectile-ownership-and-stack-2026-09-13/audit.py \
  --out /private/tmp/pu-ownership-audit
UV_CACHE_DIR=/private/tmp/crimson-uv-cache \
uv run --offline --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/projectile-ownership-and-stack-2026-09-13/verify.py \
  --suite trail --out /private/tmp/pu-ownership-trail
```

Use a distinct short output directory for each suite. `audit.py` rebuilds all
74 graph nodes and checks their saved source/body identities. Its selected
windows preserve register roles, branch topology including the window exit,
explained positional references, and local stack-home relationships. This is
not an encoded-byte comparison or a global stack-lifetime proof.

`native-receipts.json` and `audit-receipt.json` retain the verified identities,
case/observation digests and compact results. Reproduction writes full observations
and disassembly to the requested output directory. The separate
[stack-group observer](../projectile-stack-groups-2026-09-13/README.md) verifies
compiler preservation, the candidate's group membership and the primary prefix's
individual native stack accesses.

Remaining work includes the explosion creature cursor and position address,
seeker `fpatan` scheduling, burst exchange, secondary loop endpoint, particle
call-register assignments, first tint-clamp layout, and stack lifetimes. The
function remains open.
