# Projectile residual decomposition

This package separates instruction shape, value lifetime, arithmetic, and
publication order in `projectile_update`. It reconstructs eleven changes one
at a time from a pinned source. The canonical scratch and matching credit are
unchanged. **No new full function match is claimed.**

The starting source is SHA-256
`90b9bb4a39f0efd852395367bd11f71113b8812b15144301b4914f18423ac730`,
at commit `d3505333b1d3823baa705aef67e7283495ec921d`. The candidate produced by
all steps has source SHA-256
`3e861d92088ed043dfbfc701acd86d251b67921e7a9ef8271769acce0ff59a93`
and encoded body SHA-256
`223f9383676027b5b70b48ecdca73e7470ba66ac061333fab04f16f77c95c871`.

## Reproduce

```sh
uv run python tools/match/evidence/projectile-residual-decomposition-2026-09-13/audit.py --out /tmp/projectile-residual-audit
uv run --with unicorn==2.1.4 python tools/match/evidence/projectile-residual-decomposition-2026-09-13/verify.py --suite particle-impact --out /tmp/projectile-residual-impact
```

Repeat the second command with `particle-integrated`, `particle-update`,
`bubble`, `movement`, and `primary`. `--through N` reconstructs the first N
steps. The scripts do not edit the canonical scratch. The audit writes every
source and disassembly snapshot; replay writes per-case observation hashes.
Committed receipts retain aggregates and a digest of those reproducible rows.

## What each change addresses

| Step | Native window | Residual and recovered boundary |
| --- | --- | --- |
| Expiry branches | `4226af..4226e8` | Style zero checks zero intensity; other styles check `0.8`. Separate the two expiry paths. |
| Expiry reload | `4226af` | Reload style after movement rather than retaining the initial style across `vec2_add`. |
| Expiry sound | `422712..422751` | Prepare the position argument before RNG, then reload the target ID for the sound-bank lookup. |
| Geometry | `422936..422983` | Construct displacement, previous position, and hit direction as vector values. Preserve which component is stored before each subtraction. |
| Hit position | `422963..422c43` | Retain the creature-position address through damage and subsequent effects. This also restores a spilled particle index, although its home and register allocation remain different. |
| Clamp | `422ab1..422b93` | An in-place pointer helper writes only out-of-range components and reloads stored color components. Returning a float adds writes on the in-range path. |
| Bubble copy | `4228ae..4228df` | Copy the SDK vector through its reference before zeroing velocity and publishing attachment fields. A POD member copy alone still permits the early zero stores. |
| Age | `42283f..42285d` | A conditional float expression recovers the common floating-point result store. |
| Angle branches | `4228e4..422936`, `422983..4229de` | Put the value on the native side of the comparison and preserve the native branch orientation. |
| Displacement | `422c05..422c43` | Materialize reflected velocity and the time value before the final scaled displacement. |
| RNG value | `422ba3..422be6` | Keep the first RNG result as an integer until the second draw; construct the float vector afterward. |

The age window has nine instructions and 30 bytes. The audit compares every
encoded byte except two four-byte addresses, verifies both referenced constants
as `1.0f`, and compares both local branch displacements without masking them.
This closes that instruction window, not the function.

## Native replay

The final candidate passes 8,934 cases under the existing suites' observation
contracts:

| Suite | Cases | Before differs from native | Recovered differs from native |
| --- | ---: | --- | --- |
| Particle impact | 1,230 | 25 state, 683 ordered-write traces | None |
| Particle impact with native damage and randomized FX | 663 | 336 ordered-write traces | None |
| Prior trajectories | 4,817 | None | None |
| Inactive-target bubble expiry | 224 | None | None |
| Primary movement | 1,000 | None | None |
| Primary impacts | 1,000 | 70 call traces | Same 70 call traces |

Each suite compares its complete represented pools and globals, ordered writes,
callback arguments, and RNG state. Its existing runner checks register/stack
restoration and x87 state and rejects unknown transfers and out-of-scope writes.
Layouts are compiler-checked where the suite provides a layout verifier.
`particle-integrated` runs native damage and randomized FX; final allocation and
audio remain the documented recording boundaries. The primary residual remains
the previously identified PC64 `2.5` decal-product boundary. No new native
failures or changes to the four regression suites are accepted.

These finite witnesses do not prove all reachable states, arbitrary callback
mutations, NaN behavior, complete game execution, or whole-function equivalence.

## Static debt remains explicit

The baseline has 2,192 candidate instructions versus 2,203 native, a `0xcc`
frame versus `0xf4`, and 437 verified / 8 mismatched positional references. The
combined candidate has 2,182 instructions, the same `0xcc` frame, and 446 verified
/ 7 mismatched references. Both exactness flags remain false.

The diagnostic aligns more native instructions after these recoveries, but
neither that count nor the whole-function percentage accepts a change. Remaining
work includes movement block placement, retained intensity versus field reloads,
early flag loads, geometry register assignment, the first tint clamp's constant
initialization, loop-end induction, and stack owners elsewhere in the function.
The six original reference mismatches outside the particle phase remain; a
seventh comparison mismatch is in the first clamp. The generated residual
summary is explicitly heuristic and does not equate stack displacements with
variables.

The full native extent remains `0x420b90..0x422c69` (8,409 bytes). No padding,
reference aliases, scope exclusions, compiler flags, or exactness rules changed.
