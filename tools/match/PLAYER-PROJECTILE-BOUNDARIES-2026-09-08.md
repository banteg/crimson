# Player and projectile native boundaries, 2026-09-08

This tranche compares against `5d47470f0`. It retains two source-matching gains
and corrects port behavior found while tracing the same native functions.
Original-image evidence uses the pinned GOG `crimsonland.exe` with SHA-256
`771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4`.

## Matching source

| Function | Before | After | Instruction count | Reference results (ok / unresolved / mismatch) |
| --- | ---: | ---: | --- | --- |
| `player_update` | 64.023210832% | 64.047388781% | 4066 / 4206 preserved | 805 / 0 / 2 preserved |
| `projectile_render` | 58.550626482% | 59.194039959% | 2885 / 3021 preserved | 448 / 0 / 10 → 456 / 0 / 10 |

The combined gain is 84.685434885 fuzzy-weighted bytes. Both functions remain
non-exact, including encoded-body exactness. This metric is not a count of
individually identical raw bytes.

`player_update` now expresses the native autoplay branch at `0x00414ccc` through
`0x00414cd7`: pursuit is the taken branch for distance at most 300; returning to
center falls through. Reversing the source predicate and arm order recovers the
native branch direction. Only 43 bytes of its 15,891-byte compiled body change,
within offsets `0x1525..0x1555`; the remaining bytes are identical. The complete
three-control branch/copy family retains the minimal branch-only change.

`projectile_render` had a semantic error despite its previous semantic-complete
label: all four conventional trail branches placed current position at vertices
0/1 and origin at 2/3. Native does the reverse. The corrected pairs improve
alignment while preserving the materialized vector lifetimes.
[Endpoint evidence](scratches/projectile_render/CONVENTIONAL-ENDPOINT-EVIDENCE-2026-09-08.md)
records the field offsets and each native branch address.

The ledgers retain 56 complete canonical-config mutation controls: 18 for player
branch/turn-scale ownership and 38 for trail endpoint/width/output ownership.
The extra three vector-angle controls used a separately documented alias config;
they do not masquerade as canonical-epoch experiments. Neither vector-angle form
improved the caller. Native helper bytes admit both explicit output pointers and
hidden object-return buffers; the old decorated-symbol claims were unsupported.
[Reproducible ABI evidence](evidence/vector-return-contract-2026-09-08/README.md)
records that ambiguity without changing the exact helper implementations.

## Alternate Weapon firing

Native captures ordinary readiness in `BL` at `0x00415753..0x00415778` and
perk-funded readiness in `[esp+0x12]` at `0x0041577f..0x004157be`. The latter
requires a ready cooldown, positive XP, and Regression Bullets or Ammunition
Within. Both flags survive Alternate Weapon's slot exchange and added cooldown
at `0x00415813..0x004158dd`.

At `0x0041590e..0x00415918`, firing uses those saved flags. The old ordinary flag
also decides whether to charge a perk at `0x0041594d..0x00415956`, but the cost
reads the incoming weapon at `0x0041596f` or `0x004159d3`.

Both ports preserved only ordinary readiness and recomputed perk readiness from
the incoming slot. A reloading Plasma Minigun with ready cooldown, positive XP,
and either funding perk could therefore suppress a valid Pistol shot on the
swap tick. Python and Zig now carry both readiness flags through the exchange,
including a closed snapshot. The incoming cooldown is no longer artificially
zeroed. Direct firing entry points capture current readiness instead.

The new swap regression tests failed with zero shots before the fix and now
produce one shot, deduct incoming ammo, and charge the appropriate perk. A Pistol
costs one HP for Ammunition Within; Flamethrower uses the 0.15 HP class. Ordinary
readiness takes precedence over perk funding, and Regression takes precedence
when both funding perks are present.

This also exposed Python's incorrect XP arithmetic. Native `FMUL` and `FSUBP`
at `0x004159ab` and `0x004159b1` round at the gameplay PC24 precision before
`_ftol` truncation. For XP 1000 and Pistol's stored reload time
`1.2000000476837158`, the product is `240.00001525878906` and subtraction rounds
to `760.0`. Python used double arithmetic and produced 759; it now uses the
existing PC24 arithmetic helpers, agreeing with Zig. The two older tests that
asserted 759 have been corrected. The gameplay precision contract is documented
in `docs/rewrite/float-parity-policy.md`.

The independent arithmetic review also recovered two integer-conversion edges.
Native `FILD` at `0x0041597a` preserves the exact signed XP integer until the
subtraction; Zig's previous `f32` conversion rounded it too early above `2^24`.
XP 16,777,217 with Pistol now leaves 16,776,977 in both ports. At the legal signed
maximum, Flamethrower's cost of 8 rounds the remaining value to `2^31` at PC24.
The native `_ftol` at `0x00461054` stores a qword but the caller takes EAX's low
32 bits, then clamps the signed-negative result at `0x00415a0b..0x00415a1f`.
Both ports now reproduce the resulting zero without Python exceeding signed
32-bit XP or Zig trapping during a checked integer conversion.

## Runtime trail rendering

Python and Zig already had the correct origin/current endpoint order. Their
runtime discrepancies were separate from the matching scratch error:

- Conventional width follows stored projectile velocity. The multipliers are
  Assault 1.0, Pistol 1.2, Gauss 1.1, and other conventional types 0.7.
- Gauss trail alpha is independent of entity transition alpha, including a zero
  transition. The native world caller sets zero transition and still calls
  `projectile_render` at `0x00405b95`. Python's outer world-render early return
  now preserves a Gauss-only pass inside the alpha-test scope; the regression
  test enters through `draw_world`, not just the individual projectile helper.
- Trail colors use the native byte conversion, including 0.5 becoming 127 and
  conversion after applying the relevant alpha factors.

Focused renderer tests verify geometry, endpoint color slots, UV ordering, and
transition behavior. Non-unit stored velocity distinguishes raw magnitude from
normalization, and life 0.5 with transition 0.4 distinguishes deferred byte
conversion (51) from premature conversion (50). Sprite opacity outside the
conventional trail path retains its existing policy.

## Verification scope

Native disassembly, compiled-object comparisons, regression tests, and structural
links establish the results above. No interactive gameplay or screenshot-based
visual validation is claimed for this tranche.

- The final checkpoint against `5d47470f0` passes with zero scope, claim,
  evaluation, metadata, experiment, strict-experiment, native, and regression
  errors. Only the two intended functions change. Port exactness remains
  793/810 normalized and 791/810 relocation-aware encoded-body exact; fuzzy
  weighted coverage is 316,262/341,992 bytes after integer report rounding.
- The refreshed full report compares all 2,437 function rows. Excluding COFF
  object hashes, which include rebuild metadata, only `player_update` and
  `projectile_render` change; neither loses instruction, reference, extent,
  or exactness evidence. Target/inventory/scoring identities and the complete
  data evidence are unchanged. Matched data remains 326,792/517,738 bytes.
- Both `worker-check --require-outcome` checks pass in isolated checkouts at the
  baseline, each overlaid only with its claimed final scratch. Each has one
  handled target, one outcome, and zero errors. The shared integration tree
  necessarily contains changes outside either individual worker's claim.
- The vector return-contract verifier was independently rerun successfully.
  No helper signature or translation-unit ownership claim is promoted.
- Both native audits pass and `native verify --require-game-closure` reports
  current artifacts with game-owned closure. Structural links succeed with
  612 EXE inputs and 167 Grim inputs, zero retained placeholders in either,
  and the existing 28 EXE / 4 Grim translation-unit clusters unchanged.
- The final Zig suite passes 677/677 tests in both Debug and ReleaseFast;
  native window and wasm builds pass in both modes.
- The full Python suite passes 2,905 tests with 13 skips and 135 passing
  snapshots. Ruff, type checks, import contracts, documentation checks,
  strict experiment validation, and all 35 ast-grep rule tests pass.
