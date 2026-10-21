---
tags:
  - rewrite
  - contracts
---

# Rules 2 rollout and historical playback plan

Status: implemented in the second layer of the post-RTX stack, pending review
and merge. Rules 1 and 2 play through explicit profiles in Python, native/WASM,
and the game. Compatibility is tracked in
[#833](https://github.com/banteg/crimson/issues/833); the pellet-conversion
extension [#832](https://github.com/banteg/crimson/issues/832) is the next layer.
Keep the whole stack out of the RTX release; it targets the release after it.

## Selected behavior

New runs default to rules 2. Recorded rules select playback and verification.
Keep rules-1 leaderboard entries, scores, IDs, timestamps and signed replay bytes.
The board presentation combines both versions, labels each run and
offers an optional rules filter. A new season does not require a reset or
retirement of valid historical results. This is a product decision to compare
the versions together, not a claim that their balance is mathematically equal.

| Run policy | Simulation |
| --- | --- |
| Rules 1, default | Previous default fixes, before this bundle |
| Rules 2, default | Previous default plus the bundle and adopted pellet conversion |
| Either rules version, `preserve_bugs` | Original branches for these fixes |

`preserve_bugs` cannot stand in for rules 1: it also disables fixes that were
already part of the previous default. Unknown rules versions remain errors.
Replay encoding stays at format 34; its existing `rules` field is sufficient.

## Implementation

1. **Establish historical witnesses.** Retain old fixtures and checksums exactly.
   Use the pinned pre-bundle source/core as an oracle. The co-op manual-reload
   fix (original bug 40) changed behavior during rules 1 without a version bump.
   Identify affected recordings and verified build provenance before promising
   full compatibility. If necessary, use a small deterministic provenance map
   for that exception; report unknown affected provenance explicitly. Do not
   select whichever simulation happens to match a claimed result.
2. **Introduce explicit profiles.** Resolve a supported rules profile once at
   run initialization in Python and the core. Gate only this bundle's changes.
   For example, rules 1 retains the earlier Stationary Reloader correction but
   its strict-negative completion boundary; rules 2 adds exact-zero completion.
   Similarly, keep the previous Jinxed pool-size fix in both profiles. Use named
   policy predicates rather than separate user switches for each fix.
3. **Carry the profile through every entry point.** The config carries explicit rules and legacy co-op reload words
   in `PortableConfig` (272 bytes), with matching encoders and size assertions.
   Reject unsupported values at initialization. Python playback must pass
   `Replay.rules` through run initialization rather than just checking it.
   Record the actual active rules, and retain them through reset, keyframes,
   rollback, seek, retry and practice takeover. Co-op setup must agree on rules;
   snapshots/hashes must include the selected profile. A fresh ordinary run
   returns to the current default, while continuation retains its source rules.
4. **Separate identity from transport layout.** The service currently hashes a
   66-word config/input stream, removing the player-count word for solo legacy
   identity. Freeze that exact rules-1 algorithm. For rules 2+, hash a documented
   domain tag, rules number and canonical run/input serialization. Internal ABI
   changes must not change old IDs. Identical inputs under two rules versions
   must not collide. Preserve payload hashes and signatures without rewriting
   recorded bytes.
5. **Persist rules and dispatch verification.** Store a rules column and API field.
   The additive migration defaults pre-release records to rules 1: the deployed
   service accepted only rules 1 before this release. New uploads always write
   their explicit rules. Preserve IDs,
   accepted times, scores and visibility. Service verification and quest-result
   derivation use the selected profile. The quest breakdown UI can then use
   recorded rules instead of inferring the formula from the score. Accept both
   supported versions, and check historical results under their own behavior.
6. **Next layer: adopted pellet conversion.** In rules 2 default, Gauss Shotgun
   produces six Fire Bullets at its normal 1.05-second base cooldown; Multi-Plasma
   produces five at its normal approximately 0.6208117-second cooldown. Preserve
   rules-1 counts (one and three) and cadence under legacy/original policies.
   Resolve an effective conversion count without mutating shared legacy weapon
   metadata. Use it consistently for emission, cooldown and shot accounting;
   review the pellet-dependent muzzle branch explicitly. Keep normal firing,
   casing flags, existing spread/perk modifiers and Fire Bullets ammo suppression.
   Piercing damage-pool semantics remain a separate decision (#820).

## Validation and rollout

- Run rules 1/2 × default/preserve × solo/co-op parity through Python, native,
  WASM and game/verifier paths. Retain historical fixture results/checkpoints;
  create new fixtures for the final rules-2 behavior.
- Exercise watch, seek, practice continuation, retry, recording and co-op
  rollback in both profiles. Alternate profiles in the reused service verifier
  instance to detect state leaking across initialization.
- Test conversion counts, RNG draws, repeated-fire cadence, ammo, perk modifiers,
  pool pressure and shot accounting for both weapons with/without Fire Bullets.
- Lock exact legacy ID vectors, distinct cross-rules identities, and migration
  tests preserving old rows/results/visibility. Validate pre/post-manual-reload
  witnesses and unsupported-provenance diagnostics separately.
- Reverify stored runs with their selected profile before rollout. Treat any
  mismatch as a compatibility investigation, not automatic evidence that the
  historical record is invalid. Existing moderation policy remains separate.
- Ship client and verifier support together before making new rules-2 uploads
  available. Use one rules bump for the whole unreleased bundle. The earlier
  validation results cover the current nine-fix implementation, not these
  compatibility and conversion changes; their checks are recorded in each PR.

Splitter ownership/exclusion, Pistol/My Favourite Weapon drops and bounded
Plague transmission remain recommended extensions in the
[triage](original-bugs-triage.md#follow-up-review-recommendations-beyond-the-implemented-bundle).
They are not implicitly included by adopting the two pellet conversions.

## Historical reload provenance

The co-op manual-reload fix landed at `99cc34261` during 0.18.0 development.
Published releases through 0.18.0 use the old behavior; 0.19.0 and later use the
fix. The exact service-vector identity
`0.18.0+build.64a9589f5fbefdc036f0559b`, introduced at `bde24bef7` after that fix,
is explicitly mapped to the corrected behavior. Other 0.18 development identities
are refused for rules-1 default co-op until provenance is established. Solo,
original policy and rules 2 do not require this exception. This is an explicit
compatibility limitation, not a leaderboard retirement policy.

The two `rules1-ranked-*` fixtures preserve the exact service payloads at
`c0565b0b4e74c9aed422f23ddd9328027967cbc0`, with their original run-ID witnesses.
Rules-2 identity is SHA-256 over UTF-8 `crimson:run:rules` plus a NUL byte,
a little-endian uint32 rules number, and the old 66-word transport including
player count followed by its quest/input bytes. Rules 1 retains its earlier
solo/co-op identity algorithm byte for byte. Internal profile words are excluded.
