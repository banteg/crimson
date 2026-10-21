---
tags:
  - rewrite
  - contracts
---

# Rules 2 rollout and historical playback plan

Status: approved direction, implementation pending. The nine fixes in
[#829](https://github.com/banteg/crimson/issues/829) are implemented in the
working tree, but current playback and upload gates still reject rules 1.
Compatibility is tracked in [#833](https://github.com/banteg/crimson/issues/833);
the adopted Fire Bullets extension is
[#832](https://github.com/banteg/crimson/issues/832).

## Selected behavior

New runs default to rules 2. Recorded rules select playback and verification.
Keep rules-1 leaderboard entries, scores, IDs, timestamps and signed replay bytes.
The proposed board presentation combines both versions, labels each run and
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

## Implementation sequence

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
3. **Carry the profile through every entry point.** Add an explicit rules word
   to `PortableConfig`, updating its size assertions and all encoders together.
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
5. **Persist rules and dispatch verification.** Add a rules column and API field;
   backfill from retained payloads when provenance is ambiguous. Preserve IDs,
   accepted times, scores and visibility. Service verification and quest-result
   derivation use the selected profile. The quest breakdown UI can then use
   recorded rules instead of inferring the formula from the score. Accept both
   supported versions, and check historical results under their own behavior.
6. **Add the adopted pellet conversion.** In rules 2 default, Gauss Shotgun
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
  planned compatibility and conversion changes.

Splitter ownership/exclusion, Pistol/My Favourite Weapon drops and bounded
Plague transmission remain recommended extensions in the
[triage](original-bugs-triage.md#follow-up-review-recommendations-beyond-the-implemented-bundle).
They are not implicitly included by adopting the two pellet conversions.
