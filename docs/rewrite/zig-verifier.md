---
tags:
  - rewrite
  - parity
  - zig
---

# Zig replay verifier status (`crimson-zig/`)

Last reviewed: **2026-02-24**

Scope target: fast, headless, deterministic verification for **1-player Survival**
replays on the latest ruleset (`preserve_bugs=false`), with native and
`wasm32-freestanding` targets.

## Ported in Zig (current)

- Replay ingestion from `.crd` bytes (msgpack decode path in-tree).
- Deterministic Survival sim scaffold + runtime loops for:
  - player/weapon runtime (reload/fire/ammo counters, level/XP progression),
  - survival spawn system,
  - creature updates,
  - primary/secondary projectile runtime,
  - bonus/perk runtime integration,
  - run-result assembly (`ticks`, `elapsed_ms`, `score_xp`, kills, weapon usage, RNG state).
- Verification is fully self-contained from replay bytes (no checkpoint/high-score
  sidecars).
- CLI surface: `crimson-zig replay verify <replay>` with human/json outputs and
  score-claim checking (`--submitted-score`), plus replay SHA-256 reporting.
- Wasm target build + export ABI for worker-side integration.
- Differential harness for tick-level Python-vs-Zig comparisons:
  - `uv run crimson-zig/scripts/diff_survival_verifiers.py ...`
- Unsupported/not-yet-ported replay paths hard-fail instead of silently accepting.

## Not fully ported / known parity gaps

- Zig verifier is still scoped to **1-player Survival** only:
  - no Rush/Quest replay verification,
  - no multiplayer replay verification,
  - no `preserve_bugs=true` compatibility layer.
- Replay compatibility is still under active expansion using differential captures;
  parity is strong on the current working set but not yet claimed for all unseen
  Survival captures.
- Mode/scope limits still apply:
  - latest ruleset only (`preserve_bugs=false`),
  - hard-fail behavior for unsupported paths remains intentional.

## Current replay parity snapshot (2026-02-24)

- `survival_20260224_062947_score12741.crd`
  - Python: `replay verification failed: perk_pick failed at tick=2833 choice_index=0`
  - Zig: `replay verification failed: perk_pick failed at tick=2833 choice_index=0`
- `survival_20260224_113737_score4032.crd`
  - Python and Zig both `ok` with exact summary match:
    - `ticks=34808 elapsed_ms=532112 score_xp=4032 kills=1498 most_used_weapon_id=20 shots_fired=10241 shots_hit=3035 rng_state=2592828730`
- `survival_20260224_223838_score134360.crd`
  - Python and Zig both `ok` with exact summary match:
    - `ticks=32213 elapsed_ms=448469 score_xp=134360 kills=1231 most_used_weapon_id=20 shots_fired=1718 shots_hit=1030 rng_state=4205621066`

## Performance snapshot

- On `survival_20260224_113737_score4032.crd` (local benchmark, 2026-02-24):
  - Python verifier: `37.85s` wall
  - Zig verifier: `6.78s` wall
  - Speedup: `~5.6x`
