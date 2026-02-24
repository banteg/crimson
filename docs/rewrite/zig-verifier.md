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
- CLI surface: `crimson-zig replay verify <replay>` with human/json outputs and
  score-claim checking (`--submitted-score`), plus replay SHA-256 reporting.
- Wasm target build + export ABI for worker-side integration.
- Differential harness for tick-level Python-vs-Zig comparisons:
  - `uv run crimson-zig/scripts/diff_survival_verifiers.py ...`

## Not fully ported / known parity gaps

- Zig verifier does **not** yet hard-match Python for all Survival replays.
- Known examples as of 2026-02-24:
  - `survival_20260224_062947_score12741.crd`:
    - Python: fails (`perk_pick failed at tick=2833 choice_index=0`).
    - Zig: currently reports `ok` (incorrect acceptance path still present).
  - `survival_20260224_113737_score4032.crd`:
    - Both complete and agree on most fields.
    - Zig `shots_fired` is currently low (`10233` vs Python `10241`).
- Mode/scope limits still apply:
  - no Rush/Quest replay verification,
  - no multiplayer replay verification,
  - no `preserve_bugs=true` compatibility layer.

## Performance snapshot

- On `survival_20260224_113737_score4032.crd` (local benchmark, 2026-02-24):
  - Python verifier: `37.85s` wall
  - Zig verifier: `6.78s` wall
  - Speedup: `~5.6x`
