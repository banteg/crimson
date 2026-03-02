---
tags:
  - rewrite
  - parity
  - zig
---

# Zig replay verifier status (`crimson-zig/`)

Last reviewed: **2026-02-26**

Scope target: fast, headless, deterministic verification with a native fast-path
for latest-ruleset **1-4 player Survival/Rush/Quest** replays (`preserve_bugs=false`),
with explicit hard-fail behavior for unsupported native paths.

## Ported in Zig (current)

- Replay ingestion from `.crd` bytes (msgpack decode path in-tree).
- Deterministic Survival/Rush/Quest sim scaffold + runtime loops for:
  - player/weapon runtime (reload/fire/ammo counters, level/XP progression),
  - survival/quest spawn systems,
  - creature updates,
  - primary/secondary projectile runtime,
  - bonus/perk runtime integration,
  - run-result assembly (`ticks`, `elapsed_ms`, `score_xp`, kills, weapon usage, RNG state).
- Verification is fully self-contained from replay bytes (no checkpoint/high-score
  sidecars).
- Deterministic Rush spawn runtime path (`tick_rush_mode_spawns`) ported in Zig.
- Deterministic Quest spawn tables and runtime progression hooks ported in Zig.
  - Quest spawn builder logic is full-version-only in Zig (no shareware-gated branch path).
- Multiplayer gameplay logic and perk gating parity achieved.
- CLI surface: `crimson-zig replay verify <replay>` with human/json outputs,
  intrinsic replay-header claimed-stats checking, plus replay SHA-256 reporting.
- Wasm target build + export ABI for worker-side integration.
- Unsupported/not-yet-ported native paths hard-fail instead of silently accepting.

## Runtime ownership model (Zig rewrite)

- Internal gameplay runtime uses a typed owner union (`OwnerRef`) instead of raw
  magic owner IDs.
  - `OwnerRef.player{index, local_host}`
  - `OwnerRef.creature{index}`
  - `OwnerRef.none`
- Legacy owner-id encoding (`-100`, `-1-n`, `>=0`) is treated as an interop
  format only, not the internal simulation representation.
- Any required legacy serialization/trace surface is emitted by explicit
  conversion (`OwnerRef.toLegacy()`) at boundaries.

## Not fully ported / known parity gaps

- Native fast path is still scoped to **1-4 player Survival/Rush/Quest**:
  - no native `preserve_bugs=true` compatibility layer.
- Replay compatibility is still under active expansion using differential captures;
  parity is strong on the current working set but not yet claimed for all unseen
  Survival captures.
- Mode/scope limits still apply to the **native** path:
  - latest ruleset only (`preserve_bugs=false`).

## Current replay parity snapshot (2026-02-25)

- Older-version captures are no longer used as acceptance inputs for the latest
  ruleset verifier status.
- `survival_20260224_113737_score4032.crd`
  - Python and Zig both `ok` with exact summary match:
    - `ticks=34808 elapsed_ms=532112 score_xp=4032 kills=1498 most_used_weapon_id=20 shots_fired=10241 shots_hit=3035 rng_state=2592828730`
- `survival_20260224_223838_score134360.crd`
  - Python and Zig both `ok` with exact summary match:
    - `ticks=32213 elapsed_ms=448469 score_xp=134360 kills=1231 most_used_weapon_id=20 shots_fired=1718 shots_hit=1030 rng_state=4205621066`
  - Differential harness (`--skip-build`) reports exact tick parity:
    - `match: ticks=32213`

## Performance snapshot (2026-02-25)

`hyperfine './crimson-zig/zig-out/bin/crimson-zig replay verify survival_20260224_223838_score134360.crd' 'uv run crimson replay verify survival_20260224_223838_score134360.crd'`

```text
Benchmark 1: ./crimson-zig/zig-out/bin/crimson-zig replay verify survival_20260224_223838_score134360.crd
  Time (mean ± σ):     564.1 ms ±  10.0 ms    [User: 555.5 ms, System: 2.5 ms]
  Range (min … max):   555.0 ms … 588.7 ms    10 runs

Benchmark 2: uv run crimson replay verify survival_20260224_223838_score134360.crd
  Time (mean ± σ):     31.599 s ±  0.550 s    [User: 31.268 s, System: 0.115 s]
  Range (min … max):   30.912 s … 32.871 s    10 runs

Summary
  ./crimson-zig/zig-out/bin/crimson-zig replay verify survival_20260224_223838_score134360.crd ran
   56.02 ± 1.39 times faster than uv run crimson replay verify survival_20260224_223838_score134360.crd
```
