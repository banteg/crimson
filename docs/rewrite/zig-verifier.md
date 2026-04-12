---
tags:
  - rewrite
  - parity
  - zig
---

# Zig native port status (`crimson-zig/`)

Last reviewed: **2026-04-12**

Scope target: a full native Zig port of Crimson systems, content, codecs, and
product surfaces.

For the staged remaining-work breakdown, see
[`docs/rewrite/zig-roadmap.md`](zig-roadmap.md).

Replay tooling is currently the most mature public entrypoint in the Zig tree,
not the definition of the project. Today that means fast, headless,
deterministic replay verification/info for **1-4 player Survival/Rush/Quest** and
**1-player Typ-o/Tutorial**
replays, including preserve-bugs compatibility mode, with explicit hard-fail
behavior for unsupported native paths.

## Ported in Zig (current)

- Native runtime work is aimed at full gameplay/content parity, not a verifier-only fork.
- Native architecture is being shaped to mirror the Python/runtime split where it
  makes sense, so replay tooling consumes shared gameplay/runtime modules instead
  of owning a separate simulation fork.
- Shared deterministic session/state ownership now lives in
  `crimson-zig/src/runtime/session.zig` plus `session_builders.zig`; replay
  commands use compatibility wrappers around that runtime-facing layer.
- The Zig builder layer now exposes explicit mode-oriented session constructors
  (`buildSurvivalSession`, `buildRushSession`, `buildQuestSession`) to mirror the
  Python rewrite structure instead of only offering replay-specialized startup.
- Replay ingestion from `.crd` bytes (msgpack decode path in-tree).
- Deterministic Survival/Rush/Quest/Typ-o/Tutorial sim scaffold + runtime loops for:
  - player/weapon runtime (reload/fire/ammo counters, level/XP progression),
  - survival/quest spawn systems,
  - creature updates,
  - primary/secondary projectile runtime,
  - bonus/perk runtime integration,
  - run-result assembly (`ticks`, `elapsed_ms`, `score_xp`, kills, weapon usage, RNG state).
- Native checkpoint/trace plumbing and raylib/bootstrap targets are in-tree as
  part of the same port effort.
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

- The most complete native fast path is still **1-4 player Survival/Rush/Quest**
  plus **1-player Typ-o/Tutorial**
  replay execution.
- Replay compatibility is still under active expansion using differential captures;
  parity is strong on the current working set but not yet claimed for all unseen
  Survival captures or all preserve-bugs-era captures.
- Menus, live presentation, and broader game-product surfaces are now real
  native Zig surfaces, but the remaining parity debt has shifted toward mode
  breadth, replay envelope breadth, and final product-shell fidelity.

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
