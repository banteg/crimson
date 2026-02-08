# Differential Capture Sessions

Use this log for every original-vs-rewrite differential capture iteration.
Each entry should capture:

- Which recording was used (path + hash)
- Which verifier command was run
- First mismatch
- Evidence-backed findings
- Fixes landed because of that capture
- Remaining blockers / next probe

## Session template

- **Session ID:** `YYYY-MM-DD-<letter>`
- **Capture:** `<path>`
- **Capture SHA256:** `<sha256>`
- **Verifier command:** `<exact command>`
- **First mismatch:** `tick <n> (<fields>)`

### Findings

- `<finding 1>`
- `<finding 2>`

### Fixes from this session

- `<commit or file change>`
- `<commit or file change>`

### Next probe

- `<what to capture/check next>`

---

## Session 2026-02-08-a

- **Session ID:** `2026-02-08-a`
- **Capture:** `artifacts/frida/share/gameplay_diff_capture_v2.jsonl`
- **Capture SHA256:** `a40e7fed4ea7b4658d420bc31f6101307864c8de1b06f926d9ddf7c0010ac2ee`
- **Verifier command:** `uv run python scripts/original_capture_divergence_report.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --float-abs-tol 2e-3 --window 24 --lead-lookback 1024 --run-summary --json-out analysis/frida/divergence_report_latest.json`
- **First mismatch:** `tick 1794 (players[0].experience, score_xp)`

### Findings

- Rewrite awards an extra kill at tick `1794` (`+41 XP`) from the secondary-projectile path; the active rocket transitions to detonation and kills creature slot `25`.
- Native capture reports no `creature_damage`/`creature_death` telemetry at tick `1794`, so the rewrite kill is upstream drift, not just a missing reward mapping.
- Pre-divergence RNG drift is present in creature AI: rewrite consumes `crt_rand` in `creature_ai7_tick_link_timer` on tick `1791` while capture reports `rand_calls=0`; this advances timer/link branches for AI7 spiders before the kill divergence.

### Fixes from this session

- Added optional run narrative output to divergence tooling (`--run-summary`) in `scripts/original_capture_divergence_report.py`.
- Added summary extraction tests in `tests/test_original_capture_divergence_report_summary.py`.
- Added this running session ledger for capture evidence and fix provenance.

### Next probe

- Reconcile AI7 timer/link-index progression against native (`creature_update_all` / `creature_alloc_slot` semantics) to eliminate early RNG drift before tick `1794`.

---

## Session 2026-02-08-b

- **Session ID:** `2026-02-08-b`
- **Capture:** `artifacts/frida/share/gameplay_diff_capture_v2.jsonl`
- **Capture SHA256:** `a40e7fed4ea7b4658d420bc31f6101307864c8de1b06f926d9ddf7c0010ac2ee`
- **Verifier command:** `uv run python scripts/original_capture_divergence_report.py artifacts/frida/share/gameplay_diff_capture_v2.jsonl --float-abs-tol 1e-3 --window 12 --lead-lookback 512 --run-summary --json-out analysis/frida/divergence_report_latest.json`
- **First mismatch:** `tick 1794 (players[0].experience, score_xp)`

### Findings

- Focus tick `1794` has a large rewrite-only RNG burst: native `rand_calls=2`, rewrite consumes `184` draws.
- Stage attribution isolates almost all rewrite draws to `ws_after_projectiles -> ws_after_secondary_projectiles` (`182` draws), pointing directly at secondary projectile hit/explosion branches.
- Rewrite resolves a kill at tick `1794` (`creature_index=25`, `type_id=2`, `xp_awarded=41`, owner `-1`) while capture reports zero `creature_damage`/`creature_death` events on the same tick.

### Fixes from this session

- Extended `scripts/original_capture_divergence_report.py` to infer rewrite `rand_calls` from RNG marks and print `rand_calls(e/a/d)` in the divergence window.
- Added focus-tick rewrite diagnostics (stage-local RNG call breakdown + rewrite death ledger head) to the report output and JSON payload.
- Added RNG-call inference tests in `tests/test_original_capture_divergence_report_rng_calls.py`.

### Next probe

- Capture a focused run around tick `1794` with entity samples enabled so native projectile/creature positions can be compared directly:
  `CRIMSON_FRIDA_V2_FOCUS_TICK=1794 CRIMSON_FRIDA_V2_FOCUS_RADIUS=64`.
