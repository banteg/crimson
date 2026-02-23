---
tags:
  - frida
  - differential-sessions
---

## Session 13 (2026-02-12)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.json.gz`
- **Capture SHA256:** `25ef6718185ed9615d1a172caec2870689148723bb27ab113caee0b170b22599`
- **First mismatch progression:**
  - sustained (`divergence-report`): `tick 6514 (rng_stream_mismatch, missing_tail=87)`
  - checkpoint-state verifier (`verify-capture`): `tick 6527 (players[0].experience +53)`

### Key Findings

- Baseline on current rewrite branch remains late-run divergent:
  - `divergence-report` focuses at `tick 6514` with `rand_calls(e/a)=722/635` and `capture_projectile_find_hit_count=8` vs `rewrite_hits=7`.
  - `verify-capture` first fails at `tick 6527` (`score_xp`/`players[0].experience` expected `42127`, actual `42180`).
- Existing capture telemetry is insufficient for the remaining root-cause around `tick 6514`:
  - `sample_creature_rows=313581`,
  - `sample_creature_rows_with_ai_lineage=0`,
  - `creature_lifecycle_rows=1613`,
  - `creature_lifecycle_rows_with_ai_lineage=0`.
- Spot checks at `tick 6514` confirm creature snapshots under `samples.creatures`, `projectile_find_hit.creature`, and `creature_damage`/`creature_death` payloads have no `ai_mode`/`link_index` lineage data, so AI7 timer/link transitions cannot be distinguished from replay/runtime drift.

### Landed Changes

- Added AI-lineage telemetry to capture instrumentation:
  - `scripts/frida/gameplay_diff_capture.js` now records `link_index`, `ai_mode`, `heading`, `target_heading`, `orbit_angle`, `orbit_radius`, and `ai7_timer_ms` in creature sample/lifecycle snapshots used by event heads and lifecycle deltas.
- Extended typed loader schema for creature samples:
  - `src/crimson/original/schema.py` (`CaptureCreatureSample`) now accepts optional AI-lineage fields.
- Surfaced lineage fields in diagnostics summaries:
  - `src/crimson/original/divergence_report.py` and `src/crimson/original/diagnostics_cache.py` now include AI-lineage fields in `sample_creatures_head` when present.
- Updated capture docs/playbook:
  - `docs/frida/gameplay-diff-capture.md` documents creature lineage telemetry.
  - `docs/frida/differential-playbook.md` telemetry quality snippet now reports lineage coverage for `samples.creatures` and `creature_lifecycle` rows.
- Added regression coverage:
  - `tests/test_original_capture_conversion.py` validates typed sample parsing with AI-lineage fields.
- Commit: `9ba15b93` (`fix(frida): capture creature ai lineage telemetry`).

### Validation

- `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30 --json-out analysis/frida/reports/capture_25ef6718_post_pr_baseline.json` *(expected non-zero exit while diverged)*
- `uv run crimson original verify-capture artifacts/frida/share/gameplay_diff_capture.json.gz --float-abs-tol 1e-3 --max-field-diffs 32` *(expected non-zero exit while diverged)*
- `uv run python - <<'PY' ...` telemetry quality check (key/perk + AI-lineage coverage) against `artifacts/frida/share/gameplay_diff_capture.json.gz`.
- `uv run pytest tests/test_original_capture_conversion.py -k 'strict_typed_sample_rows or player_fire_debug_payloads'`
- `uv run pytest tests/test_original_capture_divergence_report_rng_calls.py tests/test_original_diagnostics_cache.py`
- `just check`

### Outcome / Next Probe

- This capture SHA is now **abandoned for further parity root-cause work** near `tick 6514`: the required AI lineage telemetry was not present in the already-recorded artifact and cannot be reconstructed post hoc.
- Next session should start with a fresh `gameplay_diff_capture` recording using the patched script, then immediately gate on telemetry quality:
  - `sample_creature_rows_with_ai_lineage > 0`,
  - `creature_lifecycle_rows_with_ai_lineage > 0`.
- After a fresh capture passes that gate, repeat:
  - `divergence-report --run-summary-focus-context`,
  - `verify-capture`,
  - `focus-trace --tick <first sustained mismatch>`.

---

