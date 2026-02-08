# Branch Wrap Handoff (2026-02-08)

This file is the handoff for wrapping `feat/rng` and continuing differential
investigation in a fresh branch after merge.

## Why wrap now

- Current branch contains useful verifier tooling, capture improvements, and
  concrete root-cause evidence.
- Remaining divergence work is now mostly math/precision parity and will be
  invasive; it is cleaner to continue from a new branch after merge.

## Confirmed finding to carry forward

- First stable root cause is precision drift in creature movement math:
  native x87 extended precision (`fsin`/`fcos`/`fpatan`) plus float stores vs
  Python `float64` math.
- That drift flips a borderline collision, which consumes different
  presentation RNG and permanently desynchronizes the single shared RNG stream.
- The later gameplay mismatch is a downstream consequence of earlier RNG drift,
  not an isolated reward bug.

Reference analysis:
- `docs/frida/rng-divergence-root-cause.md`

## Non-negotiables for next branch

1. Treat native math precision/rounding behavior as first-class parity scope.
2. Keep one RNG stream for gameplay and presentation (native-like).
3. Keep headless verification first-class while still executing RNG-consuming
   presentation command generation.
4. Keep capture defaults full-detail and unlimited enough to avoid losing rare
   edge cases.
5. Keep docs/session ledger updated on every recording-driven fix.
6. Use Ghidra decompile as authoritative when behavior is ambiguous.

## Target architecture direction

- Input stream -> deterministic simulation step -> presentation command stream.
- The same simulation step powers:
  - interactive play (commands rendered + SFX played),
  - replay playback (inputs from file),
  - headless verification (commands discarded).
- Presentation command generation must stay in deterministic step order so RNG
  consumption matches native regardless of render mode.

## Suggested next-branch execution plan

1. Add precision-parity primitives for sim-critical math.
   - Explicit float32 boundaries where native stores float fields.
   - Controlled trig/atan path that mimics native rounding behavior as closely
     as practical.
2. Apply parity primitives in creature movement/heading update paths first.
3. Re-run divergence report on latest capture and confirm whether first
   shortfall tick moves or disappears.
4. If still diverging, use focus trace to isolate next earliest RNG shortfall
   and patch in small behavior-accurate increments.
5. Keep each fix and each capture-script change in separate commits.

## Verifier/capture quality requirements

- Divergence report should keep producing:
  - first mismatch,
  - first pre-focus RNG shortfall,
  - dominant native caller buckets,
  - short run narrative (bonus/weapon/perk/level state highlights).
- Capture script defaults should avoid sample caps that can hide rare branches.
- Add focused telemetry only when needed, but do not reduce baseline capture
  detail.

## Merge handoff checklist

1. Merge `feat/rng`.
2. Start new branch from updated `master`.
3. Re-run baseline divergence command on current capture.
4. Append a new entry in `docs/frida/differential-sessions.md` for the first
   post-merge run.
5. Continue until either:
   - full verification passes, or
   - a concrete capture omission is proven and script updates are required.

## Practical commands (baseline)

```bash
uv run python scripts/original_capture_divergence_report.py \
  artifacts/frida/share/gameplay_diff_capture_v2.jsonl \
  --float-abs-tol 1e-3 \
  --window 24 \
  --lead-lookback 1024 \
  --run-summary-short \
  --run-summary-short-max-rows 30 \
  --json-out analysis/frida/divergence_report_latest.json
```

