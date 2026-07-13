---
tags:
  - frida
  - differential-sessions
---

## Session 1 (2026-02-08)

- **Legacy IDs:** `2026-02-08-a` .. `2026-02-08-e`
- **Capture:** `artifacts/frida/share/gameplay_diff_capture.json`
- **Capture SHA256:** `a40e7fed4ea7b4658d420bc31f6101307864c8de1b06f926d9ddf7c0010ac2ee`
- **Baseline verifier command:**
  `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-short-max-rows 20 --json-out`
- **First mismatch:** `tick 1794 (players[0].experience, score_xp)`

### Key Findings

- Rewrite awarded a rewrite-only kill at tick `1794` (`+41 XP`), tied to secondary projectile behavior.
- Pre-divergence RNG drift existed in AI7 timer paths, but disabling that behavior caused earlier regressions (not root fix).
- Capture coverage was initially insufficient for direct geometry/hit-resolution comparison at divergence ticks.

### Landed Changes

- Added divergence tooling upgrades:
  - `--run-summary` and later `--run-summary-short` outputs.
  - rewrite RNG-call inference and stage-attribution diagnostics.
  - sample-coverage/blocker reporting in divergence output.
- Added capture telemetry:
  - secondary projectile spawn hooks and secondary sample capture.
- Landed gameplay parity patch in `src/crimson/projectiles.py` for native-like secondary homing target semantics (active + lifecycle-stage sentinel behavior).

### Outcome / Next Probe

- Session closed when a new recording moved divergence to a later and different profile (`tick 3504` on next SHA), indicating this capture family had been exhausted.

---
