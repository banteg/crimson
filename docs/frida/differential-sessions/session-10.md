---
tags:
  - frida
  - differential-sessions
---

## Session 10 (2026-02-12)

- **Capture:** `/Users/banteg/syncthing/frida/gameplay_diff_capture.json.gz`
- **Capture SHA256:** `8d6cb578c32252b536971a12891e7701b22e3d2b3117015bca1f38567849aa41`
- **First mismatch:** `n/a (tooling/performance session)`

### Key Findings

- Baseline uncached timings on this capture:
  - `uv run crimson original divergence-report <capture> --no-cache`: `56.34s`.
  - `uv run crimson original divergence-report <capture> --no-cache --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30`: `75.24s`.
  - `uv run crimson original focus-trace <capture> --tick 389 --no-cache`: `19.73s`.
  - `uv run crimson original focus-trace <capture> --tick 10000 --no-cache`: `69.75s`.
- Cached daemon timings after clearing sidecars and restarting cold:
  - cold: `divergence-report` triage command `44.51s`.
  - hot: same `divergence-report` triage command `0.20s`.
  - `focus-trace --tick 389`: `0.71s`.
  - nearby `focus-trace --tick 390`: `0.17s`.
  - backward-nearby `focus-trace --tick 388`: `0.19s`.
  - far `focus-trace --tick 10000`: `52.47s`.
  - adjacent after far `focus-trace --tick 10001`: `0.17s`.

### Landed Changes

- Added hybrid cache daemon + sidecar caching for `original divergence-report` and `original focus-trace`.
- Added `--no-cache` opt-out and environment knobs:
  - `CRIMSON_ORIGINAL_CACHE=0|1`
  - `CRIMSON_ORIGINAL_CACHE_DIR`
  - `CRIMSON_ORIGINAL_CACHE_SOCKET`
- Added daemon fallback behavior to preserve local in-process execution when cache mode is unavailable.

### Validation

- `uv run pytest tests/test_original_diagnostics_cache.py tests/test_original_diagnostics_daemon.py`
- `uv run ruff check src/crimson/original/diagnostics_cache.py src/crimson/original/diagnostics_daemon.py src/crimson/original/divergence_report.py src/crimson/original/focus_trace.py src/crimson/cli.py tests/test_original_diagnostics_cache.py tests/test_original_diagnostics_daemon.py`
- `uv run crimson original divergence-report /Users/banteg/syncthing/frida/gameplay_diff_capture.json.gz --no-cache`
- `uv run crimson original divergence-report /Users/banteg/syncthing/frida/gameplay_diff_capture.json.gz --no-cache --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30`
- `uv run crimson original focus-trace /Users/banteg/syncthing/frida/gameplay_diff_capture.json.gz --tick 389 --no-cache`
- `uv run crimson original focus-trace /Users/banteg/syncthing/frida/gameplay_diff_capture.json.gz --tick 10000 --no-cache`
- `uv run crimson original divergence-report /Users/banteg/syncthing/frida/gameplay_diff_capture.json.gz --float-abs-tol 1e-3 --window 24 --lead-lookback 1024 --run-summary-short --run-summary-focus-context --run-summary-focus-before 8 --run-summary-focus-after 4 --run-summary-short-max-rows 30` (cold + hot)
- `uv run crimson original focus-trace /Users/banteg/syncthing/frida/gameplay_diff_capture.json.gz --tick 389`
- `uv run crimson original focus-trace /Users/banteg/syncthing/frida/gameplay_diff_capture.json.gz --tick 390`
- `uv run crimson original focus-trace /Users/banteg/syncthing/frida/gameplay_diff_capture.json.gz --tick 388`
- `uv run crimson original focus-trace /Users/banteg/syncthing/frida/gameplay_diff_capture.json.gz --tick 10000`
- `uv run crimson original focus-trace /Users/banteg/syncthing/frida/gameplay_diff_capture.json.gz --tick 10001`

### Outcome / Next Probe

- Hot-path targets are met for repeated same-capture diagnostics (`<=2s divergence hot`, `<=1s nearby focus hot`).
- Remaining cold-path bottleneck is far-tick focus replay stepping; next optimization should prioritize stronger anchor coverage or compact state snapshot restore for long-range random tick access.

---

