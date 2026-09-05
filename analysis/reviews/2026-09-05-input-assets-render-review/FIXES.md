# Input, assets, and rendering follow-up

## Changes

- `1713aa7ae` — resolve local fire presses into one-tick firing actions. Mouse-wheel
  bindings and clicks released before the next simulation tick now fire. Pending
  presses survive zero-tick frames, catch-up ticks retain only held state, and
  the existing replay encoding records the resolved action.
- `aabfc7b1f` — require complete PAQ input consumption. Truncated names, sizes,
  payloads, and trailing garbage now raise a decoding error with a stream offset.
- `52dc640e8` — roll back partial runtime texture loads, including texture-setting
  failures. GPU-upload failures release the CPU image. Font widths are validated
  before GPU allocation. Resource ownership transfers only after loading succeeds.
- `b4309e125` — remove `WorldRenderer`, its viewport cache and synchronization calls,
  the unused context back-reference, per-projectile context cloning, duplicate
  projection fields, and forwarding helpers. `ViewTransform` captures a draw's
  geometry; runtime coordinate conversions derive it from current camera and window
  dimensions. `WorldDrawContext` retains only pass-specific textures and settings.

## Verification

- Focused input coverage: 91 tests, including both wheel directions through binding
  capture, interpretation, the local tick provider, and real Tutorial simulation.
- Asset failure and decoder coverage: 15 tests. Actual local archives decode:
  `crimson.paq` and `crimson-uncompressed.paq` (79 entries each), `music.paq` (10),
  and `sfx.paq` (73). Both game archives contain the expected 256 font widths.
- Rendering, modes, replay, and simulation regressions: 827 passed, 10 skipped;
  50 snapshots passed. Tests include resize/camera coordinate round trips and a
  prepared transform remaining stable when the live viewport changes.
- [render_trace.py](render_trace.py) records ordered draw commands and their values
  from the actual world draw path. It includes living/dead players, creature types,
  primary and secondary projectile types, and Monster Vision. The GPU calls and
  ground draw are substituted with recorders; this is not a pixel comparison.
  All nine traces (three resolutions by three fade levels) are byte-identical
  between pre-refactor commit `52dc640e8` and the refactored code. Digests are in
  [render-trace-results.json](render-trace-results.json).

Run the trace with `uv run --no-sync python analysis/reviews/2026-09-05-input-assets-render-review/render_trace.py`.
For the baseline, extract `git archive 52dc640e8 src` into a temporary directory
and set `PYTHONPATH` to its `src` directory when running the same script.

## Final repository gate

`UV_CACHE_DIR=/private/tmp/crimson-uv-cache ZIG_GLOBAL_CACHE_DIR=/private/tmp/crimson-review-zig-cache just check` passed:

- 2,654 Python tests passed, 10 skipped; 135 snapshots passed.
- 652 Zig tests passed; ReleaseFast and WASM builds passed.
- Ruff, import boundaries, types, docs, structural rules and their fixtures passed.
- Matching experiment validation, native artifact verification, and matching
  regressions passed. These check repository evidence rather than executing a
  fresh original-game capture.
- `uv build` produced the source distribution and wheel successfully.

No fresh original-game capture or interactive visual playtest was performed.
