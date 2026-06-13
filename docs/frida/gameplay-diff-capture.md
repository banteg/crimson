---
tags:
  - status-validation
  - frida
  - differential-testing
---

# Gameplay Differential Capture

`scripts/frida/gameplay_diff_capture.js` captures deterministic gameplay ticks.
It now writes a single JSONL stream with explicit lifecycle markers:

- `session_start`
- `run_start`
- `tick`
- `run_end`
- `session_end`

The host (`scripts/frida/gameplay_diff_capture_host.py`) finalizes that JSONL
into one or more native `.cdt` traces plus matching `.crd` replay files via
`crimson.dbg.frida_finalize`.

## Attach via host (recommended)

```text
uv run --with frida python scripts/frida/gameplay_diff_capture_host.py \
  --process crimsonland.exe \
  --script scripts\frida\gameplay_diff_capture.js \
  --output-dir C:\share\frida
```

(`--with frida` injects the frida package; the host otherwise runs in the
project env. `just frida-gameplay-diff-capture` wraps the same invocation.
Pass host flags after `--`, for example
`just frida-gameplay-diff-capture -- --keep-raw`.)

Optional flags:

- `--raw-path <path>`: override JSONL path (otherwise host uses script stats `out_path`)
- `--finalize-only`: skip attaching and finalize an existing raw JSONL (use with `--raw-path`; works without the game running and without frida installed)
- `--keep-raw`: keep JSONL after successful finalize

## Direct attach

```text
frida -n crimsonland.exe -l scripts\frida\gameplay_diff_capture.js
```

Default raw output:

- `C:\share\frida\gameplay_diff_capture.jsonl`

If you direct-attach, run the host once afterwards with `--raw-path` to finalize to `.cdt/.crd`.

## Finalized output

Finalizer emits one `.cdt` + `.crd` pair per run boundary:

- mode runs:
  - `gameplay_diff_capture.survival.run<k>.cdt` + `gameplay_diff_capture.survival.run<k>.crd`
  - `gameplay_diff_capture.rush.run<k>.cdt` + `gameplay_diff_capture.rush.run<k>.crd`
  - unknown modes fall back to `mode_<id>`
- quest runs:
  - `gameplay_diff_capture.quest_<major>_<minor>.run<k>.cdt`
  - `gameplay_diff_capture.quest_<major>_<minor>.run<k>.crd`

These traces are directly consumable by:

- `uv run crimson dbg health`
- `uv run crimson dbg diff`
- `uv run crimson dbg bisect`
- `uv run crimson dbg focus`

## Replay seeding (capture format v13)

The session `crt_srand` seed is stale by the time a run starts (menus and
earlier runs already consumed draws), so the capture latches the rand state
observed before the run's first terrain draw (`0x004181cc`, the
terrain-generate prelude roll) and stamps it on `run_start` as
`rng_state_at_run_setup`. Finalize seeds the `.crd` replay header from that
state (`run_start_seed_source=run_setup_rng_state` in the trace meta), which
replays the run's setup draws — terrain stamps and quest build included —
value-for-value.

## RNG evidence (capture format v13)

The capture reads the real CRT rand state from memory (per-thread data +
0x14 via `_getptd`) rather than trusting a software mirror, so draws that
bypass the `crt_rand` hook are observable:

- `rng_stream` rows carry real `state_before_u32`/`state_after_u32`; unhooked
  draws appear as LCG chain gaps between consecutive rows.
- tick rows carry `rng_calls` (must equal the stream length),
  `rng_state_enter_u32`/`rng_state_leave_u32` (gpur boundary samples), and
  `rng_outside_before` (hooked draws between gpur windows: exhaustive
  per-caller counts plus a capped detail head).
- `run_end` rows flush the pending outside draws as `rng_outside_tail`.

Finalize validates all of it and writes a `.rng_evidence.json` report next to
each `.cdt`: outside-draw caller counts plus unhooked-draw counts split into
in-tick and boundary, with the hooked callers that bracket each gap. That
report is the worklist of rng behavior the port does not model yet.

## Test fixtures

`just capture-fixtures-import <captures_dir>` (wraps
`scripts/import_capture_fixtures.py`) imports finalized `.cdt`/`.crd` pairs into
`tests/fixtures/captures/`: the full replay sidecar, a trimmed window of the
native trace (default 64 ticks), and a `manifest.json` with provenance
(`seed_aligned` reflects whether the capture seeded from the run-setup rand
state).

`tests/replay/test_original_capture_fixture_parity.py` consumes the fixtures
(opt-in via `--run-replay-fixtures`): a passing ratchet asserts the first
gameplay rng draw replays exactly, and a strict windowed `dbg diff` is marked
xfail until the known native parity gaps (unhooked rng draws, run-start weapon
state, raw f32 channel encodings) are closed.

## Notes

- Legacy `dbg import-capture`, `replay convert-capture`, and postpack flow are removed.
- JSONL capture is now treated as a strict owned wire contract. Replay-grade rows are `session_start`, `run_start`, `tick`, `run_end`, and `session_end`; contract violations are capture errors, not finalize-time cleanup work.
- JSONL tick rows carry the finalized replay channels (`checkpoint`, `rng_stream`, `timing_samples`, `sim_state`, `entity_samples`) plus replay-grade packed inputs (`replay_inputs`) so replay sidecars can be generated losslessly.
- `replay_inputs` are derived from captured input intent, not post-simulation movement approximation. `input_approx` remains diagnostic-only.
- `timing_samples` are replay-grade timing evidence. Each captured tick must include a `gpur_enter` row, and tick timing is derived from that row rather than from fallback diagnostics.
- Raw capture diagnostics live in one top-level `diagnostics` bag. Replay checkpoints no longer mirror those fields under `checkpoint.debug`.
- `rng_stream` and `checkpoint.rng_state` are the only replay-significant RNG authorities. Legacy RNG summaries are diagnostic-only.
- Finalization normalizes entity UID/generation tracking so entity timelines are stable across runs.
