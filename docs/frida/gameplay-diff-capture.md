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
uv run scripts/frida/gameplay_diff_capture_host.py \
  --process crimsonland.exe \
  --script scripts\frida\gameplay_diff_capture.js \
  --output-dir C:\share\frida
```

Optional flags:

- `--raw-path <path>`: override JSONL path (otherwise host uses script stats `out_path`)
- `--keep-raw`: keep JSONL after successful finalize

## Direct attach

```text
frida -n crimsonland.exe -l C:\share\frida\gameplay_diff_capture.js
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

## Notes

- Legacy `dbg import-capture`, `replay convert-capture`, and postpack flow are removed.
- JSONL capture is now treated as a strict owned wire contract. Replay-grade rows are `session_start`, `run_start`, `tick`, `run_end`, and `session_end`; contract violations are capture errors, not finalize-time cleanup work.
- JSONL tick rows carry the finalized replay channels (`checkpoint`, `rng_stream`, `timing_samples`, `sim_state`, `entity_samples`) plus replay-grade packed inputs (`replay_inputs`) so replay sidecars can be generated losslessly.
- `replay_inputs` are derived from captured input intent, not post-simulation movement approximation. `input_approx` remains diagnostic-only.
- `timing_samples` are replay-grade timing evidence. Each captured tick must include a `gpur_enter` row, and tick timing is derived from that row rather than from fallback diagnostics.
- Raw capture diagnostics live in one top-level `diagnostics` bag. Replay checkpoints no longer mirror those fields under `checkpoint.debug`.
- `rng_stream` and `checkpoint.rng_state` are the only replay-significant RNG authorities. Legacy RNG summaries are diagnostic-only.
- Finalization normalizes entity UID/generation tracking so entity timelines are stable across runs.
