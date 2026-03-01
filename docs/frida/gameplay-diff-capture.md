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
- `--chunk-ticks <n>`: `.cdt` chunk size during finalize (default `256`)
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
- `uv run crimson dbg viz`

## Notes

- Legacy `dbg import-capture`, `replay convert-capture`, and postpack flow are removed.
- JSONL rows contain already-normalized trace channels (`checkpoint`, `rng_marks`, `rng_stream_head`, `entity_samples`, `event_heads`, `event_counts`, `micro_traces`).
- JSONL tick rows also carry replay-grade packed inputs (`replay_inputs`) and run metadata (`seed`, `player_count`) so replay sidecars can be generated losslessly.
- Finalization normalizes entity UID/generation tracking so entity timelines are stable across runs.
