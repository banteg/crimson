# Frida workflow

Use Frida as a runtime evidence engine and keep Ghidra maps as the source of truth.
Logs become machine-readable facts that we promote into `analysis/ghidra/maps/name_map.json`
and `analysis/ghidra/maps/data_map.json` after review.

## 1) Collect runtime logs

Run Frida from the Windows checkout so hook scripts load from the repo under
`scripts\frida\...`. Scripts write to `C:\share\frida` by default, which can be
kept in Syncthing; override the output directory with `CRIMSON_FRIDA_DIR`. For
`grim_hooks.js`, set `CRIMSON_FRIDA_CONFIG` to point at a different
`grim_hooks_targets.json`.

Attach by process name (required; spawn caused empty textures + crash on 2026-01-18):

```text
frida -n crimsonland.exe -l scripts\frida\grim_hooks.js
```

In a separate terminal (or a second run), attach the probe script:

```text
frida -n crimsonland.exe -l scripts\frida\crimsonland_probe.js
```

Menu logo rotation trace (focused, JSONL to `menu_logo_pivot_trace.jsonl`):

```text
frida -n crimsonland.exe -l scripts\frida\menu_logo_pivot_trace.js
```

Screen fade trace (UI/fade globals + fullscreen overlay, JSONL to `screen_fade_trace.jsonl`):

```text
frida -n crimsonland.exe -l scripts\frida\screen_fade_trace.js
```

UI render trace (menus/panels/widgets, JSONL to `ui_render_trace.jsonl`):

```text
frida -n crimsonland.exe -l scripts\frida\ui_render_trace.js
```

Panel-state resolution sweep (issue #165 capture: automatic state forcing +
panel/text capture; writes resolution-scoped JSONL):

```text
frida -n crimsonland.exe -l scripts\frida\panel_state_resolution_sweep.js
```

Just shortcut (Windows VM):

```text
just frida-panel-state-resolution-sweep
```

Comprehensive gameplay/state capture (automatic snapshots + write tracing, JSONL to
`gameplay_state_capture.jsonl`):

```text
frida -n crimsonland.exe -l scripts\frida\gameplay_state_capture.js
```

Differential gameplay capture (tick-aligned checkpoints + event summaries; writes
a raw `gameplay_diff_capture.jsonl` that the capture host finalizes into per-run
`gameplay_diff_capture.<mode>.run<k>.cdt` traces plus matching `.crd` replays):

```text
just frida-gameplay-diff-capture
```

The host attaches, captures until Ctrl+C / game exit, then finalizes and deletes
the raw JSONL (pass `--keep-raw` to keep it). To finalize a leftover raw file
without the game running: `uv run --with frida python
scripts/frida/gameplay_diff_capture_host.py --finalize-only --raw-path <jsonl>`.
Pass host flags through the `just` recipe after `--`, for example
`just frida-gameplay-diff-capture -- --keep-raw`.

Survival autoplay sidecar (manual-run helper that pins control scheme config only;
default is static movement + computer aim, JSONL to `survival_autoplay.jsonl`):

```text
frida -n crimsonland.exe -l scripts\frida\survival_autoplay.js
```

Shortcut: `just frida-survival-autoplay`

AlienZooKeeper no-unlock verifier (forces state `0x1a`, resets timer to `0x2580`, auto-solves board,
and logs a final `verdict` event to `azk_verify_no_unlock.jsonl`):

```text
frida -n crimsonland.exe -l scripts\frida\azk_verify_no_unlock.js
```

Shortcut: `just frida-azk-verify`

The UI render trace auto-inserts `auto_mark` events when it detects a screen/panel change.
You can disable or tune it via:

- `CRIMSON_UI_TRACE_AUTOMARK=0`
- `CRIMSON_UI_TRACE_AUTOMARK_MS=250`
- `CRIMSON_UI_TRACE_AUTOMARK_TEXTS=8`

Creature animation phase trace (focused, JSONL to `creature_anim_trace.jsonl`):

```text
frida -n crimsonland.exe -l scripts\frida\creature_anim_trace.js
```

Creature render trace (draw calls + alpha for dying creatures, JSONL to `creature_render_trace.jsonl`):

```text
frida -n crimsonland.exe -l scripts\frida\creature_render_trace.js
```

FX queue bake trace (corpse shadow/color passes into terrain RT, JSONL to `fx_queue_render_trace.jsonl`):

```text
frida -n crimsonland.exe -l scripts\frida\fx_queue_render_trace.js
```

Just shortcut (Windows VM):

```text
just frida-attach scripts\\frida\\crimsonland_probe.js
```

Optional overrides: a second positional arg for the process name, `CRIMSON_FRIDA_DIR`, and (for scripts with hardcoded addresses) `CRIMSON_FRIDA_ADDRS` / `CRIMSON_FRIDA_LINK_BASE` / `CRIMSON_FRIDA_MODULE`.

Default logs written by the scripts:

- `C:\share\frida\grim_hits.jsonl`
- `C:\share\frida\crimsonland_frida_hits.jsonl`
- `C:\share\frida\gameplay_diff_capture.<mode>.run<k>.cdt` / `.crd` (finalized diff captures; one pair per run)
- `C:\share\frida\survival_autoplay.jsonl` (if you ran `survival_autoplay.js`)
- `C:\share\frida\creature_anim_trace.jsonl`
- `C:\share\frida\ui_render_trace.jsonl`
- `C:\share\frida\panel_state_resolution_capture_<WIDTH>x<HEIGHT>_<RUNID>.jsonl` (if you ran `panel_state_resolution_sweep.js`)
- `C:\share\frida\demo_trial_overlay_trace.jsonl` (if you ran `demo_trial_overlay_trace.js`)
- `C:\share\frida\demo_idle_threshold_trace.jsonl` (if you ran `demo_idle_threshold_trace.js`)
- `C:\share\frida\azk_verify_no_unlock.jsonl` (if you ran `azk_verify_no_unlock.js`)

Panel-state sweep triage shortcut (issue #165):

```bash
just panel-state-resolution-reduce
```

Outputs:

- `analysis/frida/panel_state_resolution_capture_summary.json`
- `analysis/frida/panel_state_resolution_capture_report.md`

## 2) Copy logs into the repo

Store raw logs under `analysis/frida/raw/`:

```bash
mkdir -p analysis/frida/raw
cp /mnt/c/share/frida/grim_hits.jsonl analysis/frida/raw/
cp /mnt/c/share/frida/crimsonland_frida_hits.jsonl analysis/frida/raw/
cp /mnt/c/share/frida/gameplay_state_capture.jsonl analysis/frida/raw/  # optional
cp /mnt/c/share/frida/gameplay_diff_capture.*.run*.cdt analysis/frida/raw/  # optional
cp /mnt/c/share/frida/gameplay_diff_capture.*.run*.crd analysis/frida/raw/  # optional
cp /mnt/c/share/frida/demo_trial_overlay_trace.jsonl analysis/frida/raw/  # optional
cp /mnt/c/share/frida/demo_idle_threshold_trace.jsonl analysis/frida/raw/  # optional
```

Shortcut:

```bash
just frida-import-raw
```

## 3) Reduce logs into evidence

Run the reducer to normalize facts + produce summaries:

```bash
uv run scripts/frida_reduce.py \
  --log analysis/frida/raw/grim_hits.jsonl \
  --log analysis/frida/raw/crimsonland_frida_hits.jsonl \
  --log analysis/frida/raw/demo_trial_overlay_trace.jsonl \
  --log analysis/frida/raw/demo_idle_threshold_trace.jsonl \
  --out-dir analysis/frida
```

Shortcut:

```bash
just frida-reduce
```

Outputs:

- `analysis/frida/facts.jsonl` — normalized facts (one JSON object per line).
- `analysis/frida/evidence_summary.json` — per-function evidence counts.
- `analysis/frida/name_map_candidates.json` — suggested rename candidates (review only).
- `analysis/frida/player_unknown_offsets.json` — hot unknown player offsets, if tracker ran.
- `analysis/frida/unmapped_calls.json` — callsites we couldn’t map to functions.

Optional: validate `demo_trial_overlay_trace.jsonl` (or the reduced `facts.jsonl`) against the Python demo trial model:

```bash
uv run scripts/demo_trial_overlay_validate.py analysis/frida/raw/demo_trial_overlay_trace.jsonl
```

Note: the validator exits non-zero if the trace captured **zero** `demo_trial_overlay_render` events.

Print representative events:

```bash
uv run scripts/demo_trial_overlay_validate.py --samples 3 analysis/frida/raw/demo_trial_overlay_trace.jsonl
```

Shortcut:

```bash
just demo-trial-validate
```

Optional: summarize `demo_idle_threshold_trace.jsonl` (or the reduced `facts.jsonl`) to get the idle threshold:

```bash
uv run scripts/demo_idle_threshold_summarize.py analysis/frida/raw/demo_idle_threshold_trace.jsonl
```

Note: the summarizer exits non-zero if the trace captured **zero** `demo_mode_start` events (idle threshold unknown).

Include representative JSON lines:

```bash
uv run scripts/demo_idle_threshold_summarize.py --print-events analysis/frida/raw/demo_idle_threshold_trace.jsonl
```

Shortcut:

```bash
just demo-idle-summarize
```

## 4) Promote evidence into Ghidra maps

Review the summary + candidates, then manually promote good entries into:

- `analysis/ghidra/maps/name_map.json`
- `analysis/ghidra/maps/data_map.json`

Rerun headless analysis after updates:

```bash
just ghidra-exe
```

## Tips

- Diagnostics tooling:
  - Legacy `original` inline diff tools have been replaced by the decoupled `dbg` trace suite. See `docs/frida/differential-playbook.md` for updated differential parity workflows.

- Keep hooks narrow: use the Grim hot-window or limit targets in
  `scripts/frida/grim_hooks_targets.json` when tracing draw calls.

- Turn on backtraces only when needed (`CONFIG.includeBacktrace = true`).
- Use `watchPlayerOffset()` in the probe script to chase unknown struct fields.
