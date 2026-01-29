# Frida workflow

Use Frida as a runtime evidence engine and keep Ghidra maps as the source of truth.
Logs become machine-readable facts that we promote into `analysis/ghidra/maps/name_map.json`
and `analysis/ghidra/maps/data_map.json` after review.

## 1) Collect runtime logs

Copy the scripts into the VM share `C:\share\frida` (WSL path `/mnt/c/share/frida`).
You can override the output directory with `CRIMSON_FRIDA_DIR`. For `grim_hooks.js`,
set `CRIMSON_FRIDA_CONFIG` to point at a different `grim_hooks_targets.json`.

From WSL, you can sync the current repo scripts into the share:

```bash
just frida-sync-share
```

- `scripts/frida/grim_hooks.js`
- `scripts/frida/grim_hooks_targets.json`
- `scripts/frida/crimsonland_probe.js`
- `scripts/frida/menu_logo_pivot_trace.js`
- `scripts/frida/screen_fade_trace.js`
- `scripts/frida/perk_prompt_trace.js`
- `scripts/frida/creature_anim_trace.js`
- `scripts/frida/creature_render_trace.js`
- `scripts/frida/fx_queue_render_trace.js`

Attach by process name (required; spawn caused empty textures + crash on 2026-01-18):

```text
frida -n crimsonland.exe -l C:\share\frida\grim_hooks.js
```

In a separate terminal (or a second run), attach the probe script:

```text
frida -n crimsonland.exe -l C:\share\frida\crimsonland_probe.js
```

Menu logo rotation trace (focused, JSONL to `menu_logo_pivot_trace.jsonl`):

```text
frida -n crimsonland.exe -l C:\share\frida\menu_logo_pivot_trace.js
```

Screen fade trace (UI/fade globals + fullscreen overlay, JSONL to `screen_fade_trace.jsonl`):

```text
frida -n crimsonland.exe -l C:\share\frida\screen_fade_trace.js
```

Creature animation phase trace (focused, JSONL to `creature_anim_trace.jsonl`):

```text
frida -n crimsonland.exe -l C:\share\frida\creature_anim_trace.js
```

Creature render trace (draw calls + alpha for dying creatures, JSONL to `creature_render_trace.jsonl`):

```text
frida -n crimsonland.exe -l C:\share\frida\creature_render_trace.js
```

FX queue bake trace (corpse shadow/color passes into terrain RT, JSONL to `fx_queue_render_trace.jsonl`):

```text
frida -n crimsonland.exe -l C:\share\frida\fx_queue_render_trace.js
```

Just shortcut (Windows VM):

```text
just frida-attach script=scripts\\frida\\crimsonland_probe.js
```

Optional overrides: `process=crimsonland.exe` and `CRIMSON_FRIDA_DIR`.

Default logs written by the scripts:

- `C:\share\frida\grim_hits.jsonl`
- `C:\share\frida\crimsonland_frida_hits.jsonl`
- `C:\share\frida\creature_anim_trace.jsonl`
- `C:\share\frida\demo_trial_overlay_trace.jsonl` (if you ran `demo_trial_overlay_trace.js`)
- `C:\share\frida\demo_idle_threshold_trace.jsonl` (if you ran `demo_idle_threshold_trace.js`)

## 2) Copy logs into the repo

Store raw logs under `analysis/frida/raw/`:

```bash
mkdir -p analysis/frida/raw
cp /mnt/c/share/frida/grim_hits.jsonl analysis/frida/raw/
cp /mnt/c/share/frida/crimsonland_frida_hits.jsonl analysis/frida/raw/
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

For a concrete “what to run / what to capture” checklist (Milestone 16), see `docs/frida/demo-trial-overlay.md`.

## 4) Promote evidence into Ghidra maps

Review the summary + candidates, then manually promote good entries into:

- `analysis/ghidra/maps/name_map.json`
- `analysis/ghidra/maps/data_map.json`

Rerun headless analysis after updates:

```bash
just ghidra-exe
```

## Tips

- Keep hooks narrow: use the Grim hot-window or limit targets in
  `scripts/frida/grim_hooks_targets.json` when tracing draw calls.

- Turn on backtraces only when needed (`CONFIG.includeBacktrace = true`).
- Use `watchPlayerOffset()` in the probe script to chase unknown struct fields.
