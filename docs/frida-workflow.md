# Frida workflow

Use Frida as a runtime evidence engine and keep Ghidra maps as the source of truth.
Logs become machine-readable facts that we promote into `analysis/ghidra/maps/name_map.json`
and `analysis/ghidra/maps/data_map.json` after review.

## 1) Collect runtime logs

Copy the scripts into the VM share (example uses `Z:\`):

- `scripts/frida/grim_hooks.js`
- `scripts/frida/grim_hooks_targets.json`
- `scripts/frida/crimsonland_probe.js`

Attach by process name (spawn caused empty textures + crash on 2026-01-18):

```text
frida -n crimsonland.exe -l Z:\grim_hooks.js
```

In a separate terminal (or a second run), attach the probe script:

```text
frida -n crimsonland.exe -l Z:\crimsonland_probe.js
```

Default logs written by the scripts:

- `Z:\grim_hits.jsonl`
- `Z:\crimsonland_frida_hits.jsonl`

## 2) Copy logs into the repo

Store raw logs under `analysis/frida/raw/`:

```bash
mkdir -p analysis/frida/raw
cp /Users/banteg/utm/win11/share/grim_hits.jsonl analysis/frida/raw/
cp /Users/banteg/utm/win11/share/crimsonland_frida_hits.jsonl analysis/frida/raw/
```

## 3) Reduce logs into evidence

Run the reducer to normalize facts + produce summaries:

```bash
uv run python scripts/frida_reduce.py \
  --log analysis/frida/raw/grim_hits.jsonl \
  --log analysis/frida/raw/crimsonland_frida_hits.jsonl \
  --out-dir analysis/frida
```

Outputs:

- `analysis/frida/facts.jsonl` — normalized facts (one JSON object per line).
- `analysis/frida/evidence_summary.json` — per-function evidence counts.
- `analysis/frida/name_map_candidates.json` — suggested rename candidates (review only).
- `analysis/frida/player_unknown_offsets.json` — hot unknown player offsets, if tracker ran.
- `analysis/frida/unmapped_calls.json` — callsites we couldn’t map to functions.

## 4) Promote evidence into Ghidra maps

Review the summary + candidates, then manually promote good entries into:

- `analysis/ghidra/maps/name_map.json`
- `analysis/ghidra/maps/data_map.json`

Rerun headless analysis after updates:

```bash
just game_dir=game_bins/crimsonland/1.9.93-gog ghidra-exe
```

## Tips

- Keep hooks narrow: use the Grim hot-window or limit targets in
  `scripts/frida/grim_hooks_targets.json` when tracing draw calls.
- Turn on backtraces only when needed (`CONFIG.includeBacktrace = true`).
- Use `watchPlayerOffset()` in the probe script to chase unknown struct fields.
