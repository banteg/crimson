---
tags:
  - frida
  - differential-testing
  - status-analysis
---

# thunk_FUN_00452f1d runtime capture task

Use this task when we need runtime evidence for `thunk_FUN_00452f1d` (`0x00452f1d`).

Why this matters:

- The decompile signature is likely incomplete (`int(void)`).
- IDA callsites show argument passing in gameplay hotspots.
- This thunk sits on critical paths (`creature_update_all`, `projectile_update`, `player_update`).

## Goal

Collect one trace artifact that lets us answer:

1. What call shape does the thunk use at runtime (stack/register pointer candidates)?
2. Which callers dominate in real gameplay?
3. What does the callback pointer (`DAT_00479658`) resolve to at runtime?

## Windows capture steps

1. Sync scripts to the VM share:

```bash
just frida-sync-share
```

2. On Windows, attach the thunk trace script:

```text
frida -n crimsonland.exe -l C:\share\frida\thunk_452f1d_trace.js
```

3. Optional but recommended: in another terminal, run gameplay differential capture for tick anchors:

```text
frida -n crimsonland.exe -l C:\share\frida\gameplay_diff_capture.js
```

4. Play a representative run (2-5 minutes is enough). Prefer combat-heavy windows where contact/hit logic is active.

5. Stop with `Ctrl+C` in both terminals.

## Output files

- `C:\share\frida\thunk_452f1d_trace.jsonl`
- optional: `C:\share\frida\gameplay_diff_capture.json` (or quest-split files)

## Copy into repo (WSL)

```bash
mkdir -p analysis/frida/raw
cp /mnt/c/share/frida/thunk_452f1d_trace.jsonl analysis/frida/raw/
cp /mnt/c/share/frida/gameplay_diff_capture*.json analysis/frida/raw/  # optional
```

## Quick sanity check

```bash
uv run python - <<'PY'
import collections
import json
from pathlib import Path

path = Path("analysis/frida/raw/thunk_452f1d_trace.jsonl")
rows = []
for line in path.read_text().splitlines():
    if not line.strip():
        continue
    obj = json.loads(line)
    if obj.get("event") == "thunk_452f1d_call":
        rows.append(obj)

callers = collections.Counter(
    (row.get("caller") or {}).get("static") or (row.get("caller") or {}).get("runtime")
    for row in rows
)
print("call_count", len(rows))
print("top_callers")
for key, count in callers.most_common(12):
    print(f"  {key}: {count}")
PY
```

## Trace knobs

- `CRIMSON_FRIDA_DIR` controls output folder.
- `CRIMSON_THUNK_TRACE_MAX_EVENTS` caps event count (`0` = unlimited).
- `CRIMSON_THUNK_TRACE_CONSOLE=0` disables JSON lines in console.
- `CRIMSON_THUNK_TRACE_APPEND=1` appends instead of truncating.
- `CRIMSON_THUNK_TRACE_BT=1` enables backtraces (higher overhead).

## Script location

- `scripts/frida/thunk_452f1d_trace.js`
