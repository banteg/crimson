# Demo trial overlay evidence (wishlist)

This page is a **runtime capture checklist** for validating `demo_trial_overlay_render` behavior against a real demo build (or, if needed, retail with safe overrides).

## Target

- **Module:** `crimsonland.exe`
- **Hook:** `demo_trial_overlay_render` (`0x004047c0`)
- **Related gates (v1.9.93-gog addresses):**
  - `gameplay_update_and_render` (`0x0040aab0`)
  - `game_is_full_version` (`0x0041df40`)
  - `game_sequence_get` (`0x0041df60`)

## Goal

Confirm (with logs) that the overlay triggers and reports remaining time exactly as the Python model expects:

- Global playtime cap: **2,400,000 ms** (40 minutes)
- Quest grace once global is exhausted: **300,000 ms** (5 minutes)
- Quest tier limit: Quest mode + stage **tier > 1** (`major > 1` or `minor > 10`)

## Evidence capture (Frida)

### 1) Demo build (preferred)

1. Launch the **demo build**.
2. Attach:

   ```text
   frida -n crimsonland.exe -l C:\share\frida\demo_trial_overlay_trace.js
   ```

   (Or: `just frida-demo-trial-overlay`)

3. Ensure the tracer config is **not forcing anything**:
   - `CONFIG.forceDemoInGameplayLoop = false`
   - `CONFIG.forcePlaytimeMs = null`
    - Optional: `CONFIG.minOverlayLogIntervalMs = 250` to keep logs smaller

4. Trigger the overlay in at least these two ways:
   - **Quest tier lock (fast):** enter Quest mode and attempt a quest beyond Tier 1 (stage > `1_10`).
   - **Global trial expired (slow, optional):** only if you can naturally exhaust demo playtime.

5. Copy the log into the repo:

   ```bash
   mkdir -p analysis/frida/raw
   cp /mnt/c/share/frida/demo_trial_overlay_trace.jsonl analysis/frida/raw/
   ```

6. Reduce + validate:

   ```bash
   uv run scripts/frida_reduce.py \
     --log analysis/frida/raw/demo_trial_overlay_trace.jsonl \
     --out-dir analysis/frida

   uv run scripts/demo_trial_overlay_validate.py analysis/frida/raw/demo_trial_overlay_trace.jsonl
   ```

   Print a few representative events (useful for pasting into `plan.md`):

   ```bash
   uv run scripts/demo_trial_overlay_validate.py --samples 3 analysis/frida/raw/demo_trial_overlay_trace.jsonl
   ```

### 2) Retail build (overlay-only validation)

The retail binary may never naturally render the demo overlay. If you only need to validate the overlay logic end-to-end (not “prove the build is demo”), you can use **callsite-limited overrides** in the tracer:

- `CONFIG.forceDemoInGameplayLoop = true` (forces the gameplay-loop gate checks only)
- `CONFIG.forcePlaytimeMs = 2400001` (forces “trial expired” in the gameplay loop)

Then attach as usual:

```text
frida -n crimsonland.exe -l C:\share\frida\demo_trial_overlay_trace.js
```

## What to paste back

In `plan.md`, under Milestone 16, paste:

- Build info (demo/retail, version, platform)
- How you triggered the overlay (quest tier lock / forced playtime / etc)
- Output of:
  - `uv run scripts/demo_trial_overlay_validate.py ...`
  - (Optional) a few representative JSONL lines showing mode/timers/stage
