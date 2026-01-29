# Demo idle threshold evidence (wishlist)

Goal: confirm the **main menu idle timeout** (how long you must be inactive before the demo/attract loop starts) on a **demo build**, so we can replace `MENU_DEMO_IDLE_START_MS` in the rewrite.

## Capture (Windows VM)

1. Launch the **demo build** and wait until the main menu is fully visible.
2. Attach:

   ```text
   frida -n crimsonland.exe -l C:\share\frida\demo_idle_threshold_trace.js
   ```

   (Or: `just frida-demo-idle-threshold`)

3. Don’t touch input (mouse/keyboard/gamepad). Wait for the attract loop to start.
4. In the log, find the first `demo_mode_start` event and record:
   - `dt_since_ui_ready_ms` (preferred)
   - `dt_since_start_ms` (fallback)

The tracer writes (by default) to:

- `C:\share\frida\demo_idle_threshold_trace.jsonl`

## After capture (repo)

Copy into the repo (kept under ignored raw logs):

```bash
mkdir -p analysis/frida/raw
cp /mnt/c/share/frida/demo_idle_threshold_trace.jsonl analysis/frida/raw/
```

Then paste into `plan.md`:

- Build/version info
- Observed `dt_since_ui_ready_ms`
- The JSON line(s) containing `demo_mode_start`

Optional: summarize the log:

```bash
uv run scripts/demo_idle_threshold_summarize.py analysis/frida/raw/demo_idle_threshold_trace.jsonl
```

Include representative JSON lines for `ui_ready` / `demo_mode_start` (easy to paste into `plan.md`):

```bash
uv run scripts/demo_idle_threshold_summarize.py --print-events analysis/frida/raw/demo_idle_threshold_trace.jsonl
```
