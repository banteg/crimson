# Demo idle threshold evidence (wishlist)

Goal: confirm the **main menu idle timeout** (how long you must be inactive before the demo/attract loop starts) on a **demo build**, so we can replace `MENU_DEMO_IDLE_START_MS` in the rewrite.

## Capture (Windows VM)

1. Launch the **demo build** and wait until the main menu is fully visible.
   (If you only have a retail build, the tracer forces demo/shareware mode so the attract loop still triggers.)
2. Attach:

   ```text
   just frida-demo-idle-threshold
   ```

   The tracer auto-enables **demo/shareware** behavior (so the attract loop triggers on retail builds).
   To disable: set `CRIMSON_FRIDA_DEMO_PATCH=0` before attaching.

   If the script logs `error ... addr_unavailable` (or `start.addrs.* = null`), you're likely on a different build.
   Re-run with overrides (once you know the correct VAs for your demo build):

   ```text
   just frida-demo-idle-threshold addrs="demo_mode_start=0x401234,ui_elements_max_timeline=0x402345" link_base="0x00400000"
   ```

   (Or set `CRIMSON_FRIDA_ADDRS` / `CRIMSON_FRIDA_LINK_BASE` in the VM shell.)

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

Note: the summarizer exits non-zero if the trace captured **zero** `demo_mode_start` events (idle threshold unknown).
If that happens, check the log for `error` events (likely an address mismatch) or wait longer for the attract loop.

Include representative JSON lines for `ui_ready` / `demo_mode_start` (easy to paste into `plan.md`):

```bash
uv run scripts/demo_idle_threshold_summarize.py --print-events analysis/frida/raw/demo_idle_threshold_trace.jsonl
```
