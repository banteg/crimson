---
tags:
  - frida
  - differential-sessions
---

## Session 16 (2026-02-15)

- **Capture:** `artifacts/frida/share/gameplay_diff_capture.json.gz`
- **Capture SHA256:** `999bd0550e69d2a1b12551732a214a0fa2897042d07bffe7265b8ed18f2961bc`
- **Baseline verifier command:**
  `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json.gz --json-out analysis/frida/reports/capture_999bd055_after_contact_small_kill.json`
- **First mismatch progression:**
  - initial: `tick 4804 (missing_checkpoint)`
  - after replay runner fix: `tick 4810 (state_mismatch: creature_count, kills)`
  - after small-creature contact kill parity fix: `ok (no divergence found)`

### Key Findings

- The `tick 4810` kill deficit (`kills 1041 expected vs 1040 rewrite`) tracked to creature slot `53`:
  - capture shows `hp=0` at tick `4803` and the corpse lifecycle stage crossing `<=0` at tick `4810`,
  - no `creature_damage` or `creature_death` events were present at tick `4803`.
- Ghidra decompile of `creature_update_all` shows a direct-contact kill path for small creatures:
  - when `dist_to_target < 30.0` and `size <= 30.0`, native sets `health = 0.0` and `lifecycle_stage -= frame_dt`,
  - this path does not call `creature_handle_death`, so it intentionally skips XP/bonus logic and avoids capture death hooks.

### Landed Changes

- `fix(player): spill heading turn product to float32` (`1a84993e`)
- `fix(sim): do not stop original-capture replays on death` (`08b20c8c`)
- `fix(creatures): kill small creatures on contact` (`e69b065e`)
  - added `_creature_interaction_contact_kill_small` parity step + regression test.

### Validation

- `uv run crimson original divergence-report artifacts/frida/share/gameplay_diff_capture.json.gz --json-out analysis/frida/reports/capture_999bd055_after_contact_small_kill.json`
- `just check`

### Outcome / Next Probe

- Capture `999bd055` is now clean end-to-end (`4818/4818` ticks, no divergence).

---
