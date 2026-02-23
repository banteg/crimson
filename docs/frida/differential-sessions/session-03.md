---
tags:
  - frida
  - differential-sessions
---

## Session 3 (2026-02-09)

- **Legacy IDs:** `2026-02-09-p`
- **Capture:** `n/a (tooling-only session)`
- **Capture SHA256:** `n/a`
- **First mismatch:** `n/a`

### Key Findings

- Absolute ticks are weak cross-session anchors once chronology diverges.
- RNG-order anchors (`seq`, per-tick call index, seed epoch) are required for reliable cross-run alignment.

### Landed Changes

- Upgraded `scripts/frida/gameplay_diff_capture.js` RNG diagnostics:
  - per-roll sequence metadata, between-tick carry, optional full roll log, CRT mirror integrity counters.
- Extended `original divergence-report` to surface sequence/epoch anchors and mirror totals.
- Updated `docs/frida/gameplay-diff-capture.md` with full RNG trace profile guidance.

### Outcome / Next Probe

- Prepared instrumentation for the next capture family; no gameplay parity fix in this session.

---

