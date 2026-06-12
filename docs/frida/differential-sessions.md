---
tags:
  - frida
  - differential-sessions
---

# Differential Capture Sessions (Condensed)

This log tracks original-vs-rewrite differential work by **capture SHA**.
When the capture SHA is unchanged, append updates to the same session.

## Session Template

- **Title:** `Session <N> (YYYY-MM-DD)`
- **Legacy IDs:** `<optional old IDs>`
- **Capture:** `<path>`
- **Capture SHA256:** `<sha256 or n/a>`
- **Baseline verifier command:** `<exact command>`
- **First mismatch:** `tick <n> (<fields>)`

### Key Findings

- `<highest-signal findings only>`

### Landed Changes

- `<important code/tooling/doc changes only>`

### Outcome / Next Probe

- `<what remains, and where to probe next>`

---

## Capture Policy (Current)

- Default to full-detail `gameplay_diff_capture` captures (no focus window, no sample limits).
- Keep the finalized `gameplay_diff_capture.<mode>.run<k>.cdt` + `.crd` pair as the
  canonical artifacts (under `artifacts/frida/share/`) and always log SHA256.
- Compare with `uv run crimson dbg diff/bisect/focus` against a `dbg record`
  trace of the matching `.crd` replay (the legacy `crimson original
  divergence-report` flow is gone).
- If any env knobs throttle capture volume, log exact knob/value.
- If capture SHA is unchanged, update the existing session; do not create a new one.
- Expect zero divergences: the 2026-06-12 parity audit resolved all previously
  known mismatches, so any diff is a real regression or a new finding.

---

## Sessions

- [Session 1 (2026-02-08)](differential-sessions/session-01.md)
- [Session 2 (2026-02-08)](differential-sessions/session-02.md)
- [Session 3 (2026-02-09)](differential-sessions/session-03.md)
- [Session 4 (2026-02-09)](differential-sessions/session-04.md)
- [Session 5 (2026-02-10)](differential-sessions/session-05.md)
- [Session 6 (2026-02-10)](differential-sessions/session-06.md)
- [Session 7 (2026-02-11)](differential-sessions/session-07.md)
- [Session 8 (2026-02-11)](differential-sessions/session-08.md)
- [Session 9 (2026-02-11)](differential-sessions/session-09.md)
- [Session 10 (2026-02-12)](differential-sessions/session-10.md)
- [Session 11 (2026-02-12)](differential-sessions/session-11.md)
- [Session 12 (2026-02-12)](differential-sessions/session-12.md)
- [Session 13 (2026-02-12)](differential-sessions/session-13.md)
- [Session 14 (2026-02-13)](differential-sessions/session-14.md)
- [Session 15 (2026-02-13)](differential-sessions/session-15.md)
- [Session 16 (2026-02-15)](differential-sessions/session-16.md)
- [Session 17 (2026-02-18)](differential-sessions/session-17.md)
- [Session 18 (2026-02-19)](differential-sessions/session-18.md)
- [Session 19 (2026-02-24)](differential-sessions/session-19.md)

Session 18 includes continued entries in the same file.
