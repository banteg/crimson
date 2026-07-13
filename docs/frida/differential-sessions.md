---
tags:
  - frida
  - differential-sessions
---

# Differential capture sessions

This index tracks original-vs-rewrite work by **capture SHA256**. The linked
older sessions are historical investigation notes; their recordings predate the
current owned formats and are not expected to load. Do not add compatibility
code for them.

Start a current session only from a fresh Frida format 22 capture finalized as
CDT container 2/schema 15 with its CRD replay 16 and evidence sidecars.

## Session template

- **Title:** `Session <N> (YYYY-MM-DD)`
- **Capture set:** `<native.cdt>`, `<run.crd>`, `<rng_evidence.json>`,
  `<evidence.msgpack.zst>`
- **Capture versions:** `Frida 22 / CDT 2+15 / CRD 16 / evidence 2`
- **Capture SHA256:** `<sha256 for every artifact>`
- **Replay trace:** `<python-or-zig.cdt>`
- **Commands:** `<exact health, record, diff, bisect, or focus commands>`
- **First mismatch by channel:** `<channel -> tick/path>`
- **First diagnostics:** `<channel -> tick/path>`

### Key Findings

- `<highest-signal findings only>`

### Landed Changes

- `<important code/tooling/doc changes only>`

### Outcome / Next Probe

- `<what remains, and where to probe next>`

---

## Current capture policy

- Capture full-detail gameplay with every limit set to unlimited. Focus windows
  and sampled streams are not replay-grade and the finalizer rejects them.
- Keep the `.cdt`, `.crd`, `.rng_evidence.json`, and `.evidence.msgpack.zst`
  files together as the canonical native artifact set. Log their SHA256 values
  and every capture knob that changes coverage.
- Reject and regenerate any artifact that is not Frida 22, CDT 2/schema 15,
  CRD 16, and evidence 2. These files are throwaway and there is no migration
  path.
- Run `dbg health` on the native trace and the replay-recorded trace before
  reading a diff. Stop if either selected window is not parity-ready.
- Record the matching CRD with the implementation under test, then compare the
  two CDTs with `dbg diff`. Use `dbg bisect`/`dbg focus` after the first report,
  not as a substitute for the full-channel diff.
- Log `channel_first_mismatches` for all affected channels. For finite float
  differences, record the field path, bit encodings, and f32 ULP distance.
- Log `channel_first_diagnostics` separately. In particular, an RNG
  caller-attribution-only difference is useful localization evidence but not a
  behavioral mismatch.
- If the capture SHA is unchanged, continue its existing investigation notes.
  Start a new session after recapturing or changing the comparison implementation.
- Fixture parity is strict. Do not blanket-`xfail` a known mismatch; record the
  exact first mismatch and fix or isolate the responsible behavior.

The normal command sequence is:

```text
uv run crimson dbg health <native.cdt>
uv run crimson dbg record <run.crd> --out <candidate.cdt> --impl <python|zig>
uv run crimson dbg health <candidate.cdt>
uv run crimson dbg diff <native.cdt> <candidate.cdt>
```

The raw JSONL lifecycle is strict. A capture error, tick discontinuity, or EOF
with an unfinished run means recapture. EOF after `run_end` is complete;
finalization never appends or salvages lifecycle rows.

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
