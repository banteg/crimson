---
tags:
  - frida
  - differential-sessions
---

# Differential capture ledger

This page tracks current original-vs-rewrite work by **capture SHA256**.
Pre-CDT session reports 1-19 were removed from the live documentation because
their recordings use unsupported formats and their commands target deleted
tooling. They remain available in Git history under
`docs/frida/differential-sessions/`; do not restore compatibility code for
them.

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

## Active sessions

None. Add new-format session entries directly to this ledger using the template
above. Keep each entry outcome-focused; detailed command transcripts and
intermediate reports belong in local artifacts and Git history, not the live
documentation set.
