---
tags:
  - status-validation
  - frida
  - verification
---

# RNG divergence root cause playbook

This page captures the minimal workflow for isolating the first RNG call-order drift
between original and rewrite runs.

## Goal

Find the earliest tick where RNG consumption diverges, then identify the subsystem
that consumed RNG out of order.

## Workflow

1. Capture paired traces with [gameplay differential capture](gameplay-diff-capture.md).
2. Use [differential sessions](differential-sessions.md) to locate the first divergent tick.
3. Compare surrounding call sites and state deltas using the [differential playbook](differential-playbook.md).
4. Confirm candidate fix by re-running the same seed and input stream.

## Typical divergence classes

- Conditional branch drift before RNG call.
- Extra/omitted simulation update in a subsystem.
- Ordering drift across entity iteration.
- Float32 threshold drift that changes RNG-gated behavior.

## Output expected from investigations

- First divergent tick and call index.
- Suspect subsystem and function(s).
- Minimal reproducer seed/input.
- Verification run showing convergence after fix.
