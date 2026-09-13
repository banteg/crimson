# Preserving C2 traces

`crimson match c2-trace` runs a scratch through the pinned `msvc6.5` C2 backend
and records optimizer/allocation events. It accepts C and C++ scratches without
timeline-specific source hashes or source-line assumptions. The installed
compiler and canonical scratch are not edited.

```sh
uv run crimson match c2-trace tools/match/scratches/quest_spawn_timeline_update \
  --out /private/tmp/c2-timeline
uv run crimson match c2-inspect /private/tmp/c2-timeline \
  --line 87 --out /private/tmp/c2-line-87.json
uv run crimson match c2-compare /private/tmp/c2-timeline /private/tmp/c2-variant \
  --out /private/tmp/c2-comparison.json
```

Create the variant in a separate scratch directory containing `scratch.conf`,
its source and local headers, then trace it into another new output directory.
Source-line selection refers to that frozen source, not a native address.

For large functions, add `--passes-only` to retain the 12 pass boundaries while
omitting the repeated allocation callsites. The receipt records this narrower
observation scope; whole-object preservation and missing-stream controls still
apply. The observer and decoder share the same 16384-node limit.

The output must be a new, short ASCII path outside the input scratch. The
existing `msvc6.5` compiler, wibo, and generated Kernel32 import inputs from
`crimson native link --image crimsonland.exe` are required. Another compiler
hash is rejected before hooks are installed; this profile is not a generic
MSVC-version decoder.

## What is recorded

- Frozen local scratch files, normal and wrapped compiler objects, and the
  `ex`, `in`, `sy`, `gl` frontend streams.
- Standalone replay and an observer generated from [profile.json](profile.json)
  and [observer.c.in](observer.c.in). The profile contains the 12 existing pass
  boundaries and 17 allocation callsites with entry/return hooks.
- Every instruction node, its opcode, source line, raw flags, complete source
  and destination operand chains, and 16 descriptor words for temporary operands.
- Function ordinals, hook occurrence order, the loaded C2 base, and raw node /
  temporary addresses scoped to each event. Function-entry events start new
  ordinals even if the compiler reuses the function object's address.
- A manifest containing compiler/runner/helper/profile hashes, source/build
  provenance, stream/trace/snapshot hashes, and native matcher metrics.

The observer preserves registers and flags. It validates every patched CALL's
opcode and original destination, and rejects reentrant use of its return-hook
slots. It limits a snapshot to 16384 nodes and each operand chain to 16 elements;
exceeding these limits fails instead of silently truncating evidence. Only the
loaded diagnostic process is instrumented.

## Preservation and comparison

A successful trace requires normal, wrapped, replayed and observed **whole
COFF objects** to agree, excluding only timestamp bytes 4–7. Each object also
receives an independent native matcher check. Replay with the expression stream
withheld must fail without producing an object. The streams must remain
unchanged. Failed runs retain their files but receive no success manifest.

Inspect/compare validate the saved object, profile, raw trace and decoded
snapshot digests. Decoded snapshots are independently checked against the raw
trace. These are reproducibility checks, not cryptographic authentication.

Inspection follows the selected line's current temporary operands to all of
their users in each snapshot, including users on other lines. The selected
descriptor fields are shown as raw values and C2-relative register-descriptor
addresses. Their interpretation depends on the compiler phase.

Comparison pairs function ordinals and occurrences of the same hook, then
compares ordered opcode/line/flags, operand kinds, kind-7 immediate payloads,
and event-local temporary relationships. At allocation hooks it also compares
selected descriptor fields (`+04`, `+0c`, `+10`, `+24`, `+3c`). Temporary
addresses are alpha-renamed within each event, and register descriptors are
rebased against the recorded C2 load address. Early descriptor fields are
excluded: a field used as priority later can contain an arena pointer earlier.

`first_shape_difference` is the first differing observed signature, **not the
first causal compiler decision**. It includes allocation descriptors at the
supported hooks, but leaves other operand structures opaque. Source-line changes
can produce a difference. Equal signatures do not prove semantic equivalence;
function ordinals can pair different functions if source variants alter emission
order. Arena addresses can be recycled between events, so this tool never
asserts continuous value identity from address equality alone.

This tracing earns no source-match credit. Compiler interventions remain in
the historical evidence scripts; the reusable commands only observe.

## Validation and provenance

The implementation promotes the capture/replay C helpers from
[the frontend replay experiment](../evidence/vc6-intermediate-replay-2026-09-09/README.md),
the complete-operand observer from the timeline consumer investigation, and
allocation hook locations from
[the zero-splitting investigation](../evidence/vc6-timeline-zero-splitting-2026-09-12/README.md).
Historical runners remain intact as experiment receipts; new work should use
these commands instead of importing dated scripts or modifying observer strings.

[Generalization validation](../evidence/c2-trace-generalization-2026-09-13/README.md)
covers an exact C control, an exact C++ control, repeated timeline compilation,
a changed-source trace, and a deliberately wrong hook destination.

[Spawn alias-budget recovery](../evidence/spawn-exact-2026-09-13/README.md)
shows why a small instruction residual can have a distant cause. Additional
value temporaries exhausted field-alias capacity and introduced scheduler
store dependencies. That package extends the pinned observations to the actual
alias classes and scheduler graph; the ordinary operand signatures alone do
not include those fields.
