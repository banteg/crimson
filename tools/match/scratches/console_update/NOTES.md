# `console_update`

Native target: `crimsonland.exe` at `0x00401a40` (904 bytes).

Live callsites load `console_log_queue` into `ECX` and pass no stack
arguments, proving this is `console_queue_t::update()` rather than the former
flat one-argument signature. The method eases the console slide from the
per-frame delta, polls text input while open, distinguishes Ctrl+Up/Down log
scrolling from history navigation, handles cursor and page keys, completes
cvars or commands on Tab, and prepends distinct submitted lines to history
before executing them.

The native non-submission path also calls `console_input_buffer()` immediately
before polling Enter, even though the returned buffer pointer is not consumed.
Restoring that observed accessor call raises the result from 89.19% to 90.05%,
reduces the weighted gap from 97.73 to 89.94 bytes, and resolves its 64th
static reference. The candidate now has 297 instructions against 296 native
instructions because of the remaining save-placement residual.

Native VC6 delays the `ESI`/`EDI` saves until the cursor-editing tail, while
the current source saves `ESI` at entry and releases `EDI` before the
submission branch. That extra early save accounts for the candidate's one
extra instruction and shifts otherwise corresponding control-flow labels. No
volatile state, dummy dependency, or artificial control flow is used to force
that schedule.

The callsites of `console_tokenize_line` likewise preserve the queue in `ECX`;
recording it as a member call leaves both its own 55-instruction scratch and
the 90-instruction `console_exec_line` scratch exact.

## Recovery classification audit

Live callsites and Binary Ninja control flow account for the complete animation,
input-editing, history, completion, submission, and execution policy. The
current candidate has 297 instructions against 296 native instructions with
`64/0/0` audited references. Every localized mismatch is explained by the
early/shrink-wrapped saved-register lifetime and its shifted branch labels, so
the scratch is classified `semantic-complete` with a `compiler` residual.

## Late pointer declaration sweep

Live disassembly places the native `push esi; push edi` pair immediately before
the Right-arrow poll at `0x00401b91`, then keeps both saves through completion
and both submission exits. The candidate saves `ESI` at entry and shrink-wraps
only `EDI` around the string scans.

A recorded three-variant sweep moved the autocomplete pointer, history-entry
pointer, or both declarations to that native save boundary while preserving
their assignment and use sites. All three compile byte-identically to the
90.05% baseline with 297/296 instructions and `64/0/0` references. The spec
SHA-256 is
`e927fc662fb3a1729282d8d59524e42ad626c99d43c9da20fb57264dff2da4f6`.
Lexical pointer declaration scope therefore does not control VC6's register
save placement, and the narrower canonical declarations remain unchanged.

## Fresh profile and region recheck

VC6.0, VC6.5, and VC6.6 remain byte-identical at 90.0506%, a
89.9427-byte fuzzy gap, 297/296 instructions, a six-instruction prefix, and
`64/0/0` references. Processor Pack falls to 82.39% and VC7 to 54.83%.
Localized regions still form the documented cascade from the candidate's one
extra early saved-register instruction; no independent missing call, input
branch, or history operation appears. With the late pointer-declaration sweep
already byte-neutral, this recheck provides no new semantic source hypothesis,
so no additional mutation or source change is retained.

## Submission-arm lifetime sweep

`submission-arm-lifetime-mutations.json` tested four explicit ownership shapes
for the final ready/not-ready split: submit-first `if`/`else`, non-submit-first
inequality and equality forms, and a two-arm `switch`. The submit-first
`if`/`else` and `switch` are byte-identical to the 90.05% baseline at 297/296
instructions and `64/0/0` references. Both non-submit-first forms regress to
86.34% and lose two resolved references.

The spec SHA-256 is
`4d21d3c8a0c719c7af709a3a630aedeca779e40568d015ca46f014616095dc33`.
The remaining save-placement mismatch is therefore not controlled by source
ownership of the submission arms, and no source change is retained.

## Submission input-ownership sweep

`submission-input-ownership-mutations.json` tests six ordinary spellings at
the first submitted-line comparison: named input-buffer and history-line
pointers, both named operands, a named comparison result, a truthy comparison,
and value-initialization of the history node. The comparison-result, truthy,
and value-initialized-node forms are byte-identical to the 90.05% baseline at
297/296 instructions with `64/0/0` references.

Naming the input pointer, alone or with the history line, regresses to 87.35%.
Naming only the history line emits two extra instructions and regresses to
89.08%. None delays the candidate's entry `ESI` save or keeps `EDI` through the
ready branch, so explicit ownership of the comparison operands is not the
source of the native paired shrink-wrap region. The spec SHA-256 is
`ed044ff7fb725b0619e6b6d1ca03e5cc7510989b19cb9e0795761a2f952fade1`,
and no source change is retained.
