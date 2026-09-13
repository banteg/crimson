# Bonus-picker block-layout trace

The preserving C2 tracer now identifies the pass that outlines the quest checks
in two historical source controls: **C2+0x3663c**, called at **C2+0x584bc**.
Its call at **C2+0x367ce** moves the actual instruction-list range through
**C2+0x33655**. The canonical source makes no range-move call in this pass.

This is a compiler-mechanism result, not a new match. The canonical bonus picker
still has 162/162 instructions, prefix 55, 20 clean references, and false
normalized and encoded-body exactness. Its native stage-5 check is outlined at
`0x00412628`, while its compiled check remains beside stage 4.

## What the trace establishes

All three inputs keep stage 5 beside stage 4 through allocation and the first
late cleanup passes. The two controls diverge during `0x3663c`, before register
peepholes and instruction scheduling:

| Input | Instructions | Stage-5 range moved | Stage 4 moved with it |
| --- | ---: | --- | --- |
| Canonical source | 162 | No | No |
| Duplicate the common Freeze filter | 167 | Yes | Yes |
| Duplicate all common filters | 203 | Yes | Yes |

The controls are reconstructed from their existing hash-checked recipes in
`../bonus-pick-cold-edge-2026-09-11/source-controls.json`; these are fresh traces
of previously measured sources, not newly discovered source improvements.

Read-only inspection of the pinned compiler explains a relevant gate in the
first loop of `0x3663c`. It examines a direct unconditional jump over an
intervening instruction range. The jump destination's previous node must also
terminate its path (an unconditional jump or return). Only then can this loop
move the intervening range after the destination's terminating block without
changing a fall-through edge.

For the stage-4 skip edge, the canonical destination is preceded by stage 5's
**conditional** Nuke rejection. Its condition field at node+0x20 is nonzero, so
this gate rejects the move. Both duplicated controls instead have an
unconditional predecessor, and the observed helper arguments identify ranges
containing **both** stage 4 and stage 5. The smaller control therefore confirms
the mechanism while retaining five unwanted instructions and the wrong extent
of block motion.

This bounds the next source hypothesis: explain a stage-5-only movable range
without duplicating the common filters or losing stage 4's separate comparison.
It does not prove that this is the only possible compiler path to native layout,
nor recover the original source spelling.

## Isolating stage 5 and locating the early reorder

`verify_paths.py` adds two source controls, kept outside the canonical scratches.
Both replay with unchanged whole COFF output, except timestamp; neither is an
exact match.

* `controls/explicit-stage-five-tail.cpp` puts the final quest check after the
  retry backedge. C2+0x12d16, called at C2+0x53f2 inside C2+0x53de, brings it
  back ahead of the retry condition. Read-only inspection identifies this as the
  reverse-postorder rebuild. The preserving entry/return trace verifies the
  actual movement, before global optimization and register allocation. The
  final 162-instruction result is unchanged from canonical source. Source
  order and a manual tail label therefore do not solve this residual.
* `controls/inverted-hardcore-prefix.cpp` combines the duplicated Freeze prefix
  with an inverted outer hardcore-stage-2 guard. C2+0x3663c now moves a range
  containing **stage 5 alone**, leaving stage 4's separate comparisons in place.
  The output still has **169 instructions**, including seven extra instructions
  for the duplicated filter, and reverses the hardcore Freeze rejection edge.
  Its 20 clean native reference matches do not make it an acceptable replacement.

This second control answers the narrower range-boundary question from the first
trace. Inverting the hardcore guard changes its final pair from a conditional
retry plus unconditional common-filter jump to a conditional common-filter jump
plus unconditional retry. That prevents the earlier jump from moving stages 4
and 5 together. The actual stage-5-only range is checked from the helper's
arguments, not inferred from a fuzzy score.

The remaining task is to obtain this placement while removing the duplicated
filter and retaining native branch directions. The original source shape is
still unresolved. Do not promote either diagnostic source or grant match credit.

The same investigation also compiled the canonical body with the locally
available VC6 6.0, 6.3, and 6.4 bundles, and separately after each of
`bonus_spawn_at_pos`, `bonus_try_spawn_on_kill`, `bonus_apply`, `bonus_update`,
and `bonus_render` in the same translation unit. All eight controls retained
the canonical extracted-body hash
`c4cb6604f582d306a8531efbe51aff37ca6f5f3d47450d6dfd7c96d00e8158e7`.
These are bounded negative controls, not evidence about every compiler version
or possible original translation unit. `context-results.json` records their
source recipes, measurements, and compiler-tree hashes.

## Reproduce

From the repository root, with the pinned compiler and Wine available:

```sh
uv run python tools/match/evidence/bonus-pick-layout-trace-2026-09-13/verify.py \
  --out /tmp/bonus-pick-layout-trace
```

Use a fresh output directory. The verifier observes late pass entries and
returns, plus the range-move call's actual insertion/first/last arguments.
`layout.json` retains event-local node identities, list links, branch targets,
and condition presence; the compact receipt uses instruction indices rather
than cross-run arena addresses. Compiler line fields are compiler coordinates,
not assumed to be physical lines in the C++ file.

Replay the two additional paths independently:

```sh
uv run python tools/match/evidence/bonus-pick-layout-trace-2026-09-13/verify_paths.py \
  --out /tmp/bonus-pick-layout-paths
```

`path-results.json` records their successful replay. The verifier checks the
early stage-5/retry ordering on both sides of C2+0x12d16 and requires exactly
one later stage-5 range move that excludes stage 4. The checked-in source line
coordinates identify comparisons within these particular controls; they are
not generalized compiler metadata claims.

Every input must produce equal normal, captured, replayed, and observed **whole
COFF objects**, apart from the COFF timestamp. The compiler hash, CALL
destinations, missing-stream rejection, register/flag preservation, source
hashes, instruction counts, and reference audits are checked. No compiler
decision, source, emitted body, matching rule, or match credit is patched.

`results.json` records one successful replay and hashes its harness, source
recipes, manifests, and raw observations. Raw traces and compiler binaries are
kept in the chosen output directory, not checked into the repository.
