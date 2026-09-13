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

Every input must produce equal normal, captured, replayed, and observed **whole
COFF objects**, apart from the COFF timestamp. The compiler hash, CALL
destinations, missing-stream rejection, register/flag preservation, source
hashes, instruction counts, and reference audits are checked. No compiler
decision, source, emitted body, matching rule, or match credit is patched.

`results.json` records one successful replay and hashes its harness, source
recipes, manifests, and raw observations. Raw traces and compiler binaries are
kept in the chosen output directory, not checked into the repository.
