# Bonus-picker layout causality

**A permutation of existing late IL nodes produces the native encoded body
exactly.** The unmodified compiler and canonical source still do not match.
This package isolates the remaining compiler decision; it does not recover
source, patch the compiler on disk, or grant matching credit.

The earlier [layout trace](../bonus-pick-layout-trace-2026-09-13/README.md)
identified a mover and unsuccessful source controls. This follow-up answers two
different questions: can early successor order explain native's layout, and is
layout alone sufficient once allocation has finished?

## Early order has a structural constraint

Read-only inspection of the pinned C2 identifies this sequence:

1. C2+0x440d calls C2+0x448f at 0x4411. The latter visits each block's
   successor list at block+0x0c, following edge+0x0c to the destination. It
   constructs a depth-first postorder using block+0x10/+0x14.
2. C2+0x12d16, called at 0x53f2, consumes that order and rebuilds the physical
   list. C2+0x10e7c connects the blocks; C2+0x1dc8f repairs fall-through edges
   as needed. Source order alone is therefore not the physical-order control.

The preserving observer records 79 initial blocks. Two are unreachable; a
Python DFS over the captured successor lists reproduces **all 77 blocks** in
the compiler's rebuilt order, including their identities. This is a replayed
model of the implementation, not a name inferred from the decompiler.

More strongly, the draw-loop header dominates both stage five and the retry
latch. From stage five, the reachable graph with that header removed is
acyclic and reaches the latch. These properties are checked from the captured
graph. When DFS reaches stage five, the header is an active ancestor; it cannot
be traversed again through the retry backedge. The resulting acyclic paths
force the latch to finish before stage five, placing stage five **before** the
latch in reverse postorder, regardless of successor visitation order.

Native places stage five after the retry backedge. Reversing successor lists
in this fixed early graph cannot produce that order. A source hypothesis must
instead explain a different intermediate graph that subsequently simplifies,
or a later layout transformation. This does not rule out every source spelling.

## A controlled late relocation is sufficient

At entry to C2+0x3663c, after register allocation, canonical contains:

```text
hardcore rejection / jump to common
stage-four tests / jump to common       <- existing jump J
stage-five label and three tests        <- final rejection branches to retry
common: Freeze and remaining filters
retry: counter update / branch to fallback / jump to draw
success and fallback returns
```

The intervention changes only next/previous links in the existing IL list:

```text
hardcore rejection / jump to common
stage-four tests                        <- now fall through to common
common: Freeze and remaining filters
retry: counter update / branch to fallback / jump to draw
stage-five label and three tests / J    <- J still targets common
success and fallback returns
```

No opcode, operand, condition, branch destination, or instruction is supplied
by the intervention. It reuses J as stage five's fall-through exit, so both
regions preserve their original successors. Insertion follows an unconditional
backedge, and the following success label remains the destination of its
existing branches. The ordinary remaining compiler passes then emit:

| Build | Instructions | Prefix | Clean references | Encoded body exact |
| --- | ---: | ---: | ---: | --- |
| Canonical, preserving trace | 162 | 55 | 20 | No |
| Intervention disabled | 162 | 55 | 20 | No |
| Existing nodes relocated | 162 | 162 | 20 | **Yes** |

The disabled intervention reproduces the entire ordinary COFF object, except
timestamp. The enabled intervention retains all 193 IL nodes, checks their
membership and bidirectional links, and verifies every inspected non-link
field remains unchanged. Native instruction-graph comparison and the existing
relocation-aware body-byte matcher both accept its output. Compiler binaries,
canonical source, flags, and matching rules remain unchanged on disk.

The node-field guard respects C2's variable record sizes: a normal compare ends
at +0x1f, whereas a branch has its condition at +0x20. Reading +0x20 as a
condition on every node can read the next allocation's list link instead.

This establishes that the current source already supplies the necessary
operations, register allocation, references, and instruction encodings. It
does **not** establish how original source induced the layout.

## Why the known source controls couple two problems

The first loop of C2+0x3663c scans forward. For a jump over an intervening range,
it requires the destination's predecessor to terminate unconditionally before
calling C2+0x33655 at 0x367ce and deleting the original skip jump.

Canonical has two jumps to the shared Freeze label: one after the hardcore
arm, then J after stage four. Both see stage five's conditional retry branch
as the destination's predecessor, so the mover cannot use either range.
Making that predecessor unconditional also makes the **earlier** range,
containing stages four and five, eligible. Inverting the hardcore guard avoids
that earlier skip but reverses the native hardcore rejection edge. A jump
from stage five to the adjacent Freeze label disappears before it can supply
the required predecessor; jumping past Freeze survives but changes behavior.

These are separate constraints: termination at the range boundary, selection
of stage five alone, and preservation of the hardcore branch polarity. A
higher score satisfying only one or two is not progress toward source recovery.

The skip guard also tests instruction byte+9 bit 3. The branch constructor
C2+0x3aa7 sets this bit at 0x3b86 for opcodes 0x187 through 0x18c. That is not
evidence for a general source-level cold-branch hint. Another apparent direct
write at 0x91c14 operates on an operand object, not the branch record; treating
these structures as interchangeable would suggest a false control.

## Reproduce

Use a fresh output directory, the pinned compiler, and the configured runner:

```sh
uv run python tools/match/evidence/bonus-pick-layout-causality-2026-09-22/verify.py \
  --out /tmp/bonus-layout-causality
```

The verifier first proves ordinary/captured/replayed/observed whole-COFF
equality and missing-stream rejection for both early and late traces. It then
runs the disabled and enabled interventions against the same captured streams.
`results.json` records the normalized block graph, assertions, metrics, and
source/compiler/image/harness/trace hashes. Raw streams and objects remain in
the output directory. `match_credit` is explicitly false, including for the
encoded-exact diagnostic output.

The next source experiment should identify which intermediate edge or late
layout gate it intends to control, demonstrate that change in a preserving
trace, and retain native branch destinations and polarity. The source-level
mechanism remains open; this package narrows that problem without adding
another syntax sweep.
