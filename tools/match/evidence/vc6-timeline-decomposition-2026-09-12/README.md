# Decomposing the timeline residual

**The four-byte gap now has a verified allocation owner.** Reducing that owner's
late storage extent in an isolated compiler experiment changes only the frame
reservation and affected local displacements. The pointer stores and both EDI
field loads survive. The remaining normalized instruction differences are zero
materialization/reuse and their resulting branch offsets.

This is a decomposition result, not a source match. Canonical source and flags
remain at 113/115 instructions, 91.228070%, prefix 51, 13 clean references, and
a non-exact body. The stock pointer-copy witness remains at 115 instructions,
71.304348%, prefix 1, 12 clean references, and a 32-byte frame.

## Work as separate acceptance gates

| Gate | Established evidence | Condition for source progress |
|---|---|---|
| Pointer behavior | Stock witness emits the adjacent EDI pointer/zero stores and both field loads through EDI | Preserve the exact three-instruction sequence and field operands |
| Stack layout | Eight-byte copied object owns the gap; one late extent change reproduces native frame/local offsets | Stock compiler reserves 28 bytes while retaining the pointer behavior |
| Zero register | Both controls retain a shared zero seed with 12 users through `0x306c1` | Recover native initial tests and final EBX/BL clears without disturbing the other gates |
| Complete recovery | Native matcher remains authoritative | Credible source, complete body/extent equality, clean references, and applicable regression gates |

Track these gates alongside native metrics. A better aggregate score does not
establish that a gate improved, and diagnostic compiler output earns no match
credit. The artificial unused member remains a mechanism witness rather than
evidence of original game source.

## The copied object owns the gap

[layout_trace.py](layout_trace.py) extends the existing preserving observer with
callsites `C2+0x583fc` (before `0x33b7b`) and `0x5840f` (after it, before
`0x34032`). The whole observed COFF equals the stock replay except timestamps.
The added records follow memory operands to their parent descriptors and
underlying definitions. The copied and spread owners are selected by the
actual destination nodes on their respective source lines.

The optimized stack-allocation route is `0x33b7b -> 0x33bf8`; its grouping and
allocation routines include `0x33e75` and `0x4b617`. Local C2 disassembly and
the preserving measurements identify descriptor offset `+0x20` as the storage
extent used here. The underlying definition also has a size at `+0x10`, but
changing that field alone at this stage has no effect on output.

| Owner | Size | Allocator displacement |
|---|---:|---:|
| copied pointer pair | 8 | -32 |
| spread | 4 | -32 |
| offset vector | 8 | -24 |
| zero vector | 8 | -16 |
| position vector | 8 | -8 |

The pair and spread share the same starting displacement. Spread occupies only
four bytes, while the pair reserves eight. The next object begins at -24, so
the other four bytes cannot be used by the vector locals in this allocation.
These are allocator displacements, not claims that the emitted function uses
an EBP frame. [layout-results.json](layout-results.json) retains descriptor and
definition words before/after allocation, node-derived source associations,
and asserted sizes/offsets.

## Causal extent control

[extent_intervention.py](extent_intervention.py) changes the selected copied
owner immediately before allocation. Its guards require exactly one matching
memory-store destination and the expected initial sizes. It modifies only the
loaded compiler process; installed compiler files, sources, flags, candidates,
and provider state are untouched.

| Intervention | Field writes | Whole COFF equals stock* | Frame | Agreement |
|---|---:|---|---:|---:|
| None | 0 | Yes | 32 | 71.304348% |
| Descriptor `+0x20`: 8 to 4 | 1 | No | 28 | 86.956522% |
| Definition `+0x10`: 8 to 4 | 1 | Yes | 32 | 71.304348% |
| Both | 2 | No | 28 | 86.956522% |

*Timestamp bytes 4–7 are excluded. Descriptor-only and both also produce equal
whole COFFs under that normalization. Every mode has 115 instructions, 12 clean
aligned references, zero reference problems, and a non-exact body.

An assertion compares the descriptor result against the stock witness while
changing only the frame reservation and memory displacements above the gap.
It accounts for pushes and call cleanup so spread's argument-adjusted accesses
remain unchanged. The resulting normalized listing agrees exactly with that
restricted transformation. The EDI triplet, heading load, and ID load are also
asserted separately.

[extent-results.json](extent-results.json) records the verified modes and
hashes. [extent-native-diff.txt](extent-native-diff.txt) is the remaining full
native diff. It contains zero-register choices in the initial count tests,
outer-loop count test, and final clears, plus branch offsets. This comparison
is a diagnostic description of the residual, never positional or exact credit.

## Zero allocation is a later decision

[zero_seed.py](zero_seed.py) checks the already-preserved canonical and witness
replays against their observed objects and captured source hashes. It reads
the actual binary traces, confirms their complete-operand JSON copies, and
finds exactly one zero constant pseudo-definition (`0x163`) in each control.

Both seeds have 12 instruction users after `0x26d75`, before `0x30308`, and
before/after `0x306c1`. Both original seed identities and references to those
temporaries have disappeared by the snapshot before `0x336f4`. The distinct
machine-code zero strategies therefore warrant tracing that later allocation/
rewriting interval. Equal counts alone do not prove equal interference graphs,
costs, or register choices. [zero-results.json](zero-results.json) preserves the
seed identities and complete selected-user operands within each replay.

The next bounded trace should follow these zero temporaries through the later
allocation/coalescing decisions, comparing their definitions, users, conflict
sets, and costs. Keep the successful pointer-copy source fixed for that trace.
The independent source question is how to retain the dead pointer write with
only four bytes of storage charged to its owner.

## Source controls retained

[source_controls.py](source_controls.py) rebuilds 28 variants plus canonical
and witness controls; [source-results.json](source-results.json) stores every
source/COFF/instruction hash, native metric, and explicit gate check.

- Fourteen counter-lifetime variants hoist/reset the spawn counter, optionally
  sharing it in comparisons and clears. They restore the final EBX/BL clears
  but disrupt the original prologue and witness triplet. No improvement is
  accepted.
- Five four-byte-copy/union/byte-buffer forms reserve 28 bytes and keep EDI
  field loads, but lose the dead pointer store. The union forms are diagnostic
  representation controls, not proposed recovered source.
- Pointer arrays, nested structs, and an inherited member reproduce the
  witness's normalized instructions and eight-byte owner behavior.
- Six copy-loop induction controls test countdowns and pointer bounds.
  Countdown pointer loops reproduce the witness whole COFF except timestamps.
  Thus explicit initialization of the byte index to zero is not necessary for
  its zero-register behavior. The other forms do not improve the source.

## Reproduce

Use `UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python` for each
script below, from the repository root. First reproduce the earlier
[pointer-home trace](../vc6-timeline-pointer-home-2026-09-12/README.md#reproduce)
at `/private/tmp/timeline-pointer-home-trace-proof`. Its
`shape/body-copy-relative` subdirectory is the witness replay root. The earlier
[counterfactual driver](../vc6-timeline-late-removal-2026-09-12/counterfactual.py)
with `--out /private/tmp/timeline-causal-proof` supplies the canonical replay.

```text
source_controls.py --out /private/tmp/timeline-decomposition-reproduction
layout_trace.py --root /private/tmp/timeline-pointer-home-trace-proof/shape/body-copy-relative --out /private/tmp/timeline-decomposition-layout-verified
extent_intervention.py --root /private/tmp/timeline-pointer-home-trace-proof/shape/body-copy-relative --observer /private/tmp/timeline-decomposition-layout-verified/observer.c --out /private/tmp/timeline-decomposition-extent-verified
zero_seed.py --canonical-root /private/tmp/timeline-causal-proof/baseline --witness-root /private/tmp/timeline-pointer-home-trace-proof/shape/body-copy-relative --out /private/tmp/timeline-zero-seeds.json
```

Script paths are relative to this evidence directory. The witness source hash
is pinned to `5ad0be6a087969c28411fe3658c58a1dd2863f4611f4e843d684210f0a257cf9`
and C2 to `d50100ac2380d58f3f6f756961fb1319d35f5248e5fa6cafb866ca657e5dda4a`.
