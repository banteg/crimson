# `creature_find_nearest`

Current exact VC6.5 result:

```txt
match=100.00% prefix=89/89 target_insns=89 candidate_insns=89 refs=5/0/0
```

Both native search modes are represented: the `exclude_id == -1` path accepts
only active creatures at lifecycle stage 16, while the other path excludes one
index and applies `min_dist`. Both retain the nearest index and distance on the
x87 stack across the fixed-pool scan.

Direct `creature_pool[index]` expressions in the first mode recover the native
struct-base induction variable and resolve all five references. Its shared
inlined `vec2_distance` form recovers the native staged square-and-accumulate
kernel. Naming the rounded square-root result before returning it also recovers
the native x87 discard/store order, extending the exact prefix from 27 to 51
instructions. The `min_dist` mode retains the distinct direct
`dx * dx + dy * dy` shape visible in native x87 code.

The query position is a read-only `vec2f_t` in the recovered interface. That
type propagates through the live Binary Ninja database and exposes `pos->x`
and `pos->y` in both native loops instead of untyped float indexing. Existing
callers retain their native code generation by casting only at the boundary
from their embedded position storage. This is a source-shape and decompiler
improvement; it does not change the score or masked-reference audit.

Both scans now also address the canonical `creature_t.position` aggregate
directly. The remaining component reads are ordinary `position.x`/`.y`
accesses rather than provisional top-level `pos_x`/`pos_y` aliases.

The second mode makes the native two-precision lifetime explicit. The `sqrt`
result remains live as a `double` while a stored `float` copy is used for the
nearest-distance ranking. Casting the live result to `float` specifically at
the `min_dist` boundary gives both operands their native float ownership while
preserving that x87 lifetime. VC6 consequently emits native's `fsqrt`, two x87
discards, non-popping `fst`, and direct `fcomp [min_dist]` sequence. This
removes the former `fld`/`fxch`/`fcompp` residual and closes the function.

The second mode's stored square-root is behaviorally significant. Shock-chain
retargeting passes the hit creature as `exclude_id` and `100.0f` as
`min_dist`; native compares the PC=24 `fsqrt` result rather than squared host
distances. Python and Zig now use that exact ranking, including strict bounds,
the 384-slot limit, and the native slot-zero fallback only in bug-preserving
mode. A two-target regression covers a case where host-double squared distance
prefers slot 1 but native's equal stored distances retain slot 0.

## Recovery classification audit

Live Binary Ninja confirms both complete 384-slot scans, their distinct
filters, strict comparisons, slot-zero fallback, and stored `fsqrt` behavior.
The source preserves the native square-root lifetime and stored-float ranking.
The result is exact: 89/89 instructions, full 89-instruction prefix, zero fuzzy
gap, and references 5/0/0.

## Recorded distance-lifetime search

`distance-condition-mutations.json` records three assignment-in-condition
forms, all byte-neutral at the former 92.74% baseline.
`live-and-stored-distance-mutations.json` records four live/stored
representations; the explicit live-`sqrt` plus stored-float form is the sole
improvement. Recorded probes confirm that reusing the shared float-returning
helper regresses to 90.50%, while an equivalent double/output-parameter helper
is byte-neutral at 93.33%.

`lower-bound-control-flow-mutations.json` then evaluates eight ordinary
representations of the residual `min_dist` gate from that improved baseline:
comma-sequenced storage, nested comparisons, an in-guard distance, early and
positive-guard gotos, a named boolean, and reference/pointer lower bounds.
Seven are byte-neutral. Computing the distance inside the guard adds one
candidate instruction and loses 6.13 fuzzy-weighted bytes. Across the three
recorded plans, all 15 bounded lifetime/control-flow variants are now covered;
none removes VC6's `fld`/`fxch`/`fcompp` lowering within that matrix. Exact
closure instead comes from the distinct live-owner/use-site cast interaction
described above.

`wide-distance-expression-mutations.json` adds five late-rounding forms that
keep one `double` square-root result and cast only at the ranking comparison
and assignment. All five add one candidate instruction and regress: the three
direct/const/nested forms lose 6.13 weighted bytes, while assignment-in-guard
forms lose 8.62. The recorded spec SHA-256 is
`d7edfc4b1ccbd207d9c9153c07a0a3b614e7f97e5a6ac898a08d57ef8561e9c3`.
VC6.0, 6.5, and 6.6 were tied at 93.33%; `/G5`, `/Oa`, `/Ow`, `/Ob1`, and
explicit `/Ot` were byte-neutral, while `/G6`, `/Oy-`, `/Op`, Processor Pack,
and VC7 regressed. The unrecorded interaction was narrower: retain the live
wide result and cast only its lower-bound use to `float`. That source boundary
recovers the direct native `fcomp [min_dist]` without count or reference debt.
