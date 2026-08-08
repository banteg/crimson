# `creature_find_nearest`

Current honest VC6.5 result:

```txt
match=93.33% prefix=51/89 target_insns=89 candidate_insns=91 refs=5/0/0
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

The second mode now makes the native two-precision lifetime explicit. The
`sqrt` result remains live as a `double` for the strict `min_dist` comparison
while a stored `float` copy is used for the nearest-distance ranking. This
recovers native's `fsqrt`, two x87 discards, and non-popping `fst` sequence,
improving the fuzzy-weighted alignment by 1.34 bytes and the score from 92.74%
to 93.33%. VC6 lowers the live-double versus float lower-bound comparison as
`fld`/`fxch`/`fcompp`, whereas native uses a direct `fcomp` from the same x87
value. That leaves two extra candidate instructions.

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
The focused delta is confined to the second mode's lower-bound comparison
lowering after the now-matching non-popping store. The source preserves the
native live square-root comparison and stored-float ranking. All five
references resolve.

Classification is `RECOVERY=semantic-complete`, `RESIDUAL=compiler`. The
final result is 93.33%, prefix 51/89, 91 candidate versus 89 target
instructions, a 15.00-byte fuzzy gap, and references 5/0/0.

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
none removes VC6's final `fld`/`fxch`/`fcompp` lowering, so no further source
change is retained.

`wide-distance-expression-mutations.json` adds five late-rounding forms that
keep one `double` square-root result and cast only at the ranking comparison
and assignment. All five add one candidate instruction and regress: the three
direct/const/nested forms lose 6.13 weighted bytes, while assignment-in-guard
forms lose 8.62. The recorded spec SHA-256 is
`d7edfc4b1ccbd207d9c9153c07a0a3b614e7f97e5a6ac898a08d57ef8561e9c3`.
VC6.0, 6.5, and 6.6 remain tied at 93.33%; `/G5`, `/Oa`, `/Ow`, `/Ob1`, and
explicit `/Ot` are byte-neutral, while `/G6`, `/Oy-`, `/Op`, Processor Pack,
and VC7 regress. The direct native `fcomp [min_dist]` remains a backend
lowering boundary rather than a missing rounded-distance lifetime.
