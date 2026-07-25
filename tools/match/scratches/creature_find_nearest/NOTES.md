# creature_find_nearest WIP

Current best local score:

```txt
match=92.74% prefix=51/89 target_insns=89 candidate_insns=90 refs=5/0/0
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

The remaining difference is the second mode's float-spill scheduling. VC6
spills and reloads the result while clearing two temporaries; native moves the
result down the x87 stack and saves it afterward. Staged squared-distance,
shared-helper, return-value, output-parameter, aggregate, scope, and
compiler-profile variants preserve or worsen this shape. Do not manufacture
x87 liveness to hide the residual.

The second mode's stored square-root is behaviorally significant. Shock-chain
retargeting passes the hit creature as `exclude_id` and `100.0f` as
`min_dist`; native compares the PC=24 `fsqrt` result rather than squared host
distances. Python and Zig now use that exact ranking, including strict bounds,
the 384-slot limit, and the native slot-zero fallback only in bug-preserving
mode. A two-target regression covers a case where host-double squared distance
prefers slot 1 but native's equal stored distances retain slot 0.
