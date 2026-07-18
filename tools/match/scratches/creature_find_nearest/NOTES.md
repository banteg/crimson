# creature_find_nearest WIP

Current best local score:

```txt
match=91.62% prefix=27/89 target_insns=89 candidate_insns=90 refs=5/0/0
```

Both native search modes are represented: the `exclude_id == -1` path accepts
only active creatures at lifecycle stage 16, while the other path excludes one
index and applies `min_dist`. Both retain the nearest index and distance on the
x87 stack across the fixed-pool scan.

Direct `creature_pool[index]` expressions in the first mode recover the native
struct-base induction variable and resolve all five references. Its shared
inlined `vec2_distance` form recovers the native staged square-and-accumulate
kernel; the `min_dist` mode retains the distinct direct `dx * dx + dy * dy`
shape visible in native x87 code.

The remaining differences are float-spill scheduling. In the first mode VC6
saves the square root before discarding the helper temporary, while native does
those two independent instructions in the opposite order. In the second mode
VC6 spills and reloads the result while clearing two temporaries; native moves
the result down the x87 stack and saves it afterward. Return-value, output-
parameter, aggregate, scope, and compiler-profile variants preserve or worsen
these shapes. Do not manufacture x87 liveness to hide the residual.

The second mode's stored square-root is behaviorally significant. Shock-chain
retargeting passes the hit creature as `exclude_id` and `100.0f` as
`min_dist`; native compares the PC=24 `fsqrt` result rather than squared host
distances. Python and Zig now use that exact ranking, including strict bounds,
the 384-slot limit, and the native slot-zero fallback only in bug-preserving
mode. A two-target regression covers a case where host-double squared distance
prefers slot 1 but native's equal stored distances retain slot 0.
