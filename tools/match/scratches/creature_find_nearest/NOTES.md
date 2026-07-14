# creature_find_nearest WIP

Current best local score:

```txt
match=79.56% prefix=7/89 target_insns=89 candidate_insns=92 refs=3/0/1
```

Both native search modes are represented: the `exclude_id == -1` path accepts
only active creatures at lifecycle stage 16, while the other path excludes one
index and applies `min_dist`. Both retain the nearest index and distance on the
x87 stack across the fixed-pool scan.

Staging the first path's squared distance as `dx * dx` followed by the y-square
accumulation recovers its native FPU ordering. The remaining differences are
VC6 rebasing that first loop at `pos_x` instead of the active byte, an earlier
float spill in both modes, and one reload in the `min_dist` path. These are
compiler-shape residuals; the scratch does not manufacture liveness or raw
field accesses to hide them.
