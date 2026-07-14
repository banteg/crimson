# creatures_apply_radius_damage WIP

Current best local score:

```txt
match=85.22% prefix=11/57 target_insns=57 candidate_insns=58 refs=4/0/2
```

The recovered source initializes the zero impulse vector, scans all 384
creatures, applies the native distance-minus-radius test, rejects lifecycle
stages at or below `5.0f`, and calls `creature_apply_damage` with the native
argument order.

Using the same inlined `vec2_distance` shape as the exact
`plaguebearer_spread_infection` scratch recovers the native x87 evaluation and
discard sequence. A C++ reference to `creature_pool[creature_id]` also recovers
the native loop tail without an extra pointer-adjustment instruction.

The remaining mismatch is induction-variable rebasing. Native carries the
creature entry base and uses positive field offsets; VC6 carries `pos_x`, so
the active and lifecycle accesses use negative offsets and the active test is
split into `mov`/`test`. Both forms address the same fields. Do not offset the
source pointer or add dummy accesses solely to steer the register base.
