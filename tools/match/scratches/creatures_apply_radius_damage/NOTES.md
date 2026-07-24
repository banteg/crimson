# creatures_apply_radius_damage exact match

```txt
match=100.00% prefix=57/57 target_insns=57 candidate_insns=57 refs=6/0/0
```

The recovered source initializes the zero impulse vector, scans all 384
creatures, applies the native distance-minus-radius test, rejects lifecycle
stages at or below `5.0f`, and calls `creature_apply_damage` with the native
argument order.

The recovered original `Crimson.h` declares this routine's lineage as
`GAME_DamageCreaturesInRadius(vec2_t &spot, ...)`. The exact scratch and saved
Binary Ninja prototype now preserve that reference-to-vector shape, so the
distance calculation renders as `spot.x`/`spot.y` instead of raw `pos[0]` and
`pos[1]`. The explicit reference recovery remains exact at 57/57 instructions
with 6/0/0 reference agreement.

Using the same inlined `vec2_distance` shape as the exact
`plaguebearer_spread_infection` and `creature_find_in_radius` scratches recovers
the native x87 evaluation and discard sequence. Direct
`creature_pool[creature_id]` expressions make VC6 strength-reduce the scan to
the native struct-base induction variable; a temporary pointer or C++ reference
instead rebases it to `pos_x` and changes every field displacement.
