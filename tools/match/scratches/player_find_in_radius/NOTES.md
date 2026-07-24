# player_find_in_radius exact match

```txt
match=100.00% prefix=54/54 target_insns=54 candidate_insns=54 refs=5/0/0
```

The scratch preserves the owner-derived skip index, configured player-count
bound, alive-player filter, radius-plus-size test, and first-hit return.
The shared inlined `vec2_distance` helper recovers the native x87 distance
kernel. Direct `player_state_table[player_index]` expressions make VC6 retain
the native health-based induction variable; a raw `float *health` iterator is
instead rebased to `pos_y` and changes all field displacements.

A pre-tested player-count loop with a shared `found` return places the miss
epilogue on the loop fallthrough and the hit epilogue afterward, matching the
native back-edge and block order exactly.

The query position is recovered as a read-only `vec2f_t`, so the native
boundary carries the same two-component meaning as the embedded player
position. Binary Ninja uses the corresponding prototype and identifies the
compiler-selected interior iterator as `float *health_cursor`; the input now
renders as `pos->x`/`pos->y`, while the cursor's `[-4]`, `[-3]`, and `[4]`
accesses honestly remain because the native induction variable is anchored at
`player_state_t::health`, not at the struct base. Pretending that interior
pointer is a `player_state_t *` would assign the wrong addresses. The type
recovery preserves the exact 54/54 match.
