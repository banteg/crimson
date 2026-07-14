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
