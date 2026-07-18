# creature_find_in_radius exact match

```txt
match=100.00% prefix=47/47 target_insns=47 candidate_insns=47 refs=5/0/0
```

The exact source uses a pre-tested `index < 0x180` scan and direct
`creature_pool[index]` field expressions. VC6 strength-reduces those accesses
to the native struct-base pointer induction variable. Introducing a temporary
`creature_t *` instead rebases that induction variable to `pos_x`, splitting
the active check and changing every field displacement.

The shared inlined `vec2_distance` shape recovers the native x87 square, sum,
`fsqrt`, and temporary-discard sequence. A `goto found` after all three tests
places the exhausted-scan `-1` return before the successful index return,
matching the native loop back-edge and block order exactly.

The radius comparison is strict: `distance - radius < size * 0.14285715f +
3.0f`. Python and Zig now route perk targeting through the shared PC=24
predicate, including rejection when the two sides are exactly equal. Zig's
damaging-particle collision path now reuses the same predicate instead of its
former equality-accepting duplicate.
