# weapon_assign_player

Exact match:

```txt
match=100.00% prefix=61/61 target_insns=61 candidate_insns=61 refs=26/0/0
```

The recovered source accounts for every native instruction and all 26 masked
references: demo-gated usage accounting, player and weapon-table indexing,
integer-to-float clip initialization, both perk modifiers, the ammo and timer
resets, the per-player auxiliary timer, and the panned reload sound call.

Three ordinary source-shape details recover the native schedule without
artificial liveness or representation tricks:

- pass the two global perk ids directly to `perk_count_get`;
- keep the Ammo Maniac increment in a dedicated integer local;
- assign `clip_size` directly to `ammo` instead of routing it through a float
  temporary.

The native function calls `perk_count_get` for both clip modifiers, so it reads
player 0's perk counts even when assigning a weapon to player 1. The ports read
the recipient player's copy, but both normal perk-application pipelines make
player 0 authoritative and synchronize the remaining perk arrays before later
weapon assignments. This is therefore a state invariant, not a reason to add
global-player coupling to the ports' low-level assignment APIs solely for
manually constructed inconsistent state.

The panned reload sound now receives a `const vec2f_t *` cursor into the
player's embedded position instead of an untyped float pointer. This source
shape remains exact at 61/61 instructions with all 26 references.
