# weapon_assign_player WIP

Current best local score:

```txt
match=81.97% prefix=12/61 target_insns=61 candidate_insns=61 refs=21/0/0
```

The recovered source accounts for every native instruction and all 21 masked
references: demo-gated usage accounting, player and weapon-table indexing,
integer-to-float clip initialization, both perk modifiers, the ammo and timer
resets, the per-player auxiliary timer, and the panned reload sound call.

The native function calls `perk_count_get` for both clip modifiers, so it reads
player 0's perk counts even when assigning a weapon to player 1. The ports read
the recipient player's copy, but valid gameplay state keeps those arrays
synchronized whenever a perk is applied. This therefore documents an important
state invariant rather than justifying an invasive runtime API change without
an observed reachable divergence.

The remaining mismatch is compiler scheduling and register allocation. The
candidate computes the same two fixed-stride offsets in a different order,
loads the first perk id earlier, and keeps the final float copy on x87 instead
of using an integer register. VC6.6 produces the same result, while VC6.5pp and
`/O1` are worse. Leave those residuals honest rather than imposing volatile
accesses, bit-punning, or artificial liveness.
