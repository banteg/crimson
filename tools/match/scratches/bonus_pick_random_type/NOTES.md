# bonus_pick_random_type WIP

Current best local score:

```txt
match=67.28% prefix=37/162 target_insns=162 candidate_insns=162 refs=20/0/0
```

The exact prefix recovers the fixed 16-entry bonus-pool scan, the retry counter,
the `rand() % 162 + 1` bucket draw, the rare Energizer acceptance roll, and the
start of the ten-wide bonus bucket walk. All 20 masked references resolve to
the intended globals, pool fields, constants, and helper calls.

The recovered filters also expose deliberate native player-slot asymmetry:
shield suppression reads player slots 0 and 1 directly, while My Favourite
Weapon and Death Clock use `perk_count_get`, which only reads player 0. The
Python and Zig ports previously generalized those checks across every active
player; the corresponding parity fix keeps the native slot rules explicit.

The remaining mismatch is control-flow shape in the quest-specific exclusions
and the shared retry/success epilogue. The candidate expresses the same observed
conditions cleanly, but VC6 lays out the native major-stage checks and the final
major-5 exclusion in a different order. Leave this scratch WIP until adjacent
quest logic or stronger source evidence explains that layout; do not force it
with opaque boolean identities or artificial liveness.
