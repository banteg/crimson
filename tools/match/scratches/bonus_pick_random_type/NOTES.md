# bonus_pick_random_type WIP

Current best local score:

```txt
match=75.93% prefix=55/162 target_insns=162 candidate_insns=162 refs=20/0/0
```

The exact prefix recovers the fixed 16-entry bonus-pool scan, the retry counter,
the `rand() % 162 + 1` bucket draw, the rare Energizer acceptance roll, and the
complete ten-wide bonus bucket walk. Native tests `bucket <= 10` at the loop
head and `bucket_id < 15` on the backedge; expressing those as the two
structured loop conditions restores the native initialization order and grows
the exact prefix from 37 to 55 instructions.

The rejection paths now use ordinary `continue` statements and the retry limit
is the loop condition `retries++ < 100`. This reproduces native's success-first,
fallback-second return tail rather than the previous internal label and early
fallback return. The major-stage 4 Nuke and Freeze exclusions are also kept as
the two independent tests visible in native code. All 20 masked references
resolve to the intended globals, pool fields, constants, and helper calls.

The recovered filters also expose deliberate native player-slot asymmetry:
shield suppression reads player slots 0 and 1 directly, while My Favourite
Weapon and Death Clock use `perk_count_get`, which only reads player 0. The
Python and Zig ports previously generalized those checks across every active
player; the corresponding parity fix keeps the native slot rules explicit.

The remaining mismatch is confined to control-flow layout in the quest-specific
exclusions. Native outlines the final major-5 Nuke check after the retry and
success blocks, while VC6 keeps the same clean nested check beside the major-4
case. The displaced block changes downstream branch-target tokens even though
the instruction count, conditions, and references agree. Leave this scratch WIP
until stronger source evidence explains that cold-block placement; do not force
it with a manual tail label, opaque boolean identities, or artificial liveness.
