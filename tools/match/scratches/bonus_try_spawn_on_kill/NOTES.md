# bonus_try_spawn_on_kill WIP

Current best local score:

```txt
match=91.43% prefix=6/207 target_insns=207 candidate_insns=213 refs=47/0/0
```

The recovered source matches the mode and demo gates, two-player Pistol force
path, all four drop-gate RNG call sites, random weapon replacement, both fixed
16-entry duplicate scans, player-1-only PC=24 proximity conversion, native raw
amount-versus-weapon suppression, sentinel rejection, and the complete
16-particle effect-template loop. All 47 masked references resolve to the
intended fields, globals, constants, and helper calls.

Modeling the global effect template as its actual struct recovers the native
four-float color temporary and its stack frame. This target exposed three port
issues: the 56-unit proximity test used non-native precision, Zig generalized
the native player-slot check, and Zig emitted the accepted-drop burst with the
wrong lifetime and color. The corresponding fixes have focused regressions.

The kill position is now recovered as a read-only `vec2f_t`, replacing raw
component indexing in the player-proximity check and effect-spawn boundary.
Binary Ninja carries that type through the copied `drop_pos` cursor and types
both fixed-pool scans as `bonus_entry_t *`, eliminating their raw `+0x10`,
`+0x14`, and seven-word-stride interpretations. This type recovery preserves
the 91.43% score and all 47 aligned references.

A follow-up native-mode audit now also carries the exact `perk_count_get`
asymmetry through Zig's `preserve_bugs` path. My Favourite Weapon and Bonus
Magnet read player 0 only, the fallback Pistol gate reads player 0 only, and
the forced-weapon Pistol test admits player 1 only when the configured slice
has exactly two players. Corrected mode deliberately retains the generalized
co-op policy.

The Python native-mode path now preserves that final forced-weapon asymmetry as
well. It had continued to admit a Pistol from any port-side player even under
`preserve_bugs`, so a third player could consume the forced-drop RNG gate and
materialize a Weapon drop that native never attempts. Focused two- and
three-player regressions pin the exact `player_count == 2` boundary.

The two general-path suppressions are expressed as independent guards. This
plausible spelling prevents VC6 from folding both into the forced-path cleanup
and raises the fuzzy match from 88.24% to 91.43% without volatile data, dead
expressions, or register forcing. It is still not an exact CFG: native shares
one cleanup between the duplicate and current-weapon checks, while VC6 emits
one cleanup for each, leaving six extra candidate instructions. Combining the
conditions tail-merges all three cleanups and regresses the score; a layout-only
`goto` remains intentionally rejected.
