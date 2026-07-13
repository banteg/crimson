# bonus_try_spawn_on_kill WIP

Current best local score:

```txt
match=88.24% prefix=6/207 target_insns=207 candidate_insns=201 refs=47/0/0
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

The remaining six candidate instructions are a control-flow layout residual.
The calibrated compiler tail-merges the forced-path and general-path
clear-and-return blocks, while native retains a second copy after the general
duplicate/amount checks. The surrounding instructions align. Do not add a
layout-only `goto` just to defeat tail merging without stronger source or
neighboring-object evidence.
