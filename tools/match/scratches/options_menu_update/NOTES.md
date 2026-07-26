# `options_menu_update`

Native target: `crimsonland.exe` at `0x004475d0` (1,621 bytes).

Current reconstruction: **69.96%**, 372 candidate instructions versus 377
native instructions, with 138 aligned references proven, no unresolved
references, and eight alignment mismatches.

Live Binary Ninja and IDA evidence recovers the complete options-screen
callback. It positions the panel from UI element 31, renders the options
heading and labels, and owns local-static widgets for UI information text,
sound/music volume, graphics detail, mouse sensitivity, and Controls
navigation.

The callback translates the two volume sliders to 0.0..1.0 floats, clamps
graphics detail to presets 1..5 before applying it, and rounds/clamps mouse
sensitivity to 0.1..1.0. It also refreshes the violence-sensitive name and
description of the Bloody Mess / Quick Learner perk slot, routes the Controls
button, and handles Escape through the contextual Back action.

The five-instruction residual is global VC6 allocation/scheduling shape. The
native retains panel X in `edi`, later reuses that register for the detail
maximum, and orders several independent two-float widget-position stores
differently. The known VC6.5 point-profile, VC6.6, VC6.5pp, VC7, and `/G6`
checks did not reproduce that allocation; the semantically direct `/GB`
source remains the strongest result. The scratch is consequently
`semantic-complete` with a `compiler` residual. Its eight visible audit
mismatches pair adjacent static-widget fields, render constants, and the
already-recovered Bloody Mess / Quick Learner name-description values after
that scheduling divergence; none is aliased away as reference debt.

## Native-grounded SFX position sweep (2026-07-26)

Live Binary Ninja evidence localized the first slider-position divergence
without changing its recovered behavior. Native `0x004478b5..0x004478e0`
loads panel X, adds `148.0f`, stores that one x87 result first to `xy.x` and
then to the temporary slider X, and only then loads panel Y, adds `47.0f`, and
stores the temporary slider Y. The current object performs the same operations
in the same semantic order at function-relative `0x2e0..0x30b`; its different
stack slots follow the earlier frame/allocation divergence.

The recorded one-site sweep in
`sfx-slider-position-mutations.json` tested six ordinary C++ source shapes:
two declaration placements, both chained-assignment directions, a
slider-first copy, and a two-argument constructor. All six singles compiled to
the same matcher result as the baseline: **69.96%**, 372 candidate
instructions, prefix 8, `138/0/8` references, and exactly zero weighted-score
delta. There were no positive singles, so no interaction was eligible. The
complete sweep is recorded in `experiments.jsonl`; no source variant was
applied.
