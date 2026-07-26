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
