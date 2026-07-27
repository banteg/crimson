# `options_menu_update`

Native target: `crimsonland.exe` at `0x004475d0` (1,621 bytes).

Current reconstruction: **71.20%**, 373 candidate instructions versus 377
native instructions, with 146 aligned references proven, no unresolved
references, and three alignment mismatches.

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

The four-instruction residual is global VC6 allocation/scheduling shape. The
native retains panel X in `edi`, later reuses that register for the detail
maximum, and orders several independent two-float widget-position stores
differently. The known VC6.5 point-profile, VC6.6, VC6.5pp, VC7, and `/G6`
checks did not reproduce that allocation; the semantically direct `/GB`
source remains the strongest result. The scratch is consequently
`semantic-complete` with a `compiler` residual. Its three visible audit
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

## Perk-slot refresh correction (2026-07-27)

A follow-up region pass selected the concentrated perk refresh and navigation
tail at `0x00447b6b..0x00447c12`. Live Binary Ninja shows the violence branch
loading the selected Bloody Mess / Quick Learner name and description pair at
`0x00447bc8..0x00447bf4` before writing the two fields of the same indexed perk
record. The prior source routed the description through a common temporary,
which made VC6 reverse the candidate register/reference pairing despite
identical runtime values.

The schema-1 `perk-slot-refresh-order` sweep tested all 5/5 planned natural
forms. Its spec SHA-256 is
`c408f4c669b8661f8fe69fabac788aa789b8bda6a94eeafb19ae79557aebda86`.
Keeping each selected name/description assignment together in its branch is
the only strong positive and is retained. It improves weighted bytes from
`1134.0507343124166/1621` (`69.95994659546061%`) to
`1154.152/1621` (`71.2%`), a gain of `20.101265687583464`; the gap falls from
`486.9492656875834` to `466.84799999999996`. Candidate instructions move from
372 to 373 against 377 native, prefix remains 8, and references improve from
`138/0/8` to `146/0/3`.

The retained source SHA-256 is
`65275e88c71a147c98eb7893d50eb49e3329d22b3afac1eeb619810c550addc5`.
Name-first ordering with a common description store gains only
`11.45593235425008` weighted bytes; the two one-branch reorderings are weaker,
and common name/description stores regress. The retained branch-local form is
ordinary behavior-equivalent C++ and contains no match-only construct.
