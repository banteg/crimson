# `angle_approach`

Native target: `crimsonland.exe` at `0x0041f430` (299 bytes).

The current MSVC 6.5 `/O2 /GB` candidate recovers the complete wrap,
shortest-arc, clamp, and turn-step behavior. It produces 100 instructions
against 101 native instructions, scores 94.53%, shares the first 73
instructions, and resolves all nine candidate references without a mismatch.

## Corrected return type

The decompilers type this helper as `void`, but the native function returns the
clamped shortest angular distance as a `float`. Every exit deliberately leaves
that value in `st(0)`, while both callers at `0x00426c9b` and `0x00426d93`
immediately discard it with `fstp st(0)`. The analogous exact
`player_heading_approach_target` helper returns the same quantity.

The source therefore keeps the unscaled distance as `amount`, computes
`frame_dt * amount` separately from the final `rate` multiplication, updates
the referenced angle, and returns `amount`. This explains the otherwise
puzzling live x87 value at every native return and corrects the canonical signature to
`float angle_approach(float *, float, float)`.

## Remaining compiler delta

The native schedules both floating-point comparisons before choosing an arc,
then forms `frame_dt * amount` separately in each arc block, tests the saved
direction status, and only then multiplies by `rate`. Splitting the final rate
multiplication at that same semantic boundary improves the fuzzy-weighted
alignment by 11.90 bytes and raises the score from 90.55% to 94.53%. Clean C
and C++ forms still make VC6 hoist the common partial product above the branch.
The residual was tested with shared and scoped step locals, structured and
label-based control flow, asymmetric operand forms, MSVC 6.x, the Processor
Pack, MSVC 7.0, and the relevant optimization profiles. None reproduces the
branch-local scheduling without worsening already exact code. No volatile,
aliasing, or dummy operation is retained to force it.

## Recovery classification audit

Live Binary Ninja confirms the wrap loops, both shortest-arc comparisons, the
one-unit clamp, two direction tests, branch-local step calculations, and the
`float` value returned from every exit. The sole focused region is the
documented VC6 common-expression hoist plus its downstream branch layout: the
candidate has one fewer instruction but preserves the same update and returned
amount. All nine references resolve.

Classification is `RECOVERY=semantic-complete`, `RESIDUAL=compiler`. The final
result is 94.53%, prefix 73/101, 100 candidate versus 101 target instructions,
a 16.36-byte fuzzy gap, and references 9/0/0.

## Recorded step-lifetime search

`direction-schedule-mutations.json`,
`partial-step-lifetime-mutations.json`, and `arc-cfg-mutations.json` record
twelve bounded direction, product-lifetime, and control-flow variants. The
split-final-rate form is the only material improvement; explicit labels,
asymmetric products, branch-local fallback duplication, and the remaining
shared-product spellings are byte-neutral or regress.
