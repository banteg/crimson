# `angle_approach`

Native target: `crimsonland.exe` at `0x0041f430` (299 bytes).

The current MSVC 6.5 `/O2 /GB` candidate recovers the complete wrap,
shortest-arc, clamp, and turn-step behavior. It produces 100 instructions
against 101 native instructions, scores 90.55%, shares the first 73
instructions, and resolves all nine candidate references without a mismatch.

## Corrected return type

The decompilers type this helper as `void`, but the native function returns the
clamped shortest angular distance as a `float`. Every exit deliberately leaves
that value in `st(0)`, while both callers at `0x00426c9b` and `0x00426d93`
immediately discard it with `fstp st(0)`. The analogous exact
`player_heading_approach_target` helper returns the same quantity.

The source therefore keeps the unscaled distance as `amount`, computes a
separate `frame_dt * amount * rate` step, updates the referenced angle, and
returns `amount`. This explains the otherwise puzzling live x87 value at every
native return and corrects the canonical signature to
`float angle_approach(float *, float, float)`.

## Remaining compiler delta

The native schedules both floating-point comparisons before choosing an arc,
then emits the identical step calculation separately in each arc block. Clean
C and C++ forms make VC6 hoist that common calculation above the branch. The
residual was tested with pointer and reference parameters, shared and scoped
step locals, structured and label-based control flow, all ordinary operand
orders, C89 and C++, MSVC 6.5, the Processor Pack, MSVC 7.0, and the relevant
optimization profiles. None reproduces the branch-local scheduling without
worsening already exact code. No volatile, aliasing, or dummy operation is
retained to force it.
