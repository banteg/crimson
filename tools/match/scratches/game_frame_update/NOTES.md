# `game_frame_update`

Native target: `crimsonland.exe` at `0x0040c1c0` (3,588 bytes).

This is the top-level game callback registered by `game_startup_init`. Live
Binary Ninja evidence recovers its gameplay-facing frame policy: terrain
rerolls, console and screenshot input, demo/trial clocks, Reflex Boost time
scaling, screen fade, mouse and analog cursor routing, game-state dispatch,
pause and quit transitions, the shareware time bar, version rechecks, and the
discarded per-frame `crt_rand()` call that advances the shared gameplay RNG.

Two control-flow details materially corrected the first candidate. Attract mode
and the trial overlay freeze the sequence/trial clocks; the clocks advance only
when both latches are clear. `audio_resume_all()` is called only by the early
audio-suspended path. Normal completion branches directly to the shared
`return 1` epilogue, while full-version quit and update-wait paths return `0`.
That also corrects the former `void` signature in the curated name map.

The Reflex Boosted perk transform is an outer-loop operation, not a
player-movement hook. Live instructions at `0x0040c4bd..0x0040c517` perform the
perk lookup, store `frame_dt * 0.9f`, and rederive `frame_dt_ms` before the call
to `gameplay_update_and_render` at `0x0040c887`. The Python session pipeline now
applies this transform before Reflex Boost bonus scaling and shares the result
with entity updates, mode timelines, and elapsed gameplay. Native-capture
replays skip the transform because their gameplay-entry delta already includes
it; port fixed-step replays retain the transform during playback.

The native stack shape is two two-float values for analog input and cursor
delta. Axis values come from the Grim2D config-float slot at vtable offset
`0x84`; the cursor dead zone is `0.2f` and its analog scale is `540.0f`.
Component-wise assignment handles the first active stick, while the second
uses the game's ordinary vector `operator+=` shape. The shareware bar uses
`play_time_ms / demo_trial_time_limit_ms()` clamped at `1.0f`, including
its native color curve and geometry.

The mouse-delta latch at `0x0040c5ce..0x0040c632` owns two side effects that
the earlier reconstruction had placed unconditionally. Native stores the
boolean result first, then clears `ui_mouse_blocked` and
`ui_analog_cursor_active` only when both mouse axes are nonzero. Leaving either
axis at zero preserves those two existing latches.

Native cursor routing is likewise two decisions rather than one combined
condition. Gameplay first clears `ui_analog_cursor_active`; a separate
`state != Gameplay && analog_active == 1` test chooses analog menu movement.
Only the physical-mouse arm propagates the screen-space mouse pair through the
signed indexed loop to both player aim slots. The analog arm jumps directly to
the common bounds clamps and does not rewrite player aim. Recovering these
branch owners fixes observable stale-latch and aim-update behavior, extends the
exact prefix from `263` to `363` instructions, and improves reference agreement
from `299/0/0` to `314/0/0`.

The shared `mod_parms_t` union now uses a named `mod_parms_fields_t` view, so
offset `1` is authoritatively identified as `onPause` in the type graph and
source. Binary Ninja's nested-union recovery still rendered that access as
`fields.__offset(0x1)`, so its data map uses the layout-equivalent
`mod_interface_binja_t *` presentation view. That exposes
`parms.onPause` directly while the matching header retains the canonical union;
the layout and generated code are unchanged.

Both transition fades test the zero-timeline case first, leaving the constant
`1.0f` result on the native fallthrough and putting the calculated division in
the alternate arm. This source-level inversion improved the score from
`93.92%` to `94.14%`. The pause request is one key-first short-circuit
expression over render mode and the accepted gameplay states; avoiding a
cached state local restores the native byte/state load order and raises the
final score to `96.08%`.

The shareware progress ratio first converts both the elapsed sequence id and
the trial limit to named floating-point values, then divides them. That natural
expression split reproduces native's `fild`/`fild`/`fdivp` sequence instead of
VC6 folding the denominator into `fidiv`. It restores the missing instruction
and raises the score from `96.08%` to `99.45%`.

Current honest MSVC result: `99.45%`, exact prefix `363/905`, candidate
`905/905` instructions, and masked references `317/0/0`. Remaining differences
are local load/store scheduling in the two-player aim copy and three equivalent
interface-call schedules. Aggregate vector assignment, direct indexed aim
stores, and the natural `set(x, y)` helper were tested, but regressed the score
or reference audit; the scalar pointer source is retained. No known native
behavior is omitted. The candidate uses no volatile, dead-code, register,
assembly, or layout constraints.

The one-time full-version menu adjustment now addresses the owning UI element
through `ui_element_t::pos.x/y` rather than its compatibility scalar aliases.
This is byte-neutral at the same 99.45%, 905/905 instructions, 363-instruction
prefix, and `317/0/0` references.

## Recovery classification audit

The four focused regions preserve the exact 905-instruction count and all 317
references. Live Binary Ninja confirms the first region is the two-player
mouse-aim copy and the others are already recovered interface calls; only
equivalent register and load/store schedules differ. The complete timing,
input, state-dispatch, pause, trial, and return policies are accounted for.

Classification is `RECOVERY=semantic-complete`, `RESIDUAL=compiler`. The
metadata-only change is byte-neutral: before and after are 99.45%, prefix
363/905, 905/905 instructions, and references 317/0/0.

## Recorded aim-copy sweep

`aim-copy-order-mutations.json` evaluated all three natural X/Y assignment
orders around the two-player aim copy. None improved the score or reference
audit, so the canonical scalar-pointer spelling remains unchanged and the
negative result is recorded in `experiments.jsonl`.

`aim-copy-typed-view-mutations.json` additionally evaluated six typed
player/vector cursor views. They are byte-neutral or regress the same localized
region, so the scalar pointer remains the best evidenced source.

`aim-copy-inline-helper-mutations.json` broadens that search to fourteen
one- and two-site inline-helper and call-boundary combinations. Alias-aware
indexed forms are byte-neutral; named-component helper forms move an earlier
region and regress by about 293 fuzzy-weighted bytes. No helper form improves
the native schedule. The plan SHA-256 is
`060418acba5fbec508268f889cf5015caf08ea02d9d251bf8a4e0c4680a5e071`.

`final-color-inline-helper-mutations.json` evaluates nine inline,
force-inline, interface-lifetime, component-lifetime, and restored-helper
forms around the final `set_color` call. Every complete form is byte-neutral,
which bounds the remaining call-order residual to VC6 scheduling rather than a
missing source-level helper. Its SHA-256 is
`19e5f0079dc9ee5720343e25ab7e88390d943fc33ea6e8e33079467e1b2ee9df`.

`aim-copy-scalar-helper-mutations.json` additionally evaluates five bounded
single- and two-site forms around separate scalar helper calls. Helper
definitions alone are byte-neutral, while both complete call forms move an
earlier scheduling boundary and regress to 91.27% with four fewer resolved
references. This rules out a per-component inline call boundary as the source
of native's X-store-before-Y-load schedule.

`aim-copy-aggregate-mutations.json` adds 11 recorded aggregate/source-view
forms (spec
`c1b928c5598874a76c2269a6760a69f2ca235ca3d7feb84a2e7b1c9852f6bf5c`).
The ordinary source-pointer component forms are byte-neutral. Direct aggregate
assignment and `memcpy` materially regress the instruction and reference
alignment, so none improves the **99.45%**, 905/905, `317/0/0` baseline.
No source change is retained.

`mouse-y-accessor-mutations.json` tests three inline/force-inline accessors
and their interaction with the second aim-component store. Direct accessors
compile byte-identically at 99.45%; a pointer-backed accessor moves an earlier
region, loses 285.45 fuzzy-weighted bytes and three resolved references, and
does not recover the native X-store-before-Y-load order. The accessor boundary
is recorded as a negative and no source change is retained.
