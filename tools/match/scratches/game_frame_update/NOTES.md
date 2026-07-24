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
`game_sequence_id / demo_trial_time_limit_ms()` clamped at `1.0f`, including
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

Current honest MSVC result: `93.92%`, exact prefix `363/905`, candidate
`903/905` instructions, and masked references `314/0/0`. Remaining differences
are local load/store scheduling in the two-player aim copy, old-VC6 byte-load
selection in the pause gate, and equivalent x87 division/block layouts. No
known native behavior is omitted. The candidate uses no volatile, dead-code,
register, assembly, or layout constraints.
