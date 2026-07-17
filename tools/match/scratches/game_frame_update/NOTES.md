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

The native stack shape is two two-float arrays for analog input and cursor
delta. Axis values come from the Grim2D config-float slot at vtable offset
`0x84`; the cursor dead zone is `0.2f` and its analog scale is `540.0f`. The
same screen-space aim pair is propagated through a signed indexed loop to both
players. The shareware bar uses `game_sequence_id / demo_trial_time_limit_ms()`
clamped at `1.0f`, including its native color curve and geometry.

Current honest MSVC result: `86.77%`, exact prefix `263/905`, candidate
`902/905` instructions, and masked references `299/0/0`. Remaining differences
are compiler block placement around the zero-mouse-delta and analog-cursor paths,
plus local x87 scheduling; no known native behavior is omitted. The candidate
uses no volatile, dead-code, register, assembly, or layout constraints.
