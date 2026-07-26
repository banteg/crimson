# grim_timing_init

`grim_timing_init` at `0x10004920` installs the `0.001f`
milliseconds-to-seconds scale, takes one `timeGetTime` sample, and seeds the
timing epoch plus both previous/current tick samples from it. It clears the
game-time, frame-delta, FPS, and frozen state, then requests a one-millisecond
Windows multimedia timer period. The `timeBeginPeriod` result is ignored.

The recovered function matches all 13 native instructions and all 10
references under MSVC 6.5 `/O2 /GB`.
