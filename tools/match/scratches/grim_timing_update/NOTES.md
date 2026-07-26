# grim_timing_update

`grim_timing_update` at `0x10004970` waits until `timeGetTime` has advanced by
more than one millisecond. Active timing advances the game clock, publishes a
seconds-valued frame delta, and accumulates an FPS sample. Frozen timing forces
the frame delta to zero and advances only the separate timing epoch.

Once the FPS window exceeds 500 milliseconds, the function divides the frame
count by the full pre-subtraction window duration, publishes the result, clears
the frame count, and retains `elapsed - 500` milliseconds for the next window.

Keeping the FPS expression directly in terms of the globals reproduces the
native lifetime of the `timeGetTime` import register and the two unsigned
integer-to-float conversions. The recovered function matches all 53 native
instructions and all 23 references under MSVC 6.5 `/O2 /GB`.
