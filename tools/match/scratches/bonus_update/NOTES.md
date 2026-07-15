# `bonus_update`

Native target: `crimsonland.exe` at `0x0040a320` (416 bytes).

Recovered as an exact 115/115-instruction match with all 37 native references
audited.

Live Binary Ninja evidence identifies the render-pass gate and a 16-slot bonus
loop. Active pickups lose one frame delta while available, three deltas after
being claimed, and the tutorial mode pins available lifetimes to five seconds.
Expired entries are cleared before unclaimed entries test every configured
player against the native 26-pixel pickup radius.

On collision, `bonus_apply` runs before the entry is marked claimed and held
for another half-second. Because that callback can mutate shared state, the
native reloads both player count and the current overlay-player index before
continuing. After the pool pass, the function clamps the freeze and
double-experience timers and advances the non-negative bonus phase accumulator.
