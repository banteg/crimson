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

Binary Ninja retains two split views of the loop address: a
`bonus_entry_time_block_t *` induction cursor at `entry + 8` and the recovered
owning `bonus_entry_t *` base. Typing the latter exposes `bonus_id`, `state`,
and `time.time_left` on the base-dependent stores and call argument instead of
negative anonymous offsets. The interior time cursor and its 0x1c stride are
kept because they are the actual native induction shape. Both views are now
keyed to their native `mov edi, &bonus_pool[0].time` and
`lea esi, [edi-8]` definitions in the replay map.

## Port parity

The pickup gate uses the same PC24 `sqrt(dx * dx + dy * dy) < 26.0f` kernel as
the exact scratch. Python previously compared a double-precision squared
distance. At offset `(25.9999981, 0.00960000046)`, that double sum is below
`26^2`, while native rounds the PC24 sum to 676 and the hypotenuse to exactly
26, so no pickup occurs. Python and Zig now call their shared native-radius
helpers, with this strict boundary covered directly.

The separate Telekinetic pickup loop is embedded in `bonus_render`, not this
exact target. It advances per-player hover state at `0x00429df8`, but calls the
singleton `perk_count_get` at `0x00429e07` before passing the iterated player to
`bonus_apply` at `0x00429f0e`. Because `perk_count_get` reads player slot zero,
both ports now retain slot-zero Telekinetic ownership in bug-compatible mode;
corrected mode keeps intuitive ownership by the player aiming at the pickup.

## 1.9.8 (C2 9044), exact (2026-10-16)

Exact in both builds. With `picked` in a local, 9044 records the tutorial
guard's `picked == 0` as a fact and threads the tutorial store's jump past both
the decided `time_left < 0` compare and the second `picked` test. Reading
`bonus->picked` at each test (no local; the countdown as an `if`/`else` of
`-=` so the field store does not kill the byte) leaves the guard's fact on a
memory expression; 9044 then threads only the float compare, as native does.
8966 output is unchanged.
