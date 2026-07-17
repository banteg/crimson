# `quest_mode_update`

Native target: `crimsonland.exe` at `0x004070e0` (455 bytes, 108
instructions).

The recovered MSVC 6.5 `/O2 /GB` source is exact:

```txt
match=100.00% prefix=108/108 target_insns=108 candidate_insns=108 refs=52/0/0
```

## Recovered source shape

- `quest_spawn_timeline_update` runs every frame. Only the timeline and stage
  banner accumulation are paused while the console is open or the terrain-only
  render pass is active.
- The spawn timeline itself stalls once both the creature pool and spawn table
  are empty, while the stage banner still advances.
- Demo mode suppresses quest completion. Normal completion requires both no
  active creatures and an empty spawn table and clears Reflex Boost every
  qualifying frame.
- A negative transition timer starts completion by muting the extra music
  track, incrementing completed-quest counter `40 + major * 10 + minor`, and
  seeding the timer at zero.
- The mutually exclusive transition branches share one final integer frame
  delta increment. The quest-hit stinger fires only for `800 < timer <= 850`
  and seeds the timer at 851; completion music fires only for
  `2000 < timer <= 2050`, seeds it at 2051, and starts its volume at zero.
  The common increment therefore produces the observed `dt`, `851 + dt`, and
  `2051 + dt` results without branch-local arithmetic.
- Once the pre-increment timer is strictly above 2500 ms, the function advances
  the normal unlock index to `major * 10 + minor - 10`; hardcore completion
  additionally advances the full unlock index. It then saves status, requests
  quest results, resets the transition direction, flushes input through Grim2D,
  polls the console, and clears the active high-score XP field.

## Matching evidence

The zero seed must occur before the completed-quest counter update. With that
source order and the shared tail increment, VC6 retains the zero in `eax`,
emits the native indexed load/increment/store, and reproduces the hit, music,
unlock, and final timer blocks instruction for instruction. No volatile
qualifier, dummy access, artificial reference, or register-forcing construct is
used.

## Port parity

Python already models the strict event windows and advances both normal and
hardcore progress on a hardcore completion. The native unlock block revealed
that Zig advanced only the hardcore track; `c8e32bfdf` corrects it and the full
Zig suite passes all 481 tests.
