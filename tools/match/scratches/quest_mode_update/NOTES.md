# `quest_mode_update`

Native target: `crimsonland.exe` at `0x004070e0` (455 bytes, 108
instructions).

The recovered MSVC 6.5 `/O2 /GB` source is an honest WIP:

```txt
match=65.40% prefix=23/108 target_insns=108 candidate_insns=103 refs=35/0/5
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
  seeding the timer with the integer frame delta.
- The quest-hit stinger fires only for `800 < timer <= 850` and snaps the timer
  to `851 + dt`. Completion music fires only for `2000 < timer <= 2050`, snaps
  to `2051 + dt`, and starts its volume at zero.
- Once the pre-increment timer is strictly above 2500 ms, the function advances
  the normal unlock index to `major * 10 + minor - 10`; hardcore completion
  additionally advances the full unlock index. It then saves status, requests
  quest results, resets the transition direction, flushes input through Grim2D,
  polls the console, and clears the active high-score XP field.

## Remaining compiler delta

The first 23 instructions and the complete control-flow/side-effect graph agree.
The calibrated compiler emits a five-instruction-shorter body: it folds the
negative-branch counter increment into an indexed memory `inc`, folds the hit
timer seed into an immediate add, and schedules the music/unlock global loads
differently. Those shifts also change downstream branch-label tokens and cause
the five reported reference mismatches at otherwise aligned instructions.

MSVC 6.5pp and 6.6 produce the same best body. MSVC 7.0 and `/G6` both score
worse, while `/Og-` introduces a stack frame and broadly deoptimizes the
function. No volatile qualifier, dummy access, or other register-forcing source
is retained.

## Port parity

Python already models the strict event windows and advances both normal and
hardcore progress on a hardcore completion. The native unlock block revealed
that Zig advanced only the hardcore track; `c8e32bfdf` corrects it and the full
Zig suite passes all 481 tests.
