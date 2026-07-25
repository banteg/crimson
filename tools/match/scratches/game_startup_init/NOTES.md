# `game_startup_init`

Native target: `crimsonland.exe` at `0x0042b290` (4,303 bytes).

This is the startup-frame callback installed by `crimsonland_main`. It clamps
the frame delta, advances staged texture loading, runs the one-shot game
bootstrap, starts the audio loader, renders the loading screen and publisher
logos, accepts input to accelerate the intro, and finally replaces itself with
`game_frame_update`.

Live Binary Ninja evidence corrects the earlier analysis signature: the
function returns an unsigned byte, not `void`. All ordinary frames return one;
the Ctrl+Alt and quit paths return zero. The recovered source preserves that
engine callback contract.

The staged loading gate has one easily lost detail. The loading timer decays
only while both the publisher-logo sequence and the asynchronous load-ready
flag are active; every other path advances it. This ordering is visible in the
native control flow and materially changes the duration of the loading screen.
The one-shot byte at `0x00473a60` is initialized to one, cleared before this
gate, and referenced only by this callback, so it is mapped conservatively as
`startup_first_frame_latch`.

The recovered callback also includes:

- the five short post-load settle sleeps;
- the splash texture, UV, aspect-ratio, tint, and outline setup;
- loading progress text and spinner rendering;
- separate fade-in, hold, and fade-out phases for both logos;
- the native threshold ladder used when input accelerates the logo timer;
- FPS and console updates throughout startup;
- intro/theme music selection, including the demo path; and
- the final configuration callback swap to `game_frame_update`.

Current MSVC 6.5 `/O2 /GB` result:

```txt
match=98.93% prefix=1/1126 target_insns=1126 candidate_insns=1126 refs=333/0/0
first_target=sub esp, 0xc
first_candidate=sub esp, 0x10
```

The native interval ladder evaluates the second hold phase as
`timer >= 2 && timer < 4`; preserving that operand order lets VC6 reproduce
the native overlapping x87 comparisons and raises the candidate from
93.73%/1123 instructions to 98.93%/1126. Native condition masks also prove
strict lower bounds at 1 and 7, and the native progress string is
`"Grim GFX %d/%d"` without a colon. Those corrections eliminate all three
reference mismatches.

The remaining differences are compiler residue: the candidate uses a `0x10`
local frame instead of the native `0x0c`, plus one independent x87/vtable-load
scheduling swap. All recovered behavior and callsites are represented. The
scratch deliberately leaves those differences honest rather than using
volatile state, dead expressions, dummy references, inline assembly, forced
layout, or layout-only control flow.
