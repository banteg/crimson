# quest_spawn_timeline_update

Native target: `crimsonland.exe` at `0x00434250` (368 bytes, 115
instructions).

The recovered MSVC 6.5 `/O2 /GB` source is an honest WIP:

```txt
match=91.23% prefix=51/115 target_insns=115 candidate_insns=113 refs=13/0/0
```

## Recovered source shape

- The integer stall timer resets while any creature is active and otherwise
  accumulates integer `frame_dt_ms` directly in the global.
- A six-int cursor scans the 24-byte quest entries for the first positive count
  whose trigger is strictly earlier than the quest timeline.
- The fail-safe may select a future entry only when no creature is active, the
  stall timer is strictly above 3000 ms, and the timeline is strictly above
  1700 ms.
- One update fires only the selected trigger group. Adjacent entries with the
  same trigger are consumed together, and every consumed count is cleared.
- Each entry spreads successive creatures by `0, -40, +80, -120, ...`. An
  off-screen x coordinate applies that spread vertically; an on-screen x
  coordinate applies it horizontally.
- The entry heading and template id are forwarded unchanged to
  `creature_spawn_template`. Firing any group clears the global none-active
  flag.
- The entry's first two floats are the same position value object recovered in
  the quest builders. Adding the alternating offset through its inlined vector
  operator reproduces the native x87 construction and right-to-left call-
  argument schedule for the temporary passed to `creature_spawn_template`.
- The canonical entry itself now exposes flat semantic fields. This scratch
  still starts from `trigger_time_ms` because the native loop is an evidenced
  six-int interior cursor, but ordinary builder decompilation no longer pays
  for that cursor-specific presentation.
- The dispatch loop now also uses `quest_spawn_entry_t` directly instead of a
  private layout duplicate. Its position, heading, template, trigger, and count
  accesses therefore share the canonical quest type while preserving identical
  codegen. The live Binary Ninja split `ESI` cursor was independently retyped
  to the same pointer type, replacing raw float-array indexing throughout the
  spawn and group-consumption loop.

The first 51 instructions, complete scan/fail-safe policy, 28-byte frame, x87
spread loop, group-consumption tail, and all 13 masked references agree.

## Remaining compiler delta

Native creates an interior pointer to the current entry's template-id field
after the positive-count guard, briefly homes it in the stack slot that is then
reused by the integer spread, and loads heading/template through that pointer.
The source retains the scoped template-id pointer but expresses heading through
the recovered `entry->heading` field instead of a preceding-word cast. A shadow
probe confirms that VC6 folds both forms to identical code. The calibrated
compiler also folds the template pointer back to the typed entry base, removing
the native `lea` and dead home store. Those are the candidate's only two missing
instructions; their byte-length shift also changes local branch-label tokens in
the normalized diff. Recovering the typed position and vector addition raises
the honest score from `88.60%` to `91.23%` without changing the exact prefix,
instruction count delta, frame, or reference audit.

MSVC 6.0 and 6.6 produce the same best body, 6.5pp is slightly worse, and 7.0
adds its aligned-frame prologue. `/Og-` broadly deoptimizes the function. No
volatile pointer, artificial union, dummy access, or other register-forcing
construct is retained.

## Port parity

The Python and Zig quest-timeline models already implement the recovered strict
thresholds, trigger grouping, alternating spread axis, count clearing, and
none-active reset. No port edit is required.
