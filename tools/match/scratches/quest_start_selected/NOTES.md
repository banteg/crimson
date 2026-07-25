# `quest_start_selected`

Native target: `crimsonland.exe` at `0x0043a790` (434 bytes, 116
instructions).

The recovered MSVC 6.5 `/O2 /GB` source is an honest WIP:

```txt
match=91.38% prefix=80/116 target_insns=116 candidate_insns=116 refs=47/0/0
```

## Recovered source shape

- The function clears the spawn count/timeline/banner, both FX queues, and all
  active high-score run fields except the player name and sentinels. It seeds
  the record tag with `crt_rand() & 0x0fee050f` before any quest terrain or
  builder RNG work. The authoritative Binary Ninja record layout now renders
  that store as `random_tag` at `0x38` and the preceding mode byte as
  `hardcore_marker`, replacing the stale `reserved0[0].d` and
  `full_version_marker` labels from the database's older type copy.
- A local two-float position is filled from half the integer terrain width and
  height, then copied into player zero. This aggregate-copy shape reproduces
  the native eight-byte stack frame and x87 spill/copy schedule.
- Quest metadata index is `tier * 10 + index - 11`. The metadata pointer feeds
  terrain generation and the builder, while the retained byte offset feeds
  both players' starting-weapon assignments; this recovers the native register
  split and the first 80 instructions exactly.
- The builder receives the global spawn table and count pointer. A null builder
  calls `quest_build_fallback` through the same already-pushed arguments.
- A six-int interior cursor walks each 24-byte spawn entry from its count field.
  Hardcore adjusts counts above one except template `0x3c`: template `0x2b`
  gains two creatures and every other eligible template gains eight.
- The post-pass stores the adjusted total creature count and the maximum trigger
  time. Empty tables retain zero aggregates.

## Remaining compiler delta

Only the final 36-instruction aggregation pass differs. Native stores the two
zero aggregates from their eventual accumulator registers and keeps adjusted
count in `esi` with template id in `ecx`; the calibrated compiler uses the
already-zero `ebx` and swaps those two temporary registers. Instruction count,
branches, operands, all 47 masked references, and the final 16 instructions
otherwise agree.

MSVC 6.6 produces the same best tail. MSVC 6.5pp combines caller cleanup and
scores worse; `/G6` changes the x87 schedule and also scores worse. No dummy
access or register-forcing construct is retained.

## Port parity

Python and Zig already apply the recovered hardcore count rules and consume the
record-tag RNG call before explicit terrain generation. Python discarded the
masked tag and later created quest score records from a fresh RNG; `fad207fb2`
threads the native tag through completed and failed outcomes. Focused quest
mode/replay/screen tests pass, along with Ruff, import contracts, and `ty`.
