# `quest_start_selected`

Native target: `crimsonland.exe` at `0x0043a790` (434 bytes, 116
instructions).

The recovered MSVC 6.5 `/O2 /GB` source is an honest WIP:

```txt
match=98.28% prefix=80/116 target_insns=116 candidate_insns=116 refs=47/0/0
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
  gains two creatures and every other eligible template gains eight. The
  adjustment belongs directly to the entry's count field rather than a copied
  scalar; VC6 then keeps that field value in native `ESI` across the template
  tests and publishes it back through the cursor.
- The post-pass stores the adjusted total creature count and the maximum trigger
  time. Empty tables retain zero aggregates.

## Remaining compiler delta

Only the two initial aggregate stores differ. Native stores zero from the
eventual accumulator registers (`edi` and `ebp`), while the calibrated compiler
uses the already-zero `ebx`. The hardcore adjustment, count/trigger
aggregation, cursor step, branch graph, and final publications now agree.

MSVC 6.6 produces the same best tail. MSVC 6.5pp combines caller cleanup and
scores worse; `/G6` changes the x87 schedule and also scores worse. No dummy
access or register-forcing construct is retained.

Two recorded mutation sweeps cover 28 single and paired lifetime changes for
the aggregate accumulators, adjusted count, template id, and nested hardcore
locals. Every variant is byte-neutral. The native `edi`/`ebp` zero stores and
remaining aggregate publication therefore cannot be selected through these
honest source scopes; further local-name or declaration-order churn is a
documented dead end.

## Direct count-field ownership

Live native disassembly at `0x0043a8fd..0x0043a919` loads the current count
into `esi`, keeps it live across both template comparisons in `ecx`, adjusts
it, and writes it back through the six-int cursor. Expressing the adjustment
through a copied `count` scalar made VC6 swap those registers. Keeping the
ordinary source ownership on `count_cursor[0]`—testing and compound-assigning
the field directly—recovers the native allocation and removes the complete
hardcore-loop mismatch region.

This raises the global match from **91.3793%** to **98.2759%** and reduces the
fuzzy gap from 37.413793 to 7.482759 bytes. Instruction count, exact prefix,
and references remain 116/116, 80, and `47/0/0`. Repeating the template-field
expression directly was byte-neutral and is not retained; the improvement is
specific to count-field ownership, not declaration or local-order churn.

## Port parity

Python and Zig already apply the recovered hardcore count rules and consume the
record-tag RNG call before explicit terrain generation. Python discarded the
masked tag and later created quest score records from a fresh RNG; `fad207fb2`
threads the native tag through completed and failed outcomes. Focused quest
mode/replay/screen tests pass, along with Ruff, import contracts, and `ty`.

## Recovery classification audit

Fresh Binary Ninja HLIL confirms every reset, RNG use, terrain/builder call,
starting weapon assignment, hardcore adjustment, and aggregate post-pass. The
candidate and native each have 116 instructions with `47/0/0` references.
`--regions` confines the remaining difference to the two zero stores at the
start of the aggregation pass. Recovery is classified `semantic-complete` with
a `compiler` residual.

## Current-baseline accumulator replay (2026-08-11)

The older accumulator-lifetime result predated the retained direct count-field
ownership change. `current-aggregation-publication-mutations.json` therefore
replays initialized locals, assigned locals, publish-then-read, and reversed
chain assignments against the current allocation. All four remain
byte-identical at 98.28%, 116/116 instructions, and `47/0/0` references. The
two zero-store register operands are not recovered by that stale interaction.

## Current loop-lifetime interaction bound (2026-08-11)

Live Binary Ninja confirms that native and candidate both zero the eventual
`EDI` and `EBP` accumulator registers before the loop. The only mismatch is
that native sources the two initial global stores from those registers while
VC6 sources both stores from the already-zero `EBX`. This is therefore not a
missing initialization or accumulator-lifetime instruction.

`current-aggregation-loop-interactions.json` tests the remaining natural
interaction with the retained direct count-field ownership: six accumulator
publication forms, four template-id lifetimes, three trigger-time lifetimes,
and every one- and two-site combination. All 67 planned variants compile and
none improves the baseline. The 11 neutral single-site forms and every neutral
interaction retain 98.28%, 116/116 instructions, prefix 80, and `47/0/0`
references; the non-neutral variants only regress. This closes loop-local
lifetime interaction as a route to the two native store operands. Spec SHA-256:
`3041715fe3f9259de5aac7fc90a8cdb2c6064a7663dcc583119aaaf8d8d701ef`.
