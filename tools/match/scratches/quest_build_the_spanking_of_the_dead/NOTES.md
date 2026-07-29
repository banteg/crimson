# `quest_build_the_spanking_of_the_dead`

Native target: `crimsonland.exe` at `0x004358a0` (391 bytes).

Live Binary Ninja evidence recovers 132 spawn entries. Two opening bonus aliens
use template `0x27`, trigger 500, count 1, at `(256, 512)` and `(768, 512)`.
The next 128 entries form a shrinking zombie spiral. Trigger time starts at
5000 and advances by 300 while it is below 43400. For zero-based step `i`, the
native x87 sequence computes angle `i * 0.333333343`, radius
`512 - i * 3.79999995`, and position `(cos(angle) * radius + 512,
sin(angle) * radius + 512)`. Each spiral entry uses heading `angle`, template
`0x41`, and count 1. The two final template-`0x42` waves are fixed at
`(1280, 512)` and `(-256, 512)`, with count 16 and triggers `i * 300 + 10000`
and `i * 300 + 20000`.

The candidate reproduces the exact 94-instruction length, all five audited
references, the loop bounds, x87 trigonometric sequence, final indices, and
trigger arithmetic. It scores 60.64%. Residuals are unconstrained VC6
scheduling: the candidate hoists independent loop metadata stores and trigger
updates ahead of the trigonometry, and schedules parts of the opening/final
fixed entries differently. Raw indexed access kept the metadata after the
math, but regressed the register allocation and score to 57.45%; a local spawn
pointer is the strongest plausible source shape. VC6.5pp and VC6.6 reproduce
the default result, while VC7 regresses sharply, so no compiler override is
warranted.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all masked references resolved; its
localized residual is compiler scheduling/allocation only. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.

## 2026-07-27 focused profile and mutation pass

MSVC 6.0, 6.5, 6.5 Processor Pack, and 6.6 tied at
60.63829787234043%; MSVC 7.0 regressed to 31.91%. `/GB`, `/G5`, `/G7`,
`/Ox`, and `/Ob1` tied, while `/G6` regressed.

`fixed-position-store-mutations.json` (SHA-256
`f4160d3b2795d44e249c77a690b5f138929f4852eb219fe082438d6b02b7c74b`)
recorded three complete variants. The retained tail variant uses direct x/y
stores for the two fixed waves, matching the native scalar-store shape without
changing either entry. Applying the same form to the opening pair, alone or
with the tail, regressed and was rejected.

Fresh scratch recomputation improved 237.09574468085108/391 to
246.26519337016572/391 weighted bytes: 60.63829787234043% to
62.98342541436464%, with the gap falling from 153.90425531914892 to
144.73480662983428. The validated result has 87/94 instructions, prefix four,
and preserves references 5/0/0.

## Spiral induction-lifetime improvement

Live native disassembly keeps the zero-based spiral step in ESI and trigger
time in EDX. `spiral-local-lifetime-mutations.json` (SHA-256
`2ae4ef31ac07d20fda5c6389dcbe0b04c79603c0a197c29fab7c563cacd905aa`)
tested three declaration boundaries. Declaring the semantic step before the
trigger is the sole win: it adds 4.320441988950307 weighted bytes without
changing the 87 instructions, four-instruction prefix, or 5/0/0 reference
audit. The validated source now scores 250.58563535911603/391, or
64.08839779005525%, with a 140.41436464088397-byte gap.

`spiral-advance-shape-mutations.json` (SHA-256
`3d203eb6b994bdd430ba914137004531a9b82cb41f9f05c24c4f8b9830ca3a4d`)
then tested the apparent native early step/cursor advances as a justified
interaction. Preadvancing only the cursor lost 25.923 weighted bytes; moving
the step early, with or without the cursor, added three instructions, lost a
reference, and lost 93.336 weighted bytes. Those variants are rejected. The
retained source SHA-256 is
`fd84038546cad3b963e641273e966a9f6c8d386cc82ddce9c45481b2f3ee7840`.

## Carried-cursor and publication boundary

The native loop keeps an entry address in ECX and advances ECX plus the integer
step immediately after `fild`, so the earlier per-iteration cursor probe left a
plausible lifetime untested. `spiral-carried-cursor-mutations.json` (SHA-256
`da8edc5f22f9f06a626fde25da01f5caabdf40e3a2ff99d14a147f4c0555e65e`)
crossed five loop-carried/direct-index ownership forms with restoration of the
aggregate tail positions. All 11/11 variants were evaluated. The least-bad
loop change was raw indexing at 233.304/391 weighted bytes, down 17.282;
the simple carried cursor lost 25.923, and both early-advance cursor shapes
also destroyed the opening prefix. Aggregate tail positions restored the
native 94-instruction length but lost 9.330 weighted bytes alone and did not
rescue any ownership form.

`spiral-publication-boundary-mutations.json` (SHA-256
`e27aee9589dfc75d41f441fdbb97249ef4ef52e817d0a73b4a03a18827834160`)
then crossed pointer, reference, direct-index, `set_spawn`, and named position
temporary publication shapes with the same tail boundary. All 11/11 variants
were evaluated. Pointer/reference/helper spellings compiled identically to the
retained source; indexed publication reproduced the same 17.282-byte loss as
raw indexing; every aggregate-tail interaction regressed. The retained
64.08839779005525% source is therefore a bounded compiler fixed point for the
recovered loop ownership, publication, induction lifetime, and fixed-position
boundaries.
