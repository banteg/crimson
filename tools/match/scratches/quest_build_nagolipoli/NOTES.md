# `quest_build_nagolipoli`

Native target: `crimsonland.exe` at `0x00434480` (983 bytes).

Live Binary Ninja evidence recovers 164 entries in six phases:

- eight template `0x40` spiders on a radius-128 ring around (512,512), using
  angle `index * 0.785398185`, trigger 2000 ms, and count one;
- twelve more template `0x40` spiders on a radius-178 ring, using angle
  `index * 0.52359879`, trigger 8000 ms, and count one;
- 32 four-corner template `0x1c` waves from 13000 through 37800 ms by 800.
  Their positions are (-64,-64), (1088,-64), (-64,1088), and (1088,1088),
  their headings are 1.04719758, -1.04719758, -1.04719758, and 3.926991,
  and their shared count is `wave / 8 + 1`;
- two six-entry vertical lines at x 64 and x 960. Their y coordinate is
  `index * 85.3333359 + 256`; triggers are 49600 through 50100 ms and 50600
  through 51100 ms by 100; every entry uses template `0x0a` and count one;
- two template `0x0b` spawners at (512,256) and (512,768), heading pi,
  trigger 53600 ms, and count one;
- two template `0x1c` spawns at (512,1088) and (512,-64), heading 3.926991,
  trigger 54100 ms, and count eight.

The native body has no terrain-width or terrain-height references: all quest
coordinates are fixed in its 1024-by-1024 script space. That evidence also
corrected the Python and Zig ports, which previously scaled Nagolipoli against
the runtime terrain.

The current candidate represents all 258 native instructions and resolves all
14 audited references, scoring 80.62% fuzzy-weighted with a 39-instruction
exact prefix. One flat append counter preserves the native live
entry count and reusable x87 conversion slot. Separate `set` and scalar-add
calls on both ring positions recover
the native raw sine/cosine stores followed by 512 reload/add/store operations;
advancing the second-ring cursor before its index recovers the native loop
schedule. Four corner vectors recover the native stack materialization, with
the top-left vector declared before top-right to reproduce their construction
order. Reusing the bottom-left vector for both six-entry lines and assigning
their zero heading after the spawn fields improves their local store/reload
shape. A short-lived tail vector recovers the final position-copy idiom, and
repeating the four corner count expressions recovers their native publication
ownership.

The residual is consistent source and VC6 optimizer shape. Native anchors some
cursors at later fields and writes through negative offsets, reserves the ring
and line ranges before their loops, and schedules the line scalars and tail
copies through different temporary lifetimes. The candidate now preserves the
four corner count increments and indexed phase ownership, but publishes the
fixed ring and line range advances after their loops and chooses other legal
registers or line stack slots.

Eight address-keyed Binary Ninja local types preserve the recovered record
shape across compiler-generated cursor expressions. All four corner entries
and all four tail entries now render as `quest_spawn_entry_t` fields rather
than untyped dword offsets. Ring and line cursors intentionally remain interior
pointers: their negative displacements are native VC6 strength reduction, not
missing record fields.

The earlier 36.68% flat-count measurement predated the staged publication
recoveries and is superseded. Replaying the ordinary function-local counter
against the recovered source raises the result from 60.04% to 61.99% and
removes the provisional builder type. Indexing every corner wave back through
the append count, extending an existing corner vector through the tail,
reusing the bottom-right vector for the line loops,
aggregate-constructor ring assignments, and alternative line temporaries all
scored worse. A combined entry setter was codegen-equivalent for the line
loops. No artificial dependencies, volatile state, dummy work, or
register-forcing constructs are used.

## First vertical-line advance-order sweep

Fresh live Binary Ninja output from target `3023:2:9499448411019345244`
grounds a bounded follow-up in the first six-entry vertical line at
`0x0043465e..0x004346d1`. Native advances its interior entry cursor at loop
entry, then finishes each iteration with the line-index increment followed by
the 100 ms trigger-time increment. The candidate preserves those semantics but
hoists the trigger-time increment ahead of the final position and heading
stores.

`first-line-advance-order-mutations.json` tests the five other natural
permutations of the independent line-index, entry-cursor, and trigger-time
advances. Its SHA-256 is
`6a4e405d0812ecd3896fa9bba3ba6b732da85dd89c4abd6feee39606514bfc96`.
The recorded single-change sweep evaluated all five possible variants without
truncation. Every variant was byte-neutral: match ratio, fuzzy-weighted bytes,
instruction count, exact prefix, and reference counts all had zero delta.
There was no positive single, so no interaction sweep was run and
`scratch.cpp` remains unchanged at SHA-256
`83ac8f02a631f5f3036f15ad168eb4942d0b3b90dcf574e5fd55a4434ce55285`.

At that checkpoint the scratch was classified `semantic-complete` with a
`compiler` residual. Fresh live Binary Ninja output confirmed all 164 entries
and each ring, corner wave, vertical line, and four-entry tail. The candidate
then remained 255/258 instructions with all 12 audited references resolved and
matched.

## Superseded builder and second-ring cursor bounds

Two more complete mutation matrices tested the remaining native-looking
cursor idioms without changing the canonical source.

`corner-builder-advance-mutations.json` evaluated all 15 single and pair
variants. The three helper-only `next_entry` spellings were byte-neutral.
Actually routing the corner stores through post-increment indexing or a
builder-returned entry collapsed the score from 590.18 to 213.36 weighted
bytes, shortened the exact prefix from seven instructions to one, and lost
three resolved references; several incomplete site combinations correctly
failed compilation. Its SHA-256 is
`dfc12b469bb91202eb9dc387ce3f6c19ec2c86444f4838a0839e40cbb9cc4ac1`.

`second-ring-cursor-mutations.json` evaluated all seven natural cursor forms.
Pointer addition and a scoped entry cursor were byte-identical. Position,
entry-reference, and indexed-entry forms lost between 3.09 and 11.95 weighted
bytes, with the latter forms also losing a resolved reference. Its SHA-256 is
`5c43d7fcd6b249adfe38052a4b01e472eae0f8b0468a35153b286d50b2c1cddc`.

At that checkpoint these complete negatives strengthened the existing
compiler-residual classification. The then-current source was SHA-256
`83ac8f02a631f5f3036f15ad168eb4942d0b3b90dcf574e5fd55a4434ce55285`,
at **60.04%**, 255/258 instructions, and reference audit 12/0/0. The updated
`experiments.jsonl` SHA-256 is
`6ba887e1f4aa932a067e42515c71c89a711b110b9d04f7d8105cecb2fda05477`.

## 2026-07-27 focused profile and mutation pass

The compiler profile matrix left the default source at 60.03898635477583%:
MSVC 6.0, 6.5, and 6.6 tied; 6.5 Processor Pack fell to 55.45% with
247 instructions and eight matched references, and MSVC 7.0 fell to 27.97%.
`/GB`, `/G5`, `/G7`, `/Ox`, and `/Ob1` were byte-identical, while `/G6`
regressed.

`metadata-helper-shape-mutations.json` (SHA-256
`eff4f02fc31cd68015005e127d560fd282e016cfdddf01c662f15aae582e6c6f`)
recorded five complete variants. Explicit-inline, force-inline, and
return-by-reference helper spellings were byte-neutral; moving count before
trigger lost 22.994 weighted bytes and reversing the metadata stores lost
49.821. No variant was retained. At that checkpoint the validated source was
at
590.1832358674463/983 weighted bytes, a 392.81676413255366 gap, 255/258
instructions, prefix seven, and references 12/0/0.

## 2026-08-09 flat append-counter recovery

The surviving SDK's ordinary function-local counter style transfers after the
later ring and publication recoveries. Replacing the two-field builder with a
plain `entry_count` lets VC6 keep the append count in `ESI` while reusing the
native `esp+0x10` scalar conversion slot. The first ring consequently matches
through 32 instructions instead of seven.

The retained source improves from 590.1832358674463/983 weighted bytes
(60.04%) to 609.3450292397661/983 (61.99%). It preserves 255/258 instructions
and references `12/0/0`; no quest entry, trigger, position, heading, or count
changes. A hybrid that reintroduced the builder after the rings reached only
61.21%, and interior `pos.y` cursor aliases were neutral or regressed, so the
smaller flat-counter source is retained. Source SHA-256:
`776cec3d813c94de1229e5c213256ff868710a5af8f8a09c7d8963511a567870`.

## 2026-08-09 ring and tail publication recovery

Two ordinary record-publication boundaries transfer from the exact quest
builders. A narrow heading/template helper for both rings keeps the live x87
angle pop between the native template and trigger stores. It raises the match
from 67.83% to 68.60% and extends the exact prefix from 32 to 38 instructions.

The four fixed tail positions now use short-lived `quest_vec2_t` constructor
temporaries instead of one repeatedly mutated vector. VC6 consequently reuses
the native `esp+0x28`/`esp+0x2c` temporary slots. Publishing each temporary and
its template through the narrower position/template helper also recovers the
native template-before-heading stores. Together the retained changes reach
**74.81%**, 258/258 instructions, prefix 38, and references `14/0/0`.

The same narrow position/template helper also transfers to the four corner
publications. It preserves the native position-copy-then-template boundary
before the remaining heading, trigger, and count stores, raising the current
result to **75.58%** without changing instruction or reference counts.

Rechecking the native `esp+0x28`/`esp+0x2c` line-scalar ownership after the
tail recovery did not overturn the earlier bound: extending the fourth corner
vector through both lines fell to 70.16%, and a dedicated scoped line vector
fell to 69.77%. Swapping cursor/count advance order at the recovered corner
helper boundaries was byte-neutral. None of those variants is retained.

## 2026-08-09 indexed phase interaction

The exact Lizard Kings ring supplies a second transferable house-style rule:
repeat `spawns[entry_count + index]` at every publication site rather than
retaining a phase-local record cursor. Applying that spelling to Nagolipoli's
second ring and both six-entry lines folds the native `+4` and two `+8` member
offsets into their scaled `lea` instructions. On its own this reaches 76.80%
but emits 255/258 instructions because the three fixed range advances move out
of the native pre-loop slots.

Direct indexed publication for all four corner records has the complementary
effect. It preserves VC6's four per-wave `entry_count` increments instead of
collapsing 128 entries into one pre-loop add, but on its own emits 261/258
instructions and is therefore a tradeoff. Combining the two natural forms
restores the exact 258-instruction extent and improves the retained result from
75.58% to **76.74%**, the exact prefix from 38 to 39 instructions, and weighted
matched bytes by 11.43, with references still `14/0/0`.

Saved-start forms that reserve the ring or line ranges before their loops add
one or two instructions and are rejected. A complete 15-combination matrix of
direct indexed publication across the four fixed tail records is neutral except
for the first record, which regresses by 7.62 weighted bytes; no tail change is
retained.

## 2026-08-09 corner count expression ownership

The four corner count publications match better when each repeats
`wave / 8 + 1` instead of sharing a loop-local `spawn_count`. This is a pure
source-ownership correction: position/template helpers, loop structure, entry
advances, trigger stores, and quest semantics are unchanged.

The retained source improves from 754.395348837209/983 weighted bytes
(76.744186%) to 792.496124031008/983 (80.620155%), a gain of 38.100775193798
weighted bytes. It preserves 258/258 instructions, prefix 39, and references
`14/0/0`. Source SHA-256:
`e7c1adb9fd116a8736054b840f1249292c7d766381123739771f5efb09fefe5b`.

## 2026-08-09 tail trigger-expression ownership

The next independent residual was the four fixed tail entries at
`0x00434753..0x00434846`. Native publishes the first position/template pair
before evaluating `(wave * 5 + 175) * 160`, and likewise publishes the third
position/template pair before evaluating `wave * 800 + 0x6f54`. The former
source evaluated both expressions before their owning entry publications.

A complete three-variant matrix measured the two ordinary statement moves
separately and together. Moving only the first expression reaches
849.6472868217054/983 (86.434109%); moving only the second reaches
800.1162790697674/983 (81.395349%); retaining both reaches
853.4573643410853/983 (**86.821705%**). The combined gain is
60.9612403100775 weighted bytes over the 80.620155% baseline. All variants
preserve 258/258 instructions, prefix 39, references `14/0/0`, and identical
quest semantics. No helper, count, angle, loop, cursor, or aggregate shape is
changed. Final source SHA-256:
`18362782e7eca1384262144327827a540ecb9daa86eac5ada87a64fc9cd2c49a`.

## 2026-08-10 loop-carried count and corner lifetime recovery

The second ring and both six-entry line phases now carry `entry_count` as the
publication cursor instead of indexing from a fixed base and advancing the
count after each loop. This is the source shape implied by the native `ESI`
lifetime: VC6 hoists the known `+12`, `+6`, and `+6` trip-count advances into
the three pre-loop setup blocks while retaining separate angle or line
coordinate counters. It also preserves the native `+4` ring and `+8` line
member offsets in their scaled address calculations.

Moving the corner `wave` declaration ahead of the four position temporaries
then places its zeroing before their eight constant stores, as at the native
corner-loop boundary. These four ownership corrections are semantic no-ops:
all 164 entries, positions, templates, headings, triggers, counts, and final
publication count remain unchanged.

The complete 15-variant reverse matrix in
`count-cursor-lifetime-mutations.json` measures every non-empty combination of
the former ring owner, two former line owners, and former `wave` lifetime.
Every reversion is worse. Reverting all four reproduces the prior
853.4573643410853/983 (86.821705%) result and prefix 39; retaining all four
reaches 902.9883720930233/983 (**91.860465%**) and prefix 77. The gain is
49.531007751938 weighted bytes, with the exact 258/258 instruction extent and
references `14/0/0` preserved. The remaining first mismatch is the
compiler-scheduling swap between the corner cursor `lea` and the 13000-ms
trigger load. Mutation spec SHA-256:
`34ce129c84ef10bab15f548f0a9dd258c88d92aed420df774a13ae91ad88190d`.
Final source SHA-256:
`52fd6cbac0cab62a63d0a8e562d2f95c5c4e26a1d678e4e5ec3d3591d5978248`.

## 2026-08-12 line-vector and corner-cursor recovery

Replaying the stale line ownership evidence after the 2026-08-10 count
recovery exposed a different allocation result. Live native disassembly maps
the four corner vectors to distinct stack pairs and then reuses
`[esp+0x28]/[esp+0x2c]` for both six-entry line loops. Directly renaming the
line owner to `bottom_right` still perturbs the corner allocation and regresses,
but two short-lived line vectors give VC6 the native dead-slot coalescing
without touching the corner objects.

`line-vector-lifetime-interactions.json` evaluates both declaration orders and
each line owner independently. A dedicated first-line vector improves
902.9883720930233/983 (91.860465%) to 918.2286821705426/983
(93.410853%), a gain of 15.240310077519325 weighted bytes.
`second-line-vector-lifetime-mutations.json` then gives the second loop its own
non-overlapping vector and adds another 15.240310077519439 weighted bytes,
reaching 933.468992248062/983 (94.961240%). Both changes preserve 258/258
instructions, prefix 77, and references `14/0/0`; using one vector across both
loops extends its lifetime and regresses.

The remaining corner-boundary swap also has an honest owner. Native computes
the first corner entry address before loading 13000 ms, then carries that first
record cursor through each wave. A full cursor perturbs the already-recovered
indexed publications, but `corner-cursor-owner-mutations.json` shows that a
first-entry-only cursor, refreshed after each wave, preserves the other three
direct indexed records. It adds 3.810077519379888 weighted bytes and extends
the exact prefix from 77 to 202 instructions.

The retained source is now 937.2790697674419/983 (**95.348837%**), 258/258
instructions, prefix 202, and references `14/0/0`. Its only region is the
49-instruction four-entry fixed tail at native
`0x00434780..0x00434840`; operations and operands are identical, with 12
scheduled positions differing. Final source SHA-256:
`62899e80bca277ecb2e79c5c65e6f833445aa87afcaa0dbb9d52637f38790849`.

Three complete tail matrices bound straightforward source-order explanations.
`tail-trigger-order-mutations.json` tests both trigger/heading orders,
`tail-count-advance-order-mutations.json` tests all 15 count-advance
combinations, and `tail-publication-helper-interactions.json` tests 47 helper
ownership and member-order combinations. Natural variants are byte-neutral or
worse. No artificial dependency, dummy store, volatile spill, or register
constraint is retained.

The final position-lifetime pass is also saturated.
`tail-position-lifetime-mutations.json` evaluates all 80 single through
four-entry combinations of named position temporaries placed before or after
their entry cursors; every variant is byte-identical at 95.348837%.
`tail-position-reuse-mutations.json` tests three ordinary reusable-vector
forms. All three regress by 49.53100775193798 weighted bytes to
887.7480620155039/983 (90.310078%) and move the exact prefix back to 191.
The four short-lived constructor temporaries therefore remain the strongest
evidenced source shape for the compiler-scheduled tail.

## Exact indexed tail-record recovery (2026-09-05)

Current result: **100%**, 258/258 instructions, full prefix, and references
**14 resolved / 0 unresolved / 0 mismatched**. The earlier tail-scheduling
bounds are superseded by `indexed-tail-records-mutations.json`.

The final four fixed entries now publish through `spawns[entry_count]` instead
of refreshing and retaining a pointer to each current entry. This removes all
12 scheduled-position differences while preserving the exact preceding 202
instructions. Direct versus helper metadata and separate versus field-local
count advances all produce the same exact bytes with indexed ownership. Their
pointer-owned controls remain at 95.35%.

The retained form changes only the owning expression and removes the four
obsolete pointer assignments. The ring, corner, line, and tail entries retain
all positions, headings, templates, triggers, and counts. No compiler settings,
layout-only object, or artificial dependency was introduced.
