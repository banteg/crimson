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

The candidate represents 255 of the native body's 258 instructions and
resolves all 12 audited references, scoring 60.04% fuzzy-weighted with a
seven-instruction exact prefix. A two-field builder preserves the native live
entry count. Separate `set` and scalar-add calls on both ring positions recover
the native raw sine/cosine stores followed by 512 reload/add/store operations;
advancing the second-ring cursor before its index recovers the native loop
schedule. Four corner vectors recover the native stack materialization, with
the top-left vector declared before top-right to reproduce their construction
order. Reusing the bottom-left vector for both six-entry lines and assigning
their zero heading after the spawn fields improves their local store/reload
shape. A short-lived tail vector recovers the final position-copy idiom.

The residual is consistent source and VC6 optimizer shape. Native anchors some
cursors at later fields and writes through negative offsets, distributes four
count increments through the corner-wave stores, and schedules the line and
final literal-vector copies through different stack slots; the candidate uses
record-base cursors, collapses the four increments, and chooses other legal
temporary slots.

Eight address-keyed Binary Ninja local types preserve the recovered record
shape across compiler-generated cursor expressions. All four corner entries
and all four tail entries now render as `quest_spawn_entry_t` fields rather
than untyped dword offsets. Ring and line cursors intentionally remain interior
pointers: their negative displacements are native VC6 strength reduction, not
missing record fields.

A flat local count scored 36.68%; adding the builder and using its count for
the first ring materially improved the result. Indexing every corner wave back
through the builder count, extending an existing corner vector through the
tail, reusing the bottom-right vector for the line loops,
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

The scratch is classified `semantic-complete` with a `compiler` residual.
Fresh live Binary Ninja output confirms all 164 entries and each ring, corner
wave, vertical line, and four-entry tail. The candidate remains 255/258
instructions with all 12 audited references resolved and matched.

## Builder and second-ring cursor bounds

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

These complete negatives strengthen the existing compiler-residual
classification. The source remains SHA-256
`83ac8f02a631f5f3036f15ad168eb4942d0b3b90dcf574e5fd55a4434ce55285`,
at **60.04%**, 255/258 instructions, and reference audit 12/0/0. The updated
`experiments.jsonl` SHA-256 is
`6ba887e1f4aa932a067e42515c71c89a711b110b9d04f7d8105cecb2fda05477`.
