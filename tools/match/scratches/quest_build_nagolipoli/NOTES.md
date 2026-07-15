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

The candidate represents 247 of the native body's 258 instructions and
resolves all ten audited references, scoring 55.05% with a seven-instruction
exact prefix. A two-field builder preserves the native live entry count. Four
corner vectors recover the native stack materialization, reusing the
bottom-left vector for both six-entry lines improves the local store/reload
shape, and a short-lived tail vector recovers the final position-copy idiom.

The residual is consistent source and VC6 optimizer shape. Native stores each
ring's raw sine/cosine products before reloading them to add 512, while the
candidate fuses those additions. Native anchors some cursors at later fields
and writes through negative offsets, distributes four count increments through
the corner-wave stores, and schedules the final literal-vector copies through
different stack slots; the candidate uses record-base cursors, collapses the
four increments, and chooses another legal temporary slot.

A flat local count scored 36.68%; adding the builder and using its count for
the first ring materially improved the result. Indexing every corner wave back
through the builder count, extending an existing corner vector through the
tail, and alternative line temporaries all scored worse. No artificial
dependencies, volatile state, dummy work, or register-forcing constructs are
used.
