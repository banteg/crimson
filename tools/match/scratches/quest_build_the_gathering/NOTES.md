# `quest_build_the_gathering`

Native target: `crimsonland.exe` at `0x004349c0` (725 bytes).

Live Binary Ninja evidence recovers a thirteen-entry fixed table. Heading is
left untouched for every entry:

- template `0x01` at (256,512), trigger 500 ms, count one;
- template `0x01` at (768,512), trigger 9500 ms, count two;
- template `0x3a` at (256,512) and (768,512), triggers 15500 and 24500 ms,
  count two;
- template `0x00` at (256,512) and (768,512), triggers 30500 and 39500 ms,
  count two;
- template `0x3c` at the four inset corners (64,64), (960,64), (64,960),
  and (960,960), all at 54500 ms with counts 2, 1, 2, and 1;
- template `0x3a` at (-128,512), trigger 90500 ms, count six;
- template `0x01` twice at (1152,512), triggers 99500 and 109500 ms,
  with counts four and two.

The absence of terrain-dimension references proves that the final three edge
coordinates are fixed. This corrected the Zig port, which previously scaled
their x coordinates with runtime width while the Python port already preserved
the native values.

The candidate matches all 134 native instructions with no static-reference
debt, scoring 89.55% with a 12-instruction exact prefix. An inlined combined
position-and-metadata setter is the strongest source shape: like native, VC6
materializes float coordinate literals through two eight-byte-frame temporary
slots while reusing integer constants across entries.

The residual consists only of legal independent-store scheduling. The
candidate occasionally loads the next entry's coordinate literal before
storing the current template id, and schedules a few final-entry stores across
the epilogue in a different order. Separate position assignment followed by a
metadata setter scored 88.06%; direct-field and statement-order variants did
not justify artificial barriers. No volatile state, dummy dependencies, or
register-forcing constructs are used.
