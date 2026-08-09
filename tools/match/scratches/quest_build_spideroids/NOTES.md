# `quest_build_spideroids`

Native target: `crimsonland.exe` at `0x004373c0` (224 bytes).

Live Binary Ninja evidence recovers three unconditional splitter entries at
`(1088, 512)`/1000 ms, `(-64, 512)`/3000 ms, and `(1088, 256)`/6000 ms. When
the byte currently named `config_hardcore` is nonzero, the builder adds
`(1088, 762)` and `(512, 1088)` at 9000 ms. It then adds `(-64, 762)` at
9000 ms when there are at least two players or that same byte is nonzero.
Every entry uses template `0x01` and count one, producing 3, 4, 5, or 6
entries according to those branches.

The exact source uses one continuous append count for all six possible
entries. VC6 constant-folds the first five indexed publications into their
native fixed offsets, initializes the live count to three at the first branch,
and raises it to five on the hardcore path. The final optional entry consumes
the same append count through a record pointer.

The first entry publishes x and y directly, while the remaining fixed entries
retain the inlined two-float position setter. This boundary interacts with the
append ownership: the append count alone is byte-identical to the prior
98.39% fixed-index form, and direct first-position fields alone were also
byte-identical there. Together they delay the shared integer constant `1`
until after the first x-coordinate store, exactly reproducing the native
schedule without an artificial dependency or register forcing.

The candidate is exact: all 62 instructions and 224 bytes match, including
the complete 62-instruction prefix and all three static references.
