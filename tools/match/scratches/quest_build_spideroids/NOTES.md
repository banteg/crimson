# `quest_build_spideroids`

Native target: `crimsonland.exe` at `0x004373c0` (224 bytes).

Live Binary Ninja evidence recovers three unconditional splitter entries at
`(1088, 512)`/1000 ms, `(-64, 512)`/3000 ms, and `(1088, 256)`/6000 ms. When
the byte currently named `config_hardcore` is nonzero, the builder adds
`(1088, 762)` and `(512, 1088)` at 9000 ms. It then adds `(-64, 762)` at
9000 ms when there are at least two players or that same byte is nonzero.
Every entry uses template `0x01` and count 1, producing 3, 4, 5, or 6 entries
according to those branches.

The fixed entries now use the same inlined two-float position setter and
two-field spawn-metadata setter recovered independently in the exact
`quest_build_zombie_masters` and `quest_build_two_fronts` neighbors. Those
translation-unit-local helper boundaries compile to the same strongest body
as the flattened stores while recovering a more plausible shared source idiom.
The candidate reproduces the native shared constants, branch shape, scaled
final-entry address, early-pop return path, and all 62 instructions. It scores
98.39%. The sole residual is a scheduling swap: VC6 loads the shared integer
constant 1 immediately before the first x-coordinate store in the candidate
and immediately after it in the target. The evidenced helper shape is retained
without adding an artificial ordering constraint.

Moving the shared template-id declaration to the first setter boundary produces
the identical candidate: VC6 still hoists the constant load ahead of the first
x-coordinate store. The residual is therefore not explained by local lifetime.

`initial-constant-lifetime-mutations.json` records that boundary explicitly.
All five declaration, literal, scalar-position, and const-local alternatives
compile byte-identically at 98.39%, 62/62 instructions. This complete negative
sweep leaves the helper-based source as the smallest honest representation.

`helper-boundary-mutations.json` adds a complete 69-variant single/pair sweep
over position and metadata helper forms plus typed first-entry boundaries.
Every variant is byte-neutral. `setter-store-order-mutations.json` checks all
three position/metadata reversal combinations; all regress. Their SHA-256
values are
`9dcba33d9a58541ec5667a3091ab7acdaf8ee09f60026f650c10efc74154c11e`
and
`b995511a540ec5d4809b661b41accd20f3952b12ba128b71838dae65d3f4796b`.
MSVC 6.0/6.5/6.5 Processor Pack/6.6 tie, MSVC 7.0 regresses, and `/G5`,
`/G7`, `/Ox`, and `/Ob1` are byte-neutral while `/G6` regresses.
