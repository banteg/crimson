# grim_state_init

Native target: `grim.dll` at `0x100052f0..0x10005a40` (1872 bytes).

This scratch reconstructs the observed global initialization domains:
the 128-entry configuration table and callback defaults, fixed-function draw
state, input and texture defaults, title/error strings, font lookup tables,
and the 2x2 through 16x16 atlas UV grids.

The callback values, scalar defaults, table dimensions, and loop order come
from live Binary Ninja disassembly and address/reference inspection. The
default callback at `0x10001150` is the two-instruction true-return stub.
The byte at `0x1005d3ac` has only the initializer write as a static xref, so it
is retained under the evidence-limited name `grim_reserved_d3ac`.

Microsoft Visual C++ 6.5 with `/O2 /GB /W3 /GR- /MD` currently produces a
`79.67%` match with a `167/425` exact instruction prefix, `425/416`
target/candidate instructions, and references `135/0/9`. All references
resolve. The font atlas uses a typed row/entry cursor with separate outer and
inner counter lifetimes; the four subrect tables retain direct row-major
indexing. Both forms preserve the recovered interleaved `GrimUV` layout
without padding or byte-level match constructs.

The remaining diff is compiler-shaped: scheduling of the configuration-value
constructor temporaries and current-UV stores, plus counter-versus-end-pointer
forms for the atlas loops. Every
observed state store, callback assignment, allocation/copy, and table loop is
represented, so the recovery is marked semantic-complete rather than exact.

A focused atlas-loop source-shape check originally rejected simple row locals
and explicit row-pointer increments. Reusing shared `x`/`y` counters and
spelling the grids as two-dimensional arrays compile byte-identically to the
flat row-major form. A later native-schedule pass separated the two missing
ingredients: advancing row/entry cursors plus declaring the inner counter
before those cursors. That combination is retained for the font table; the
same change on the subrect tables loses resolved-reference coverage and is not
retained.

The recorded config-tail ordering sweep covers eleven permutations of the
adjacent `0x64`, `0x12`, `0x13`, and `0x14` assignments that contain all nine
masked conflicts. Canonical order remains best. The apparent best
reference-count variant reduces mismatches from 9 to 7, but also shortens the
candidate to 413 instructions, moves the exact prefix from 167 to 165, and
drops the aggregate match from 78.67% to 73.99%; it is rejected as a
misleading reference-only improvement.

A stock-VC6 diagnostic matrix further bounds the scheduling residual. `/G5`,
`/Ob1`, and explicit `/Ot` are byte-identical to `/GB`; `/G6` drops to 61.74%,
disabling intrinsics drops to 30.83%, and disabling global optimization drops
to 16.50%. No function-local profile override is justified.

The nine reported reference mismatches were audited as alignment artifacts in
the single constructor/store-scheduling region. Every native destination is
also present as an exact candidate relocation, including all four words of
config value `0x64` (`grim_config_values + 0x640..0x64c`), the config-value
words at offsets `0x120..0x14c`, and current-UV destinations `0x1005b294` and
`0x1005b298`. The latter are emitted through `grim_uv_u0 + 4` and
`grim_uv_u1`, respectively. The matcher pairs them with nearby scheduled stores
after the instruction streams diverge, but no referenced destination is
missing or unresolved. The residual is therefore compiler-only.

`config-constructor-spelling-mutations.json` closes the remaining shared-type
hypothesis at the first divergence. Explicit `grim_config_value_t`
construction, explicit scalar casts, and direct assignment-operator spelling
all compile byte-identically at 78.67%, prefix 167, 414 instructions, and
references `134/9/0` in `ok/mismatch/unresolved` order. Live Binary Ninja also
types the native table at `0x1005cb88` as 128 16-byte
`grim_config_value_t` records. No constructor or shared-header correction is
supported.

`atlas-counter-lifetime-mutations.json` tests the native font-atlas loop's
distinct outer-counter and conversion-slot lifetimes. Live disassembly at
`0x10005856..0x100058ae` keeps the outer count in `esi`, mirrors it to
`[esp+0xc]` for `fild`, and advances a separate row pointer in `edx`. Explicit
conversion copies, row offsets, and nested `do/while` loops are byte-neutral;
`!=` counters lose 2.71 fuzzy-weighted bytes, a named row pointer loses 35.70,
and unsigned counters perturb the earlier allocator enough to fall to 46.96%.
The sweep therefore supplies negative allocation evidence and does not support
a source change.

The native `_strdup` call at `0x1000583c` is import-indirect. Adding `/MD`
reproduces that call and relocation directly, improving the fuzzy-weighted
score by 4.46 bytes and exact references from 134 to 135 without changing the
167-instruction prefix. `/GX` is byte-neutral on top of `/MD`, so the smaller
runtime profile is retained.

The post-profile scheduling probes close several tempting source-only
explanations. Reusing one named config value for the adjacent true defaults
shortens the candidate and regresses the first mismatch. Constructor-body,
explicit assignment, and named-temporary spellings for `GrimUV` are either
byte-neutral or materially worse. Function-scoped and `register` loop counters
are byte-neutral even when reused across all five grids. Moving the vertex
initializer among the last config assignments yields only metric tradeoffs:
the best weighted result adds three reference mismatches, while the best
reference result moves the first mismatch earlier. None is retained.

Forcing the four color stores through volatile lvalues improves 8.92
fuzzy-weighted bytes, but there is no xref or type evidence that these globals
were volatile. That source changes the program's observable semantics and is
rejected as a scheduling-only fakematch.

## Atlas cursor and counter lifetime recovery

Live disassembly at `0x10005856..0x100058a2` shows a persistent outer counter
in `esi`, a row cursor in `edx`, an entry cursor in `eax`, and a separately
initialized inner counter in `ecx`. `atlas-row-cursor-mutations.json`
recovered the row and entry lifetimes: the retained named-row-value variant
adds 5.39 fuzzy-weighted bytes and two instructions without changing the
`167`-instruction prefix or `135/0/9` reference result.

`atlas-counter-cursor-order-mutations.json` then tested the declaration order
predicted by that instruction schedule. Declaring the inner counter before
copying and advancing the row cursor adds another 8.90 fuzzy-weighted bytes
with no reference, prefix, or instruction-count tradeoff. Declaring both
counters before their cursors reaches 79.90%, but creates a tenth reference
mismatch, so the reference-clean inner-only improvement is retained. Reversing
the source field-store order is byte-neutral, while aggregate `GrimUV`
assignment materially regresses and perturbs constructor scheduling near the
function entry.

The same native cursor shape repeats at `0x10005914..0x10005a37` for the 2x2,
4x4, 8x8, and 16x16 subrect tables. Two exhaustive 15-combination sweeps,
`subrect-counter-cursor-interactions.json` and
`subrect-inner-counter-interactions.json`, confirm that the cursor shapes can
add up to 24.80 fuzzy-weighted bytes, but every improvement reduces resolved
references or adds mismatch debt. The earlier
`subrect-row-cursor-interactions.json` reaches the same conclusion. Those
tradeoffs fail the no-regression gate and remain negative evidence.

`subrect-shared-counter-cursor-interactions.json` closes the remaining
cross-grid lifetime hypothesis. It exhaustively evaluates all 31 combinations
of function-scoped atlas counters and typed row/entry cursors across the four
subrect grids. Shared counters alone are byte-neutral. The best weighted
variant adds 20.38 fuzzy-weighted bytes but moves references from `135/0/9` to
`134/0/11`; the isolated 16x16-grid improvement adds 14.23 bytes while losing
one resolved reference. No combination preserves reference fidelity, so no
source change is retained.
