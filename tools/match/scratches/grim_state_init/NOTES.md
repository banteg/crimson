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
`94.81%` match with a `293/425` exact instruction prefix, `425/423`
target/candidate instructions, and references `165/0/0`. All references
resolve. The exact prefix now covers every configuration constructor, default
state store, current-UV initializer, title allocation/copy, callback store,
and `_strdup` call before entering the font-atlas loop.

The remaining diff is confined to atlas loop allocation. Four recovered
V-field row/entry cursor loops reuse `[esp+0xc]` for the inner integer-to-float
conversion where the native compiler keeps a distinct `[esp+0x10]` slot. The
final 16x16 subrect grid still uses the semantically equivalent direct-index
form because adding a fourth long-lived row cursor changes whole-function
register allocation. Every observed state store, callback assignment,
allocation/copy, and table loop is represented, so the recovery remains
semantic-complete rather than exact.

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

## Default-state and atlas interior-pointer recovery

The earlier configuration/UV residual was not missing data. Live relocation
inspection showed that the native compiler holds the four current-UV values
across the fixed default-state and color stores. The exhaustive
`uv-default-state-interleaving-mutations.json` sweep recovered that source
order by placing the four aggregate UV assignments after the color defaults.
The retained variant adds 142.46 fuzzy-weighted bytes, advances the exact
prefix from 167 to 245 instructions, eliminates all nine reference
mismatches, and raises resolved references from 135 to 158 without changing
the 416-instruction candidate size.

The next native sequence clears both mouse-button latches through a distinct
zero register. `mouse-latch-store-shape-mutations.json` identifies an inlined
two-word `memset` as the only improving source shape. It adds the native
`xor` instruction, 29.19 fuzzy-weighted bytes, three resolved references, and
advances the exact prefix from 245 to 288. Chained and named-zero assignments
are byte-identical to the weaker baseline.

Exact `grim_draw_quad` and `grim_draw_quad_points` scratches establish that
the depth pair is a distinct `GrimDepth` aggregate and that the four current
UVs are one `GrimUV[4]` array. The recorded
`vertex-depth-type-recovery-mutations.json` and
`current-uv-array-recovery-mutations.json` sweeps show that adopting those
shared types is byte- and reference-neutral at the improved baseline, so the
source now uses the evidence-backed types rather than four synthetic scalar
aliases.

Live native disassembly initializes the font atlas through the interior
`v`-field address and stores each `u` at the preceding float. The retained
`font-atlas-v-cursor-mutations.json` variant models that directly with a
V-field row cursor, advances the prefix by five instructions, adds 13.34
fuzzy-weighted bytes, and resolves the interior `grim_font2_uv_v` reference.
`font-atlas-increment-order-mutations.json` then recovers the native
pointer-before-counter update order for another 4.45 bytes.

The same V-field cursor pattern repeats in the subrect tables.
`subrect-v-cursor-interactions.json` exhaustively evaluates all 15
combinations. Retaining the 2x2, 4x4, and 8x8 cursor loops adds six native
instructions, 94.07 fuzzy-weighted bytes, and three resolved references,
reaching the current `94.81%`, `423/425`, `165/0/0` result. Adding the fourth
16x16 cursor changes whole-function register allocation and falls to 64.71%;
every smaller final-grid cursor variant hits the same cliff. The shared-inner
counter, counter-identity, and final-grid control-shape sweeps are negative.

## Shared atlas counters and final-grid row recovery

The four repeated conversion-spill differences were one shared lifetime
constraint, not independent compiler noise. Native consistently uses
`[esp+0xc]` for the outer row counter and `[esp+0x10]` for the inner column
counter across the font atlas and every subrect grid. Declaring `x` and `y`
once at function scope and reusing them in the already-retained V-field loops
prevents VC6 from coalescing those slots. That source-backed interaction raises
the scratch from **94.81%** to **97.64%**, advances the exact prefix from
**293** to **397** instructions, and preserves references **165/0/0**.

`shared-counter-final-grid-mutations.json` then evaluates eight ordinary
translations of the remaining 16x16 initializer. Deriving the V-field entry
cursor from `&grim_subrect_table[y * 16].v` is the only clean improvement. It
recovers the native **425/425** instruction count, adds one resolved reference,
and raises the result to **98.35%** with references **166/0/0** and a
30.83-byte fuzzy gap. The flat row expression is a direct view of the recovered
256-entry `GrimUV` storage and retains the exact 397-instruction prefix.

Two bounded follow-ups close the obvious remaining distinctions.
`final-grid-counter-allocation-mutations.json` crosses four final-loop forms
with `register`, declaration-order, and signed 32-bit `long` counter variants;
none of its 34 variants improves the retained object.
`final-grid-array-shape-mutations.json` jointly tests the equivalent
`GrimUV[16][16]` declaration, pointer publication, and three matrix
initializers; the complete matrix V-field form is byte-identical, while the
other forms regress.

Only the final outer induction remains different. Native initializes `y` in
`ESI`, advances a separate row cursor before the inner loop, and tests
`y < 16`; VC6 strength-reduces the retained row-from-index source to a
row-end comparison and advances the row pointer after the inner loop. The
uniform cursor spelling still triggers the documented whole-function
allocation cliff. The remaining residual is therefore a bounded backend
induction choice rather than missing state, type, or referenced data.

## Shared row-cursor identity audit

`shared-row-cursor-lifetime-interactions.json` tests the last plausible way to
obtain the uniform final-grid cursor without adding a fifth compiler local. It
declares one function-scoped row cursor and exhaustively crosses its reuse in
the font, 2x2, 4x4, 8x8, and 16x16 loops.

All **63/63** combinations were evaluated. The declaration and every
combination limited to the first four loops are byte-identical to the retained
**98.35%**, **425/425**, `refs=166/0/0` object. Every combination that also
uses the cursor in the final 16x16 loop falls to the same **64.71%**,
`refs=103/0/21` allocation cliff, including the full six-site reuse. Cursor
identity and compiler-local count therefore do not explain the final induction
choice; the source-shape route is saturated pending new compiler or
translation-unit provenance.

## Typed row and interior-V hybrid audit (2026-08-11)

`final-grid-typed-row-v-anchor-mutations.json` crosses the previously separate
typed `GrimUV *` row cursor and interior `float *` V-field cursor hypotheses.
All four ordinary preincrement, outer-increment, indexed, and copied-entry
forms trigger the same whole-function allocation cliff: the best reaches only
64.71% with `103/0/21` references. The missing final-grid induction is not a
typed-row/interior-field interaction.

## Texture-predecessor translation-unit closure

`grim_draw_text_mono` proved that VC6 global-optimizer state can depend on an
immediate predecessor, so this scratch was compiled after its complete native
texture predecessor chain: name comparison, named lookup, free-slot lookup,
and file loading. The combined source preserves native address order and the
canonical target profile.

The result is byte-identical to the standalone **98.35294%**, 425/425,
prefix-397, `166/0/0` candidate. Its wrapper SHA-256 is
`34b5f49f640965d3dfd1c88a1e4aaa5048559aa5f1b6381e94ebb6e3661d22e7`;
the dependency-aware source-tree SHA-256 is
`f91b9bf5812ec40f70f17b04f65b3ec68c42f2a96ac20400efa7624d92f60276`.
The final-grid induction is therefore not another immediate-predecessor TU
effect.

## Full texture-island translation-unit closure

The narrower predecessor replay was expanded to every recovered texture
function before `grim_state_init` in native address order: texture init and
release, extension testing, JAZ decode, file loading, name comparison, named
lookup, free-slot lookup, and internal loading. Scratch-local identities are
renamed only where independently recovered files would otherwise collide.

The complete island remains byte-identical to the standalone **98.35294%**,
425/425-instruction, prefix-397, `166/0/0` candidate. The recorded wrapper
SHA-256 is
`d64707f54626d29fe6477e9bd2b98e8b2ed7b144f2cc98bc2b2300f8e8af1fc2`;
its dependency-aware source-tree SHA-256 is
`1f5ef2a340009ce0a4e54f2949b32eb59815b9621a29d58d994f8f218cee4d88`.
This closes the broader texture-island optimizer-context hypothesis without
changing the canonical source.

## Final-grid type and stack-coloring audit (2026-08-14)

`final-grid-original-type-interactions.json` crosses the target-era `GrimUV`
union/storage spelling, its constructor body, the recovered `GrimDepth`
constructor body, and the native-looking final 16x16 row cursor. The three
original type and constructor spellings are byte-neutral on their own. Every
combination containing the native-looking cursor falls to the same **64.71%**,
425/425-instruction, prefix-zero, `103/21/0` object. The original aggregate
definitions therefore do not restore the native induction schedule.

`final-grid-matrix-cursor-interaction.json` repeats the test with the complete
`GrimUV[16][16]` storage declaration and first-row pointer publication. Its
only valid three-site combination reaches the identical allocation cliff, so
flat-versus-matrix ownership is also closed.

A direct object diff identifies the mechanism. The uniform row cursor lets
VC6 shrink the stack frame from native `0x14` bytes to `0x10` and coalesce the
outer and inner integer-to-float conversion spills at `[esp+0xc]`. Native keeps
the outer `y` spill at `[esp+0xc]` and the inner `x` spill at `[esp+0x10]`.
The retained row-from-index spelling preserves that native frame and all 397
preceding exact instructions, leaving only the final loop's backend induction
choice. Artificial address-taking, volatility, or dummy dependencies would
force layout rather than recover source and are not justified.

## Published-pointer, successor-TU, and cursor-reuse audit (2026-08-15)

Live Binary Ninja initially skipped this function
(`ExceedFunctionAnalysisTimeSkipReason`), so `bn decompile` / `bn il` returned
an empty body. Forced analysis recovers HLIL and confirms the 16x16 tail is the
same V-field row/entry cursor shape as the 2x2, 4x4, and 8x8 grids: `y` in
`ESI`, row cursor in `EDX` advanced by `0x80` before the inner loop, inner `x`
in `ECX` spilled at `[esp+0x10]`, and `cmp esi, 0x10` / `jl`.

`final-grid-published-pointer-mutations.json` tests eight previously untried
final-loop forms. Walking the already-published `grim_subrect_ptr_table[16]`
pointer, a local `GrimUV *table`, `do/while`, `!=`, and `while` either stay
byte-identical at **98.35%** / prefix **397** / `refs=166/0/0` or fall to the
same **64.71%** / prefix-zero / `103/0/21` allocation cliff. No tradeoff-free
improvement.

`probe_successor_translation_unit.cpp` compiles `grim_state_init` with the
immediately following `grim_lookup_blob_load`. The object is byte-identical to
the standalone candidate but loses three resolved references. A parameterized
shared helper for all four grids, including `__forceinline`, is worse
(**81.82%** / **64.71%**). `final-grid-cursor-reuse-mutations.json` then
swaps the 8x8 and 16x16 control shapes and reuses the 8x8 row cursor into the
16x16 loop; the best result is again byte-identical, and every native-looking
16x16 cursor still cliffs.

A later `GrimUV(*)[16]` view of the existing 256-entry table is also
byte-neutral unless the native cursor is reintroduced. The remaining residual
is still the final-loop backend induction: VC6 strength-reduces
`&grim_subrect_table[y * 16].v` to a row-end comparison and advances the row
after the inner loop. Emitting the native `add edx, 0x80` / `cmp esi, 0x10`
schedule on that last grid changes whole-function allocation. Do not force
that layout with volatility or dummy liveness.

## Exact atlas-counter lifetime recovery (2026-08-15)

The collapsed scores hid a useful backend clue. A final-grid row cursor with
the `v` store written directly from `y` emits the native 425-instruction
control shape and preserves all 166 resolved references. Its only material
difference is global stack coloring: VC6 assigns outer `y` to `[esp+0x10]`
and inner `x` to `[esp+0xc]`, the reverse of native, across the font atlas and
all four subrect grids. Initializer order, declaration order and location,
`register`, `long` / `__int32`, cursor scheduling, and row-value statement
order do not reverse those homes.

A mixed-scope diagnostic isolates the constraint. Keeping the shared outer
`y` but declaring a local inner counter only in the final grid makes the
entire 16x16 tail byte-exact: `y` stays at `[esp+0xc]` and the local counter
uses `[esp+0x10]`. The earlier cursor loops still coalesce their shared inner
counter with `y`, so that isolated form reaches 97.18% rather than matching.

`all-grid-shared-row-local-column-mutations.json` applies the same ordinary
source lifetime to every atlas initializer: retain the shared outer `y`, use
a block-local `column` for each inner loop, and write the invariant row value
directly from `y`. All 31 combinations were evaluated. Four combinations are
exact, including the coherent five-grid form retained in `scratch.cpp`.
That source produces **100.00%**, an exact **425/425** instruction prefix,
and references **166/0/0**. The fakematch validator passes.

For historical provenance, the archived official Grim2D 1.2.1 SDK package
contains the authenticated older DLL but no engine source. Its older state
initializer uses the same V-field cursor family and coalesces its conversion
spills, which is consistent with the observed VC6 behavior but does not by
itself identify the later source lifetime.
