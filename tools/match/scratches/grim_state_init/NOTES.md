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

Microsoft Visual C++ 6.5 with `/O2 /GB /W3 /GR-` currently produces a
`78.67%` match with a `167/425` exact instruction prefix, `425/414`
target/candidate instructions, and references `134/0/9`. All references
resolve. Direct row-major indexing reproduces the native interleaved UV
field references without layout padding or byte-level match constructs.

The remaining diff is compiler-shaped: scheduling of the configuration-value
constructor temporaries and current-UV stores, direct versus import-indirect
`strdup`, and counter-versus-end-pointer forms for the atlas loops. Every
observed state store, callback assignment, allocation/copy, and table loop is
represented, so the recovery is marked semantic-complete rather than exact.

A focused atlas-loop source-shape check rejected row locals and explicit
row-pointer increments (both fell to 78.19%). Reusing shared `x`/`y` counters
and spelling the grids as two-dimensional arrays compile byte-identically to
the retained flat row-major form. These variants therefore do not recover the
native outer-counter allocation and are not retained.

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
