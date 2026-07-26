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

The nine reported reference mismatches were audited as alignment artifacts in
the single constructor/store-scheduling region. Every native destination is
also present as an exact candidate relocation, including all four words of
config value `0x64` (`grim_config_values + 0x640..0x64c`), the config-value
words at offsets `0x120..0x14c`, and current-UV destinations `0x1005b294` and
`0x1005b298`. The latter are emitted through `grim_uv_u0 + 4` and
`grim_uv_u1`, respectively. The matcher pairs them with nearby scheduled stores
after the instruction streams diverge, but no referenced destination is
missing or unresolved. The residual is therefore compiler-only.
