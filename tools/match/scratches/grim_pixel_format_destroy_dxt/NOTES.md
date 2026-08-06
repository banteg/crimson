# `grim_pixel_format_destroy_dxt`

Native target: `grim.dll` at `0x10016c3c`, 160 bytes and 49 normalized
instructions.

The recovered destructor releases every per-block cache allocation when the
cache is active and its entry table is present. It walks columns from
`column_begin` to `column_end` and rows from `row_begin` to `row_end` in
four-byte steps, advancing one eight-byte cache entry per block. The two outer
allocations at offsets `0x10b8` and `0x10c0` are then released unconditionally,
before the base vertex-space converter destructor runs.

MSVC 6.5 with `/O1 /G6 /W3 /GR- /GX /MD` reproduces the native 49-instruction
control-flow graph and reaches 75.51% similarity with a 14-instruction exact
prefix. Six relocations are resolved. The remaining unresolved relocation is
the compiler-generated local exception-handler label; it is not exposed as a
selectable COFF function symbol and is therefore not assigned a fabricated
alias.

The byte-level delta is confined to loop allocation and one inner-loop
precheck. Native assigns the outer counter to `ebx` and the row cursor to
`edi`, entering the inner condition through a jump. The available compiler
assigns those two registers in the opposite order and emits an equivalent
`cmp`/`jae` precheck. MSVC 7.0 reproduces the same instruction count and
control-flow shape but retains the register swap. MSVC 6.0, 6.5 Processor
Pack, 6.6, `/Oa`, `/Ow`, `/Oy-`, `/Ob0`, `/Ob2`, `/G5`, `/GB`, and `/G7`
either preserve the residual or regress the result. Pointer-versus-integer
cursor types, explicit `register`, and natural guard/lifetime rewrites also do
not recover the native allocation.

No inline assembly, volatile state, dummy dependency, or fake relocation is
retained. The source is classified `semantic-complete` with `compiler` and
`references` residuals.
