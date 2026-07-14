# mod_api_init

Native target: `crimsonland.exe` at `0x40dfa0` (21 bytes).

The data reference from the CRT initializer table at `0x471018` and the
generated `_E1` candidate identify this as the inlined global constructor for
`mod_api_context`. VC6 installs the class vtable and writes `1` to the context
tail field at offset `0x68`. The field is intentionally offset-named because
its meaning is not yet proven.

The compiler-generated initializer matches all 3 instructions and both native
references exactly; no hand-written vtable store is used.
