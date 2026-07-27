# mod_api_init

Native target: `crimsonland.exe` at `0x40dfa0` (21 bytes).

The data reference from the CRT initializer table at `0x471018` identifies
this as the inlined global constructor for `mod_api_context`. VC6 installs the
class vtable and writes `1` to the context tail field at offset `0x68`. The
field is intentionally offset-named because its meaning is not yet proven.

The named provider placement-constructs the external object. Static storage
makes its address non-null; expressing that invariant retains the exact
three-instruction constructor and both native references without a hand-written
vtable store. The object now defines `_mod_api_init` directly instead of the
compiler-local `_$E1` identity.
