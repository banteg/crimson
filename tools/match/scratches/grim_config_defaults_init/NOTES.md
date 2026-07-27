# `grim_config_defaults_init`

Native target: `grim.dll` at `0x10001710` (734 bytes).

The complete native instruction stream is identical to the executable's
`config_init_defaults` at `0x004028f0` after image relocations are normalized.
Both functions have the same 734-byte extent, 140 instructions, stack layout,
saved-name loop, configuration stores, and final `0x17e` EAX residue.

The two images therefore compile the same recovered implementation against
different instances of the 0x480-byte `crimson_cfg_t` blob. The shared
`crimson_config_defaults_impl.h` body records that provenance without
duplicating or coercing source.

The stock VC6 `/O2 /GB` profile produced 77.74%, 140 native versus 143
candidate normalized instructions, and references `65/0/2`. Live comparison
with the byte-identical executable copy then isolated the same profitable
function-local frame-pointer override: compiling the shared implementation with
`/O2 /GB /Oy- /W3 /GR-` raises the scratch to 86.62%, 144 candidate
instructions, and references `80/0/0`.

The `/Oy-` override is retained because the independently matched executable
copy of this exact function body already carries the same focused profile
evidence, not because of a broad profile search. It removes both apparent
reference conflicts and recovers all 80 referenced destinations. The remaining
mismatch is compiler scheduling and register allocation around the saved-name
loop; it is not missing behavior. No inline assembly, volatile state, dummy
references, forced addresses, or layout-only expressions are used, and the
residual remains compiler-only.

A fresh stock-VC6 matrix confirms the focused override. `/G5`, `/Ob1`, and
explicit `/Ot` are byte-identical when combined with `/Oy-`; removing `/Oy-`
falls to 77.74% with two reference conflicts, and `/G6 /Oy-` falls to 71.83%.
The retained `/O2 /GB /Oy- /W3 /GR-` profile remains the only justified local
configuration and keeps all 80 references exact.
