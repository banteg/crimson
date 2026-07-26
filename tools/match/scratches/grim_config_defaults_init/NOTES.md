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

VC6 `/O2 /GB` produces the same semantic-complete candidate as the executable
copy: 77.74%, 140 native versus 143 candidate normalized instructions, and
references `65/0/2`. The remaining mismatch is compiler scheduling and register
allocation around the saved-name loop, plus the associated relocated-reference
ordering; it is not missing behavior. No inline assembly, volatile state,
dummy references, forced addresses, or layout-only expressions are used.
