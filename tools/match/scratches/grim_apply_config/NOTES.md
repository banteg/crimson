# grim_apply_config

`grim_apply_config` is the vtable slot `0x10` method at `0x10005d40`. It lazily
loads the dialog icon, creates a temporary Direct3D8 interface, captures device
capabilities, runs dialog resource `0x74`, and releases the temporary interface.

Direct3D creation failure records the native error text, shows a `Grim`
message box, and returns false. A canceled dialog returns false without
applying settings. Accepted settings update config IDs `0x54`, `0x2b`, `8`,
`0x34`, `8`, `0x29`, and `0x2a` in that native order; the duplicated `0x54`
and `8` writes are intentionally preserved.

The `grim_config_value_t` boolean constructor writes only its first byte,
whereas integer values write the first dword. Those overloads reproduce the
native 16-byte by-value calls without an ABI shim. The recovered method matches
all 124 native instructions and all 25 references under MSVC 6.5 `/O2 /GB`.
